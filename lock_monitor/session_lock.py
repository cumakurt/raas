from __future__ import annotations

import json
import logging
import os
import pwd
import shutil
import subprocess
import time
from pathlib import Path

logger = logging.getLogger(__name__)

# Log once if session DBus is unreachable (wrong uid / permission).
_dbus_access_warned = False
# Log once if runuser+gdbus fails for root (helps debug "input but not locked").
_runuser_gdbus_fail_logged = False
_runuser_missing_logged = False

_CACHE: tuple[bool | None, float] = (None, 0.0)
_CACHE_TTL_SEC = 0.15

# Session screensaver / lock — GetActive == True means lock screen or saver is active.
# systemd LockedHint is often "no" on GNOME/MATE/XFCE even when the screen is locked.
_DBUS_GET_ACTIVE: tuple[tuple[str, str, str], ...] = (
    ("org.gnome.ScreenSaver", "/org/gnome/ScreenSaver", "org.gnome.ScreenSaver.GetActive"),
    ("org.mate.ScreenSaver", "/org/mate/ScreenSaver", "org.mate.ScreenSaver.GetActive"),
    ("org.cinnamon.ScreenSaver", "/org/cinnamon/ScreenSaver", "org.cinnamon.ScreenSaver.GetActive"),
    ("org.kde.screensaver", "/ScreenSaver", "org.kde.screensaver.GetActive"),
    ("org.kde.screensaver", "/org/kde/ScreenSaver", "org.kde.screensaver.GetActive"),
    ("org.xfce.ScreenSaver", "/org/xfce/ScreenSaver", "org.xfce.ScreenSaver.GetActive"),
)


def _session_bus_env_for_uid(uid: int) -> dict[str, str]:
    """Build env for the given login uid's session bus (needed when RAAS runs as root)."""
    env = os.environ.copy()
    if os.getuid() == uid and os.environ.get("DBUS_SESSION_BUS_ADDRESS"):
        return env
    bus = f"/run/user/{uid}/bus"
    if os.path.exists(bus):
        env["DBUS_SESSION_BUS_ADDRESS"] = f"unix:path={bus}"
    elif uid == os.getuid() and "DBUS_SESSION_BUS_ADDRESS" not in env:
        pass
    return env


def _seat_session_uids() -> list[int]:
    """
    Uids likely to own the graphical session bus.

    Prefer sessions with a seat; also include user sessions of type x11/wayland when seat is
    missing or '-' (some setups omit seat in loginctl JSON).
    """
    try:
        r = subprocess.run(
            ["loginctl", "list-sessions", "--json=short"],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
    except FileNotFoundError:
        return []
    if r.returncode != 0 or not r.stdout.strip():
        return []
    try:
        sessions = json.loads(r.stdout)
    except json.JSONDecodeError:
        return []
    uids: set[int] = set()
    for s in sessions:
        raw_uid = s.get("uid")
        if raw_uid is None:
            continue
        try:
            uid = int(raw_uid)
        except (TypeError, ValueError):
            continue
        if uid == 0:
            continue
        class_ = str(s.get("class") or "").lower()
        if class_ not in ("user", ""):
            continue
        typ = str(s.get("type") or "").lower()
        seat = s.get("seat")
        has_seat = seat is not None and str(seat) not in ("", "-")
        is_graphical = typ in ("x11", "wayland")
        if has_seat or is_graphical:
            uids.add(uid)
    return sorted(uids)


def _dbus_uids_to_probe() -> list[int]:
    """
    Uids whose session bus we query.
    As root: prefer users with a seat session, then any uid with /run/user/<uid>/bus.
    """
    uid = os.getuid()
    if uid != 0:
        return [uid]

    seat_uids = _seat_session_uids()
    run_user = Path("/run/user")
    if not run_user.is_dir():
        logger.warning("/run/user missing — cannot locate session DBus sockets")
        return []

    ordered: list[int] = []
    seen: set[int] = set()
    for u in seat_uids:
        if (Path(f"/run/user/{u}/bus")).exists():
            ordered.append(u)
            seen.add(u)
    for child in sorted(run_user.iterdir(), key=lambda p: p.name):
        if not child.name.isdigit():
            continue
        if not (child / "bus").exists():
            continue
        u = int(child.name)
        if u not in seen:
            ordered.append(u)
            seen.add(u)
    if not ordered:
        logger.warning(
            "No /run/user/<uid>/bus sockets found — DBus lock detection unavailable. "
            "Is a graphical user session running?",
        )
    return ordered


def _log_runuser_gdbus_failure(r: subprocess.CompletedProcess[str], dest: str) -> None:
    global _runuser_gdbus_fail_logged
    if _runuser_gdbus_fail_logged or os.getuid() != 0:
        return
    if r.returncode == 0:
        return
    err = (r.stderr or "") + (r.stdout or "")
    if "ServiceUnknown" in err or "was not provided" in err or "does not exist" in err:
        return
    _runuser_gdbus_fail_logged = True
    logger.warning(
        "runuser+gdbus failed for %s (exit=%s). Sample stderr: %s",
        dest,
        r.returncode,
        (err[:500] or "(empty)").strip(),
    )


def _parse_gdbus_bool(r: subprocess.CompletedProcess[str]) -> bool | None:
    """Interpret gdbus exit code and stdout; update _dbus_access_warned on hard failures."""
    global _dbus_access_warned
    err = (r.stderr or "") + (r.stdout or "")
    if r.returncode != 0:
        if not _dbus_access_warned and (
            "Permission denied" in err or "Could not connect" in err
        ):
            logger.warning(
                "DBus session bus not usable (%s). As root, ensure util-linux (runuser) is installed "
                "so RAAS can query the desktop user's session bus.",
                (err[:200] or "error").strip(),
            )
            _dbus_access_warned = True
        if "ServiceUnknown" in err or "was not provided" in err or "does not exist" in err:
            return None
        return None

    out = (r.stdout or "").strip()
    if out.startswith("(true") or out == "true":
        return True
    if out.startswith("(false") or out == "false":
        return False
    return None


def _gdbus_get_active(dest: str, object_path: str, method: str, *, for_uid: int) -> bool | None:
    """
    Call GetActive on a screensaver interface for the given login uid's session bus.

    When RAAS runs as root, we invoke gdbus via `runuser` so the connection matches the
    desktop user's session bus (direct root access is often rejected).
    """
    global _runuser_missing_logged
    bus_path = f"/run/user/{for_uid}/bus"
    if not os.path.exists(bus_path):
        return None

    gdbus = shutil.which("gdbus")
    if not gdbus:
        return None

    use_runuser = os.getuid() == 0 and for_uid != 0
    runuser_bin = shutil.which("runuser") if use_runuser else None

    if use_runuser and not runuser_bin:
        if not _runuser_missing_logged:
            logger.warning(
                "util-linux `runuser` not in PATH — root cannot run gdbus as the desktop user. "
                "Install util-linux (e.g. apt install util-linux) or run RAAS without sudo.",
            )
            _runuser_missing_logged = True

    if use_runuser and runuser_bin:
        try:
            uname = pwd.getpwuid(for_uid).pw_name
        except KeyError:
            return None
        cmd = [
            runuser_bin,
            "-u",
            uname,
            "--",
            "env",
            f"DBUS_SESSION_BUS_ADDRESS=unix:path={bus_path}",
            f"XDG_RUNTIME_DIR=/run/user/{for_uid}",
            gdbus,
            "call",
            "--session",
            "--dest",
            dest,
            "--object-path",
            object_path,
            "--method",
            method,
        ]
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=3, check=False)
        except (OSError, subprocess.SubprocessError):
            return None
        _log_runuser_gdbus_failure(r, dest)
        return _parse_gdbus_bool(r)

    env = _session_bus_env_for_uid(for_uid)
    if not env.get("DBUS_SESSION_BUS_ADDRESS"):
        return None
    try:
        r = subprocess.run(
            [
                gdbus,
                "call",
                "--session",
                "--dest",
                dest,
                "--object-path",
                object_path,
                "--method",
                method,
            ],
            capture_output=True,
            text=True,
            timeout=2,
            env=env,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    return _parse_gdbus_bool(r)


def _locked_hint_dbus() -> bool:
    """True if any known session screensaver reports active (locked / saver on)."""
    uids = _dbus_uids_to_probe()
    if not uids:
        return False
    for uid in uids:
        for dest, path, method in _DBUS_GET_ACTIVE:
            v = _gdbus_get_active(dest, path, method, for_uid=uid)
            if v is True:
                return True
    return False


# Standalone lockers often expose no DBus; detect by process name (exact match).
_LOCK_SCREEN_PROCS = (
    "swaylock",
    "i3lock",
    "gtklock",
    "hyprlock",
    "xsecurelock",
    "waylock",
    "light-locker",
    "slock",
    "xlock",
)


def _locked_hint_process() -> bool:
    pgrep = shutil.which("pgrep")
    if not pgrep:
        return False
    for name in _LOCK_SCREEN_PROCS:
        try:
            r = subprocess.run(
                ["pgrep", "-x", name],
                capture_output=True,
                timeout=2,
                check=False,
            )
            if r.returncode == 0:
                return True
        except OSError:
            continue
    return False


def _session_locked_combined() -> bool:
    """DBus screensaver, systemd logind LockedHint, or known lock-screen process."""
    if _locked_hint_dbus():
        return True
    if _locked_hint_loginctl():
        return True
    if _locked_hint_process():
        return True
    return False


def format_lock_diagnosis() -> str:
    """Human-readable snapshot for `raas.py --diagnose-lock`."""
    lines: list[str] = ["=== RAAS lock detection ===", f"getuid()={os.getuid()}"]
    uids = _dbus_uids_to_probe()
    lines.append(f"graphical/logind uids: {_seat_session_uids()}")
    lines.append(f"DBus uids to probe: {uids}")
    if os.getuid() == 0:
        lines.append(f"runuser for session gdbus: {shutil.which('runuser') or '(not found — install util-linux)'}")
    if not uids:
        lines.append("(no session bus paths — DBus lock checks skipped)")
    for uid in uids:
        bus = f"unix:path=/run/user/{uid}/bus"
        lines.append(f"uid={uid} bus={bus}")
        for dest, path, method in _DBUS_GET_ACTIVE:
            v = _gdbus_get_active(dest, path, method, for_uid=uid)
            lines.append(f"  {dest} GetActive -> {v}")
    lines.append(f"loginctl LockedHint (any session): {_locked_hint_loginctl()}")
    lines.append(f"pgrep lock-screen procs: {_locked_hint_process()}")
    invalidate_lock_cache()
    lines.append(f"combined (fresh): {_session_locked_combined()}")
    return "\n".join(lines)


def is_session_locked(*, use_cache: bool = True) -> bool:
    """
    True if the graphical session appears locked or the screen saver is active.

    Uses DBus (GNOME/MATE/Cinnamon/KDE/XFCE screensaver GetActive) first, then
    systemd logind LockedHint. Plain logind is unreliable on many desktops.

    - Normal user: any session belonging to the current UID (logind path).
    - root (e.g. systemd service): any session on the system (logind path).
    """
    global _CACHE
    now = time.monotonic()
    if use_cache and _CACHE[0] is not None and (now - _CACHE[1]) < _CACHE_TTL_SEC:
        return _CACHE[0]

    locked = _session_locked_combined()
    _CACHE = (locked, now)
    return locked


def invalidate_lock_cache() -> None:
    global _CACHE
    _CACHE = (None, 0.0)


def _locked_hint_loginctl() -> bool:
    my_uid = os.getuid()
    if my_uid == 0:
        return _any_user_session_locked_hint()
    try:
        r = subprocess.run(
            ["loginctl", "list-sessions", "--json=short"],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
    except FileNotFoundError:
        logger.warning("loginctl not found — cannot detect screen lock")
        return False

    if r.returncode == 0 and r.stdout.strip():
        try:
            sessions = json.loads(r.stdout)
            for s in sessions:
                uid = s.get("uid")
                if uid is None:
                    continue
                try:
                    if int(uid) != my_uid:
                        continue
                except (TypeError, ValueError):
                    continue
                sid = s.get("session") or s.get("id")
                if sid is None:
                    continue
                if _session_locked_hint(str(sid)):
                    return True
            return False
        except json.JSONDecodeError:
            pass

    return _locked_hint_parse_text(my_uid)


def _any_user_session_locked_hint() -> bool:
    """When running as root, detect lock on any graphical/login session (service context)."""
    try:
        r = subprocess.run(
            ["loginctl", "list-sessions", "--json=short"],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
    except FileNotFoundError:
        logger.warning("loginctl not found — cannot detect screen lock")
        return False

    if r.returncode == 0 and r.stdout.strip():
        try:
            sessions = json.loads(r.stdout)
            for s in sessions:
                sid = s.get("session") or s.get("id")
                if sid is None:
                    continue
                if _session_locked_hint(str(sid)):
                    return True
            return False
        except json.JSONDecodeError:
            pass

    try:
        r = subprocess.run(
            ["loginctl", "list-sessions", "--no-legend"],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
    except FileNotFoundError:
        return False

    if r.returncode != 0:
        return False

    for line in r.stdout.strip().splitlines():
        parts = line.split()
        if not parts:
            continue
        sid = parts[0]
        if _session_locked_hint(sid):
            return True
    return False


def _locked_hint_parse_text(my_uid: int) -> bool:
    try:
        r = subprocess.run(
            ["loginctl", "list-sessions", "--no-legend"],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
    except FileNotFoundError:
        return False

    if r.returncode != 0:
        return False

    for line in r.stdout.strip().splitlines():
        parts = line.split()
        if len(parts) < 2:
            continue
        sid = parts[0]
        try:
            uid = int(parts[1])
        except ValueError:
            continue
        if uid != my_uid:
            continue
        if _session_locked_hint(sid):
            return True
    return False


def _session_locked_hint(session_id: str) -> bool:
    try:
        r = subprocess.run(
            ["loginctl", "show-session", session_id, "-p", "LockedHint"],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
    except FileNotFoundError:
        return False

    if r.returncode != 0:
        return False

    for pline in r.stdout.splitlines():
        if pline.startswith("LockedHint="):
            return pline.split("=", 1)[1].strip() == "yes"
    return False
