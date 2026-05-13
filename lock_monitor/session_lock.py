from __future__ import annotations

import json
import logging
import os
import pwd
import re
import shutil
import subprocess
import threading
import time
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# Log once if session DBus is unreachable (wrong uid / permission).
_dbus_access_warned = False
# Log once if privilege-drop gdbus fails for root (helps debug "input but not locked").
_runuser_gdbus_fail_logged = False
_runuser_missing_logged = False

_CACHE: tuple[bool | None, float] = (None, 0.0)
_CACHE_LOCK = threading.Lock()
_CACHE_REFRESH_LOCK = threading.Lock()
_CACHE_TTL_SEC = 1.5
_SESSION_LIST_CACHE: tuple[list[dict[str, Any]] | None, float] = (None, 0.0)
_SESSION_LIST_TTL_SEC = 10.0
_DBUS_UIDS_CACHE: tuple[list[int] | None, float] = (None, 0.0)
_DBUS_UIDS_TTL_SEC = 10.0
_DBUS_METHOD_CACHE: dict[int, tuple[tuple[tuple[str, str, str], ...], float]] = {}
_DBUS_METHOD_TTL_SEC = 60.0
_DBUS_NO_METHOD_CACHE: dict[int, float] = {}
_DBUS_NO_METHOD_TTL_SEC = 10.0


def set_lock_cache_ttl(seconds: float) -> None:
    """How long is_session_locked(use_cache=True) may reuse a verdict (config: lock_intrusion.lock_state_cache_ttl_seconds)."""
    global _CACHE_TTL_SEC
    _CACHE_TTL_SEC = max(0.05, min(3.0, float(seconds)))


def _loginctl_sessions_json(*, use_cache: bool = True) -> list[dict[str, Any]]:
    global _SESSION_LIST_CACHE
    now = time.monotonic()
    with _CACHE_LOCK:
        cached, cached_at = _SESSION_LIST_CACHE
        if use_cache and cached is not None and (now - cached_at) < _SESSION_LIST_TTL_SEC:
            return list(cached)

    try:
        r = subprocess.run(
            ["loginctl", "list-sessions", "--json=short"],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
    except FileNotFoundError:
        sessions: list[dict[str, Any]] = []
    else:
        sessions = []
        if r.returncode == 0 and r.stdout.strip():
            try:
                raw = json.loads(r.stdout)
            except json.JSONDecodeError:
                raw = []
            if isinstance(raw, list):
                sessions = [s for s in raw if isinstance(s, dict)]

    with _CACHE_LOCK:
        _SESSION_LIST_CACHE = (sessions, time.monotonic())
    return list(sessions)


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
    sessions = _loginctl_sessions_json()
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
    global _DBUS_UIDS_CACHE
    uid = os.getuid()
    if uid != 0:
        return [uid]

    now = time.monotonic()
    with _CACHE_LOCK:
        cached, cached_at = _DBUS_UIDS_CACHE
        if cached is not None and (now - cached_at) < _DBUS_UIDS_TTL_SEC:
            return list(cached)

    seat_uids = _seat_session_uids()
    run_user = Path("/run/user")
    if not run_user.is_dir():
        logger.warning("/run/user missing — cannot locate session DBus sockets")
        with _CACHE_LOCK:
            _DBUS_UIDS_CACHE = ([], time.monotonic())
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
    with _CACHE_LOCK:
        _DBUS_UIDS_CACHE = (ordered, time.monotonic())
    return ordered


def _log_privdrop_gdbus_failure(
    r: subprocess.CompletedProcess[str],
    dest: str,
    helper: str,
) -> None:
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
        "%s+gdbus failed for %s (exit=%s). Sample stderr: %s",
        helper,
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
                "DBus session bus not usable (%s). As root, ensure util-linux (setpriv/runuser) is installed "
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

    When RAAS runs as root, we invoke gdbus as the desktop uid so the connection
    matches the user's session bus (direct root access is often rejected).
    """
    global _runuser_missing_logged
    bus_path = f"/run/user/{for_uid}/bus"
    if not os.path.exists(bus_path):
        return None

    gdbus = shutil.which("gdbus")
    if not gdbus:
        return None

    use_privdrop = os.getuid() == 0 and for_uid != 0
    setpriv_bin = shutil.which("setpriv") if use_privdrop else None
    runuser_bin = shutil.which("runuser") if use_privdrop else None

    if use_privdrop and not (setpriv_bin or runuser_bin):
        if not _runuser_missing_logged:
            logger.warning(
                "util-linux `setpriv`/`runuser` not in PATH — root cannot run gdbus as the desktop user. "
                "Install util-linux (e.g. apt install util-linux) or run RAAS without sudo.",
            )
            _runuser_missing_logged = True

    gdbus_call = [
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

    if use_privdrop and (setpriv_bin or runuser_bin):
        try:
            pwent = pwd.getpwuid(for_uid)
        except KeyError:
            return None

        if setpriv_bin:
            cmd = [
                setpriv_bin,
                "--reuid",
                str(for_uid),
                "--regid",
                str(pwent.pw_gid),
                "--init-groups",
                "env",
                f"DBUS_SESSION_BUS_ADDRESS=unix:path={bus_path}",
                f"XDG_RUNTIME_DIR=/run/user/{for_uid}",
                *gdbus_call,
            ]
            try:
                r = subprocess.run(cmd, capture_output=True, text=True, timeout=3, check=False)
            except (OSError, subprocess.SubprocessError):
                return None
            _log_privdrop_gdbus_failure(r, dest, "setpriv")
            return _parse_gdbus_bool(r)

        cmd = [
            runuser_bin,
            "-u",
            pwent.pw_name,
            "--",
            "env",
            f"DBUS_SESSION_BUS_ADDRESS=unix:path={bus_path}",
            f"XDG_RUNTIME_DIR=/run/user/{for_uid}",
            *gdbus_call,
        ]
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=3, check=False)
        except (OSError, subprocess.SubprocessError):
            return None
        _log_privdrop_gdbus_failure(r, dest, "runuser")
        return _parse_gdbus_bool(r)

    env = _session_bus_env_for_uid(for_uid)
    if not env.get("DBUS_SESSION_BUS_ADDRESS"):
        return None
    try:
        r = subprocess.run(
            gdbus_call,
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
    now = time.monotonic()
    for uid in uids:
        with _CACHE_LOCK:
            cached_methods, cached_at = _DBUS_METHOD_CACHE.get(uid, ((), 0.0))
            known_methods = cached_methods if now - cached_at < _DBUS_METHOD_TTL_SEC else ()
            if cached_methods and not known_methods:
                _DBUS_METHOD_CACHE.pop(uid, None)
            no_method_at = _DBUS_NO_METHOD_CACHE.get(uid, 0.0)
            no_methods_recent = bool(no_method_at and now - no_method_at < _DBUS_NO_METHOD_TTL_SEC)
            if no_method_at and not no_methods_recent:
                _DBUS_NO_METHOD_CACHE.pop(uid, None)

        if known_methods:
            responsive: list[tuple[str, str, str]] = []
            for dest, path, method in known_methods:
                v = _gdbus_get_active(dest, path, method, for_uid=uid)
                if v is True:
                    return True
                if v is False:
                    responsive.append((dest, path, method))
            if responsive:
                with _CACHE_LOCK:
                    _DBUS_METHOD_CACHE[uid] = (tuple(responsive), cached_at)
                    _DBUS_NO_METHOD_CACHE.pop(uid, None)
                continue
        elif no_methods_recent:
            continue

        responsive = []
        for dest, path, method in _DBUS_GET_ACTIVE:
            v = _gdbus_get_active(dest, path, method, for_uid=uid)
            if v is True:
                responsive.append((dest, path, method))
                with _CACHE_LOCK:
                    _DBUS_METHOD_CACHE[uid] = (tuple(responsive), now)
                    _DBUS_NO_METHOD_CACHE.pop(uid, None)
                return True
            if v is False:
                responsive.append((dest, path, method))
        if responsive:
            with _CACHE_LOCK:
                _DBUS_METHOD_CACHE[uid] = (tuple(responsive), now)
                _DBUS_NO_METHOD_CACHE.pop(uid, None)
        else:
            with _CACHE_LOCK:
                _DBUS_NO_METHOD_CACHE[uid] = time.monotonic()
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
    pattern = "|".join(re.escape(name) for name in _LOCK_SCREEN_PROCS)
    try:
        r = subprocess.run(
            ["pgrep", "-x", pattern],
            capture_output=True,
            timeout=2,
            check=False,
        )
    except OSError:
        return False
    return r.returncode == 0


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
    invalidate_lock_cache()
    lines: list[str] = ["=== RAAS lock detection ===", f"getuid()={os.getuid()}"]
    uids = _dbus_uids_to_probe()
    lines.append(f"graphical/logind uids: {_seat_session_uids()}")
    lines.append(f"DBus uids to probe: {uids}")
    if os.getuid() == 0:
        lines.append(f"setpriv for session gdbus: {shutil.which('setpriv') or '(not found — install util-linux)'}")
        lines.append(f"runuser fallback for session gdbus: {shutil.which('runuser') or '(not found — install util-linux)'}")
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
    with _CACHE_LOCK:
        if use_cache and _CACHE[0] is not None and (now - _CACHE[1]) < _CACHE_TTL_SEC:
            return _CACHE[0]

    with _CACHE_REFRESH_LOCK:
        now = time.monotonic()
        with _CACHE_LOCK:
            if use_cache and _CACHE[0] is not None and (now - _CACHE[1]) < _CACHE_TTL_SEC:
                return _CACHE[0]

        locked = _session_locked_combined()
        checked_at = time.monotonic()

        with _CACHE_LOCK:
            _CACHE = (locked, checked_at)
        return locked


def invalidate_lock_cache() -> None:
    global _CACHE, _DBUS_UIDS_CACHE, _SESSION_LIST_CACHE
    with _CACHE_LOCK:
        _CACHE = (None, 0.0)
        _DBUS_UIDS_CACHE = (None, 0.0)
        _SESSION_LIST_CACHE = (None, 0.0)
        _DBUS_METHOD_CACHE.clear()
        _DBUS_NO_METHOD_CACHE.clear()


def _locked_hint_loginctl() -> bool:
    my_uid = os.getuid()
    if my_uid == 0:
        return _any_user_session_locked_hint()
    sessions = _loginctl_sessions_json()
    if sessions:
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

    return _locked_hint_parse_text(my_uid)


def _any_user_session_locked_hint() -> bool:
    """When running as root, detect lock on any graphical/login session (service context)."""
    sessions = _loginctl_sessions_json()
    if sessions:
        for s in sessions:
            sid = s.get("session") or s.get("id")
            if sid is None:
                continue
            if _session_locked_hint(str(sid)):
                return True
        return False

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
