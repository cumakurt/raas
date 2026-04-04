from __future__ import annotations

import json
import logging
import os
import pwd
import shutil
import subprocess
from pathlib import Path

logger = logging.getLogger(__name__)


def _environ_from_pid(pid: int) -> dict[str, str]:
    env: dict[str, str] = {}
    try:
        raw = Path(f"/proc/{pid}/environ").read_bytes()
    except OSError:
        return env
    for pair in raw.split(b"\0"):
        if not pair or b"=" not in pair:
            continue
        k, _, v = pair.partition(b"=")
        try:
            env[k.decode(errors="replace")] = v.decode(errors="replace")
        except Exception:
            continue
    return env


def _leader_env_for_uid(uid: int) -> dict[str, str]:
    """DISPLAY / WAYLAND_DISPLAY from the graphical session leader (loginctl)."""
    try:
        r = subprocess.run(
            ["loginctl", "list-sessions", "--json=short"],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
    except FileNotFoundError:
        return {}
    if r.returncode != 0 or not r.stdout.strip():
        return {}
    try:
        sessions = json.loads(r.stdout)
    except json.JSONDecodeError:
        return {}
    for s in sessions:
        raw_uid = s.get("uid")
        if raw_uid is None:
            continue
        try:
            if int(raw_uid) != uid:
                continue
        except (TypeError, ValueError):
            continue
        leader = s.get("leader")
        if leader is None:
            continue
        try:
            pid = int(leader)
        except (TypeError, ValueError):
            continue
        env = _environ_from_pid(pid)
        if env.get("DISPLAY") or env.get("WAYLAND_DISPLAY"):
            return env
    return {}


def _merged_subprocess_env(desktop_uid: int, session_env: dict[str, str]) -> dict[str, str]:
    env = os.environ.copy()
    for k in ("DISPLAY", "WAYLAND_DISPLAY", "XDG_SESSION_TYPE"):
        if session_env.get(k):
            env[k] = session_env[k]
    rt = f"/run/user/{desktop_uid}"
    if Path(rt).exists():
        env["XDG_RUNTIME_DIR"] = rt
    return env


def _run_as_user(
    cmd: list[str],
    *,
    desktop_uid: int,
    session_env: dict[str, str],
    timeout_seconds: float,
) -> subprocess.CompletedProcess[bytes]:
    runuser = shutil.which("runuser")
    use_runuser = os.getuid() == 0 and desktop_uid != 0 and runuser
    if use_runuser:
        try:
            uname = pwd.getpwuid(desktop_uid).pw_name
        except KeyError:
            return subprocess.CompletedProcess(cmd, -1, b"", b"")
        rt = f"/run/user/{desktop_uid}"
        prefix = [
            runuser,
            "-u",
            uname,
            "--",
            "env",
        ]
        if session_env.get("WAYLAND_DISPLAY"):
            prefix.append(f"WAYLAND_DISPLAY={session_env['WAYLAND_DISPLAY']}")
        if session_env.get("DISPLAY"):
            prefix.append(f"DISPLAY={session_env['DISPLAY']}")
        prefix.append(f"XDG_RUNTIME_DIR={rt}")
        full = prefix + cmd
        return subprocess.run(
            full,
            capture_output=True,
            timeout=timeout_seconds,
            check=False,
        )
    return subprocess.run(
        cmd,
        capture_output=True,
        timeout=timeout_seconds,
        env=_merged_subprocess_env(desktop_uid, session_env),
        check=False,
    )


def capture_screen_png(*, desktop_uid: int, timeout_seconds: float = 15.0) -> bytes | None:
    """
    Capture the current screen as PNG bytes.
    Uses the desktop user's DISPLAY / WAYLAND_DISPLAY (from session leader).
    When RAAS runs as root, runs grim/ffmpeg/import via runuser.
    """
    session_env = _leader_env_for_uid(desktop_uid)
    try:
        uname = pwd.getpwuid(desktop_uid).pw_name
    except KeyError:
        uname = ""

    wayland = session_env.get("WAYLAND_DISPLAY")
    display = session_env.get("DISPLAY")

    grim = shutil.which("grim")
    if wayland and grim:
        r = _run_as_user([grim, "-"], desktop_uid=desktop_uid, session_env=session_env, timeout_seconds=timeout_seconds)
        if r.returncode == 0 and r.stdout and len(r.stdout) > 100:
            return r.stdout
        logger.debug("grim stderr: %s", (r.stderr or b"")[:300])

    ffmpeg = shutil.which("ffmpeg")
    if display and ffmpeg:
        disp = display.split()[0] if display else ":0"
        r = _run_as_user(
            [
                ffmpeg,
                "-hide_banner",
                "-loglevel",
                "error",
                "-y",
                "-f",
                "x11grab",
                "-framerate",
                "1",
                "-i",
                disp,
                "-frames:v",
                "1",
                "-f",
                "image2pipe",
                "-vcodec",
                "png",
                "-",
            ],
            desktop_uid=desktop_uid,
            session_env=session_env,
            timeout_seconds=timeout_seconds,
        )
        if r.returncode == 0 and r.stdout and len(r.stdout) > 100:
            return r.stdout
        logger.debug("ffmpeg stderr: %s", (r.stderr or b"")[:300])

    import_bin = shutil.which("import")
    if display and import_bin:
        r = _run_as_user(
            [import_bin, "-silent", "-window", "root", "png:-"],
            desktop_uid=desktop_uid,
            session_env=session_env,
            timeout_seconds=timeout_seconds,
        )
        if r.returncode == 0 and r.stdout and len(r.stdout) > 100:
            return r.stdout
        logger.debug("import stderr: %s", (r.stderr or b"")[:300])

    if not wayland and not display:
        logger.warning(
            "Screen capture skipped: no DISPLAY/WAYLAND in session leader env for uid=%s (%s).",
            desktop_uid,
            uname or "?",
        )
    else:
        logger.warning(
            "Screen capture failed for uid=%s — install grim (Wayland) or ffmpeg/ImageMagick (X11).",
            desktop_uid,
        )
    return None
