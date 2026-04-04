from __future__ import annotations

import logging
import os
import threading
import time
from pathlib import Path

from config.settings import Settings
from lock_monitor.intrusion_notify import LockMediaThrottle, send_lock_intrusion_alert
from lock_monitor.lock_auth_patterns import is_probable_lock_screen_auth_failure
from lock_monitor.session_lock import _dbus_uids_to_probe, invalidate_lock_cache, is_session_locked
from notifier.telegram import TelegramNotifier
from utils.alarm_file_log import AlarmFileLogger

logger = logging.getLogger(__name__)


def _desktop_uid(settings: Settings) -> int:
    if settings.lock_intrusion.desktop_uid is not None:
        return int(settings.lock_intrusion.desktop_uid)
    uids = _dbus_uids_to_probe()
    if uids:
        return uids[0]
    return os.getuid()


def run_auth_unlock_watch(
    settings: Settings,
    notifier: TelegramNotifier | None,
    telegram_ok: bool,
    stop_event: threading.Event,
    alarm_file: AlarmFileLogger | None,
    *,
    media_throttle: LockMediaThrottle,
) -> None:
    """
    While the session is locked, poll auth.log for new lines that look like failed
    greeter/lock-screen authentication. Password characters are never read from evdev.
    """
    if not settings.lock_intrusion.enabled:
        return
    if not settings.lock_intrusion.watch_auth_failures:
        return

    path = Path(settings.log.path).expanduser()
    position = 0
    if path.is_file():
        try:
            position = path.stat().st_size
        except OSError:
            position = 0

    poll = max(0.1, float(settings.lock_intrusion.auth_poll_interval_seconds))
    last_emit = 0.0
    min_gap = max(0.0, float(settings.lock_intrusion.auth_failure_min_interval_seconds))

    logger.info(
        "Lock auth-failure watch active (poll=%ss, min_gap=%ss)",
        poll,
        min_gap,
    )

    while not stop_event.is_set():
        if stop_event.wait(timeout=poll):
            break
        invalidate_lock_cache()
        if not is_session_locked(use_cache=True):
            continue
        if not path.is_file():
            continue
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                f.seek(0, os.SEEK_END)
                size = f.tell()
                if size < position:
                    position = 0
                if size <= position:
                    continue
                f.seek(position)
                chunk = f.read()
                position = f.tell()
        except OSError as e:
            logger.debug("auth unlock watch read error: %s", e)
            continue

        for line in chunk.splitlines():
            line = line.strip()
            if not line or not is_probable_lock_screen_auth_failure(line):
                continue
            now = time.monotonic()
            if now - last_emit < min_gap:
                continue
            last_emit = now
            send_lock_intrusion_alert(
                settings,
                notifier,
                telegram_ok,
                alarm_file,
                input_kind="lock_auth_failure",
                desktop_uid=_desktop_uid(settings),
                media_throttle=media_throttle,
                extra_text="Failed unlock attempt (from auth log). Password is never sent by RAAS.",
                log_excerpt=line[:800],
            )
