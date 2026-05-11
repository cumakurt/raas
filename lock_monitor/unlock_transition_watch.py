from __future__ import annotations

import logging
import os
import threading

from config.settings import Settings
from lock_monitor.intrusion_notify import LockMediaThrottle, send_lock_intrusion_alert
from lock_monitor.session_lock import _dbus_uids_to_probe, is_session_locked
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


def run_unlock_transition_watch(
    settings: Settings,
    notifier: TelegramNotifier | None,
    telegram_ok: bool,
    stop_event: threading.Event,
    alarm_file: AlarmFileLogger | None,
    *,
    media_throttle: LockMediaThrottle,
) -> None:
    """
    When the session goes from locked to unlocked (successful unlock, etc.),
    send one notification. Does not read passwords.
    """
    if not settings.lock_intrusion.enabled:
        return
    if not settings.lock_intrusion.notify_on_unlock:
        return

    poll = max(0.1, float(settings.lock_intrusion.unlock_poll_interval_seconds))
    prev_locked: bool | None = None
    desktop_uid = _desktop_uid(settings)

    logger.info("Unlock transition watch active (poll=%ss)", poll)

    while not stop_event.is_set():
        if stop_event.wait(timeout=poll):
            break
        locked = is_session_locked(use_cache=True)
        if prev_locked is True and not locked:
            send_lock_intrusion_alert(
                settings,
                notifier,
                telegram_ok,
                alarm_file,
                input_kind="session_unlocked",
                desktop_uid=desktop_uid,
                media_throttle=media_throttle,
                extra_text="Screen lock released — session unlocked (successful authentication).",
            )
        prev_locked = locked
