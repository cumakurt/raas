from __future__ import annotations

import logging
import os
import pwd
import select
import threading
import time

from config.settings import Settings
from lock_monitor.intrusion_notify import LockMediaThrottle, send_lock_intrusion_alert
from lock_monitor.session_lock import _dbus_uids_to_probe, is_session_locked
from notifier.telegram import TelegramNotifier
from utils.alarm_file_log import AlarmFileLogger

logger = logging.getLogger(__name__)


def _is_meaningful_event(ev: object, ecodes: object) -> bool:
    """Filter sync/repeat noise; count key down, mouse move, etc."""
    t = ev.type
    if t == ecodes.EV_SYN:
        return False
    if t == ecodes.EV_MSC:
        return False
    if t == ecodes.EV_KEY:
        if ev.value in (0, 2):
            return False
    return True


def _classify_input(ev: object, ecodes: object) -> str:
    """Describe the event for Telegram (English labels)."""
    if ev.type == ecodes.EV_KEY:
        if getattr(ev, "value", 0) != 1:
            return "unknown"
        code = getattr(ev, "code", 0)
        mouse_btns: set[int] = set()
        for name in (
            "BTN_LEFT",
            "BTN_RIGHT",
            "BTN_MIDDLE",
            "BTN_SIDE",
            "BTN_EXTRA",
            "BTN_FORWARD",
            "BTN_BACK",
            "BTN_TASK",
        ):
            v = getattr(ecodes, name, None)
            if v is not None:
                mouse_btns.add(int(v))
        if code in mouse_btns:
            return "mouse_button"
        return "keyboard"
    if ev.type == ecodes.EV_REL:
        return "mouse"
    if ev.type == ecodes.EV_ABS:
        return "touchpad_or_touchscreen"
    return "input"


def _desktop_uid_for_capture(settings: Settings) -> int:
    if settings.lock_intrusion.desktop_uid is not None:
        return int(settings.lock_intrusion.desktop_uid)
    uids = _dbus_uids_to_probe()
    if uids:
        return uids[0]
    return os.getuid()


def run_input_watch(
    settings: Settings,
    notifier: TelegramNotifier | None,
    telegram_ok: bool,
    stop_event: threading.Event,
    alarm_file: AlarmFileLogger | None = None,
    *,
    media_throttle: LockMediaThrottle | None = None,
) -> None:
    """Block until stop_event: watch input devices while lock-intrusion is enabled."""
    try:
        from evdev import InputDevice, ecodes, list_devices
    except ImportError:
        logger.error(
            "lock_intrusion requires the 'evdev' package. Install: pip install evdev",
        )
        return

    if not settings.lock_intrusion.enabled:
        return

    mt = media_throttle or LockMediaThrottle(settings.lock_intrusion.media_cooldown_seconds)

    devices: list = []
    for path in list_devices():
        try:
            dev = InputDevice(path)
        except OSError as e:
            logger.debug("Skip input device %s: %s", path, e)
            continue
        caps = dev.capabilities()
        has_key = ecodes.EV_KEY in caps
        has_rel = ecodes.EV_REL in caps
        has_abs = ecodes.EV_ABS in caps
        if not (has_key or has_rel or has_abs):
            dev.close()
            continue
        try:
            os.set_blocking(dev.fd, False)
        except (AttributeError, OSError, ValueError):
            pass
        devices.append(dev)

    if not devices:
        try:
            run_as = pwd.getpwuid(os.getuid()).pw_name
        except KeyError:
            run_as = "YOUR_USER"
        if os.getuid() == 0:
            logger.warning(
                "No accessible input devices (/dev/input/event*) — lock-intrusion input monitoring is disabled. "
                "As root, ensure /dev/input/* nodes exist and are readable; lock detection still uses "
                "DBus (via runuser), logind, and pgrep without input devices.",
            )
        else:
            logger.warning(
                "No accessible input devices (/dev/input/event*). Lock-intrusion input monitoring is disabled. "
                "Fix: sudo usermod -aG input %s  then log out and log back in (or reboot). "
                "Check: ls -l /dev/input/event0",
                run_as,
            )
        return

    cooldown = max(0.0, float(settings.lock_intrusion.cooldown_seconds))
    ptr_throttle = max(0.0, float(settings.lock_intrusion.pointer_move_throttle_seconds))

    logger.info(
        "Lock intrusion input monitor (%d device(s)): cooldown=%ss pointer_rel_throttle=%ss media_cd=%ss",
        len(devices),
        cooldown,
        ptr_throttle,
        settings.lock_intrusion.media_cooldown_seconds,
    )

    if not telegram_ok:
        logger.warning(
            "Telegram token/chat_id not set — lock-intrusion alerts will not be sent via Telegram "
            "(check config telegram.bot_token and telegram.chat_id).",
        )

    fds = [d.fd for d in devices]
    last_lock_deny_log = 0.0
    last_global_fire = 0.0
    last_rel_fire = 0.0
    desktop_uid = _desktop_uid_for_capture(settings)
    select_timeout = max(
        0.05,
        min(2.0, float(settings.lock_intrusion.input_select_timeout_seconds)),
    )

    try:
        while not stop_event.is_set():
            try:
                r, _, _ = select.select(fds, [], [], select_timeout)
            except (OSError, ValueError):
                alive = []
                alive_fds = []
                for d in devices:
                    try:
                        os.fstat(d.fd)
                        alive.append(d)
                        alive_fds.append(d.fd)
                    except OSError:
                        logger.warning("Input device removed: %s", getattr(d, "name", d.fd))
                        try:
                            d.close()
                        except OSError:
                            pass
                devices = alive
                fds = alive_fds
                if not devices:
                    logger.error("All input devices lost — stopping input watch")
                    return
                continue

            if stop_event.is_set():
                break
            if not r:
                continue

            for dev in devices:
                if dev.fd not in r:
                    continue
                try:
                    for ev in dev.read():
                        if stop_event.is_set():
                            return
                        if not _is_meaningful_event(ev, ecodes):
                            continue
                        input_kind = _classify_input(ev, ecodes)
                        now = time.monotonic()

                        if not is_session_locked(use_cache=True):
                            t0 = time.monotonic()
                            if t0 - last_lock_deny_log >= 30.0:
                                last_lock_deny_log = t0
                                logger.warning(
                                    "Lock intrusion: input seen but lock not detected (DBus/logind/pgrep). "
                                    "If running as root: ensure util-linux (runuser) is installed. "
                                    "While locked: python3 /opt/raas/raas.py --diagnose-lock",
                                )
                            continue

                        if input_kind == "mouse":
                            if now - last_rel_fire < ptr_throttle:
                                continue

                        if cooldown > 0 and (now - last_global_fire) < cooldown:
                            continue

                        if input_kind == "mouse":
                            last_rel_fire = now
                        last_global_fire = now

                        send_lock_intrusion_alert(
                            settings,
                            notifier,
                            telegram_ok,
                            alarm_file,
                            input_kind=input_kind,
                            desktop_uid=desktop_uid,
                            media_throttle=mt,
                        )
                except BlockingIOError:
                    continue
                except OSError:
                    logger.warning("Input device read error: %s", getattr(dev, "name", dev.fd))
                    continue
    finally:
        for d in devices:
            try:
                d.close()
            except OSError:
                pass
