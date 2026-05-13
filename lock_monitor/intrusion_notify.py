from __future__ import annotations

import logging
import threading
import time
from typing import TYPE_CHECKING

from lock_monitor.camera_capture import capture_jpeg

if TYPE_CHECKING:
    from config.settings import Settings
    from notifier.telegram import TelegramNotifier
    from utils.alarm_file_log import AlarmFileLogger

logger = logging.getLogger(__name__)

# Plain-text Telegram bodies (no HTML); short English labels for operators.
_INPUT_KIND_LABELS: dict[str, str] = {
    "keyboard": "Keyboard key press",
    "mouse": "Mouse movement",
    "mouse_button": "Mouse button",
    "touchpad_or_touchscreen": "Touchpad / touchscreen",
    "input": "Generic input event",
    "lock_auth_failure": "Failed unlock attempt",
    "session_unlocked": "Session unlocked (lock released)",
}

_WEBCAM_CAPTURE_KINDS: frozenset[str] = frozenset(
    {
        "keyboard",
        "mouse",
        "mouse_button",
        "touchpad_or_touchscreen",
        "input",
        "lock_auth_failure",
    },
)


def _should_capture_webcam(input_kind: str) -> bool:
    return input_kind in _WEBCAM_CAPTURE_KINDS


def _webcam_throttle_key(input_kind: str) -> str:
    if input_kind == "lock_auth_failure":
        return "webcam:auth"
    return "webcam:input"


def _one_line(text: str, *, limit: int) -> str:
    compact = " ".join(text.strip().split())
    if len(compact) <= limit:
        return compact
    return compact[: max(0, limit - 3)].rstrip() + "..."


def _build_lock_summary(input_kind: str, *, extra_text: str = "", log_excerpt: str = "") -> str:
    activity = _INPUT_KIND_LABELS.get(input_kind, input_kind.replace("_", " ").title())
    lines = [
        "RAAS lock alert",
        f"Event: {activity}",
    ]
    if extra_text.strip():
        lines.append(f"Note: {_one_line(extra_text, limit=220)}")
    if log_excerpt.strip():
        lines.append(f"Log: {_one_line(log_excerpt, limit=500)}")
    return "\n".join(lines)[:3900]


class LockMediaThrottle:
    """Throttle screen/webcam captures to avoid Telegram rate limits; text can still be frequent."""

    def __init__(self, media_cooldown_seconds: float) -> None:
        self.media_cooldown_seconds = max(0.0, float(media_cooldown_seconds))
        self._last_media_by_key: dict[str, float] = {}
        self._lock = threading.Lock()

    def should_capture_media(self, key: str = "default") -> bool:
        if self.media_cooldown_seconds <= 0:
            return True
        with self._lock:
            now = time.monotonic()
            last_media = self._last_media_by_key.get(key, 0.0)
            if now - last_media >= self.media_cooldown_seconds:
                self._last_media_by_key[key] = now
                return True
            return False


def send_lock_intrusion_alert(
    settings: "Settings",
    notifier: "TelegramNotifier | None",
    telegram_ok: bool,
    alarm_file: "AlarmFileLogger | None",
    *,
    input_kind: str,
    desktop_uid: int,
    media_throttle: LockMediaThrottle,
    extra_text: str = "",
    log_excerpt: str = "",
) -> None:
    """Send Telegram + optional screen/webcam + alarm JSON for one lock-related event."""
    jpeg: bytes | None = None
    want_webcam = _should_capture_webcam(input_kind)
    capture_webcam_now = (
        want_webcam
        and settings.lock_intrusion.capture_webcam
        and media_throttle.should_capture_media(_webcam_throttle_key(input_kind))
    )

    if capture_webcam_now:
        logger.warning("Lock screen alert — capturing webcam")
        jpeg = capture_jpeg(
            settings.lock_intrusion.camera_device,
            prefer_ffmpeg=settings.lock_intrusion.prefer_ffmpeg,
            width=settings.lock_intrusion.capture_width,
            height=settings.lock_intrusion.capture_height,
        )

    summary = _build_lock_summary(
        input_kind,
        extra_text=extra_text,
        log_excerpt=log_excerpt,
    )

    photo_caption = (
        f"RAAS lock - {_INPUT_KIND_LABELS.get(input_kind, input_kind)} - {settings.lock_intrusion.camera_device}"
    )[:1024]

    delivered = False
    if telegram_ok and notifier is not None:
        delivered = bool(notifier.send_plain_text(summary))
        if capture_webcam_now and jpeg:
            delivered = bool(notifier.send_photo(jpeg, caption=photo_caption)) or delivered
        elif capture_webcam_now and not jpeg:
            delivered = bool(
                notifier.send_plain_text(
                    "Webcam capture failed — check ffmpeg/OpenCV and /dev/video permissions.",
                ),
            ) or delivered
    else:
        logger.info("Telegram not configured — lock alert not sent")

    if alarm_file:
        alarm_file.write_lock_intrusion(
            caption=summary[:2000],
            input_kind=input_kind,
            auth_hint=_one_line(log_excerpt, limit=2000) if log_excerpt else "",
            camera_captured=bool(jpeg),
            screen_captured=False,
            telegram_attempted=telegram_ok,
            telegram_delivered=delivered,
        )
