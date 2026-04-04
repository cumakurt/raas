from __future__ import annotations

import logging
import threading
import time
from typing import TYPE_CHECKING

from lock_monitor.camera_capture import capture_jpeg
from lock_monitor.screen_capture import capture_screen_png
from utils.auth_tail_hint import tail_auth_hints

if TYPE_CHECKING:
    from config.settings import Settings
    from notifier.telegram import TelegramNotifier
    from utils.alarm_file_log import AlarmFileLogger

logger = logging.getLogger(__name__)


class LockMediaThrottle:
    """Throttle screen/webcam captures to avoid Telegram rate limits; text can still be frequent."""

    def __init__(self, media_cooldown_seconds: float) -> None:
        self.media_cooldown_seconds = max(0.0, float(media_cooldown_seconds))
        self._last_media = 0.0
        self._lock = threading.Lock()

    def should_capture_media(self) -> bool:
        if self.media_cooldown_seconds <= 0:
            return True
        with self._lock:
            now = time.monotonic()
            if now - self._last_media >= self.media_cooldown_seconds:
                self._last_media = now
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
    auth_hint = tail_auth_hints(settings.log.path)
    screen_png: bytes | None = None
    jpeg: bytes | None = None
    want_media = media_throttle.should_capture_media()

    if want_media and settings.lock_intrusion.capture_screen:
        logger.warning("Lock screen alert — capturing screen (uid=%s)", desktop_uid)
        screen_png = capture_screen_png(desktop_uid=desktop_uid)

    if want_media and settings.lock_intrusion.capture_webcam:
        logger.warning("Lock screen alert — capturing webcam")
        jpeg = capture_jpeg(
            settings.lock_intrusion.camera_device,
            prefer_ffmpeg=settings.lock_intrusion.prefer_ffmpeg,
            width=settings.lock_intrusion.capture_width,
            height=settings.lock_intrusion.capture_height,
        )

    lines = [
        "RAAS lock alert",
        f"Input: {input_kind}",
    ]
    if extra_text:
        lines.append(extra_text)
    else:
        lines.append("Screen locked — input activity detected.")
    if log_excerpt.strip():
        lines.append("")
        lines.append("Auth log (excerpt):")
        lines.append(log_excerpt.strip()[:900])
    if auth_hint.strip():
        lines.append("")
        lines.append("Recent auth.log hints (may include older lines):")
        lines.append(auth_hint.strip()[:900])
    summary = "\n".join(lines)[:3900]

    photo_caption = (
        f"RAAS — locked | {input_kind} | cam={settings.lock_intrusion.camera_device}"
    )[:1024]

    delivered = False
    if telegram_ok and notifier is not None:
        delivered = bool(notifier.send_plain_text(summary))
        if want_media and settings.lock_intrusion.capture_screen and screen_png:
            delivered = bool(
                notifier.send_photo(
                    screen_png,
                    caption="Screen capture",
                    filename="screen.png",
                    mime_type="image/png",
                ),
            ) or delivered
        elif want_media and settings.lock_intrusion.capture_screen and not screen_png:
            delivered = bool(
                notifier.send_plain_text(
                    "Screen capture failed (grim/ffmpeg/import missing or no DISPLAY).",
                ),
            ) or delivered

        if want_media and settings.lock_intrusion.capture_webcam and jpeg:
            delivered = bool(notifier.send_photo(jpeg, caption=photo_caption)) or delivered
        elif want_media and settings.lock_intrusion.capture_webcam and not jpeg:
            delivered = bool(
                notifier.send_plain_text(
                    "Webcam capture failed — check ffmpeg/OpenCV and /dev/video permissions.",
                ),
            ) or delivered
    else:
        logger.info("Telegram not configured — lock alert not sent")

    if alarm_file:
        cap = summary
        if log_excerpt:
            cap = (summary + "\n" + log_excerpt)[:2000]
        alarm_file.write_lock_intrusion(
            caption=cap,
            input_kind=input_kind,
            auth_hint=(auth_hint + "\n" + log_excerpt)[:2000],
            camera_captured=bool(jpeg),
            screen_captured=bool(screen_png),
            telegram_attempted=telegram_ok,
            telegram_delivered=delivered,
        )
