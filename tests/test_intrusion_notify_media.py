from __future__ import annotations

from pathlib import Path
from typing import Any

from config.settings import LockIntrusionConfig, LogConfig, Settings
import lock_monitor.intrusion_notify as intrusion_notify


class _Notifier:
    def __init__(self) -> None:
        self.texts: list[str] = []
        self.photos: list[dict[str, Any]] = []

    def send_plain_text(self, text: str) -> bool:
        self.texts.append(text)
        return True

    def send_photo(
        self,
        data: bytes,
        *,
        caption: str = "",
        filename: str = "photo.jpg",
        mime_type: str = "image/jpeg",
    ) -> bool:
        self.photos.append(
            {
                "data": data,
                "caption": caption,
                "filename": filename,
                "mime_type": mime_type,
            },
        )
        return True


class _AlarmFile:
    def __init__(self) -> None:
        self.records: list[dict[str, Any]] = []

    def write_lock_intrusion(self, **record: Any) -> None:
        self.records.append(record)


def _settings(tmp_path: Path) -> Settings:
    return Settings(
        log=LogConfig(path=tmp_path / "auth.log"),
        lock_intrusion=LockIntrusionConfig(
            capture_screen=True,
            capture_webcam=True,
            desktop_uid=1000,
        ),
    )


def test_lock_auth_failure_sends_webcam_capture_only(
    tmp_path: Path,
    monkeypatch: Any,
) -> None:
    notifier = _Notifier()
    alarm_file = _AlarmFile()
    webcam_calls: list[str] = []

    monkeypatch.setattr(
        intrusion_notify,
        "capture_jpeg",
        lambda device, **_kwargs: webcam_calls.append(device) or b"webcam",
    )

    intrusion_notify.send_lock_intrusion_alert(
        _settings(tmp_path),
        notifier,  # type: ignore[arg-type]
        True,
        alarm_file,  # type: ignore[arg-type]
        input_kind="lock_auth_failure",
        desktop_uid=1000,
        media_throttle=intrusion_notify.LockMediaThrottle(0),
        log_excerpt="mate-screensaver authentication failure",
    )

    assert webcam_calls == ["/dev/video0"]
    assert len(notifier.photos) == 1
    assert notifier.photos[0]["data"] == b"webcam"
    assert notifier.photos[0]["filename"] == "photo.jpg"
    assert notifier.photos[0]["mime_type"] == "image/jpeg"
    assert alarm_file.records[0]["screen_captured"] is False
    assert alarm_file.records[0]["camera_captured"] is True
    assert notifier.texts == [
        "RAAS lock alert\n"
        "Event: Failed unlock attempt\n"
        "Log: mate-screensaver authentication failure",
    ]
    assert "Recent auth log hints" not in notifier.texts[0]
    assert alarm_file.records[0]["caption"] == notifier.texts[0]
    assert alarm_file.records[0]["auth_hint"] == "mate-screensaver authentication failure"


def test_locked_keyboard_input_sends_webcam_capture_only(
    tmp_path: Path,
    monkeypatch: Any,
) -> None:
    notifier = _Notifier()
    alarm_file = _AlarmFile()
    webcam_calls: list[str] = []

    monkeypatch.setattr(
        intrusion_notify,
        "capture_jpeg",
        lambda device, **_kwargs: webcam_calls.append(device) or b"webcam",
    )

    intrusion_notify.send_lock_intrusion_alert(
        _settings(tmp_path),
        notifier,  # type: ignore[arg-type]
        True,
        alarm_file,  # type: ignore[arg-type]
        input_kind="keyboard",
        desktop_uid=1000,
        media_throttle=intrusion_notify.LockMediaThrottle(0),
    )

    assert webcam_calls == ["/dev/video0"]
    assert len(notifier.photos) == 1
    assert notifier.photos[0]["data"] == b"webcam"
    assert notifier.photos[0]["filename"] == "photo.jpg"
    assert notifier.photos[0]["mime_type"] == "image/jpeg"
    assert alarm_file.records[0]["screen_captured"] is False
    assert alarm_file.records[0]["camera_captured"] is True
    assert notifier.texts == [
        "RAAS lock alert\n"
        "Event: Keyboard key press",
    ]
    assert alarm_file.records[0]["caption"] == notifier.texts[0]
    assert alarm_file.records[0]["auth_hint"] == ""


def test_auth_and_input_webcam_have_independent_throttle_keys(
    tmp_path: Path,
    monkeypatch: Any,
) -> None:
    notifier = _Notifier()
    alarm_file = _AlarmFile()
    webcam_calls: list[str] = []
    throttle = intrusion_notify.LockMediaThrottle(45)

    monkeypatch.setattr(intrusion_notify.time, "monotonic", lambda: 100.0)
    monkeypatch.setattr(
        intrusion_notify,
        "capture_jpeg",
        lambda device, **_kwargs: webcam_calls.append(device) or b"webcam",
    )

    intrusion_notify.send_lock_intrusion_alert(
        _settings(tmp_path),
        notifier,  # type: ignore[arg-type]
        True,
        alarm_file,  # type: ignore[arg-type]
        input_kind="keyboard",
        desktop_uid=1000,
        media_throttle=throttle,
    )
    intrusion_notify.send_lock_intrusion_alert(
        _settings(tmp_path),
        notifier,  # type: ignore[arg-type]
        True,
        alarm_file,  # type: ignore[arg-type]
        input_kind="lock_auth_failure",
        desktop_uid=1000,
        media_throttle=throttle,
        log_excerpt="mate-screensaver authentication failure",
    )

    assert webcam_calls == ["/dev/video0", "/dev/video0"]
    assert [p["data"] for p in notifier.photos] == [b"webcam", b"webcam"]
    assert alarm_file.records[0]["camera_captured"] is True
    assert alarm_file.records[0]["screen_captured"] is False
    assert alarm_file.records[1]["camera_captured"] is True
    assert alarm_file.records[1]["screen_captured"] is False


def test_lock_summary_does_not_repeat_log_excerpt() -> None:
    summary = intrusion_notify._build_lock_summary(
        "lock_auth_failure",
        log_excerpt="unix_chkpwd: password check failed for user (cuma)",
    )

    assert summary.count("password check failed") == 1
    assert "Recent auth log hints" not in summary
    assert "Password is never sent" not in summary
