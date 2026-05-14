from __future__ import annotations

from pathlib import Path
from typing import Any

from config.settings import LockIntrusionConfig, LogConfig, Settings
from lock_monitor.intrusion_notify import LockMediaThrottle
import lock_monitor.auth_unlock_watch as auth_watch


class _StopAfterOnePoll:
    def __init__(self, auth_log: Path, text: str) -> None:
        self.auth_log = auth_log
        self.text = text
        self.calls = 0

    def is_set(self) -> bool:
        return False

    def wait(self, timeout: float) -> bool:
        self.calls += 1
        if self.calls == 1:
            self.auth_log.write_text(self.text, encoding="utf-8")
            return False
        return True


def _settings(auth_log: Path, **lock_overrides: Any) -> Settings:
    return Settings(
        log=LogConfig(path=auth_log),
        lock_intrusion=LockIntrusionConfig(
            enabled=True,
            watch_auth_failures=True,
            desktop_uid=1000,
            auth_poll_interval_seconds=0.1,
            **lock_overrides,
        ),
    )


def test_auth_failure_uses_fresh_lock_state_before_dropping_candidate(
    tmp_path: Path,
    monkeypatch: Any,
) -> None:
    auth_log = tmp_path / "auth.log"
    auth_log.write_text("", encoding="utf-8")
    line = "mate-screensaver: pam_unix(mate-screensaver:auth): authentication failure\n"
    sent: list[str] = []
    lock_checks: list[bool] = []

    def fake_locked(*, use_cache: bool) -> bool:
        lock_checks.append(use_cache)
        return not use_cache

    def fake_send(*_args: object, log_excerpt: str = "", **_kwargs: object) -> None:
        sent.append(log_excerpt)

    monkeypatch.setattr(auth_watch, "is_session_locked", fake_locked)
    monkeypatch.setattr(auth_watch, "send_lock_intrusion_alert", fake_send)

    auth_watch.run_auth_unlock_watch(
        _settings(auth_log),
        notifier=None,
        telegram_ok=False,
        stop_event=_StopAfterOnePoll(auth_log, line),  # type: ignore[arg-type]
        alarm_file=None,
        media_throttle=LockMediaThrottle(0),
    )

    assert lock_checks == [False]
    assert sent == [line.strip()]


def test_auth_failure_min_gap_is_independent_from_input_cooldown(
    tmp_path: Path,
    monkeypatch: Any,
) -> None:
    auth_log = tmp_path / "auth.log"
    auth_log.write_text("", encoding="utf-8")
    lines = (
        "unix_chkpwd[1]: password check failed for user (alice)\n"
        "unix_chkpwd[2]: password check failed for user (alice)\n"
    )
    sent: list[str] = []

    def fake_send(*_args: object, log_excerpt: str = "", **_kwargs: object) -> None:
        sent.append(log_excerpt)

    monkeypatch.setattr(auth_watch, "is_session_locked", lambda *, use_cache: True)
    monkeypatch.setattr(auth_watch, "send_lock_intrusion_alert", fake_send)

    auth_watch.run_auth_unlock_watch(
        _settings(
            auth_log,
            cooldown_seconds=45.0,
            auth_failure_min_interval_seconds=0.0,
        ),
        notifier=None,
        telegram_ok=False,
        stop_event=_StopAfterOnePoll(auth_log, lines),  # type: ignore[arg-type]
        alarm_file=None,
        media_throttle=LockMediaThrottle(0),
    )

    assert sent == [
        "unix_chkpwd[1]: password check failed for user (alice)",
        "unix_chkpwd[2]: password check failed for user (alice)",
    ]
