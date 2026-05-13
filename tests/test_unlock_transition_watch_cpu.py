from __future__ import annotations

from pathlib import Path
from typing import Any

from config.settings import LockIntrusionConfig, LogConfig, Settings
from lock_monitor.intrusion_notify import LockMediaThrottle
import lock_monitor.unlock_transition_watch as unlock_watch


def test_unlock_transition_watch_throttles_flapping_unlocks(monkeypatch: Any) -> None:
    settings = Settings(
        log=LogConfig(path=Path("/tmp/auth.log")),
        lock_intrusion=LockIntrusionConfig(
            enabled=True,
            notify_on_unlock=True,
            desktop_uid=1000,
            cooldown_seconds=45.0,
            unlock_poll_interval_seconds=0.1,
        ),
    )
    states = iter([True, False, True, False])
    sent: list[str] = []

    class StopAfterStates:
        calls = 0

        def is_set(self) -> bool:
            return False

        def wait(self, timeout: float) -> bool:
            self.calls += 1
            return self.calls > 4

    def fake_send(*_args: object, input_kind: str, **_kwargs: object) -> None:
        sent.append(input_kind)

    monkeypatch.setattr(unlock_watch, "is_session_locked", lambda use_cache: next(states))
    monkeypatch.setattr(unlock_watch.time, "monotonic", lambda: 100.0)
    monkeypatch.setattr(unlock_watch, "send_lock_intrusion_alert", fake_send)

    unlock_watch.run_unlock_transition_watch(
        settings,
        notifier=None,
        telegram_ok=False,
        stop_event=StopAfterStates(),  # type: ignore[arg-type]
        alarm_file=None,
        media_throttle=LockMediaThrottle(0),
    )

    assert sent == ["session_unlocked"]
