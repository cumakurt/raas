from __future__ import annotations

import sys
import threading
import types
from pathlib import Path
from typing import Any

from config.settings import LockIntrusionConfig, LogConfig, Settings
import lock_monitor.input_watch as input_watch


def test_input_watch_drops_device_after_read_oserror(monkeypatch: Any) -> None:
    class FakeDevice:
        fd = 42
        name = "bad keyboard"

        def __init__(self) -> None:
            self.closed = False

        def capabilities(self) -> dict[int, list[int]]:
            return {1: [30]}

        def read(self) -> list[object]:
            raise OSError("device disconnected")

        def close(self) -> None:
            self.closed = True

    dev = FakeDevice()
    ecodes = types.SimpleNamespace(EV_SYN=0, EV_KEY=1, EV_REL=2, EV_ABS=3, EV_MSC=4)
    fake_evdev = types.SimpleNamespace(
        InputDevice=lambda _path: dev,
        ecodes=ecodes,
        list_devices=lambda: ["/dev/input/event0"],
    )
    monkeypatch.setitem(sys.modules, "evdev", fake_evdev)

    select_calls = 0

    def fake_select(
        fds: list[int],
        _write: list[int],
        _error: list[int],
        _timeout: float,
    ) -> tuple[list[int], list[int], list[int]]:
        nonlocal select_calls
        select_calls += 1
        if select_calls > 1:
            raise AssertionError("input watch spun after a persistent read error")
        assert fds == [dev.fd]
        return [dev.fd], [], []

    monkeypatch.setattr(input_watch.select, "select", fake_select)

    settings = Settings(
        log=LogConfig(path=Path("/tmp/auth.log")),
        lock_intrusion=LockIntrusionConfig(enabled=True, desktop_uid=1000),
    )
    input_watch.run_input_watch(
        settings,
        notifier=None,
        telegram_ok=False,
        stop_event=threading.Event(),
    )

    assert dev.closed is True
    assert select_calls == 1


def test_input_watch_confirms_stale_unlocked_cache(monkeypatch: Any) -> None:
    stop_event = threading.Event()
    sent: list[str] = []

    class FakeEvent:
        type = 1
        value = 1
        code = 30

    class FakeDevice:
        fd = 43
        name = "keyboard"

        def __init__(self, _path: str) -> None:
            self.closed = False

        def capabilities(self) -> dict[int, list[int]]:
            return {1: [30]}

        def read(self) -> list[object]:
            return [FakeEvent()]

        def close(self) -> None:
            self.closed = True

    ecodes = types.SimpleNamespace(EV_SYN=0, EV_KEY=1, EV_REL=2, EV_ABS=3, EV_MSC=4)
    fake_evdev = types.SimpleNamespace(
        InputDevice=FakeDevice,
        ecodes=ecodes,
        list_devices=lambda: ["/dev/input/event0"],
    )
    monkeypatch.setitem(sys.modules, "evdev", fake_evdev)
    monkeypatch.setattr(
        input_watch.select,
        "select",
        lambda fds, _write, _error, _timeout: (fds, [], []),
    )

    lock_checks: list[bool] = []

    def fake_locked(*, use_cache: bool) -> bool:
        lock_checks.append(use_cache)
        return not use_cache

    def fake_send(*_args: object, input_kind: str, **_kwargs: object) -> None:
        sent.append(input_kind)
        stop_event.set()

    monkeypatch.setattr(input_watch, "is_session_locked", fake_locked)
    monkeypatch.setattr(input_watch, "send_lock_intrusion_alert", fake_send)

    settings = Settings(
        log=LogConfig(path=Path("/tmp/auth.log")),
        lock_intrusion=LockIntrusionConfig(
            enabled=True,
            desktop_uid=1000,
            cooldown_seconds=0.0,
        ),
    )
    input_watch.run_input_watch(
        settings,
        notifier=None,
        telegram_ok=False,
        stop_event=stop_event,
    )

    assert lock_checks == [True, False]
    assert sent == ["keyboard"]
