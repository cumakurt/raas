from __future__ import annotations

import subprocess
import types
from typing import Any

import lock_monitor.session_lock as session_lock


def test_lock_cache_timestamp_is_after_slow_probe(monkeypatch: Any) -> None:
    session_lock.invalidate_lock_cache()
    session_lock.set_lock_cache_ttl(1.5)
    clock = {"now": 100.0}
    calls = 0

    def fake_monotonic() -> float:
        return clock["now"]

    def fake_combined() -> bool:
        nonlocal calls
        calls += 1
        clock["now"] += 10.0
        return False

    monkeypatch.setattr(session_lock.time, "monotonic", fake_monotonic)
    monkeypatch.setattr(session_lock, "_session_locked_combined", fake_combined)

    assert session_lock.is_session_locked(use_cache=True) is False
    clock["now"] += 0.1
    assert session_lock.is_session_locked(use_cache=True) is False
    assert calls == 1


def test_dbus_lock_probe_reuses_responsive_method(monkeypatch: Any) -> None:
    session_lock.invalidate_lock_cache()
    first_method = session_lock._DBUS_GET_ACTIVE[0]
    calls: list[tuple[str, str, str]] = []

    monkeypatch.setattr(session_lock, "_dbus_uids_to_probe", lambda: [1000])

    def fake_get_active(
        dest: str,
        path: str,
        method: str,
        *,
        for_uid: int,
    ) -> bool | None:
        assert for_uid == 1000
        probe = (dest, path, method)
        calls.append(probe)
        return False if probe == first_method else None

    monkeypatch.setattr(session_lock, "_gdbus_get_active", fake_get_active)

    assert session_lock._locked_hint_dbus() is False
    assert len(calls) == len(session_lock._DBUS_GET_ACTIVE)

    calls.clear()
    assert session_lock._locked_hint_dbus() is False
    assert calls == [first_method]


def test_dbus_lock_probe_caches_no_responsive_methods(monkeypatch: Any) -> None:
    session_lock.invalidate_lock_cache()
    calls: list[tuple[str, str, str]] = []

    monkeypatch.setattr(session_lock, "_dbus_uids_to_probe", lambda: [1000])

    def fake_get_active(
        dest: str,
        path: str,
        method: str,
        *,
        for_uid: int,
    ) -> bool | None:
        assert for_uid == 1000
        calls.append((dest, path, method))
        return None

    monkeypatch.setattr(session_lock, "_gdbus_get_active", fake_get_active)

    assert session_lock._locked_hint_dbus() is False
    assert len(calls) == len(session_lock._DBUS_GET_ACTIVE)

    calls.clear()
    assert session_lock._locked_hint_dbus() is False
    assert calls == []


def test_root_gdbus_probe_prefers_setpriv_without_pam(monkeypatch: Any) -> None:
    session_lock.invalidate_lock_cache()
    calls: list[list[str]] = []

    def fake_which(name: str) -> str | None:
        return {
            "gdbus": "/usr/bin/gdbus",
            "setpriv": "/usr/bin/setpriv",
            "runuser": "/usr/sbin/runuser",
        }.get(name)

    def fake_run(
        cmd: list[str],
        *,
        capture_output: bool,
        text: bool,
        timeout: float,
        check: bool,
        env: dict[str, str] | None = None,
    ) -> subprocess.CompletedProcess[str]:
        assert capture_output is True
        assert text is True
        assert check is False
        assert env is None
        assert timeout == 3
        calls.append(cmd)
        return subprocess.CompletedProcess(cmd, 0, stdout="(false,)", stderr="")

    monkeypatch.setattr(session_lock.os, "getuid", lambda: 0)
    monkeypatch.setattr(session_lock.os.path, "exists", lambda _path: True)
    monkeypatch.setattr(session_lock.shutil, "which", fake_which)
    monkeypatch.setattr(
        session_lock.pwd,
        "getpwuid",
        lambda _uid: types.SimpleNamespace(pw_name="cuma", pw_gid=1000),
    )
    monkeypatch.setattr(session_lock.subprocess, "run", fake_run)

    assert (
        session_lock._gdbus_get_active(
            "org.gnome.ScreenSaver",
            "/org/gnome/ScreenSaver",
            "org.gnome.ScreenSaver.GetActive",
            for_uid=1000,
        )
        is False
    )
    assert calls
    assert calls[0][:6] == [
        "/usr/bin/setpriv",
        "--reuid",
        "1000",
        "--regid",
        "1000",
        "--init-groups",
    ]
    assert "/usr/sbin/runuser" not in calls[0]
