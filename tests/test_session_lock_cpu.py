from __future__ import annotations

from typing import Any

import lock_monitor.session_lock as session_lock


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
