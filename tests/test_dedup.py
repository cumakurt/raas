from __future__ import annotations

from parser.events import AccessEvent, EventKind
from utils.event_dedup import AuthEventDedup


def test_pam_suppressed_after_sshd_fail() -> None:
    d = AuthEventDedup(ttl_seconds=2.0)
    ssh = AccessEvent(
        kind=EventKind.SSH_FAILED,
        raw_line="x",
        user="u",
        source_ip="1.1.1.1",
        auth_method="password",
    )
    pam = AccessEvent(
        kind=EventKind.PAM_SSHD_FAILURE,
        raw_line="y",
        user="u",
        source_ip="1.1.1.1",
    )
    assert d.should_emit(ssh) is True
    assert d.should_emit(pam) is False


def test_unrelated_events_pass() -> None:
    d = AuthEventDedup()
    e1 = AccessEvent(kind=EventKind.SUDO, raw_line="x", user="a")
    assert d.should_emit(e1) is True
