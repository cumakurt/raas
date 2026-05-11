from __future__ import annotations

from engine.risk_engine import RiskEngine
from parser.events import AccessEvent, EventKind


def test_ssh_failed_base() -> None:
    eng = RiskEngine()
    ev = AccessEvent(
        kind=EventKind.SSH_FAILED,
        raw_line="x",
        user="u",
        source_ip="10.0.0.1",
        auth_method="password",
    )
    r = eng.evaluate(ev)
    assert 40 <= r.score <= 100
    assert any("SSH" in x for x in r.reasons)


def test_score_override() -> None:
    eng = RiskEngine(night_bonus=0, score_overrides={"ssh_failed": 10})
    ev = AccessEvent(
        kind=EventKind.SSH_FAILED,
        raw_line="x",
        user="u",
        source_ip="10.0.0.1",
        auth_method="password",
    )
    r = eng.evaluate(ev)
    assert r.score == 10


def test_unknown_kind_bucket() -> None:
    eng = RiskEngine(night_bonus=0)
    ev = AccessEvent(kind=EventKind.UNKNOWN, raw_line="x")
    r = eng.evaluate(ev)
    assert r.score == 10
