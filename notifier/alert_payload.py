from __future__ import annotations

from typing import Any

from engine.risk_engine import RiskResult
from parser.events import AccessEvent


def alert_to_dict(event: AccessEvent, risk: RiskResult, *, raw_line_max: int = 2000) -> dict[str, Any]:
    """Structured payload for webhooks, future APIs, and tests (schema-stable JSON)."""
    return {
        "schema": "raas.alert.v1",
        "kind": event.kind.value,
        "risk_score": risk.score,
        "reasons": risk.reasons,
        "user": event.user,
        "source_ip": event.source_ip,
        "auth_method": event.auth_method,
        "extra": event.extra or {},
        "raw_line": event.raw_line[:raw_line_max],
    }
