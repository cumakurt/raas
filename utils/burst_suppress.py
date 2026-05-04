"""Suppress repeated identical alerts within a short window; emit a summary when the window rolls."""

from __future__ import annotations

from engine.risk_engine import RiskResult
from parser.events import AccessEvent


def _event_key(ev: AccessEvent) -> tuple[str, str, str]:
    return (ev.kind.value, ev.source_ip or "", (ev.user or "").lower())


class BurstSuppressor:
    """
    Per-key: emit the first alert immediately; suppress duplicates for window_seconds.
    When the window expires and a new alert arrives for the same key, emit one synthetic
    summary for the suppressed count, then emit the new alert.
    """

    def __init__(self, window_seconds: float, enabled: bool) -> None:
        self.window_seconds = max(0.05, float(window_seconds))
        self.enabled = enabled
        self._state: dict[
            tuple[str, str, str],
            tuple[float, int, AccessEvent, RiskResult, int],
        ] = {}
        # key -> (window_start_monotonic, suppressed_after_first, last_ev, last_risk, notify_threshold)

    def process(
        self,
        event: AccessEvent,
        risk: RiskResult,
        notify_threshold: int,
        now: float,
    ) -> list[tuple[AccessEvent, RiskResult, int]]:
        if not self.enabled:
            return [(event, risk, notify_threshold)]
        key = _event_key(event)
        if key not in self._state:
            self._state[key] = (now, 0, event, risk, notify_threshold)
            return [(event, risk, notify_threshold)]
        t0, suppressed, _le, _lr, th_old = self._state[key]
        if now - t0 < self.window_seconds:
            self._state[key] = (t0, suppressed + 1, event, risk, th_old)
            return []
        out: list[tuple[AccessEvent, RiskResult, int]] = []
        if suppressed > 0:
            out.append(_summary(key, suppressed, event, risk, notify_threshold))
        self._state[key] = (now, 0, event, risk, notify_threshold)
        out.append((event, risk, notify_threshold))
        return out


def _summary(
    key: tuple[str, str, str],
    suppressed: int,
    last_ev: AccessEvent,
    last_risk: RiskResult,
    notify_threshold: int,
) -> tuple[AccessEvent, RiskResult, int]:
    kind_s, ip_s, user_s = key
    raw = (
        f"[RAAS coalesce] {suppressed} similar event(s) in window "
        f"(kind={kind_s} ip={ip_s or '-'} user={user_s or '-'})"
    )
    syn = AccessEvent(
        kind=last_ev.kind,
        raw_line=raw,
        user=last_ev.user,
        source_ip=last_ev.source_ip,
        auth_method=last_ev.auth_method,
        extra={**(last_ev.extra or {}), "coalesced_similar": suppressed},
    )
    reasons = list(last_risk.reasons)
    reasons.append(f"Coalesced {suppressed} similar event(s) in {kind_s}")
    r = RiskResult(
        score=last_risk.score,
        reasons=reasons,
        severity=last_risk.severity,
        mitre_techniques=list(last_risk.mitre_techniques),
    )
    return (syn, r, notify_threshold)
