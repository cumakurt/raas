from __future__ import annotations

from typing import Protocol, runtime_checkable

from engine.risk_engine import RiskResult
from parser.events import AccessEvent


@runtime_checkable
class AlertNotifier(Protocol):
    """
    Pluggable delivery channel for auth-log alerts that crossed the risk threshold.
    Implementations: TelegramNotifier, WebhookNotifier, future SMTP/Matrix/etc.
    """

    @property
    def channel_id(self) -> str:
        """Stable id for logging (e.g. telegram, webhook)."""
        ...

    def send_alert(self, event: AccessEvent, risk: RiskResult) -> bool:
        """Return True if delivery succeeded."""
        ...
