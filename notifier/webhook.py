from __future__ import annotations

import logging
from typing import Any

import requests

from engine.risk_engine import RiskResult
from notifier.alert_payload import alert_to_dict
from parser.events import AccessEvent

logger = logging.getLogger(__name__)


class WebhookNotifier:
    """POST JSON alert payload to a configurable HTTPS (or HTTP) URL."""

    channel_id = "webhook"

    def __init__(
        self,
        url: str,
        *,
        timeout_seconds: float = 10.0,
        headers: dict[str, str] | None = None,
    ) -> None:
        self.url = url.strip()
        self.timeout_seconds = timeout_seconds
        self.headers: dict[str, str] = dict(headers) if headers else {}

    def send_alert(self, event: AccessEvent, risk: RiskResult) -> bool:
        payload = alert_to_dict(event, risk)
        hdrs: dict[str, str] = {"Content-Type": "application/json; charset=utf-8", **self.headers}
        try:
            r = requests.post(self.url, json=payload, headers=hdrs, timeout=self.timeout_seconds)
            if r.status_code < 200 or r.status_code >= 300:
                logger.error("Webhook POST error: %s %s", r.status_code, (r.text or "")[:500])
                return False
            return True
        except requests.RequestException as e:
            logger.error("Webhook request failed: %s", e)
            return False
