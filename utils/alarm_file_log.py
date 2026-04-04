from __future__ import annotations

import json
import logging
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from engine.risk_engine import RiskResult
from parser.events import AccessEvent

logger = logging.getLogger(__name__)


class AlarmFileLogger:
    """
    Append-only JSON lines file for alerts that crossed the notify threshold
    (per-channel delivery in `deliveries`; legacy `telegram_*` keys kept).
    """

    def __init__(self, path: Path, *, enabled: bool = True) -> None:
        self.path = path.expanduser()
        self.enabled = enabled
        self._lock = threading.Lock()

    def _append(self, record: dict[str, Any]) -> None:
        if not self.enabled:
            return
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            line = json.dumps(record, ensure_ascii=False) + "\n"
            with self._lock:
                with open(self.path, "a", encoding="utf-8") as f:
                    f.write(line)
                    f.flush()
        except OSError as e:
            logger.error("Cannot write alarm log %s: %s", self.path, e)

    def write_auth_event(
        self,
        *,
        event: AccessEvent,
        risk: RiskResult,
        notify_threshold: int,
        deliveries: dict[str, bool],
    ) -> None:
        """deliveries maps notifier channel_id (telegram, webhook, …) to success."""
        notify_attempted = bool(deliveries)
        notify_delivered = any(deliveries.values()) if deliveries else False
        self._append(
            {
                "ts": datetime.now(timezone.utc).isoformat(),
                "channel": "auth_log",
                "kind": event.kind.value,
                "risk_score": risk.score,
                "notify_threshold": notify_threshold,
                "user": event.user,
                "source_ip": event.source_ip,
                "auth_method": event.auth_method,
                "reasons": risk.reasons,
                "extra": event.extra or {},
                "raw_line": event.raw_line[:2000],
                "notify_attempted": notify_attempted,
                "notify_delivered": notify_delivered,
                "deliveries": deliveries,
                "telegram_attempted": "telegram" in deliveries,
                "telegram_delivered": deliveries.get("telegram", False),
            },
        )

    def write_lock_intrusion(
        self,
        *,
        caption: str,
        camera_captured: bool,
        screen_captured: bool = False,
        input_kind: str = "",
        auth_hint: str = "",
        telegram_attempted: bool,
        telegram_delivered: bool,
    ) -> None:
        self._append(
            {
                "ts": datetime.now(timezone.utc).isoformat(),
                "channel": "lock_intrusion",
                "kind": "lock_intrusion",
                "caption": caption[:2000],
                "input_kind": input_kind[:64],
                "auth_hint": auth_hint[:2000],
                "camera_captured": camera_captured,
                "screen_captured": screen_captured,
                "telegram_attempted": telegram_attempted,
                "telegram_delivered": telegram_delivered,
            },
        )
