from __future__ import annotations

import logging
from typing import Any

import requests

from engine.risk_engine import RiskResult
from parser.events import AccessEvent

logger = logging.getLogger(__name__)

# https://core.telegram.org/bots/api#sendmessage
TELEGRAM_MAX_MESSAGE_LENGTH = 4096


class TelegramNotifier:
    """Telegram Bot API channel; implements AlertNotifier via send_alert."""

    channel_id = "telegram"

    def __init__(
        self,
        bot_token: str,
        chat_id: str,
        *,
        api_base_url: str = "https://api.telegram.org",
        timeout_seconds: float = 15.0,
    ) -> None:
        self.bot_token = bot_token
        self.chat_id = chat_id
        self.api_base_url = api_base_url.rstrip("/")
        self.timeout_seconds = timeout_seconds

    def send_alert(self, event: AccessEvent, risk: RiskResult) -> bool:
        return self.send_event(event, risk)

    def send_event(self, event: AccessEvent, risk: RiskResult) -> bool:
        text = self._format_message(event, risk)
        return self._send_message(text)

    def _format_message(self, event: AccessEvent, risk: RiskResult) -> str:
        lines = [
            f"RAAS — {event.kind.value}",
            f"Risk: {risk.score}/100",
            "",
        ]
        if event.user:
            lines.append(f"User: {event.user}")
        if event.source_ip:
            lines.append(f"Source IP: {event.source_ip}")
        if event.auth_method:
            lines.append(f"Auth: {event.auth_method}")
        for k, v in (event.extra or {}).items():
            if k in ("port", "command", "target_user", "service"):
                lines.append(f"{k}: {v}")
        lines.append("")
        lines.append("Reasons:")
        for r in risk.reasons:
            lines.append(f"• {r}")
        lines.append("")
        raw = event.raw_line[:800].replace("\n", " ")
        lines.append(f"Raw: {raw}")
        return "\n".join(lines)

    def _send_message(self, text: str) -> bool:
        if len(text) > TELEGRAM_MAX_MESSAGE_LENGTH:
            text = text[: TELEGRAM_MAX_MESSAGE_LENGTH - 20] + "\n…(truncated)"
        url = f"{self.api_base_url}/bot{self.bot_token}/sendMessage"
        payload: dict[str, Any] = {
            "chat_id": self.chat_id,
            "text": text,
        }
        try:
            r = requests.post(url, json=payload, timeout=self.timeout_seconds)
            if r.status_code != 200:
                logger.error("Telegram API error: %s %s", r.status_code, r.text[:500])
                return False
            return True
        except requests.RequestException as e:
            logger.error("Telegram request failed: %s", e)
            return False

    def send_plain_text(self, text: str) -> bool:
        return self._send_message(text)

    def send_photo(
        self,
        photo_bytes: bytes,
        caption: str = "",
        *,
        filename: str = "capture.jpg",
        mime_type: str = "image/jpeg",
    ) -> bool:
        url = f"{self.api_base_url}/bot{self.bot_token}/sendPhoto"
        files = {"photo": (filename, photo_bytes, mime_type)}
        data: dict[str, Any] = {"chat_id": self.chat_id}
        if caption:
            data["caption"] = caption[:1024]
        try:
            r = requests.post(url, data=data, files=files, timeout=self.timeout_seconds)
            if r.status_code != 200:
                logger.error("Telegram sendPhoto error: %s %s", r.status_code, r.text[:500])
                return False
            return True
        except requests.RequestException as e:
            logger.error("Telegram sendPhoto failed: %s", e)
            return False
