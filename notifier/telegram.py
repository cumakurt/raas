from __future__ import annotations

import html
import logging
import time
from collections import deque
from pathlib import Path
from typing import Any, Callable

import requests

from engine.risk_engine import RiskResult
from parser.events import AccessEvent
from utils.delivery_retry import append_telegram_retry_locked

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
        parse_mode: str = "HTML",
        rate_limit_per_minute: int = 0,
        retry_enabled: bool = False,
        retry_queue_path: Path | None = None,
        on_delivery_result: Callable[[bool], None] | None = None,
    ) -> None:
        self.bot_token = bot_token
        self.chat_id = chat_id
        self.api_base_url = api_base_url.rstrip("/")
        self.timeout_seconds = timeout_seconds
        self.parse_mode = parse_mode or ""
        self.rate_limit_per_minute = max(0, int(rate_limit_per_minute))
        self.retry_enabled = retry_enabled
        self.retry_queue_path = retry_queue_path
        self._on_delivery = on_delivery_result
        self._rl_times: deque[float] = deque()

    def send_alert(self, event: AccessEvent, risk: RiskResult) -> bool:
        return self.send_event(event, risk)

    def send_event(self, event: AccessEvent, risk: RiskResult) -> bool:
        text = self._format_message_html(event, risk) if self.parse_mode == "HTML" else self._format_message_plain(event, risk)
        parse = self.parse_mode if self.parse_mode in ("HTML", "Markdown", "MarkdownV2") else ""
        return self._send_message(text, parse_mode=parse)

    def _format_message_plain(self, event: AccessEvent, risk: RiskResult) -> str:
        lines = [
            f"RAAS — {event.kind.value}",
            f"Risk: {risk.score}/100 · Severity: {risk.severity}",
            "",
        ]
        if event.user:
            lines.append(f"User: {event.user}")
        if event.source_ip:
            lines.append(f"Source IP: {event.source_ip}")
        if event.auth_method:
            lines.append(f"Auth: {event.auth_method}")
        for k, v in (event.extra or {}).items():
            if k in ("port", "command", "target_user", "service", "coalesced_similar"):
                lines.append(f"{k}: {v}")
        if risk.mitre_techniques:
            lines.append(f"MITRE: {', '.join(risk.mitre_techniques)}")
        lines.append("")
        lines.append("Reasons:")
        for r in risk.reasons:
            lines.append(f"• {r}")
        lines.append("")
        raw = event.raw_line[:800].replace("\n", " ")
        lines.append(f"Raw: {raw}")
        return "\n".join(lines)

    def _format_message_html(self, event: AccessEvent, risk: RiskResult) -> str:
        e = html.escape
        lines = [
            f"<b>RAAS</b> — <code>{e(event.kind.value)}</code>",
            f"Risk: <b>{risk.score}</b>/100 · Severity: <b>{e(risk.severity)}</b>",
            "",
        ]
        if event.user:
            lines.append(f"User: <code>{e(event.user)}</code>")
        if event.source_ip:
            lines.append(f"Source IP: <code>{e(event.source_ip)}</code>")
        if event.auth_method:
            lines.append(f"Auth: <code>{e(event.auth_method)}</code>")
        for k, v in (event.extra or {}).items():
            if k in ("port", "command", "target_user", "service", "coalesced_similar"):
                lines.append(f"{e(k)}: <code>{e(str(v))}</code>")
        if risk.mitre_techniques:
            mt = ", ".join(f"<code>{e(t)}</code>" for t in risk.mitre_techniques)
            lines.append(f"MITRE: {mt}")
        lines.append("")
        lines.append("<b>Reasons:</b>")
        for r in risk.reasons:
            lines.append(f"• {e(r)}")
        lines.append("")
        raw = e(event.raw_line[:800].replace("\n", " "))
        lines.append(f"Raw: <code>{raw}</code>")
        return "\n".join(lines)

    def _consume_rate_or_block(self) -> bool:
        """Return True if send should be blocked (rate exceeded). Consumes a slot when allowed."""
        if self.rate_limit_per_minute <= 0:
            return False
        now = time.monotonic()
        while self._rl_times and now - self._rl_times[0] > 60.0:
            self._rl_times.popleft()
        if len(self._rl_times) >= self.rate_limit_per_minute:
            return True
        self._rl_times.append(now)
        return False

    def _send_message(self, text: str, *, parse_mode: str = "") -> bool:
        if len(text) > TELEGRAM_MAX_MESSAGE_LENGTH:
            text = text[: TELEGRAM_MAX_MESSAGE_LENGTH - 20] + "\n…(truncated)"
        if self._consume_rate_or_block():
            logger.warning("Telegram rate limit reached — queueing or dropping")
            if self.retry_enabled and self.retry_queue_path is not None:
                append_telegram_retry_locked(
                    self.retry_queue_path,
                    {"text": text, "parse_mode": parse_mode, "chat_id": self.chat_id, "attempts": 0},
                )
            if self._on_delivery:
                self._on_delivery(False)
            return False

        url = f"{self.api_base_url}/bot{self.bot_token}/sendMessage"
        payload: dict[str, Any] = {
            "chat_id": self.chat_id,
            "text": text,
        }
        if parse_mode:
            payload["parse_mode"] = parse_mode
        try:
            r = requests.post(url, json=payload, timeout=self.timeout_seconds)
            if r.status_code != 200:
                logger.error("Telegram API error: %s %s", r.status_code, r.text[:500])
                if self.retry_enabled and self.retry_queue_path is not None:
                    append_telegram_retry_locked(
                        self.retry_queue_path,
                        {"text": text, "parse_mode": parse_mode, "chat_id": self.chat_id, "attempts": 0},
                    )
                if self._on_delivery:
                    self._on_delivery(False)
                return False
            if self._on_delivery:
                self._on_delivery(True)
            return True
        except requests.RequestException as e:
            logger.error("Telegram request failed: %s", e)
            if self.retry_enabled and self.retry_queue_path is not None:
                append_telegram_retry_locked(
                    self.retry_queue_path,
                    {"text": text, "parse_mode": parse_mode, "chat_id": self.chat_id, "attempts": 0},
                )
            if self._on_delivery:
                self._on_delivery(False)
            return False

    def send_plain_text(self, text: str) -> bool:
        """Lock-intrusion and plain notices: no parse_mode to avoid HTML injection from captures."""
        return self._send_message(text, parse_mode="")

    def send_text_raw(self, text: str, *, parse_mode: str = "") -> bool:
        """Retry worker entrypoint: same transport as sendMessage."""
        return self._send_message(text, parse_mode=parse_mode)

    def send_photo(
        self,
        photo_bytes: bytes,
        caption: str = "",
        *,
        filename: str = "capture.jpg",
        mime_type: str = "image/jpeg",
    ) -> bool:
        if self._consume_rate_or_block():
            logger.warning("Telegram rate limit — skip sendPhoto")
            if self._on_delivery:
                self._on_delivery(False)
            return False
        url = f"{self.api_base_url}/bot{self.bot_token}/sendPhoto"
        files = {"photo": (filename, photo_bytes, mime_type)}
        data: dict[str, Any] = {"chat_id": self.chat_id}
        if caption:
            data["caption"] = caption[:1024]
        try:
            r = requests.post(url, data=data, files=files, timeout=self.timeout_seconds)
            if r.status_code != 200:
                logger.error("Telegram sendPhoto error: %s %s", r.status_code, r.text[:500])
                if self._on_delivery:
                    self._on_delivery(False)
                return False
            if self._on_delivery:
                self._on_delivery(True)
            return True
        except requests.RequestException as e:
            logger.error("Telegram sendPhoto failed: %s", e)
            if self._on_delivery:
                self._on_delivery(False)
            return False
