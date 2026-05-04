from __future__ import annotations

import logging
from collections.abc import Callable

from config.settings import Settings
from notifier.base import AlertNotifier
from notifier.telegram import TelegramNotifier
from notifier.webhook import WebhookNotifier

logger = logging.getLogger(__name__)


class TelegramHighSeverityNotifier(TelegramNotifier):
    """Same transport as TelegramNotifier; distinct channel_id for delivery logging."""

    channel_id = "telegram_high"


def build_alert_notifiers(
    settings: Settings,
    *,
    on_telegram_delivery: Callable[[bool], None] | None = None,
) -> list[AlertNotifier]:
    """
    Build all enabled auth-alert channels from settings.
    Lock-intrusion still uses TelegramNotifier separately (photos).
    """
    out: list[AlertNotifier] = []

    tg = settings.telegram
    tg_ok = tg.enabled and bool(tg.bot_token) and bool(tg.chat_id)
    if tg.enabled and not tg_ok:
        logger.warning(
            "Telegram enabled but bot_token or chat_id empty — skipping Telegram alert channel",
        )
    common_kw = dict(
        api_base_url=tg.api_base_url,
        timeout_seconds=tg.timeout_seconds,
        parse_mode=tg.parse_mode,
        rate_limit_per_minute=tg.rate_limit_per_minute,
        retry_enabled=tg.retry_enabled,
        retry_queue_path=tg.retry_queue_path if tg.retry_enabled else None,
        on_delivery_result=on_telegram_delivery,
    )
    if tg_ok:
        out.append(
            TelegramNotifier(
                tg.bot_token,
                tg.chat_id,
                **common_kw,
            ),
        )
        hi = (tg.high_severity_chat_id or "").strip()
        if hi and hi != str(tg.chat_id).strip():
            out.append(
                TelegramHighSeverityNotifier(
                    tg.bot_token,
                    hi,
                    **common_kw,
                ),
            )

    wh = settings.webhook
    if wh.enabled and (wh.url or "").strip():
        out.append(
            WebhookNotifier(
                wh.url.strip(),
                timeout_seconds=wh.timeout_seconds,
                headers=wh.headers,
            ),
        )
    elif wh.enabled and not (wh.url or "").strip():
        logger.warning("webhook.enabled is true but webhook.url is empty — skipping webhook channel")

    return out
