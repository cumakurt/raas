from __future__ import annotations

import logging

from config.settings import Settings
from notifier.base import AlertNotifier
from notifier.telegram import TelegramNotifier
from notifier.webhook import WebhookNotifier

logger = logging.getLogger(__name__)


def build_alert_notifiers(settings: Settings) -> list[AlertNotifier]:
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
    if tg_ok:
        out.append(
            TelegramNotifier(
                tg.bot_token,
                tg.chat_id,
                api_base_url=tg.api_base_url,
                timeout_seconds=tg.timeout_seconds,
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
