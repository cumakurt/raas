from __future__ import annotations

import tempfile
from pathlib import Path

from config.settings import load_settings
from notifier.alert_payload import alert_to_dict
from notifier.build import build_alert_notifiers
from notifier.webhook import WebhookNotifier
from parser.events import AccessEvent, EventKind
from engine.risk_engine import RiskResult


def test_alert_to_dict_schema() -> None:
    ev = AccessEvent(kind=EventKind.SSH_FAILED, raw_line="x", user="u", source_ip="1.1.1.1")
    risk = RiskResult(score=40, reasons=["test"])
    d = alert_to_dict(ev, risk)
    assert d["schema"] == "raas.alert.v1"
    assert d["kind"] == "ssh_failed"
    assert d["risk_score"] == 40


def test_build_notifiers_telegram_and_webhook() -> None:
    yaml_text = """
log:
  path: auto
telegram:
  enabled: true
  bot_token: "1:token"
  chat_id: "1"
webhook:
  enabled: true
  url: "https://example.com/hook"
  headers:
    X-Key: "secret"
"""
    with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False) as f:
        f.write(yaml_text)
        p = Path(f.name)
    try:
        s = load_settings(p)
        notifiers = build_alert_notifiers(s)
        assert len(notifiers) == 2
        ids = {n.channel_id for n in notifiers}
        assert ids == {"telegram", "webhook"}
        by_id = {n.channel_id: n for n in notifiers}
        assert isinstance(by_id["webhook"], WebhookNotifier)
    finally:
        p.unlink(missing_ok=True)
