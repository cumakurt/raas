from __future__ import annotations

from engine.risk_engine import RiskResult
from notifier.telegram import TelegramNotifier
from parser.events import AccessEvent, EventKind


def test_file_deletion_alert_text_is_compact_and_non_repeating() -> None:
    path = "/home/user/Documents/report.txt"
    event = AccessEvent(
        kind=EventKind.FILE_DELETED,
        raw_line=(
            "file_deletion action=deleted item_type=file "
            f"path={path} watched_root=/home/user"
        ),
        user="user",
        extra={
            "action": "deleted",
            "item_type": "file",
            "path": path,
            "watched_root": "/home/user",
        },
    )
    risk = RiskResult(
        score=70,
        reasons=["File or directory deletion observed"],
        severity="high",
        mitre_techniques=["T1485"],
    )
    notifier = TelegramNotifier("token", "chat")

    text = notifier._format_message_html(event, risk)

    assert "Source log line" not in text
    assert text.count(path) == 1
    assert "RAAS file alert" in text
