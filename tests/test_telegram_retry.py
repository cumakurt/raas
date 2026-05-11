from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from notifier.telegram import TelegramNotifier
from utils.delivery_retry import append_telegram_retry_locked, drain_telegram_retry_file


class _Response:
    def __init__(self, status_code: int, text: str = "") -> None:
        self.status_code = status_code
        self.text = text


def test_retry_worker_send_does_not_requeue_on_failure(
    tmp_path: Path,
    monkeypatch: Any,
) -> None:
    queue_path = tmp_path / "retry.jsonl"
    notifier = TelegramNotifier(
        "token",
        "primary",
        retry_enabled=True,
        retry_queue_path=queue_path,
    )

    def post_fail(*args: Any, **kwargs: Any) -> _Response:
        return _Response(500, "bad")

    monkeypatch.setattr("notifier.telegram.requests.post", post_fail)

    assert notifier.send_text_raw("queued payload", chat_id="secondary") is False
    assert not queue_path.exists()


def test_retry_worker_uses_payload_chat_id(monkeypatch: Any) -> None:
    seen_chat_ids: list[str] = []
    notifier = TelegramNotifier("token", "primary")

    def post_ok(*args: Any, **kwargs: Any) -> _Response:
        seen_chat_ids.append(str(kwargs["json"]["chat_id"]))
        return _Response(200, "ok")

    monkeypatch.setattr("notifier.telegram.requests.post", post_ok)

    assert notifier.send_text_raw("queued payload", chat_id="secondary") is True
    assert seen_chat_ids == ["secondary"]


def test_retry_drain_preserves_concurrent_appends(tmp_path: Path) -> None:
    queue_path = tmp_path / "retry.jsonl"
    append_telegram_retry_locked(
        queue_path,
        {"text": "old", "parse_mode": "", "chat_id": "primary", "attempts": 0},
    )

    def send_payload(_obj: dict[str, Any]) -> bool:
        append_telegram_retry_locked(
            queue_path,
            {"text": "new", "parse_mode": "", "chat_id": "primary", "attempts": 0},
        )
        return False

    assert drain_telegram_retry_file(queue_path, send_payload, max_per_tick=1) == 0

    rows = [json.loads(line) for line in queue_path.read_text(encoding="utf-8").splitlines()]
    assert {row["text"] for row in rows} == {"old", "new"}
    old = next(row for row in rows if row["text"] == "old")
    assert old["attempts"] == 1
