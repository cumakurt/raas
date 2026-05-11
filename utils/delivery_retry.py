"""Best-effort Telegram retry queue (JSON Lines)."""

from __future__ import annotations

import json
import logging
import threading
import time
from pathlib import Path
from typing import Any, Callable

logger = logging.getLogger(__name__)

_MAX_LINE_BYTES = 1_000_000
_MAX_APPEND_BYTES = 512_000

_queue_lock = threading.Lock()


def append_telegram_retry_locked(path: Path, payload: dict[str, Any]) -> None:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        line = json.dumps(payload, ensure_ascii=False) + "\n"
        if len(line.encode("utf-8")) > _MAX_APPEND_BYTES:
            logger.warning("telegram retry payload too large; skipping queue append")
            return
        with _queue_lock:
            with open(path, "a", encoding="utf-8") as f:
                f.write(line)
                f.flush()
    except OSError as e:
        logger.error("retry queue append failed: %s", e)


def drain_telegram_retry_file(
    path: Path,
    send_payload: Callable[[dict[str, Any]], bool],
    *,
    max_per_tick: int = 5,
) -> int:
    """
    Try up to max_per_tick pending JSON objects; successful sends are removed.
    send_payload(obj) -> bool
    """
    with _queue_lock:
        if not path.is_file():
            return 0
        try:
            raw = path.read_text(encoding="utf-8")
        except OSError as e:
            logger.debug("retry queue read: %s", e)
            return 0
        try:
            path.unlink(missing_ok=True)
        except OSError as e:
            logger.debug("retry queue unlink: %s", e)
            return 0
        lines = [ln for ln in raw.splitlines() if ln.strip()]

    if not lines:
        return 0

    kept: list[str] = []
    sent = 0
    now = time.time()
    for i, ln in enumerate(lines):
        if sent >= max_per_tick:
            kept.extend(lines[i:])
            break
        if len(ln.encode("utf-8")) > _MAX_LINE_BYTES:
            continue
        try:
            obj = json.loads(ln)
        except json.JSONDecodeError:
            continue
        text = str(obj.get("text", ""))
        if not text:
            continue
        next_try = float(obj.get("next_try_ts", 0) or 0)
        if next_try and now < next_try:
            kept.append(ln)
            continue
        try:
            ok = bool(send_payload(obj))
        except Exception:
            logger.exception("retry send failed")
            kept.append(ln)
            continue
        if ok:
            sent += 1
        else:
            obj["attempts"] = int(obj.get("attempts", 0)) + 1
            obj["next_try_ts"] = time.time() + min(3600.0, 15.0 * (2 ** min(obj["attempts"], 6)))
            if obj["attempts"] > 50:
                logger.warning("dropping telegram retry after many attempts")
                continue
            kept.append(json.dumps(obj, ensure_ascii=False))

    with _queue_lock:
        try:
            if kept:
                path.parent.mkdir(parents=True, exist_ok=True)
                with open(path, "a", encoding="utf-8") as f:
                    f.write("\n".join(kept) + "\n")
        except OSError as e:
            logger.error("retry queue update failed: %s", e)
    return sent
