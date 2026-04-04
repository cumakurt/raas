from __future__ import annotations

import logging
import os
from pathlib import Path

logger = logging.getLogger(__name__)

_TAIL_READ_BYTES = 256 * 1024

# Recent auth.log / secure lines — best-effort hints (not cryptographically bound to the event).
_FAIL_MARKERS = (
    "authentication failure",
    "failed password",
    "auth could not identify password",
    "incorrect password",
    "bad password",
)
_SUCCESS_MARKERS = (
    "session opened for user",
    "session opened for",
    "accepted password",
)


def tail_auth_hints(auth_log_path: Path, *, max_lines: int = 120, max_chars: int = 600) -> str:
    """
    Read the last lines of the auth log and return a short hint about recent
    failed/successful-looking PAM/session lines (for Telegram context).
    """
    path = auth_log_path.expanduser()
    if not path.is_file():
        return ""
    try:
        with open(path, "rb") as f:
            f.seek(0, os.SEEK_END)
            size = f.tell()
            start = max(0, size - _TAIL_READ_BYTES)
            f.seek(start)
            raw = f.read()
        text = raw.decode("utf-8", errors="replace")
    except OSError as e:
        logger.debug("Cannot read auth log for hints: %s", e)
        return ""
    lines = text.splitlines()
    if start > 0 and lines:
        lines = lines[1:]
    tail = lines[-max_lines:] if len(lines) > max_lines else lines
    hits: list[str] = []
    # Scan from newest to oldest
    for line in reversed(tail):
        low = line.lower()
        if any(m in low for m in _FAIL_MARKERS):
            hits.append(f"[possible fail] {line.strip()[:220]}")
        elif any(m in low for m in _SUCCESS_MARKERS):
            hits.append(f"[possible ok] {line.strip()[:220]}")
        if len(hits) >= 4:
            break
    if not hits:
        return ""
    out = "\n".join(reversed(hits))
    return out[:max_chars]
