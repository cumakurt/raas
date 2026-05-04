from __future__ import annotations

import logging
import os
import threading
import time
from collections.abc import Iterator
from pathlib import Path

logger = logging.getLogger(__name__)


def _interruptible_sleep(
    seconds: float,
    stop_event: threading.Event | None,
) -> bool:
    """Sleep up to `seconds`; return True if `stop_event` was set (caller should exit)."""
    if stop_event is not None:
        return stop_event.wait(timeout=seconds)
    time.sleep(seconds)
    return False


def follow_file_lines(
    path: Path,
    *,
    tail_from_end: bool = True,
    poll_interval_seconds: float = 0.8,
    encoding: str = "utf-8",
    errors: str = "replace",
    stop_event: threading.Event | None = None,
) -> Iterator[str]:
    """
    Yield new lines from a log file as they are appended (similar to tail -f).
    Recovers if the file is rotated/truncated and recreated.
    """
    path = path.expanduser()
    if not path.is_file():
        logger.warning("Log file does not exist yet: %s — waiting...", path)

    inode: int | None = None
    position = 0

    while True:
        if stop_event is not None and stop_event.is_set():
            return
        try:
            if not path.is_file():
                if _interruptible_sleep(poll_interval_seconds, stop_event):
                    return
                continue

            st = path.stat()
            current_inode = st.st_ino

            if inode is not None and current_inode != inode:
                logger.info("Log rotated or recreated: %s", path)
                position = 0
            inode = current_inode

            if st.st_size < position:
                logger.info("Log truncated: %s", path)
                position = 0

            with open(path, "r", encoding=encoding, errors=errors) as f:
                if tail_from_end and position == 0 and st.st_size > 0:
                    f.seek(0, os.SEEK_END)
                    position = f.tell()
                else:
                    f.seek(min(position, st.st_size))

                while True:
                    if stop_event is not None and stop_event.is_set():
                        return
                    line = f.readline()
                    if not line:
                        break
                    position = f.tell()
                    yield line.rstrip("\n\r")

        except OSError as e:
            logger.error("Error reading log %s: %s", path, e)
            if _interruptible_sleep(1.0, stop_event):
                return

        if _interruptible_sleep(poll_interval_seconds, stop_event):
            return
