from __future__ import annotations

import logging
import select
import shutil
import subprocess
import threading
from collections.abc import Iterator
from typing import Sequence

logger = logging.getLogger(__name__)

_DEFAULT_JOURNALCTL_ARGS: tuple[str, ...] = ("-f", "-n", "0", "-o", "cat")


def follow_journal_lines(
    journalctl_args: Sequence[str] | None = None,
    *,
    stop_event: threading.Event | None = None,
    encoding: str = "utf-8",
    errors: str = "replace",
) -> Iterator[str]:
    """
    Stream text lines from `journalctl` (systemd journal). Requires journalctl on PATH.
    """
    jc = shutil.which("journalctl")
    if not jc:
        raise RuntimeError("journalctl not found; install systemd or use log.backend: file")

    args = list(journalctl_args) if journalctl_args else list(_DEFAULT_JOURNALCTL_ARGS)
    cmd = [jc, *args]
    logger.info("Starting journal follow: %s", " ".join(cmd))

    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        stdin=subprocess.DEVNULL,
        bufsize=0,
    )
    assert proc.stdout is not None
    fd = proc.stdout.fileno()

    def _kill() -> None:
        if proc.poll() is None:
            try:
                proc.terminate()
                proc.wait(timeout=3)
            except (subprocess.TimeoutExpired, OSError):
                try:
                    proc.kill()
                except OSError:
                    pass

    try:
        while True:
            if stop_event is not None and stop_event.is_set():
                break
            timeout = 0.5 if stop_event is not None else None
            if timeout is not None:
                r, _, _ = select.select([fd], [], [], timeout)
                if stop_event is not None and stop_event.is_set():
                    break
                if not r:
                    continue
            else:
                r, _, _ = select.select([fd], [], [])
                if not r:
                    continue
            raw = proc.stdout.readline()
            if not raw:
                if proc.poll() is not None:
                    logger.error("journalctl exited with code %s", proc.returncode)
                    break
                continue
            line = raw.decode(encoding, errors=errors).rstrip("\n\r")
            yield line
    finally:
        _kill()


def default_journalctl_args() -> list[str]:
    return list(_DEFAULT_JOURNALCTL_ARGS)
