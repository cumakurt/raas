from __future__ import annotations

import time

from parser.events import AccessEvent, EventKind


class AuthEventDedup:
    """
    Suppress pam_unix(sshd:auth) lines that duplicate a recent sshd Failed password/publickey
    line for the same (user, source_ip). Does not suppress repeated sshd failures.
    """

    def __init__(self, ttl_seconds: float = 1.5) -> None:
        self.ttl_seconds = ttl_seconds
        self._recent_sshd_fail: dict[tuple[str | None, str | None], float] = {}

    def _key(self, event: AccessEvent) -> tuple[str | None, str | None]:
        return (event.user, event.source_ip)

    def should_emit(self, event: AccessEvent) -> bool:
        k = self._key(event)
        now = time.monotonic()

        if event.kind in (EventKind.SSH_FAILED, EventKind.SSH_PUBLICKEY_FAILED):
            self._recent_sshd_fail[k] = now
            self._prune(now)
            return True

        if event.kind == EventKind.PAM_SSHD_FAILURE:
            t = self._recent_sshd_fail.get(k)
            if t is not None and (now - t) < self.ttl_seconds:
                return False
            return True

        return True

    def _prune(self, now: float) -> None:
        if len(self._recent_sshd_fail) <= 256:
            return
        cutoff = now - self.ttl_seconds * 6
        self._recent_sshd_fail = {a: b for a, b in self._recent_sshd_fail.items() if b > cutoff}
