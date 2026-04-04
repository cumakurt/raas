from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from zoneinfo import ZoneInfo

from parser.events import AccessEvent, EventKind


@dataclass
class RiskResult:
    score: int
    reasons: list[str]


class RiskEngine:
    """Assigns a 0-100 risk score and human-readable reasons."""

    def __init__(
        self,
        night_start: int = 22,
        night_end: int = 6,
        *,
        night_timezone: str = "UTC",
        night_bonus: int = 10,
        score_overrides: dict[str, int] | None = None,
    ) -> None:
        self.night_start = int(night_start) % 24
        self.night_end = int(night_end) % 24
        self.night_bonus = max(0, min(100, int(night_bonus)))
        self._score_overrides = dict(score_overrides) if score_overrides else {}
        tz_name = (night_timezone or "UTC").strip() or "UTC"
        try:
            self._night_tz = ZoneInfo(tz_name)
        except (KeyError, OSError):
            self._night_tz = ZoneInfo("UTC")
            tz_name = "UTC"
        self._night_tz_name = tz_name

    def _ov(self, key: str, default: int) -> int:
        if key in self._score_overrides:
            return max(0, min(100, int(self._score_overrides[key])))
        return default

    def _hour_night_zone(self) -> int:
        return datetime.now(self._night_tz).hour

    def _is_night_now(self) -> bool:
        h = self._hour_night_zone()
        a, b = self.night_start, self.night_end
        if a == b:
            return False
        if a > b:
            return h >= a or h < b
        return a <= h < b

    def evaluate(self, event: AccessEvent) -> RiskResult:
        reasons: list[str] = []
        score = 0

        k = event.kind

        if k == EventKind.SSH_FAILED:
            score = self._ov(EventKind.SSH_FAILED.value, 45)
            reasons.append("SSH authentication failure")
            if event.auth_method == "keyboard-interactive":
                score += 5
                reasons.append("keyboard-interactive auth failure")
        elif k == EventKind.SSH_PUBLICKEY_FAILED:
            score = self._ov(EventKind.SSH_PUBLICKEY_FAILED.value, 45)
            reasons.append("SSH public key authentication failure")
        elif k == EventKind.PAM_SSHD_FAILURE:
            score = self._ov(EventKind.PAM_SSHD_FAILURE.value, 44)
            reasons.append("PAM sshd authentication failure")
        elif k == EventKind.SSH_INVALID_USER:
            score = self._ov(EventKind.SSH_INVALID_USER.value, 55)
            reasons.append("SSH login attempt for invalid user")
        elif k == EventKind.SSH_MAX_AUTH:
            score = self._ov(EventKind.SSH_MAX_AUTH.value, 68)
            reasons.append("SSH maximum authentication attempts exceeded")
        elif k == EventKind.SSH_BRUTE_FORCE:
            score = self._ov(EventKind.SSH_BRUTE_FORCE.value, 72)
            reasons.append("SSH disconnect: too many authentication failures")
        elif k == EventKind.SSH_PREAUTH:
            score = self._ov(EventKind.SSH_PREAUTH.value, 38)
            reasons.append("SSH pre-authentication disconnect / probe")
        elif k == EventKind.SSH_ACCEPTED:
            score = self._ov(EventKind.SSH_ACCEPTED.value, 25)
            reasons.append("Successful SSH login")
            if event.user == "root":
                score = self._ov("ssh_accepted_root", 75)
                reasons.append("SSH session as root")
            elif event.auth_method == "password":
                score += 10
                reasons.append("Password-based SSH (weaker than key-based)")
            elif event.auth_method and event.auth_method != "password":
                score += 10
                reasons.append(f"SSH login via {event.auth_method}")
        elif k == EventKind.SUDO:
            score = self._ov(EventKind.SUDO.value, 35)
            reasons.append("sudo command executed")
            tgt = (event.extra or {}).get("target_user", "")
            if str(tgt).lower() == "root":
                score += 15
                reasons.append("sudo to root user")
        elif k == EventKind.SU:
            score = self._ov(EventKind.SU.value, 40)
            reasons.append("su user switch")
        elif k == EventKind.ROOT_LOGIN:
            score = self._ov(EventKind.ROOT_LOGIN.value, 70)
            reasons.append("Switch to root context")
        elif k == EventKind.LOCAL_LOGIN:
            score = self._ov(EventKind.LOCAL_LOGIN.value, 30)
            reasons.append("Local console login")
        elif k == EventKind.FTP_AUTH_FAILED:
            score = self._ov(EventKind.FTP_AUTH_FAILED.value, 42)
            reasons.append("FTP authentication failure")
        elif k == EventKind.TELNET_AUTH_FAILED:
            score = self._ov(EventKind.TELNET_AUTH_FAILED.value, 52)
            reasons.append("Telnet authentication failure")
        elif k == EventKind.MAIL_AUTH_FAILED:
            score = self._ov(EventKind.MAIL_AUTH_FAILED.value, 38)
            reasons.append("Mail/IMAP/SMTP authentication failure")
        elif k == EventKind.COCKPIT_SESSION:
            score = self._ov(EventKind.COCKPIT_SESSION.value, 28)
            reasons.append("Cockpit web console session opened")
        else:
            score = self._ov(EventKind.UNKNOWN.value, 10)
            reasons.append("Access-related event")

        if self._is_night_now():
            score = min(100, score + self.night_bonus)
            reasons.append(f"Event during night hours ({self._night_tz_name})")

        return RiskResult(score=min(100, max(0, score)), reasons=reasons)
