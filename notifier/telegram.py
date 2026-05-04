from __future__ import annotations

import html
import logging
import time
from collections import deque
from pathlib import Path
from typing import Any, Callable

import requests

from engine.risk_engine import RiskResult
from parser.events import AccessEvent
from utils.delivery_retry import append_telegram_retry_locked

logger = logging.getLogger(__name__)

# https://core.telegram.org/bots/api#sendmessage
TELEGRAM_MAX_MESSAGE_LENGTH = 4096

# Short titles for Telegram (English UI labels; code uses EventKind.value keys).
_KIND_TITLES: dict[str, str] = {
    "ssh_accepted": "Successful SSH login",
    "ssh_failed": "SSH authentication failure",
    "ssh_invalid_user": "SSH attempt for invalid user",
    "ssh_publickey_failed": "SSH public key authentication failed",
    "ssh_max_auth_exceeded": "SSH max authentication attempts exceeded",
    "ssh_brute_force_disconnect": "SSH disconnected (too many failures)",
    "ssh_preauth_disconnect": "SSH pre-auth disconnect / probe",
    "pam_sshd_auth_failure": "PAM sshd authentication failure",
    "sudo": "sudo activity",
    "su": "su (user switch)",
    "root_login": "Root / privileged context",
    "local_login": "Local console session",
    "ftp_auth_failed": "FTP authentication failure",
    "telnet_auth_failed": "Telnet authentication failure",
    "mail_auth_failed": "Mail service authentication failure",
    "cockpit_session": "Cockpit web session opened",
    "audit_user_login_failure": "Auditd: login/auth failure",
    "audit_avc_denied": "SELinux / AppArmor access denied",
    "audit_user_account_change": "User or group account change (audit)",
    "ufw_block": "UFW firewall blocked traffic",
    "nftables_drop": "nftables dropped packet (logged)",
    "fail2ban_ban": "fail2ban banned an IP",
    "fail2ban_unban": "fail2ban unbanned an IP",
    "polkit_auth_failure": "Polkit authorization failure",
    "vpn_auth_failure": "VPN authentication failure",
    "database_auth_failure": "Database authentication failure",
    "container_runtime_auth": "Container / registry auth issue",
    "unknown": "Security-related event",
}

_EXTRA_DISPLAY_KEYS: frozenset[str] = frozenset({
    "port",
    "command",
    "target_user",
    "service",
    "coalesced_similar",
    "dst",
    "dpt",
    "db",
    "binary",
    "comm",
    "audit",
    "service_hint",
    "runtime",
    "result",
})

_EXTRA_LABELS: dict[str, str] = {
    "port": "Port",
    "command": "Command",
    "target_user": "Target user",
    "service": "Service",
    "coalesced_similar": "Similar events merged",
    "dst": "Destination",
    "dpt": "Dest. port",
    "db": "Database",
    "binary": "Program",
    "comm": "Process (comm)",
    "audit": "Audit flag",
    "service_hint": "Hint",
    "runtime": "Runtime",
    "result": "Result",
}


def _human_kind_title(kind_value: str) -> str:
    return _KIND_TITLES.get(kind_value, kind_value.replace("_", " ").title())


def _severity_emoji(severity: str) -> str:
    return {"high": "🔴", "medium": "🟠", "low": "🟢"}.get(severity.lower(), "⚪")


def _suggested_checks(kind_value: str) -> list[str]:
    """Short, actionable hints (English) for the operator."""
    s = {
        "ssh_failed": [
            "Treat repeated failures as possible brute-force; review source IP and time window.",
            "Consider fail2ban / firewall rules; ensure SSH hardening matches your policy.",
        ],
        "ssh_invalid_user": [
            "Often reconnaissance or guessing; block or rate-limit the source if untrusted.",
            "Confirm no legitimate automation uses those usernames.",
        ],
        "ssh_accepted": [
            "Verify the user and source IP are expected (VPN, jump host, automation).",
            "If unexpected: inspect keys and passwords, and review `~/.ssh/authorized_keys`.",
        ],
        "ssh_publickey_failed": [
            "Can indicate key mismatch or key-based probing; correlate with other SSH events.",
        ],
        "ssh_max_auth_exceeded": [
            "Strong signal of automated attacks; review IP and consider blocking.",
        ],
        "ssh_brute_force_disconnect": [
            "Client exceeded allowed auth attempts; often tied to credential stuffing.",
        ],
        "ssh_preauth_disconnect": [
            "May be scanners or broken clients; low context alone—watch for clustering from one IP.",
        ],
        "pam_sshd_auth_failure": [
            "Often duplicates sshd “Failed password”; use logs to confirm user and rhost.",
        ],
        "sudo": [
            "Validate the actor and command in the raw log; ensure change-control if production.",
        ],
        "su": [
            "Confirm the target account switch was authorized and logged per policy.",
        ],
        "root_login": [
            "Review who obtained root context and from where; extra scrutiny on shared systems.",
        ],
        "local_login": [
            "Physical or serial access; confirm expected maintenance or console use.",
        ],
        "fail2ban_ban": [
            "A ban was applied—check jail name in full logs; watch for false positives.",
        ],
        "fail2ban_unban": [
            "Ban lifted—confirm whether manual or timed expiry; monitor the IP afterward.",
        ],
        "ufw_block": [
            "Expected if you log drops; verify SRC/DST and that rules match intent.",
        ],
        "nftables_drop": [
            "Firewall drop logged—correlate with services you expose.",
        ],
        "audit_user_login_failure": [
            "Use `ausearch` / audit logs for full context (UID, terminal, exe).",
        ],
        "audit_avc_denied": [
            "SELinux/AppArmor denied an action; often policy or mislabeled files.",
        ],
        "audit_user_account_change": [
            "Account lifecycle event; confirm via ticketing / admin roster.",
        ],
        "polkit_auth_failure": [
            "User or agent failed elevated action; check desktop session and polkit rules.",
        ],
        "vpn_auth_failure": [
            "Invalid VPN credentials or cert issue; check IdP and client time skew.",
        ],
        "database_auth_failure": [
            "Failed DB login—watch for app misconfig vs. attack; rotate secrets if suspicious.",
        ],
        "container_runtime_auth": [
            "Registry or daemon denied pull/login; verify tokens and image names.",
        ],
        "cockpit_session": [
            "Web admin session opened; confirm operator and source network.",
        ],
        "ftp_auth_failed": [
            "Legacy FTP is high-risk; prefer SFTP and tighten or disable anonymous FTP.",
        ],
        "telnet_auth_failed": [
            "Telnet is cleartext—migrate to SSH and restrict exposure if still required.",
        ],
        "mail_auth_failed": [
            "Mail credential guess or misconfigured client; watch the client IP volume.",
        ],
    }
    return s.get(
        kind_value,
        [
            "Open the raw log on the host and correlate timestamps with other services.",
            "If risk is high, treat as incident until ruled out.",
        ],
    )


class TelegramNotifier:
    """Telegram Bot API channel; implements AlertNotifier via send_alert."""

    channel_id = "telegram"

    def __init__(
        self,
        bot_token: str,
        chat_id: str,
        *,
        api_base_url: str = "https://api.telegram.org",
        timeout_seconds: float = 15.0,
        parse_mode: str = "HTML",
        rate_limit_per_minute: int = 0,
        retry_enabled: bool = False,
        retry_queue_path: Path | None = None,
        on_delivery_result: Callable[[bool], None] | None = None,
    ) -> None:
        self.bot_token = bot_token
        self.chat_id = chat_id
        self.api_base_url = api_base_url.rstrip("/")
        self.timeout_seconds = timeout_seconds
        self.parse_mode = parse_mode or ""
        self.rate_limit_per_minute = max(0, int(rate_limit_per_minute))
        self.retry_enabled = retry_enabled
        self.retry_queue_path = retry_queue_path
        self._on_delivery = on_delivery_result
        self._rl_times: deque[float] = deque()

    def send_alert(self, event: AccessEvent, risk: RiskResult) -> bool:
        return self.send_event(event, risk)

    def send_event(self, event: AccessEvent, risk: RiskResult) -> bool:
        text = self._format_message_html(event, risk) if self.parse_mode == "HTML" else self._format_message_plain(event, risk)
        parse = self.parse_mode if self.parse_mode in ("HTML", "Markdown", "MarkdownV2") else ""
        return self._send_message(text, parse_mode=parse)

    def _format_message_plain(self, event: AccessEvent, risk: RiskResult) -> str:
        kind_v = event.kind.value
        title = _human_kind_title(kind_v)
        emoji = _severity_emoji(risk.severity)
        lines = [
            "🛡 RAAS — Security alert",
            "━" * 28,
            "",
            f"{emoji} Severity: {risk.severity.upper()} · Risk {risk.score}/100",
            "",
            "What happened:",
            title,
            "",
        ]
        if event.user:
            lines.append(f"User: {event.user}")
        if event.source_ip:
            lines.append(f"Source IP: {event.source_ip}")
        if event.auth_method:
            lines.append(f"Auth method: {event.auth_method}")
        for k, v in sorted((event.extra or {}).items()):
            if k in _EXTRA_DISPLAY_KEYS:
                label = _EXTRA_LABELS.get(k, k)
                lines.append(f"{label}: {v}")
        if risk.mitre_techniques:
            lines.append("MITRE: " + ", ".join(risk.mitre_techniques))
        lines.append("")
        lines.append("Why this risk score:")
        for r in risk.reasons:
            lines.append(f"  • {r}")
        lines.append("")
        lines.append("Suggested checks:")
        for hint in _suggested_checks(kind_v)[:4]:
            lines.append(f"  • {hint}")
        lines.append("")
        raw = (event.raw_line[:900]).replace("\n", " ")
        lines.append("Source log line:")
        lines.append(raw)
        return "\n".join(lines)

    def _format_message_html(self, event: AccessEvent, risk: RiskResult) -> str:
        esc = html.escape
        kind_v = event.kind.value
        title = esc(_human_kind_title(kind_v))
        emoji = _severity_emoji(risk.severity)
        lines: list[str] = [
            "🛡 <b>RAAS — Security alert</b>",
            "<i>Real-time access &amp; security monitor</i>",
            "",
            f"{emoji} <b>Severity:</b> {esc(risk.severity.upper())} · "
            f"<b>Risk score:</b> <code>{risk.score}</code>/100",
            "",
            "📋 <b>What happened</b>",
            title,
            "",
        ]
        details: list[str] = []
        if event.user:
            details.append(f"👤 <b>User</b> · <code>{esc(event.user)}</code>")
        if event.source_ip:
            details.append(f"🌐 <b>Source IP</b> · <code>{esc(event.source_ip)}</code>")
        if event.auth_method:
            details.append(f"🔑 <b>Auth method</b> · <code>{esc(event.auth_method)}</code>")
        for k, v in sorted((event.extra or {}).items()):
            if k in _EXTRA_DISPLAY_KEYS:
                label = esc(_EXTRA_LABELS.get(k, k.replace("_", " ").title()))
                details.append(f"▫️ <b>{label}</b> · <code>{esc(str(v))}</code>")
        if details:
            lines.append("📎 <b>Key details</b>")
            lines.extend(details)
            lines.append("")

        if risk.mitre_techniques:
            lines.append("🎯 <b>MITRE ATT&amp;CK (reference)</b>")
            lines.append(", ".join(f"<code>{esc(t)}</code>" for t in risk.mitre_techniques))
            lines.append("")

        lines.append("📌 <b>Why this risk score</b>")
        for r in risk.reasons:
            lines.append(f"  • {esc(r)}")
        lines.append("")

        lines.append("🧭 <b>Suggested checks</b>")
        for hint in _suggested_checks(kind_v)[:4]:
            lines.append(f"  • {esc(hint)}")
        lines.append("")

        raw_snip = esc(event.raw_line[:900].replace("\n", " "))
        lines.append("📄 <b>Source log line</b>")
        lines.append(f"<pre>{raw_snip}</pre>")

        text = "\n".join(lines)
        if len(text) > TELEGRAM_MAX_MESSAGE_LENGTH - 60:
            text = text[: TELEGRAM_MAX_MESSAGE_LENGTH - 60].rstrip() + "\n\n<i>(truncated for Telegram limit)</i>"
        return text

    def _consume_rate_or_block(self) -> bool:
        """Return True if send should be blocked (rate exceeded). Consumes a slot when allowed."""
        if self.rate_limit_per_minute <= 0:
            return False
        now = time.monotonic()
        while self._rl_times and now - self._rl_times[0] > 60.0:
            self._rl_times.popleft()
        if len(self._rl_times) >= self.rate_limit_per_minute:
            return True
        self._rl_times.append(now)
        return False

    def _send_message(self, text: str, *, parse_mode: str = "") -> bool:
        if len(text) > TELEGRAM_MAX_MESSAGE_LENGTH:
            text = text[: TELEGRAM_MAX_MESSAGE_LENGTH - 20] + "\n…(truncated)"
        if self._consume_rate_or_block():
            logger.warning("Telegram rate limit reached — queueing or dropping")
            if self.retry_enabled and self.retry_queue_path is not None:
                append_telegram_retry_locked(
                    self.retry_queue_path,
                    {"text": text, "parse_mode": parse_mode, "chat_id": self.chat_id, "attempts": 0},
                )
            if self._on_delivery:
                self._on_delivery(False)
            return False

        url = f"{self.api_base_url}/bot{self.bot_token}/sendMessage"
        payload: dict[str, Any] = {
            "chat_id": self.chat_id,
            "text": text,
            "disable_web_page_preview": True,
        }
        if parse_mode:
            payload["parse_mode"] = parse_mode
        try:
            r = requests.post(
                url,
                json=payload,
                timeout=self.timeout_seconds,
                allow_redirects=False,
            )
            if r.status_code != 200:
                logger.error("Telegram API error: %s %s", r.status_code, r.text[:500])
                if self.retry_enabled and self.retry_queue_path is not None:
                    append_telegram_retry_locked(
                        self.retry_queue_path,
                        {"text": text, "parse_mode": parse_mode, "chat_id": self.chat_id, "attempts": 0},
                    )
                if self._on_delivery:
                    self._on_delivery(False)
                return False
            if self._on_delivery:
                self._on_delivery(True)
            return True
        except requests.RequestException as e:
            logger.error("Telegram request failed: %s", e)
            if self.retry_enabled and self.retry_queue_path is not None:
                append_telegram_retry_locked(
                    self.retry_queue_path,
                    {"text": text, "parse_mode": parse_mode, "chat_id": self.chat_id, "attempts": 0},
                )
            if self._on_delivery:
                self._on_delivery(False)
            return False

    def send_plain_text(self, text: str) -> bool:
        """Lock-intrusion and plain notices: no parse_mode to avoid HTML injection from captures."""
        return self._send_message(text, parse_mode="")

    def send_text_raw(self, text: str, *, parse_mode: str = "") -> bool:
        """Retry worker entrypoint: same transport as sendMessage."""
        return self._send_message(text, parse_mode=parse_mode)

    def send_photo(
        self,
        photo_bytes: bytes,
        caption: str = "",
        *,
        filename: str = "capture.jpg",
        mime_type: str = "image/jpeg",
    ) -> bool:
        if self._consume_rate_or_block():
            logger.warning("Telegram rate limit — skip sendPhoto")
            if self._on_delivery:
                self._on_delivery(False)
            return False
        url = f"{self.api_base_url}/bot{self.bot_token}/sendPhoto"
        files = {"photo": (filename, photo_bytes, mime_type)}
        data: dict[str, Any] = {"chat_id": self.chat_id}
        if caption:
            data["caption"] = caption[:1024]
        try:
            r = requests.post(
                url,
                data=data,
                files=files,
                timeout=self.timeout_seconds,
                allow_redirects=False,
            )
            if r.status_code != 200:
                logger.error("Telegram sendPhoto error: %s %s", r.status_code, r.text[:500])
                if self._on_delivery:
                    self._on_delivery(False)
                return False
            if self._on_delivery:
                self._on_delivery(True)
            return True
        except requests.RequestException as e:
            logger.error("Telegram sendPhoto failed: %s", e)
            if self._on_delivery:
                self._on_delivery(False)
            return False
