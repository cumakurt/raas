from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class EventKind(str, Enum):
    # SSH / remote shell
    SSH_ACCEPTED = "ssh_accepted"
    SSH_FAILED = "ssh_failed"
    SSH_INVALID_USER = "ssh_invalid_user"
    SSH_PUBLICKEY_FAILED = "ssh_publickey_failed"
    SSH_MAX_AUTH = "ssh_max_auth_exceeded"
    SSH_BRUTE_FORCE = "ssh_brute_force_disconnect"
    SSH_PREAUTH = "ssh_preauth_disconnect"
    # PAM (often co-emitted with sshd; dedup recommended upstream)
    PAM_SSHD_FAILURE = "pam_sshd_auth_failure"
    # Privilege / local
    SUDO = "sudo"
    SU = "su"
    ROOT_LOGIN = "root_login"
    LOCAL_LOGIN = "local_login"
    # Other network login services (when logged to auth/secure)
    FTP_AUTH_FAILED = "ftp_auth_failed"
    TELNET_AUTH_FAILED = "telnet_auth_failed"
    MAIL_AUTH_FAILED = "mail_auth_failed"
    COCKPIT_SESSION = "cockpit_session"
    # Host security extras (auth.log, secure, journal, audit, firewall agents)
    AUD_LOGIN_FAIL = "audit_user_login_failure"
    AUD_AVC_DENIED = "audit_avc_denied"
    AUD_USER_ACCT = "audit_user_account_change"
    UFW_BLOCK = "ufw_block"
    NFT_DROP = "nftables_drop"
    FAIL2BAN_BAN = "fail2ban_ban"
    FAIL2BAN_UNBAN = "fail2ban_unban"
    POLKIT_AUTH_FAIL = "polkit_auth_failure"
    VPN_AUTH_FAIL = "vpn_auth_failure"
    DB_AUTH_FAIL = "database_auth_failure"
    CONTAINER_AUTH = "container_runtime_auth"
    UNKNOWN = "unknown"


@dataclass
class AccessEvent:
    kind: EventKind
    raw_line: str
    user: str | None = None
    source_ip: str | None = None
    auth_method: str | None = None
    extra: dict[str, Any] = field(default_factory=dict)
