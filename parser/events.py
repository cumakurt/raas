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
    UNKNOWN = "unknown"


@dataclass
class AccessEvent:
    kind: EventKind
    raw_line: str
    user: str | None = None
    source_ip: str | None = None
    auth_method: str | None = None
    extra: dict[str, Any] = field(default_factory=dict)
