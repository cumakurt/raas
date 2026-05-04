"""Loose MITRE ATT&CK technique IDs per EventKind (informational tagging)."""

from __future__ import annotations

from parser.events import EventKind

_KIND_TO_MITRE: dict[EventKind, list[str]] = {
    EventKind.SSH_FAILED: ["T1110"],
    EventKind.SSH_PUBLICKEY_FAILED: ["T1110"],
    EventKind.SSH_INVALID_USER: ["T1078", "T1110"],
    EventKind.SSH_MAX_AUTH: ["T1110"],
    EventKind.SSH_BRUTE_FORCE: ["T1110"],
    EventKind.SSH_PREAUTH: ["T1046", "T1595"],
    EventKind.PAM_SSHD_FAILURE: ["T1110"],
    EventKind.SSH_ACCEPTED: ["T1078"],
    EventKind.SUDO: ["T1548"],
    EventKind.SU: ["T1548"],
    EventKind.ROOT_LOGIN: ["T1078"],
    EventKind.LOCAL_LOGIN: ["T1078"],
    EventKind.FTP_AUTH_FAILED: ["T1110"],
    EventKind.TELNET_AUTH_FAILED: ["T1110"],
    EventKind.MAIL_AUTH_FAILED: ["T1110"],
    EventKind.COCKPIT_SESSION: ["T1190", "T1078"],
    EventKind.AUD_LOGIN_FAIL: ["T1110"],
    EventKind.AUD_AVC_DENIED: ["T1562"],
    EventKind.AUD_USER_ACCT: ["T1136", "T1098"],
    EventKind.UFW_BLOCK: ["T1046"],
    EventKind.NFT_DROP: ["T1046"],
    EventKind.FAIL2BAN_BAN: ["T1046"],
    EventKind.FAIL2BAN_UNBAN: [],
    EventKind.POLKIT_AUTH_FAIL: ["T1548"],
    EventKind.VPN_AUTH_FAIL: ["T1110"],
    EventKind.DB_AUTH_FAIL: ["T1110"],
    EventKind.CONTAINER_AUTH: ["T1552"],
    EventKind.UNKNOWN: [],
}


def mitre_for_kind(kind: EventKind) -> list[str]:
    return list(_KIND_TO_MITRE.get(kind, []))
