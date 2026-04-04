from __future__ import annotations

import re

from parser.events import AccessEvent, EventKind

# OpenSSH 9.6+ / some distros log as sshd-session[pid]: instead of sshd[pid]:
_SSHD = r"(?:sshd|sshd-session)\[\d+\]:"

# --- SSH: successful authentication (OpenSSH — password, pubkey, hostbased, GSSAPI, etc.) ---
_RE_ACCEPTED = re.compile(
    _SSHD + r"\s*Accepted\s+([\w-]+)\s+for\s+(\S+)\s+from\s+(\S+)\s+port\s+(\d+)",
    re.IGNORECASE,
)

_RE_FAILED_PASSWORD = re.compile(
    _SSHD + r"\s*Failed\s+password\s+for\s+(?:invalid\s+user\s+)?(\S+)\s+from\s+(\S+)\s+port\s+(\d+)",
    re.IGNORECASE,
)

_RE_FAILED_PUBLICKEY = re.compile(
    _SSHD + r"\s*Failed\s+publickey\s+for\s+(?:invalid\s+user\s+)?(\S+)\s+from\s+(\S+)\s+port\s+(\d+)",
    re.IGNORECASE,
)

_RE_FAILED_KBINTERACTIVE = re.compile(
    _SSHD + r"\s*Failed\s+keyboard-interactive\s+for\s+(?:invalid\s+user\s+)?(\S+)\s+from\s+(\S+)\s+port\s+(\d+)",
    re.IGNORECASE,
)

_RE_INVALID_USER = re.compile(
    _SSHD + r"\s*Invalid\s+user\s+(\S+)\s+from\s+(\S+)\s+port\s+(\d+)",
    re.IGNORECASE,
)

_RE_MAX_AUTH = re.compile(
    _SSHD + r"\s*error:\s*maximum\s+authentication\s+attempts\s+exceeded\s+for\s+"
    r"(?:invalid\s+user\s+)?(\S+)\s+from\s+(\S+)\s+port\s+(\d+)",
    re.IGNORECASE,
)

_RE_TOO_MANY_AUTH = re.compile(
    _SSHD + r"\s*error:\s*Received\s+disconnect\s+from\s+(\S+)\s+port\s+(\d+):\s*Too\s+many\s+authentication\s+failures",
    re.IGNORECASE,
)

# preauth: "Connection closed by invalid user NAME IP port" or "by IP port" only
_RE_CONN_CLOSED_INVALID_USER = re.compile(
    _SSHD + r"\s*Connection\s+closed\s+by\s+invalid\s+user\s+(\S+)\s+(\S+)\s+port\s+(\d+)\s+\[preauth\]",
    re.IGNORECASE,
)
_RE_CONN_CLOSED_BY_IP = re.compile(
    _SSHD + r"\s*Connection\s+closed\s+by\s+(\d{1,3}(?:\.\d{1,3}){3})\s+port\s+(\d+)\s+\[preauth\]",
    re.IGNORECASE,
)

_RE_DISCONNECTED_PREAUTH = re.compile(
    _SSHD + r"\s*Disconnected\s+from\s+(?:invalid\s+user\s+)?(\S+)\s+(\S+)\s+port\s+(\d+)\s+\[preauth\]",
    re.IGNORECASE,
)
_RE_DISCONNECTED_IP_ONLY = re.compile(
    _SSHD + r"\s*Disconnected\s+from\s+(\d{1,3}(?:\.\d{1,3}){3})\s+port\s+(\d+)\s+\[preauth\]",
    re.IGNORECASE,
)

_RE_SUDO = re.compile(
    r"sudo:\s*(\S+)\s*:\s*.*?USER=(\S+)\s*;\s*COMMAND=(.+)$",
    re.IGNORECASE,
)

_RE_SU = re.compile(
    r"su(?:\[\d+\])?:\s*\(to\s+(\S+)\)\s+(\S+)\s+on",
    re.IGNORECASE,
)

_RE_LOCAL_LOGIN = re.compile(
    r"(?:login|getty|agetty).*session\s+opened\s+for\s+(\S+)",
    re.IGNORECASE,
)

_RE_VSFTP_FAIL = re.compile(
    r"vsftpd.*(?:FAIL\s+LOGIN|authentication\s+failure).*Client\s+\"([^\"]+)\"",
    re.IGNORECASE,
)

_RE_PROFTP_FAIL = re.compile(
    r"proftpd\[\d+\].*?(?:FAIL\s+LOGIN|Authentication\s+failed).*?(?:from\s+)(\S+)",
    re.IGNORECASE,
)

_RE_TELNET_FAIL = re.compile(
    r"telnetd.*(?:authentication\s+failure|Failed\s+login).*?(?:from|rhost=)\s*(\S+)",
    re.IGNORECASE,
)

_RE_DOVECOT_RIP = re.compile(r"\brip=([^\s,]+)", re.IGNORECASE)
_RE_DOVECOT_USER = re.compile(r"user=<([^>]+)>", re.IGNORECASE)
_RE_DOVECOT_PASSWD_USER = re.compile(r"passwd\(([^)]+)\)", re.IGNORECASE)

_RE_POSTFIX_SASL = re.compile(
    r"postfix/smtpd\[\d+\]:.*(?:SASL\s+(?:LOGIN|PLAIN)\s+authentication failed|authentication failed).*?\[(\d{1,3}(?:\.\d{1,3}){3})\]",
    re.IGNORECASE,
)

_RE_COCKPIT = re.compile(
    r"cockpit(?:-session)?(?:\[\d+\])?:.*session\s+opened\s+for\s+user\s+(\S+)",
    re.IGNORECASE,
)


def _pam_sshd_auth_failure(line: str) -> tuple[str | None, str | None] | None:
    """Extract rhost and login user from pam_unix(sshd:auth) failure lines."""
    low = line.lower()
    if "pam_unix(sshd:auth)" not in low or "authentication failure" not in low:
        return None
    rhost_m = re.search(r"\brhost=(\S+)", line)
    # Prefer final ` user=name` (account), not logname=
    users = re.findall(r"(?:^|\s)user=(\S+)", line)
    user = users[-1] if users else None
    ip = rhost_m.group(1) if rhost_m else None
    if not ip and not user:
        return None
    return (ip, user)


def parse_auth_line(line: str) -> AccessEvent | None:
    """Parse one auth/secure log line: SSH, PAM, sudo, su, FTP, mail, cockpit, console."""
    line = line.strip()
    if not line:
        return None

    lower = line.lower()

    if "sshd" in lower or "sshd-session" in lower:
        m = _RE_ACCEPTED.search(line)
        if m:
            method, user, ip, port = m.groups()
            return AccessEvent(
                kind=EventKind.SSH_ACCEPTED,
                raw_line=line,
                user=user,
                source_ip=ip,
                auth_method=method.lower(),
                extra={"port": int(port)},
            )

        m = _RE_INVALID_USER.search(line)
        if m:
            user, ip, port = m.groups()
            return AccessEvent(
                kind=EventKind.SSH_INVALID_USER,
                raw_line=line,
                user=user,
                source_ip=ip,
                extra={"port": int(port)},
            )

        m = _RE_MAX_AUTH.search(line)
        if m:
            user, ip, port = m.groups()
            return AccessEvent(
                kind=EventKind.SSH_MAX_AUTH,
                raw_line=line,
                user=user,
                source_ip=ip,
                extra={"port": int(port)},
            )

        m = _RE_TOO_MANY_AUTH.search(line)
        if m:
            ip, port = m.groups()
            return AccessEvent(
                kind=EventKind.SSH_BRUTE_FORCE,
                raw_line=line,
                source_ip=ip,
                extra={"port": int(port)},
            )

        m = _RE_FAILED_PUBLICKEY.search(line)
        if m:
            user, ip, port = m.groups()
            return AccessEvent(
                kind=EventKind.SSH_PUBLICKEY_FAILED,
                raw_line=line,
                user=user,
                source_ip=ip,
                extra={"port": int(port)},
            )

        m = _RE_FAILED_KBINTERACTIVE.search(line)
        if m:
            user, ip, port = m.groups()
            return AccessEvent(
                kind=EventKind.SSH_FAILED,
                raw_line=line,
                user=user,
                source_ip=ip,
                auth_method="keyboard-interactive",
                extra={"port": int(port)},
            )

        m = _RE_FAILED_PASSWORD.search(line)
        if m:
            user, ip, port = m.groups()
            return AccessEvent(
                kind=EventKind.SSH_FAILED,
                raw_line=line,
                user=user,
                source_ip=ip,
                auth_method="password",
                extra={"port": int(port)},
            )

        m = _RE_CONN_CLOSED_INVALID_USER.search(line)
        if m:
            user, ip, port = m.groups()
            return AccessEvent(
                kind=EventKind.SSH_PREAUTH,
                raw_line=line,
                user=user,
                source_ip=ip,
                extra={"port": int(port)},
            )

        m = _RE_CONN_CLOSED_BY_IP.search(line)
        if m:
            ip, port = m.groups()
            return AccessEvent(
                kind=EventKind.SSH_PREAUTH,
                raw_line=line,
                source_ip=ip,
                extra={"port": int(port)},
            )

        m = _RE_DISCONNECTED_PREAUTH.search(line)
        if m:
            user_or_name, ip, port = m.groups()
            return AccessEvent(
                kind=EventKind.SSH_PREAUTH,
                raw_line=line,
                user=user_or_name,
                source_ip=ip,
                extra={"port": int(port)},
            )

        m = _RE_DISCONNECTED_IP_ONLY.search(line)
        if m:
            ip, port = m.groups()
            return AccessEvent(
                kind=EventKind.SSH_PREAUTH,
                raw_line=line,
                source_ip=ip,
                extra={"port": int(port)},
            )

    pam = _pam_sshd_auth_failure(line)
    if pam is not None:
        ip, user = pam
        return AccessEvent(
            kind=EventKind.PAM_SSHD_FAILURE,
            raw_line=line,
            user=user,
            source_ip=ip,
            extra={},
        )

    if "sudo:" in lower:
        m = _RE_SUDO.search(line)
        if m:
            actor, target_user, command = m.groups()
            return AccessEvent(
                kind=EventKind.SUDO,
                raw_line=line,
                user=actor,
                extra={"target_user": target_user.strip(), "command": command.strip()},
            )

    m = _RE_SU.search(line)
    if m:
        target, actor = m.groups()
        kind = EventKind.ROOT_LOGIN if target.lower() == "root" else EventKind.SU
        return AccessEvent(
            kind=kind,
            raw_line=line,
            user=actor,
            extra={"target_user": target},
        )

    if "vsftpd" in lower:
        m = _RE_VSFTP_FAIL.search(line)
        if m:
            return AccessEvent(
                kind=EventKind.FTP_AUTH_FAILED,
                raw_line=line,
                source_ip=m.group(1),
                extra={"service": "vsftpd"},
            )

    if "proftpd" in lower:
        m = _RE_PROFTP_FAIL.search(line)
        if m:
            return AccessEvent(
                kind=EventKind.FTP_AUTH_FAILED,
                raw_line=line,
                source_ip=m.group(1),
                extra={"service": "proftpd"},
            )

    if "telnetd" in lower:
        m = _RE_TELNET_FAIL.search(line)
        if m:
            return AccessEvent(
                kind=EventKind.TELNET_AUTH_FAILED,
                raw_line=line,
                source_ip=m.group(1),
                extra={},
            )

    if "dovecot" in lower and (
        "auth failed" in lower or "authentication failure" in lower or "password mismatch" in lower
    ):
        rip = _RE_DOVECOT_RIP.search(line)
        u = _RE_DOVECOT_USER.search(line)
        pwd_u = _RE_DOVECOT_PASSWD_USER.search(line)
        acc_user = u.group(1) if u else (pwd_u.group(1) if pwd_u else None)
        if rip or u or pwd_u:
            return AccessEvent(
                kind=EventKind.MAIL_AUTH_FAILED,
                raw_line=line,
                user=acc_user,
                source_ip=rip.group(1) if rip else None,
                extra={"service": "dovecot"},
            )

    if "postfix" in lower and "sasl" in lower and "fail" in lower:
        m = _RE_POSTFIX_SASL.search(line)
        if m:
            return AccessEvent(
                kind=EventKind.MAIL_AUTH_FAILED,
                raw_line=line,
                source_ip=m.group(1),
                extra={"service": "postfix-sasl"},
            )

    if "cockpit" in lower:
        m = _RE_COCKPIT.search(line)
        if m:
            return AccessEvent(
                kind=EventKind.COCKPIT_SESSION,
                raw_line=line,
                user=m.group(1),
                extra={},
            )

    m = _RE_LOCAL_LOGIN.search(line)
    if m and "sshd" not in lower:
        return AccessEvent(
            kind=EventKind.LOCAL_LOGIN,
            raw_line=line,
            user=m.group(1),
        )

    return None
