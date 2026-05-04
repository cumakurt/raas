"""Parse security-related log lines not covered by ssh_parser (firewall, audit, fail2ban, etc.)."""

from __future__ import annotations

import re

from parser.events import AccessEvent, EventKind

_RE_AUDIT_ADDR = re.compile(r"\baddr=(?P<addr>\S+)", re.IGNORECASE)

_RE_AUDIT_AVC = re.compile(
    r"type=AVC\s+.*\bavc:\s+denied\b.*?for\s+(?:pid=\d+\s+)?comm=\"(?P<comm>[^\"]*)\"",
    re.IGNORECASE,
)

_RE_AUDIT_USER_MGMT = re.compile(
    r"type=(?:USER_(?:MGMT|ACCT))|SYSCALL.*?exe=\"/(?:usr/)?sbin/(?P<bin>user(?:add|del|mod)|group(?:add|mod|del)|passwd|chage)\"",
    re.IGNORECASE,
)

_RE_UFW_BLOCK = re.compile(
    r"\[UFW\s+BLOCK\].*?SRC=(?P<src>\S+).*?DST=(?P<dst>\S+).*?(?:DPT=(?P<dpt>\d+))?",
    re.IGNORECASE,
)

_RE_FAIL2BAN_BAN = re.compile(
    r"fail2ban(?:\.actions)?(?:\s+|\[).*?(?:Ban|BAN)\s+(?P<ip>\S+)",
    re.IGNORECASE,
)
_RE_FAIL2BAN_UNBAN = re.compile(
    r"fail2ban(?:\.actions)?(?:\s+|\[).*?(?:Unban|UNBAN)\s+(?P<ip>\S+)",
    re.IGNORECASE,
)

_RE_POLKIT = re.compile(
    r"polkit.*(?:authentication failed|not authorized|Agent responded|failed).*?(?:user\s+(?P<user>\S+))?",
    re.IGNORECASE,
)

# OpenVPN inline TLS auth failure
_RE_OPENVPN_AUTH_FAIL = re.compile(
    r"openvpn(?:\[\d+\])?:\s+.*?TLS Auth Error:\s*Auth Username\/Password.*|openvpn.*: authentication failed",
    re.IGNORECASE,
)

# wireguard is usually silent; generic "Authentication failed" with wg in line
_RE_WG_AUTH = re.compile(
    r"wireguard|wg-quick", re.IGNORECASE
)

# PostgreSQL FATAL authentication failed
_RE_PG_AUTH = re.compile(
    r"postgres(?:ql)?(?:\[\d+\])?:.*?FATAL:\s+password authentication failed for user \"(?P<user>[^\"]+)\"",
    re.IGNORECASE,
)
_RE_MYSQL_AUTH = re.compile(
    r"mysqld(?:\[\d+\])?:.*?Access denied for user '(?P<user>[^']+)'@'(?P<host>[^']+)'",
    re.IGNORECASE,
)

# docker logins (registry / dockerd)
_RE_DOCKER_AUTH = re.compile(
    r"dockerd(?:\[\d+\])?:.*?Authorization|docker:\s+denied|containerd:.*unauthorized",
    re.IGNORECASE,
)

# sudo authentication failure (distinct from successful sudo)
_RE_SUDO_AUTH_FAIL = re.compile(
    r"sudo:\s*(?P<who>\S+)\s*:\s*\d+\s+incorrect password attempts|sudo:.*authentication failure",
    re.IGNORECASE,
)


def parse_security_extras(line: str) -> AccessEvent | None:
    """Best-effort parse for firewall, audit, fail2ban, VPN, DB, polkit."""
    line = line.strip()
    if not line:
        return None
    low = line.lower()

    if "type=sudo" in low and "res=failed" in low:
        who = None
        mwho = re.search(r"\bacct=\"([^\"]+)\"", line)
        if mwho:
            who = mwho.group(1)
        return AccessEvent(
            kind=EventKind.SUDO,
            raw_line=line,
            user=who,
            extra={"audit": True, "result": "failed"},
        )

    m = _RE_SUDO_AUTH_FAIL.search(line)
    if m:
        return AccessEvent(
            kind=EventKind.SUDO,
            raw_line=line,
            user=m.group("who"),
            extra={"result": "auth_failure"},
        )

    if "type=" in line:
        if "type=avc" in low and "denied" in low and "avc:" in low:
            comm = ""
            mm = _RE_AUDIT_AVC.search(line)
            if mm:
                comm = mm.group("comm") or ""
            return AccessEvent(
                kind=EventKind.AUD_AVC_DENIED,
                raw_line=line,
                extra={"comm": comm},
            )
        mm_usr = _RE_AUDIT_USER_MGMT.search(line)
        if mm_usr:
            b = (mm_usr.group("bin") or "user_mgmt").strip()
            return AccessEvent(
                kind=EventKind.AUD_USER_ACCT,
                raw_line=line,
                extra={"binary": b},
            )
        if ("user_login" in low or "user_auth" in low or "cred_acq" in low) and "res=failed" in low:
            addr_m = _RE_AUDIT_ADDR.search(line)
            return AccessEvent(
                kind=EventKind.AUD_LOGIN_FAIL,
                raw_line=line,
                source_ip=addr_m.group("addr") if addr_m else None,
                extra={"audit": True},
            )

    low_nf = line.lower()
    if ("nftables" in low_nf or "nft_" in low_nf) and "drop" in low_nf:
        src_m = re.search(r"\bSRC=(?P<src>\S+)", line, re.IGNORECASE)
        return AccessEvent(
            kind=EventKind.NFT_DROP,
            raw_line=line,
            source_ip=src_m.group("src") if src_m else None,
            extra={},
        )

    m_ufw = _RE_UFW_BLOCK.search(line)
    if m_ufw:
        return AccessEvent(
            kind=EventKind.UFW_BLOCK,
            raw_line=line,
            source_ip=m_ufw.group("src"),
            extra={"dst": m_ufw.group("dst"), "dpt": m_ufw.group("dpt") or ""},
        )

    m = _RE_FAIL2BAN_UNBAN.search(line)
    if m:
        return AccessEvent(
            kind=EventKind.FAIL2BAN_UNBAN,
            raw_line=line,
            source_ip=m.group("ip"),
            extra={},
        )
    m = _RE_FAIL2BAN_BAN.search(line)
    if m:
        return AccessEvent(
            kind=EventKind.FAIL2BAN_BAN,
            raw_line=line,
            source_ip=m.group("ip"),
            extra={},
        )

    if "polkit" in low:
        m_pk = _RE_POLKIT.search(line)
        if m_pk:
            return AccessEvent(
                kind=EventKind.POLKIT_AUTH_FAIL,
                raw_line=line,
                user=m_pk.groupdict().get("user"),
                extra={},
            )

    if _RE_OPENVPN_AUTH_FAIL.search(line) or (
        "authentication failed" in low and _RE_WG_AUTH.search(line)
    ):
        return AccessEvent(
            kind=EventKind.VPN_AUTH_FAIL,
            raw_line=line,
            extra={"service_hint": "vpn"},
        )

    m_pg = _RE_PG_AUTH.search(line)
    if m_pg:
        return AccessEvent(
            kind=EventKind.DB_AUTH_FAIL,
            raw_line=line,
            user=m_pg.group("user"),
            extra={"db": "postgresql"},
        )

    m = _RE_MYSQL_AUTH.search(line)
    if m:
        return AccessEvent(
            kind=EventKind.DB_AUTH_FAIL,
            raw_line=line,
            user=m.group("user"),
            source_ip=m.group("host"),
            extra={"db": "mysql"},
        )

    if _RE_DOCKER_AUTH.search(line):
        return AccessEvent(
            kind=EventKind.CONTAINER_AUTH,
            raw_line=line,
            extra={"runtime": "docker"},
        )

    return None
