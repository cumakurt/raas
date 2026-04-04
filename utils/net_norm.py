from __future__ import annotations

import ipaddress


def normalize_source_ip(raw: str | None) -> str | None:
    """
    Canonical IPv4/IPv6 string for matching; non-IP hostnames returned lowercased.
    Strips IPv6 brackets as in [::1].
    """
    if raw is None:
        return None
    s = raw.strip()
    if not s:
        return None
    if s.startswith("[") and s.endswith("]"):
        s = s[1:-1]
    try:
        ip = ipaddress.ip_address(s)
        return str(ip)
    except ValueError:
        return s.lower()
