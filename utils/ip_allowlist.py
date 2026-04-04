from __future__ import annotations

import ipaddress
import logging
from typing import Any

logger = logging.getLogger(__name__)


def compile_ignore_rules(entries: list[str]) -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
    """Parse CIDR or single IP strings into network objects (host bits allowed)."""
    out: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
    for raw in entries:
        s = (raw or "").strip()
        if not s or s.startswith("#"):
            continue
        try:
            net = ipaddress.ip_network(s, strict=False)
            out.append(net)
        except ValueError as e:
            logger.warning("Invalid ignore_source_ips entry %r: %s", s, e)
    return out


def is_source_ignored(
    source_ip: str | None,
    rules: list[ipaddress.IPv4Network | ipaddress.IPv6Network],
) -> bool:
    """True if source_ip matches any rule (IPs only; hostnames never match CIDR rules)."""
    if not source_ip or not rules:
        return False
    try:
        addr = ipaddress.ip_address(source_ip.strip())
    except ValueError:
        return False
    return any(addr in net for net in rules)


def load_ignore_rules_from_config(raw: Any) -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
    if raw is None:
        return []
    if isinstance(raw, list):
        return compile_ignore_rules([str(x) for x in raw])
    return compile_ignore_rules([str(raw)])
