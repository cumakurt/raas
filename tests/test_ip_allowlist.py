from __future__ import annotations

import ipaddress

from utils.ip_allowlist import compile_ignore_rules, is_source_ignored


def test_cidr_match() -> None:
    rules = compile_ignore_rules(["10.0.0.0/8"])
    assert is_source_ignored("10.5.1.1", rules)
    assert not is_source_ignored("192.168.1.1", rules)


def test_single_ip() -> None:
    rules = compile_ignore_rules(["192.168.1.10"])
    assert is_source_ignored("192.168.1.10", rules)


def test_ipv6_network() -> None:
    rules = compile_ignore_rules(["fe80::/10"])
    assert is_source_ignored(str(ipaddress.IPv6Address("fe80::1")), rules)


def test_hostname_no_match() -> None:
    rules = compile_ignore_rules(["192.168.0.0/16"])
    assert not is_source_ignored("router.lan", rules)
