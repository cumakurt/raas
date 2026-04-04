from __future__ import annotations

from utils.net_norm import normalize_source_ip


def test_ipv4_unchanged() -> None:
    assert normalize_source_ip("192.168.0.1") == "192.168.0.1"


def test_ipv6_canonical() -> None:
    assert normalize_source_ip("0:0:0:0:0:0:0:1") == "::1"
    assert normalize_source_ip("[::1]") == "::1"


def test_hostname_lower() -> None:
    assert normalize_source_ip("EXAMPLE.local") == "example.local"


def test_none_empty() -> None:
    assert normalize_source_ip(None) is None
    assert normalize_source_ip("") is None
    assert normalize_source_ip("  ") is None
