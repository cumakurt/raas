"""Unified log line parsing: auth/SSH first, then extended security patterns."""

from __future__ import annotations

from parser.events import AccessEvent
from parser.security_extras import parse_security_extras
from parser.ssh_parser import parse_auth_line


def parse_log_line(line: str) -> AccessEvent | None:
    """Parse one syslog/auth/journal line into an AccessEvent if recognized."""
    ev = parse_auth_line(line)
    if ev is not None:
        return ev
    return parse_security_extras(line)
