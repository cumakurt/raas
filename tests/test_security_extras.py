from __future__ import annotations

from parser.events import EventKind
from parser.log_parser import parse_log_line
from utils.quiet_hours import QuietHoursConfig, is_quiet_hours


def test_fail2ban_ban_parsed() -> None:
    line = "2026-01-01 host fail2ban.actions[1]: Ban 203.0.113.5"
    ev = parse_log_line(line)
    assert ev is not None
    assert ev.kind == EventKind.FAIL2BAN_BAN
    assert ev.source_ip == "203.0.113.5"


def test_ufw_block_parsed() -> None:
    line = "[UFW BLOCK] IN=eth0 OUT= MAC= SRC=10.0.0.1 DST=10.0.0.2 LEN=1 PROTO=TCP DPT=22"
    ev = parse_log_line(line)
    assert ev is not None
    assert ev.kind == EventKind.UFW_BLOCK


def test_quiet_hours_disabled() -> None:
    assert is_quiet_hours(QuietHoursConfig(enabled=False)) is False
