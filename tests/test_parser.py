from __future__ import annotations

from parser.events import EventKind
from parser.ssh_parser import parse_auth_line


def test_ssh_accepted() -> None:
    line = (
        "Jan 1 10:00:00 host sshd[1]: Accepted password for alice from 203.0.113.5 port 22 ssh2"
    )
    ev = parse_auth_line(line)
    assert ev is not None
    assert ev.kind == EventKind.SSH_ACCEPTED
    assert ev.user == "alice"
    assert ev.source_ip == "203.0.113.5"


def test_sudo() -> None:
    line = (
        "Jan 1 10:00:00 host sudo: bob : TTY=pts/0 ; PWD=/home/bob ; "
        "USER=root ; COMMAND=/bin/ls"
    )
    ev = parse_auth_line(line)
    assert ev is not None
    assert ev.kind == EventKind.SUDO
    assert ev.user == "bob"
    assert ev.extra.get("target_user") == "root"


def test_ignore_empty() -> None:
    assert parse_auth_line("") is None
    assert parse_auth_line("   ") is None
