from __future__ import annotations

from lock_monitor.lock_auth_patterns import is_probable_lock_screen_auth_failure


def test_gdm_failure_matches() -> None:
    line = "Apr 4 12:00:00 host gdm-password: pam_unix(gdm-password:auth): authentication failure"
    assert is_probable_lock_screen_auth_failure(line) is True


def test_sshd_failure_excluded() -> None:
    line = "Apr 4 12:00:00 host sshd[1]: Failed password for x from 1.2.3.4"
    assert is_probable_lock_screen_auth_failure(line) is False


def test_random_line_no_match() -> None:
    assert is_probable_lock_screen_auth_failure("session opened for user joe") is False
