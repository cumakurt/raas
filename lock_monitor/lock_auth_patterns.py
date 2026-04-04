from __future__ import annotations

import re

# Lines in auth.log / secure that often indicate unlock attempt on greeter / lock screen (not sshd).
_FAILURE_MARKERS = (
    "authentication failure",
    "auth could not identify password",
    "authentication token manipulation error",
    "failed password",
    "password check failed",
    "incorrect password",
    "bad password",
)

# Substrings tying failure to local session / DM / greeter (not remote ssh).
_LOCAL_CONTEXT = (
    "gdm",
    "gdm-password",
    "gdm-autologin",
    "lightdm",
    "sddm",
    "xdm",
    "lxdm",
    "gnome-screensaver",
    "cinnamon-screensaver",
    "mate-screensaver",
    "xfce4-screensaver",
    "kde",
    "kscreenlocker",
    "screen",
    "greeter",
    "unix_chkpwd",
    "polkit",
    "login",
    "pam_unix",
    "sssd",
)


def is_probable_lock_screen_auth_failure(line: str) -> bool:
    """
    Heuristic: failed local PAM / greeter auth while investigating lock-screen unlock attempts.
    Excludes obvious sshd-only lines to reduce noise from remote SSH failures.
    """
    low = line.lower()
    if not any(m in low for m in _FAILURE_MARKERS):
        return False
    if "sshd" in low or "sshd-session" in low:
        return False
    if any(ctx in low for ctx in _LOCAL_CONTEXT):
        return True
    # journal-style: _COMM=gdm-password etc.
    if re.search(r"\bcomm=\w*gdm\w*", low):
        return True
    return False
