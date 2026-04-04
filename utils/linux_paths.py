from __future__ import annotations

import logging
from pathlib import Path

logger = logging.getLogger(__name__)

# Common paths across Debian/Ubuntu/Kali vs RHEL/Fedora/Alma/Rocky vs others
AUTH_LOG_CANDIDATES: tuple[str, ...] = (
    "/var/log/auth.log",
    "/var/log/secure",
)


def resolve_auth_log_path_auto() -> Path:
    """
    Pick the first existing auth-style log file from known distro paths.
    If none exist yet (fresh install), return the first candidate so the watcher can wait.
    """
    for p in AUTH_LOG_CANDIDATES:
        path = Path(p)
        if path.is_file():
            logger.info("Using auth log file: %s", path)
            return path
    fallback = Path(AUTH_LOG_CANDIDATES[0])
    logger.warning(
        "No auth log file found yet among %s — will watch %s when it appears",
        list(AUTH_LOG_CANDIDATES),
        fallback,
    )
    return fallback


def parse_log_path_config(raw: object | None) -> Path:
    """If raw is missing, empty, or 'auto' (case-insensitive), pick first known distro file."""
    if raw is None:
        return resolve_auth_log_path_auto()
    s = str(raw).strip()
    if s == "" or s.lower() == "auto":
        return resolve_auth_log_path_auto()
    return Path(s).expanduser()
