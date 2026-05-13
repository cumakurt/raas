from __future__ import annotations

import tempfile
from pathlib import Path

from config.settings import load_settings


def test_load_ignore_and_scores() -> None:
    yaml_text = """
log:
  path: auto
  backend: file
risk:
  notify_threshold: 20
  ignore_source_ips:
    - "192.168.0.0/16"
  scores:
    ssh_failed: 40
  notify_threshold_by_kind:
    ssh_accepted: 99
health:
  enabled: true
  bind: "127.0.0.1"
  port: 18080
"""
    with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False) as f:
        f.write(yaml_text)
        p = Path(f.name)
    try:
        s = load_settings(p)
        assert s.risk.notify_threshold == 20
        assert s.risk.scores.get("ssh_failed") == 40
        assert s.risk.notify_threshold_by_kind.get("ssh_accepted") == 99
        assert len(s.risk.ignore_networks) >= 1
        assert s.health.enabled is True
        assert s.health.port == 18080
    finally:
        p.unlink(missing_ok=True)


def test_telegram_api_base_rejects_non_official_host() -> None:
    yaml_text = """
log:
  path: auto
telegram:
  enabled: true
  bot_token: "123:ABC"
  chat_id: "1"
  api_base_url: "https://metadata.internal/bot"
"""
    with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False) as f:
        f.write(yaml_text)
        p = Path(f.name)
    try:
        s = load_settings(p)
        assert s.telegram.api_base_url == "https://api.telegram.org"
    finally:
        p.unlink(missing_ok=True)


def test_webhook_url_http_only_loopback() -> None:
    for raw, expected in (
        ("https://siem.example/hook", "https://siem.example/hook"),
        ("http://192.168.1.1/x", ""),
        ("http://127.0.0.1:9090/ingest", "http://127.0.0.1:9090/ingest"),
        ("http://[::1]/hook", "http://[::1]/hook"),
    ):
        yaml_text = f"""
log:
  path: auto
webhook:
  enabled: true
  url: "{raw}"
"""
        with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False) as f:
            f.write(yaml_text)
            path = Path(f.name)
        try:
            s = load_settings(path)
            assert s.webhook.url == expected
        finally:
            path.unlink(missing_ok=True)


def test_telegram_api_base_strips_double_bot_path() -> None:
    """api_base_url must be origin only; /bot in URL causes Telegram 404."""
    yaml_text = """
log:
  path: auto
telegram:
  enabled: true
  bot_token: "123:ABC"
  chat_id: "1"
  api_base_url: "https://api.telegram.org/bot"
"""
    with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False) as f:
        f.write(yaml_text)
        p = Path(f.name)
    try:
        s = load_settings(p)
        assert s.telegram.api_base_url == "https://api.telegram.org"
    finally:
        p.unlink(missing_ok=True)


def test_lock_intrusion_cpu_defaults() -> None:
    yaml_text = """
log:
  path: auto
"""
    with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False) as f:
        f.write(yaml_text)
        p = Path(f.name)
    try:
        s = load_settings(p)
        assert s.lock_intrusion.auth_failure_min_interval_seconds == 10.0
        assert s.lock_intrusion.unlock_poll_interval_seconds == 2.0
        assert s.lock_intrusion.lock_state_cache_ttl_seconds == 3.0
    finally:
        p.unlink(missing_ok=True)


def test_file_deletion_config_defaults_and_overrides() -> None:
    yaml_text = """
log:
  path: auto
file_deletion:
  enabled: true
  paths:
    - /etc
    - /boot
  recursive: false
  include_moves: false
  cooldown_seconds: 2.5
  ignore_globs:
    - "*/tmp/*"
  max_watch_dirs: 64
"""
    with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False) as f:
        f.write(yaml_text)
        p = Path(f.name)
    try:
        s = load_settings(p)
        assert tuple(str(x) for x in s.file_deletion.paths) == ("/etc", "/boot")
        assert s.file_deletion.recursive is False
        assert s.file_deletion.include_moves is False
        assert s.file_deletion.cooldown_seconds == 2.5
        assert s.file_deletion.ignore_globs == ("*/tmp/*",)
        assert s.file_deletion.max_watch_dirs == 64
    finally:
        p.unlink(missing_ok=True)
