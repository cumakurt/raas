from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
import re as _re
from urllib.parse import urlparse, urlunparse

import yaml

from utils.ip_allowlist import load_ignore_rules_from_config
from utils.linux_paths import parse_log_path_config
from utils.quiet_hours import QuietHoursConfig

logger = logging.getLogger(__name__)


@dataclass
class JournalConfig:
    """Arguments passed to `journalctl` when log.backend is journal (include -f)."""

    journalctl_args: list[str] = field(default_factory=list)


@dataclass
class ResourceConfig:
    """
    Reduce CPU contention with other workloads. process_nice is applied once at startup (not on SIGHUP).
    A hard CPU percentage cap requires cgroups/systemd (e.g. CPUQuota=) — see config comments.
    """

    process_nice: int = 10


@dataclass
class LogConfig:
    path: Path
    backend: str = "file"
    tail_from_end: bool = True
    poll_interval_seconds: float = 0.8
    journal: JournalConfig = field(default_factory=JournalConfig)


@dataclass
class TelegramConfig:
    """All Telegram delivery settings (API endpoint + credentials + target chat)."""

    enabled: bool = True
    api_base_url: str = "https://api.telegram.org"
    bot_token: str = ""
    chat_id: str = ""
    timeout_seconds: float = 15.0
    parse_mode: str = "HTML"
    rate_limit_per_minute: int = 0
    retry_enabled: bool = False
    retry_queue_path: Path = field(default_factory=lambda: Path("/var/lib/raas/telegram_retry.jsonl"))
    high_severity_chat_id: str = ""


@dataclass
class WebhookConfig:
    """Optional HTTP POST (JSON) for SIEM / Slack-compatible receivers / custom endpoints."""

    enabled: bool = False
    url: str = ""
    timeout_seconds: float = 10.0
    headers: dict[str, str] = field(default_factory=dict)


@dataclass
class RiskConfig:
    notify_threshold: int = 15
    notify_threshold_by_kind: dict[str, int] = field(default_factory=dict)
    night_start: int = 22
    night_end: int = 6
    night_timezone: str = "UTC"
    night_bonus: int = 10
    scores: dict[str, int] = field(default_factory=dict)
    ignore_networks: tuple[Any, ...] = ()  # ipaddress networks; filled by load_settings
    ignore_users: frozenset[str] = field(default_factory=frozenset)


@dataclass
class AlarmLogConfig:
    """Separate file for alerts that met the risk threshold (JSON Lines)."""

    enabled: bool = True
    path: Path = field(default_factory=lambda: Path("/var/log/raas/alarms.jsonl"))


@dataclass
class LockIntrusionConfig:
    """When enabled, input activity while the screen is locked triggers alerts (and throttled media)."""

    enabled: bool = True
    # Minimum seconds between any two input-based notifications (0 = as fast as possible).
    cooldown_seconds: float = 0.0
    # Mouse movement (EV_REL) fires very often; throttle move alerts (0 = every move batch).
    pointer_move_throttle_seconds: float = 0.25
    # Minimum seconds between screen/webcam captures (text alerts are not limited by this).
    media_cooldown_seconds: float = 2.5
    # Poll auth.log for failed greeter / lock-screen PAM failures while locked.
    watch_auth_failures: bool = True
    auth_poll_interval_seconds: float = 1.0
    auth_failure_min_interval_seconds: float = 10.0
    # Notify when lock state goes from locked -> unlocked (successful unlock).
    notify_on_unlock: bool = True
    unlock_poll_interval_seconds: float = 2.0
    camera_device: str = "/dev/video0"
    prefer_ffmpeg: bool = True
    capture_width: int | None = None
    capture_height: int | None = None
    capture_screen: bool = False
    capture_webcam: bool = True
    desktop_uid: int | None = None
    # select() timeout for evdev (seconds); higher = lower idle wakeups / CPU.
    input_select_timeout_seconds: float = 1.0
    # Max age for lock-state cache during input watch (DBus/loginctl is expensive).
    lock_state_cache_ttl_seconds: float = 3.0


@dataclass
class HealthConfig:
    """Minimal JSON HTTP endpoint for ops (localhost by default)."""

    enabled: bool = False
    bind: str = "127.0.0.1"
    port: int = 8765


@dataclass
class AlertCoalesceConfig:
    """Suppress duplicate (kind,user,ip) alerts within a short window; emit a summary when window rolls."""

    enabled: bool = False
    window_seconds: float = 2.0


@dataclass
class PrometheusConfig:
    """Prometheus text metrics on GET /metrics (same HTTP server as health when health.enabled)."""

    enabled: bool = False


@dataclass
class Settings:
    """Loaded entirely from the YAML config file (see config.yaml.example)."""

    log: LogConfig
    telegram: TelegramConfig = field(default_factory=TelegramConfig)
    webhook: WebhookConfig = field(default_factory=WebhookConfig)
    risk: RiskConfig = field(default_factory=RiskConfig)
    alarm_log: AlarmLogConfig = field(default_factory=AlarmLogConfig)
    lock_intrusion: LockIntrusionConfig = field(default_factory=LockIntrusionConfig)
    health: HealthConfig = field(default_factory=HealthConfig)
    quiet_hours: QuietHoursConfig = field(default_factory=QuietHoursConfig)
    alert_coalesce: AlertCoalesceConfig = field(default_factory=AlertCoalesceConfig)
    prometheus: PrometheusConfig = field(default_factory=PrometheusConfig)
    resource: ResourceConfig = field(default_factory=ResourceConfig)


def _merge_dict(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    out = dict(base)
    for k, v in override.items():
        if k in out and isinstance(out[k], dict) and isinstance(v, dict):
            out[k] = _merge_dict(out[k], v)
        else:
            out[k] = v
    return out


_OFFICIAL_TELEGRAM_API = "https://api.telegram.org"


def _normalize_telegram_api_base(url: str) -> str:
    """
    Telegram Bot API URLs must be built as {base}/bot{token}/method.
    If api_base_url mistakenly includes /bot or /bot<token> (common copy-paste),
    requests hit .../bot/botTOKEN/... and Telegram returns 404 Not Found.

    Host is restricted to api.telegram.org over https (default port only) so a
    tampered config cannot point outbound requests (and the bot token in the URL
    path) at an arbitrary host (SSRF / token exfiltration).
    """
    u = (url or "").strip()
    if not u:
        return _OFFICIAL_TELEGRAM_API
    if "://" not in u:
        u = "https://" + u
    parsed = urlparse(u)
    path = (parsed.path or "").rstrip("/")
    if _re.match(r"/bot(\d|/|$)", path):
        parsed = parsed._replace(path="", params="", query="", fragment="")
        u = urlunparse(parsed).rstrip("/")
        logger.warning(
            "telegram.api_base_url must not contain /bot (use %s only; token goes in bot_token). Normalized",
            _OFFICIAL_TELEGRAM_API,
        )
        parsed = urlparse(u if "://" in u else "https://" + u)

    scheme = (parsed.scheme or "").lower()
    host = (parsed.hostname or "").lower()
    port = parsed.port
    path = (parsed.path or "").rstrip("/")

    if scheme != "https":
        logger.warning("telegram.api_base_url must use https; using %s", _OFFICIAL_TELEGRAM_API)
        return _OFFICIAL_TELEGRAM_API
    if parsed.username or parsed.password:
        logger.warning("telegram.api_base_url must not embed userinfo; using %s", _OFFICIAL_TELEGRAM_API)
        return _OFFICIAL_TELEGRAM_API
    if host != "api.telegram.org":
        logger.warning(
            "telegram.api_base_url host %r is not api.telegram.org (SSRF mitigation); using %s",
            host or "",
            _OFFICIAL_TELEGRAM_API,
        )
        return _OFFICIAL_TELEGRAM_API
    if port is not None and port != 443:
        logger.warning(
            "telegram.api_base_url must use the default https port; using %s",
            _OFFICIAL_TELEGRAM_API,
        )
        return _OFFICIAL_TELEGRAM_API
    if path:
        logger.warning(
            "telegram.api_base_url must be an origin without a path; using %s",
            _OFFICIAL_TELEGRAM_API,
        )
        return _OFFICIAL_TELEGRAM_API
    return _OFFICIAL_TELEGRAM_API


def _sanitize_webhook_url(url: str) -> str:
    """
    Outbound webhook POSTs should use TLS. http is allowed only for explicit
    loopback targets (local dev / same-host receiver).
    """
    u = (url or "").strip()
    if not u:
        return ""
    parsed = urlparse(u)
    scheme = (parsed.scheme or "").lower()
    host = (parsed.hostname or "").lower() if parsed.hostname else ""
    if not host:
        logger.warning("webhook.url has no host; dropping URL")
        return ""
    if scheme == "https":
        return u
    if scheme == "http" and host in ("127.0.0.1", "localhost", "::1"):
        return u
    logger.warning(
        "webhook.url must use https (http is only allowed for 127.0.0.1, localhost, or ::1); dropping URL",
    )
    return ""


def _parse_scores(risk_cfg: dict[str, Any]) -> dict[str, int]:
    raw = risk_cfg.get("scores")
    if not isinstance(raw, dict):
        return {}
    out: dict[str, int] = {}
    for k, v in raw.items():
        try:
            out[str(k)] = int(v)
        except (TypeError, ValueError):
            continue
    return out


def _parse_threshold_by_kind(risk_cfg: dict[str, Any]) -> dict[str, int]:
    raw = risk_cfg.get("notify_threshold_by_kind")
    if not isinstance(raw, dict):
        return {}
    out: dict[str, int] = {}
    for k, v in raw.items():
        try:
            out[str(k)] = int(v)
        except (TypeError, ValueError):
            continue
    return out


def _parse_ignore_users(raw: Any) -> frozenset[str]:
    if raw is None:
        return frozenset()
    if isinstance(raw, list):
        return frozenset(str(x).strip().lower() for x in raw if str(x).strip())
    s = str(raw).strip().lower()
    return frozenset({s}) if s else frozenset()


def _parse_telegram_parse_mode(raw: Any) -> str:
    s = str(raw or "HTML").strip().upper()
    if s in ("NONE", "OFF", "", "FALSE", "PLAIN"):
        return ""
    if s in ("HTML", "MARKDOWN", "MARKDOWNV2"):
        return s
    return "HTML"


def load_settings(config_path: Path | None = None) -> Settings:
    """Load all settings from a single YAML file. No environment-variable overrides."""
    base_dir = Path(__file__).resolve().parent
    if config_path is not None:
        path = config_path
    else:
        # Packaged install: /opt/raas/config/config.yaml; dev: config/config.yaml beside this package
        installed = Path("/opt/raas/config/config.yaml")
        if installed.is_file():
            path = installed
        else:
            path = base_dir / "config.yaml"

    cfg: dict[str, Any] = {}
    if path.is_file():
        with open(path, encoding="utf-8") as f:
            cfg = yaml.safe_load(f) or {}

    legacy_log = {
        k: v
        for k, v in {
            "path": cfg.get("log_path"),
            "tail_from_end": cfg.get("tail_from_end"),
            "poll_interval_seconds": cfg.get("poll_interval_seconds"),
        }.items()
        if v is not None
    }
    raw_log = cfg.get("log")
    nested_log = dict(raw_log) if isinstance(raw_log, dict) else {}
    log_block = _merge_dict(legacy_log, nested_log)

    log_path = parse_log_path_config(log_block.get("path"))
    backend = str(log_block.get("backend", "file") or "file").strip().lower()
    if backend not in ("file", "journal"):
        backend = "file"

    journal_raw = log_block.get("journal") if isinstance(log_block.get("journal"), dict) else {}
    jc_args = journal_raw.get("journalctl_args")
    journalctl_args: list[str] = (
        [str(x) for x in jc_args] if isinstance(jc_args, list) else []
    )

    tail_from_end = bool(log_block.get("tail_from_end", True))
    poll_interval_seconds = max(0.05, float(log_block.get("poll_interval_seconds", 0.8)))

    tg_block = cfg.get("telegram") if isinstance(cfg.get("telegram"), dict) else {}
    telegram = TelegramConfig(
        enabled=bool(tg_block.get("enabled", True)),
        api_base_url=_normalize_telegram_api_base(str(tg_block.get("api_base_url", "https://api.telegram.org"))),
        bot_token=str(tg_block.get("bot_token", "") or ""),
        chat_id=str(tg_block.get("chat_id", "") or ""),
        timeout_seconds=float(tg_block.get("timeout_seconds", 15.0)),
        parse_mode=_parse_telegram_parse_mode(tg_block.get("parse_mode", "HTML")),
        rate_limit_per_minute=int(tg_block.get("rate_limit_per_minute", 0)),
        retry_enabled=bool(tg_block.get("retry_enabled", False)),
        retry_queue_path=Path(str(tg_block.get("retry_queue_path", "/var/lib/raas/telegram_retry.jsonl"))).expanduser(),
        high_severity_chat_id=str(tg_block.get("high_severity_chat_id", "") or ""),
    )

    wh_block = cfg.get("webhook") if isinstance(cfg.get("webhook"), dict) else {}
    wh_headers = wh_block.get("headers")
    wh_url = _sanitize_webhook_url(str(wh_block.get("url", "") or ""))
    webhook = WebhookConfig(
        enabled=bool(wh_block.get("enabled", False)),
        url=wh_url,
        timeout_seconds=float(wh_block.get("timeout_seconds", 10.0)),
        headers={str(k): str(v) for k, v in wh_headers.items()} if isinstance(wh_headers, dict) else {},
    )

    risk_cfg = cfg.get("risk") if isinstance(cfg.get("risk"), dict) else {}
    notify_threshold = int(risk_cfg.get("notify_threshold", 15))
    night_start = int(risk_cfg.get("night_start", 22))
    night_end = int(risk_cfg.get("night_end", 6))
    night_timezone = str(risk_cfg.get("night_timezone", "UTC") or "UTC").strip() or "UTC"
    night_bonus = int(risk_cfg.get("night_bonus", 10))
    scores = _parse_scores(risk_cfg)
    notify_threshold_by_kind = _parse_threshold_by_kind(risk_cfg)
    ignore_ips_raw = risk_cfg.get("ignore_source_ips")
    ignore_networks = tuple(load_ignore_rules_from_config(ignore_ips_raw))
    ignore_users = _parse_ignore_users(risk_cfg.get("ignore_users"))

    risk = RiskConfig(
        notify_threshold=notify_threshold,
        notify_threshold_by_kind=notify_threshold_by_kind,
        night_start=night_start,
        night_end=night_end,
        night_timezone=night_timezone,
        night_bonus=night_bonus,
        scores=scores,
        ignore_networks=ignore_networks,
        ignore_users=ignore_users,
    )

    al = cfg.get("alarm_log") if isinstance(cfg.get("alarm_log"), dict) else {}
    alarm_log = AlarmLogConfig(
        enabled=bool(al.get("enabled", True)),
        path=Path(str(al.get("path", "/var/log/raas/alarms.jsonl"))).expanduser(),
    )

    li = cfg.get("lock_intrusion") if isinstance(cfg.get("lock_intrusion"), dict) else {}
    lock_intrusion = LockIntrusionConfig(
        enabled=bool(li.get("enabled", True)),
        cooldown_seconds=float(li.get("cooldown_seconds", 0.0)),
        pointer_move_throttle_seconds=float(li.get("pointer_move_throttle_seconds", 0.25)),
        media_cooldown_seconds=float(li.get("media_cooldown_seconds", 2.5)),
        watch_auth_failures=bool(li.get("watch_auth_failures", True)),
        auth_poll_interval_seconds=float(li.get("auth_poll_interval_seconds", 1.0)),
        auth_failure_min_interval_seconds=float(li.get("auth_failure_min_interval_seconds", 10.0)),
        notify_on_unlock=bool(li.get("notify_on_unlock", True)),
        unlock_poll_interval_seconds=float(li.get("unlock_poll_interval_seconds", 2.0)),
        camera_device=str(li.get("camera_device", "/dev/video0")),
        prefer_ffmpeg=bool(li.get("prefer_ffmpeg", True)),
        capture_width=int(li["capture_width"]) if li.get("capture_width") is not None else None,
        capture_height=int(li["capture_height"]) if li.get("capture_height") is not None else None,
        capture_screen=bool(li.get("capture_screen", False)),
        capture_webcam=bool(li.get("capture_webcam", True)),
        desktop_uid=int(li["desktop_uid"]) if li.get("desktop_uid") is not None else None,
        input_select_timeout_seconds=max(
            0.05,
            min(2.0, float(li.get("input_select_timeout_seconds", 1.0))),
        ),
        lock_state_cache_ttl_seconds=max(
            0.05,
            min(3.0, float(li.get("lock_state_cache_ttl_seconds", 3.0))),
        ),
    )

    hb = cfg.get("health") if isinstance(cfg.get("health"), dict) else {}
    hb_bind = str(hb.get("bind", "127.0.0.1") or "127.0.0.1").strip()
    if hb_bind in ("0.0.0.0", "::", "[::]", "[::0]"):
        logger.warning(
            "health.bind is all-interfaces (%s); JSON /health and /metrics are exposed on every "
            "address — prefer 127.0.0.1 or firewall the port",
            hb_bind,
        )
    health = HealthConfig(
        enabled=bool(hb.get("enabled", False)),
        bind=hb_bind,
        port=int(hb.get("port", 8765)),
    )

    qh = cfg.get("quiet_hours") if isinstance(cfg.get("quiet_hours"), dict) else {}
    quiet_hours = QuietHoursConfig(
        enabled=bool(qh.get("enabled", False)),
        start_hour=int(qh.get("start_hour", qh.get("start", 23))),
        end_hour=int(qh.get("end_hour", qh.get("end", 7))),
        timezone=str(qh.get("timezone", "UTC") or "UTC").strip() or "UTC",
        suppress_alerts=bool(qh.get("suppress_alerts", True)),
    )

    ac = cfg.get("alert_coalesce") if isinstance(cfg.get("alert_coalesce"), dict) else {}
    alert_coalesce = AlertCoalesceConfig(
        enabled=bool(ac.get("enabled", False)),
        window_seconds=float(ac.get("window_seconds", 2.0)),
    )

    prom = cfg.get("prometheus") if isinstance(cfg.get("prometheus"), dict) else {}
    prometheus = PrometheusConfig(enabled=bool(prom.get("enabled", False)))

    res_block = cfg.get("resource") if isinstance(cfg.get("resource"), dict) else {}
    _pn = int(res_block.get("process_nice", 10))
    resource = ResourceConfig(process_nice=max(0, min(19, _pn)))

    return Settings(
        log=LogConfig(
            path=log_path,
            backend=backend,
            tail_from_end=tail_from_end,
            poll_interval_seconds=poll_interval_seconds,
            journal=JournalConfig(journalctl_args=journalctl_args),
        ),
        telegram=telegram,
        webhook=webhook,
        risk=risk,
        alarm_log=alarm_log,
        lock_intrusion=lock_intrusion,
        health=health,
        quiet_hours=quiet_hours,
        alert_coalesce=alert_coalesce,
        prometheus=prometheus,
        resource=resource,
    )
