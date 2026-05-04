#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Cuma Kurt
"""RAAS — Real-Time Linux Access Monitoring Agent (MVP)."""

from __future__ import annotations

import argparse
import logging
import signal
import sys
import threading
import time
from collections.abc import Iterator
from http.server import ThreadingHTTPServer
from pathlib import Path

from config.settings import Settings, load_settings
from engine.risk_engine import RiskEngine
from notifier.build import build_alert_notifiers
from notifier.telegram import TelegramNotifier
from parser.log_parser import parse_log_line
from utils.alarm_file_log import AlarmFileLogger
from utils.burst_suppress import BurstSuppressor
from utils.delivery_retry import drain_telegram_retry_file
from utils.event_dedup import AuthEventDedup
from utils.health_http import HealthState, start_health_server
from utils.ip_allowlist import is_source_ignored
from utils.logging_config import setup_logging
from utils.net_norm import normalize_source_ip
from utils.quiet_hours import is_quiet_hours
from watcher.journal_watcher import default_journalctl_args, follow_journal_lines
from watcher.log_watcher import follow_file_lines

logger = logging.getLogger(__name__)

__version__ = "0.1.0"

_DEVELOPER_EPILOG = """Developer: Cuma Kurt
  Email:    cumakurt@gmail.com
  LinkedIn: https://www.linkedin.com/in/cuma-kurt-34414917/
  GitHub:   https://github.com/cumakurt/raas
"""


def _line_source(settings: Settings, stop_event: threading.Event) -> Iterator[str]:
    backend = settings.log.backend.lower()
    if backend == "journal":
        args = settings.log.journal.journalctl_args or default_journalctl_args()
        yield from follow_journal_lines(args, stop_event=stop_event)
        return
    yield from follow_file_lines(
        settings.log.path,
        tail_from_end=settings.log.tail_from_end,
        poll_interval_seconds=settings.log.poll_interval_seconds,
        stop_event=stop_event,
    )


def _telegram_for_lock(settings: Settings) -> tuple[TelegramNotifier | None, bool]:
    """Lock-intrusion uses Telegram only (photos); same credentials as alert Telegram."""
    tg = settings.telegram
    ok = tg.enabled and bool(tg.bot_token) and bool(tg.chat_id)
    if not ok:
        return None, False
    return (
        TelegramNotifier(
            tg.bot_token,
            tg.chat_id,
            api_base_url=tg.api_base_url,
            timeout_seconds=tg.timeout_seconds,
            parse_mode="",
            rate_limit_per_minute=0,
            retry_enabled=False,
            retry_queue_path=None,
        ),
        True,
    )


def _user_ignored(user: str | None, ignored: frozenset[str]) -> bool:
    if not user or not ignored:
        return False
    return user.strip().lower() in ignored


def main() -> int:
    setup_logging()
    ap = argparse.ArgumentParser(
        description="RAAS — Real-Time Access Alert System (access monitor)",
        epilog=_DEVELOPER_EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument(
        "--config",
        type=Path,
        default=None,
        help="Path to config YAML (default: /opt/raas/config/config.yaml if present, else config/config.yaml next to the config package)",
    )
    ap.add_argument(
        "--diagnose-lock",
        action="store_true",
        help="Print screen-lock detection status (DBus, logind, lock processes) and exit",
    )
    ap.add_argument(
        "--version",
        action="store_true",
        help="Print version and developer contact, then exit",
    )
    args = ap.parse_args()

    if args.version:
        print(f"RAAS {__version__}\n")
        print(_DEVELOPER_EPILOG.strip())
        return 0

    if args.diagnose_lock:
        from lock_monitor.session_lock import format_lock_diagnosis

        print(format_lock_diagnosis())
        return 0

    config_path: Path | None = args.config
    stop_event = threading.Event()
    reload_requested = threading.Event()

    def _handle_shutdown(_s: int, _f: object) -> None:
        stop_event.set()
        logger.info("Shutdown requested")

    def _handle_hup(_s: int, _f: object) -> None:
        reload_requested.set()
        logger.info("Config reload requested (SIGHUP)")

    signal.signal(signal.SIGINT, _handle_shutdown)
    signal.signal(signal.SIGTERM, _handle_shutdown)
    signal.signal(signal.SIGHUP, _handle_hup)

    health_state = HealthState()

    settings = load_settings(config_path)
    ignore_rules = list(settings.risk.ignore_networks)
    suppressor = BurstSuppressor(
        settings.alert_coalesce.window_seconds,
        settings.alert_coalesce.enabled,
    )
    engine = RiskEngine(
        settings.risk.night_start,
        settings.risk.night_end,
        night_timezone=settings.risk.night_timezone,
        night_bonus=settings.risk.night_bonus,
        score_overrides=settings.risk.scores,
    )
    alert_notifiers = build_alert_notifiers(
        settings,
        on_telegram_delivery=lambda ok: health_state.record_telegram_delivery(ok),
    )

    if settings.telegram.enabled and not (
        settings.telegram.bot_token and settings.telegram.chat_id
    ):
        logger.warning(
            "Telegram enabled in config but telegram.bot_token or telegram.chat_id is empty "
            "— Telegram alert channel disabled; lock-intrusion Telegram also disabled",
        )

    if alert_notifiers:
        logger.info(
            "Auth alert channels: %s",
            ", ".join(n.channel_id for n in alert_notifiers),
        )
    else:
        logger.warning("No auth alert channels configured — only local logging / alarm file")

    telegram_notifier, telegram_ok = _telegram_for_lock(settings)

    event_dedup = AuthEventDedup()
    alarm_file = AlarmFileLogger(settings.alarm_log.path, enabled=settings.alarm_log.enabled)

    health_state.set_backend(settings.log.backend)
    health_server: ThreadingHTTPServer | None = None
    if settings.health.enabled:
        try:
            health_server, _ = start_health_server(
                settings.health.bind,
                settings.health.port,
                health_state,
                prometheus_enabled=settings.prometheus.enabled,
            )
            logger.info(
                "Health HTTP http://%s:%s/health%s",
                settings.health.bind,
                settings.health.port,
                " (GET /metrics enabled)" if settings.prometheus.enabled else "",
            )
        except OSError as e:
            logger.error("Could not start health server: %s", e)

    def run_lock_intrusion_thread() -> None:
        try:
            from lock_monitor.auth_unlock_watch import run_auth_unlock_watch
            from lock_monitor.intrusion_notify import LockMediaThrottle
            from lock_monitor.input_watch import run_input_watch

            media_thr = LockMediaThrottle(settings.lock_intrusion.media_cooldown_seconds)

            def _input() -> None:
                run_input_watch(
                    settings,
                    telegram_notifier,
                    telegram_ok,
                    stop_event,
                    alarm_file,
                    media_throttle=media_thr,
                )

            def _auth() -> None:
                run_auth_unlock_watch(
                    settings,
                    telegram_notifier,
                    telegram_ok,
                    stop_event,
                    alarm_file,
                    media_throttle=media_thr,
                )

            def _unlock() -> None:
                from lock_monitor.unlock_transition_watch import run_unlock_transition_watch

                run_unlock_transition_watch(
                    settings,
                    telegram_notifier,
                    telegram_ok,
                    stop_event,
                    alarm_file,
                    media_throttle=media_thr,
                )

            threading.Thread(target=_input, name="lock-intrusion-input", daemon=True).start()
            threading.Thread(target=_auth, name="lock-auth-failures", daemon=True).start()
            threading.Thread(target=_unlock, name="lock-unlock-transition", daemon=True).start()
        except Exception:
            logger.exception("Lock intrusion monitor crashed")

    if settings.lock_intrusion.enabled:
        t = threading.Thread(target=run_lock_intrusion_thread, name="lock-intrusion", daemon=True)
        t.start()
        logger.info(
            "Lock intrusion monitoring enabled (input + auth-failure poll + throttled media)",
        )
    else:
        logger.info("Lock intrusion monitoring disabled (see lock_intrusion in config)")

    if settings.log.backend == "journal":
        logger.info("Watching systemd journal (journalctl)")
    else:
        logger.info("Watching log file: %s", settings.log.path)
    if settings.risk.ignore_networks:
        logger.info("ignore_source_ips rules loaded: %d", len(settings.risk.ignore_networks))
    if settings.risk.ignore_users:
        logger.info("ignore_users rules loaded: %d", len(settings.risk.ignore_users))
    if settings.alarm_log.enabled:
        logger.info("Alarm log file: %s", settings.alarm_log.path)
    if settings.alert_coalesce.enabled:
        logger.info("Alert coalesce: window=%ss", settings.alert_coalesce.window_seconds)
    if settings.quiet_hours.enabled:
        logger.info("Quiet hours: enabled (suppress_alerts=%s)", settings.quiet_hours.suppress_alerts)

    def reload_runtime(*, initial: bool = False) -> None:
        nonlocal settings, ignore_rules, engine, suppressor, alert_notifiers
        settings = load_settings(config_path)
        ignore_rules = list(settings.risk.ignore_networks)
        engine = RiskEngine(
            settings.risk.night_start,
            settings.risk.night_end,
            night_timezone=settings.risk.night_timezone,
            night_bonus=settings.risk.night_bonus,
            score_overrides=settings.risk.scores,
        )
        suppressor = BurstSuppressor(
            settings.alert_coalesce.window_seconds,
            settings.alert_coalesce.enabled,
        )
        alert_notifiers = build_alert_notifiers(
            settings,
            on_telegram_delivery=lambda ok: health_state.record_telegram_delivery(ok),
        )
        health_state.set_backend(settings.log.backend)
        if not initial:
            health_state.record_config_reload()
            logger.info("Runtime config reloaded from disk")

    try:
        while not stop_event.is_set():
            source_reopen = False
            for line in _line_source(settings, stop_event):
                if stop_event.is_set():
                    break
                if reload_requested.is_set():
                    reload_requested.clear()
                    try:
                        reload_runtime(initial=False)
                    except Exception:
                        logger.exception("Config reload failed")
                    source_reopen = True
                    break

                if settings.telegram.retry_enabled and settings.telegram.retry_queue_path:
                    primary = next(
                        (n for n in alert_notifiers if getattr(n, "channel_id", "") == "telegram"),
                        None,
                    )
                    if isinstance(primary, TelegramNotifier):
                        drain_telegram_retry_file(
                            settings.telegram.retry_queue_path,
                            lambda o: primary.send_text_raw(
                                str(o.get("text", "")),
                                parse_mode=str(o.get("parse_mode", "") or ""),
                            ),
                            max_per_tick=3,
                        )

                health_state.record_line()
                event = parse_log_line(line)
                if event is None:
                    continue
                if event.source_ip:
                    event.source_ip = normalize_source_ip(event.source_ip)
                if is_source_ignored(event.source_ip, ignore_rules):
                    continue
                if _user_ignored(event.user, settings.risk.ignore_users):
                    continue
                if not event_dedup.should_emit(event):
                    continue
                health_state.record_parsed_event(event.kind.value)
                risk = engine.evaluate(event)
                notify_threshold = settings.risk.notify_threshold_by_kind.get(
                    event.kind.value,
                    settings.risk.notify_threshold,
                )
                logger.info(
                    "Event %s risk=%s severity=%s user=%s ip=%s",
                    event.kind.value,
                    risk.score,
                    risk.severity,
                    event.user,
                    event.source_ip,
                )
                if risk.score < notify_threshold:
                    continue

                packs = suppressor.process(event, risk, notify_threshold, time.monotonic())
                if not packs:
                    health_state.record_coalesce_suppressed(1)
                    continue
                for ev2, rk2, th2 in packs:
                    quiet = is_quiet_hours(settings.quiet_hours) and settings.quiet_hours.suppress_alerts
                    deliveries: dict[str, bool] = {}
                    if quiet:
                        health_state.record_quiet_suppress()
                    else:
                        for n in alert_notifiers:
                            if n.channel_id == "telegram_high" and rk2.severity != "high":
                                continue
                            deliveries[n.channel_id] = n.send_alert(ev2, rk2)
                    if settings.alarm_log.enabled:
                        alarm_file.write_auth_event(
                            event=ev2,
                            risk=rk2,
                            notify_threshold=th2,
                            deliveries=deliveries,
                        )
                    health_state.record_alert()
            if stop_event.is_set():
                break
            if source_reopen:
                continue
            break
    finally:
        if health_server is not None:
            try:
                health_server.shutdown()
            except Exception:
                pass
            try:
                health_server.server_close()
            except Exception:
                pass

    return 0


if __name__ == "__main__":
    sys.exit(main())
