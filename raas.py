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
from collections.abc import Iterator
from http.server import ThreadingHTTPServer
from pathlib import Path

from config.settings import Settings, load_settings
from engine.risk_engine import RiskEngine
from notifier.build import build_alert_notifiers
from notifier.telegram import TelegramNotifier
from parser.ssh_parser import parse_auth_line
from utils.alarm_file_log import AlarmFileLogger
from utils.event_dedup import AuthEventDedup
from utils.health_http import HealthState, start_health_server
from utils.ip_allowlist import is_source_ignored
from utils.logging_config import setup_logging
from utils.net_norm import normalize_source_ip
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
        ),
        True,
    )


def main() -> int:
    setup_logging()
    parser = argparse.ArgumentParser(
        description="RAAS — Real-Time Access Alert System (access monitor)",
        epilog=_DEVELOPER_EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--config",
        type=Path,
        default=None,
        help="Path to config YAML (default: /opt/raas/config/config.yaml if present, else config/config.yaml next to the config package)",
    )
    parser.add_argument(
        "--diagnose-lock",
        action="store_true",
        help="Print screen-lock detection status (DBus, logind, lock processes) and exit",
    )
    parser.add_argument(
        "--version",
        action="store_true",
        help="Print version and developer contact, then exit",
    )
    args = parser.parse_args()

    if args.version:
        print(f"RAAS {__version__}\n")
        print(_DEVELOPER_EPILOG.strip())
        return 0

    if args.diagnose_lock:
        from lock_monitor.session_lock import format_lock_diagnosis

        print(format_lock_diagnosis())
        return 0

    settings = load_settings(args.config)
    stop_event = threading.Event()

    def _handle_sig(_s: int, _f: object) -> None:
        stop_event.set()
        logger.info("Shutdown requested")

    signal.signal(signal.SIGINT, _handle_sig)
    signal.signal(signal.SIGTERM, _handle_sig)

    if settings.telegram.enabled and not (
        settings.telegram.bot_token and settings.telegram.chat_id
    ):
        logger.warning(
            "Telegram enabled in config but telegram.bot_token or telegram.chat_id is empty "
            "— Telegram alert channel disabled; lock-intrusion Telegram also disabled",
        )

    alert_notifiers = build_alert_notifiers(settings)
    if alert_notifiers:
        logger.info(
            "Auth alert channels: %s",
            ", ".join(n.channel_id for n in alert_notifiers),
        )
    else:
        logger.warning("No auth alert channels configured — only local logging / alarm file")

    telegram_notifier, telegram_ok = _telegram_for_lock(settings)

    engine = RiskEngine(
        settings.risk.night_start,
        settings.risk.night_end,
        night_timezone=settings.risk.night_timezone,
        night_bonus=settings.risk.night_bonus,
        score_overrides=settings.risk.scores,
    )
    event_dedup = AuthEventDedup()
    alarm_file = AlarmFileLogger(settings.alarm_log.path, enabled=settings.alarm_log.enabled)

    health_state = HealthState()
    health_state.set_backend(settings.log.backend)
    health_server: ThreadingHTTPServer | None = None
    if settings.health.enabled:
        try:
            health_server, _ = start_health_server(
                settings.health.bind,
                settings.health.port,
                health_state,
            )
            logger.info(
                "Health HTTP endpoint http://%s:%s/health",
                settings.health.bind,
                settings.health.port,
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
    if settings.alarm_log.enabled:
        logger.info("Alarm log file: %s", settings.alarm_log.path)

    try:
        for line in _line_source(settings, stop_event):
            if stop_event.is_set():
                break
            health_state.record_line()
            event = parse_auth_line(line)
            if event is None:
                continue
            if event.source_ip:
                event.source_ip = normalize_source_ip(event.source_ip)
            if is_source_ignored(event.source_ip, list(settings.risk.ignore_networks)):
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
                "Event %s risk=%s user=%s ip=%s",
                event.kind.value,
                risk.score,
                event.user,
                event.source_ip,
            )
            if risk.score < notify_threshold:
                continue
            deliveries: dict[str, bool] = {}
            for n in alert_notifiers:
                deliveries[n.channel_id] = n.send_alert(event, risk)
            if settings.alarm_log.enabled:
                alarm_file.write_auth_event(
                    event=event,
                    risk=risk,
                    notify_threshold=notify_threshold,
                    deliveries=deliveries,
                )
            health_state.record_alert()
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
