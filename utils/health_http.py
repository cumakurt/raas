from __future__ import annotations

import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any


class HealthState:
    """Thread-safe counters for the HTTP health endpoint."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.started_monotonic = time.monotonic()
        self.started_unix = time.time()
        self.lines_read: int = 0
        self.events_parsed: int = 0
        self.alerts_sent: int = 0
        self.last_event_ts: float | None = None
        self.last_event_kind: str | None = None
        self.backend: str = "file"
        self.coalesce_suppressed: int = 0
        self.quiet_suppressed: int = 0
        self.telegram_failures: int = 0
        self.telegram_successes: int = 0
        self.config_reloads: int = 0
        self.last_telegram_error: str | None = None

    def record_line(self) -> None:
        with self._lock:
            self.lines_read += 1

    def record_parsed_event(self, kind: str) -> None:
        with self._lock:
            self.events_parsed += 1
            self.last_event_ts = time.time()
            self.last_event_kind = kind

    def record_alert(self) -> None:
        with self._lock:
            self.alerts_sent += 1

    def record_coalesce_suppressed(self, n: int = 1) -> None:
        with self._lock:
            self.coalesce_suppressed += n

    def record_quiet_suppressed(self) -> None:
        with self._lock:
            self.quiet_suppressed += 1

    def record_config_reload(self) -> None:
        with self._lock:
            self.config_reloads += 1

    def record_telegram_delivery(self, ok: bool, error_hint: str = "") -> None:
        with self._lock:
            if ok:
                self.telegram_successes += 1
            else:
                self.telegram_failures += 1
                if error_hint:
                    self.last_telegram_error = error_hint[:500]

    def set_backend(self, name: str) -> None:
        with self._lock:
            self.backend = name

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            uptime = time.monotonic() - self.started_monotonic
            return {
                "status": "ok",
                "backend": self.backend,
                "uptime_s": round(uptime, 3),
                "started_unix": self.started_unix,
                "lines_read": self.lines_read,
                "events_parsed": self.events_parsed,
                "alerts_sent": self.alerts_sent,
                "last_event_ts": self.last_event_ts,
                "last_event_kind": self.last_event_kind,
                "coalesce_suppressed": self.coalesce_suppressed,
                "quiet_suppressed": self.quiet_suppressed,
                "telegram_failures": self.telegram_failures,
                "telegram_successes": self.telegram_successes,
                "config_reloads": self.config_reloads,
                "last_telegram_error": self.last_telegram_error,
            }


def prometheus_text(state: HealthState) -> bytes:
    snap = state.snapshot()
    lines = [
        "# HELP raas_lines_read_total Log lines read from file or journal.",
        "# TYPE raas_lines_read_total counter",
        f"raas_lines_read_total {snap['lines_read']}",
        "# HELP raas_events_parsed_total Parsed security events.",
        "# TYPE raas_events_parsed_total counter",
        f"raas_events_parsed_total {snap['events_parsed']}",
        "# HELP raas_alerts_sent_total Alerts that crossed notify threshold.",
        "# TYPE raas_alerts_sent_total counter",
        f"raas_alerts_sent_total {snap['alerts_sent']}",
        "# HELP raas_coalesce_suppressed_total Alerts suppressed by coalescer.",
        "# TYPE raas_coalesce_suppressed_total counter",
        f"raas_coalesce_suppressed_total {snap['coalesce_suppressed']}",
        "# HELP raas_quiet_suppressed_total Alerts suppressed by quiet hours.",
        "# TYPE raas_quiet_suppressed_total counter",
        f"raas_quiet_suppressed_total {snap['quiet_suppressed']}",
        "# HELP raas_telegram_deliveries_total Telegram delivery attempts (label simulated via separate series).",
        "# TYPE raas_telegram_deliveries_total counter",
        f"raas_telegram_success_total {snap['telegram_successes']}",
        f"raas_telegram_failure_total {snap['telegram_failures']}",
        "# HELP raas_config_reloads_total SIGHUP reload count.",
        "# TYPE raas_config_reloads_total counter",
        f"raas_config_reloads_total {snap['config_reloads']}",
        "",
    ]
    return "\n".join(lines).encode("utf-8")


class _HealthHandler(BaseHTTPRequestHandler):
    server_version = "RAAS-Health/1.1"

    def log_message(self, format: str, *args: Any) -> None:
        return

    def do_GET(self) -> None:
        prometheus_enabled: bool = getattr(self.server, "prometheus_enabled", False)  # type: ignore[attr-defined]
        if self.path == "/metrics":
            if not prometheus_enabled:
                self.send_error(404, "Not Found")
                return
            state: HealthState = self.server.state  # type: ignore[attr-defined]
            body = prometheus_text(state)
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if self.path not in ("/", "/health"):
            self.send_error(404, "Not Found")
            return
        state = self.server.state  # type: ignore[attr-defined]
        body = json.dumps(state.snapshot(), indent=2).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)


def start_health_server(
    bind: str,
    port: int,
    state: HealthState,
    *,
    prometheus_enabled: bool = False,
) -> tuple[ThreadingHTTPServer, threading.Thread]:
    server = ThreadingHTTPServer((bind, port), _HealthHandler)
    server.state = state
    server.prometheus_enabled = prometheus_enabled

    thread = threading.Thread(target=server.serve_forever, name="health-http", daemon=True)
    thread.start()
    return server, thread
