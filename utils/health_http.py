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
            }


class _HealthHandler(BaseHTTPRequestHandler):
    server_version = "RAAS-Health/1.0"

    def log_message(self, format: str, *args: Any) -> None:
        return

    def do_GET(self) -> None:
        if self.path not in ("/", "/health"):
            self.send_error(404, "Not Found")
            return
        state: HealthState = self.server.state  # type: ignore[attr-defined]
        body = json.dumps(state.snapshot(), indent=2).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def start_health_server(
    bind: str,
    port: int,
    state: HealthState,
) -> tuple[ThreadingHTTPServer, threading.Thread]:
    server = ThreadingHTTPServer((bind, port), _HealthHandler)
    server.state = state

    thread = threading.Thread(target=server.serve_forever, name="health-http", daemon=True)
    thread.start()
    return server, thread
