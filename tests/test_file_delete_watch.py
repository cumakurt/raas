from __future__ import annotations

import threading
import time
from pathlib import Path

from config.settings import FileDeletionConfig, LogConfig, Settings
from watcher.file_delete_watch import FileDeletionEvent, _path_ignored, run_file_delete_watch


def _settings(root: Path) -> Settings:
    return Settings(
        log=LogConfig(path=root / "auth.log"),
        file_deletion=FileDeletionConfig(
            enabled=True,
            paths=(root,),
            recursive=True,
            include_moves=True,
            cooldown_seconds=0,
            ignore_globs=(),
        ),
    )


def _wait_for(events: list[FileDeletionEvent], predicate: object) -> FileDeletionEvent | None:
    pred = predicate  # keep mypy-style narrowing out of the test body
    deadline = time.monotonic() + 3.0
    while time.monotonic() < deadline:
        for ev in events:
            if pred(ev):  # type: ignore[operator]
                return ev
        time.sleep(0.05)
    return None


def test_file_delete_watch_emits_delete(tmp_path: Path) -> None:
    events: list[FileDeletionEvent] = []
    stop_event = threading.Event()
    ready_event = threading.Event()
    t = threading.Thread(
        target=run_file_delete_watch,
        args=(_settings(tmp_path), stop_event, events.append),
        kwargs={"ready_event": ready_event},
        daemon=True,
    )
    t.start()
    try:
        assert ready_event.wait(timeout=3.0)
        target = tmp_path / "deleted.txt"
        target.write_text("x", encoding="utf-8")
        target.unlink()

        ev = _wait_for(
            events,
            lambda e: e.path == target and e.action == "deleted" and not e.is_dir,
        )
        assert ev is not None
        assert ev.item_type == "file"
    finally:
        stop_event.set()
        t.join(timeout=3.0)


def test_file_delete_watch_emits_move_away(tmp_path: Path) -> None:
    root = tmp_path / "watched"
    root.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    events: list[FileDeletionEvent] = []
    stop_event = threading.Event()
    ready_event = threading.Event()
    t = threading.Thread(
        target=run_file_delete_watch,
        args=(_settings(root), stop_event, events.append),
        kwargs={"ready_event": ready_event},
        daemon=True,
    )
    t.start()
    try:
        assert ready_event.wait(timeout=3.0)
        source = root / "moved.txt"
        dest = outside / "moved.txt"
        source.write_text("x", encoding="utf-8")
        source.rename(dest)

        ev = _wait_for(
            events,
            lambda e: e.path == source and e.action == "moved_from" and not e.is_dir,
        )
        assert ev is not None
    finally:
        stop_event.set()
        t.join(timeout=3.0)


def test_file_delete_watch_emits_modify(tmp_path: Path) -> None:
    events: list[FileDeletionEvent] = []
    stop_event = threading.Event()
    ready_event = threading.Event()
    t = threading.Thread(
        target=run_file_delete_watch,
        args=(_settings(tmp_path), stop_event, events.append),
        kwargs={"ready_event": ready_event},
        daemon=True,
    )
    t.start()
    try:
        assert ready_event.wait(timeout=3.0)
        target = tmp_path / "changed.txt"
        target.write_text("x", encoding="utf-8")

        ev = _wait_for(
            events,
            lambda e: e.path == target and e.action == "modified" and not e.is_dir,
        )
        assert ev is not None
    finally:
        stop_event.set()
        t.join(timeout=3.0)


def test_ignore_globs_prune_directory_and_contents() -> None:
    patterns = ("*/.*", "*/node_modules/*", "*/__pycache__/*")

    assert _path_ignored(Path("/home/user/.mozilla"), patterns)
    assert _path_ignored(Path("/home/user/.mozilla/firefox/data.sqlite-journal"), patterns)
    assert _path_ignored(Path("/home/user/project/node_modules"), patterns)
    assert _path_ignored(Path("/home/user/project/node_modules/pkg/index.js"), patterns)
    assert _path_ignored(Path("/home/user/project/__pycache__"), patterns)
    assert _path_ignored(Path("/home/user/project/__pycache__/mod.pyc"), patterns)
