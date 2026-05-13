from __future__ import annotations

import ctypes
import fnmatch
import logging
import os
import pwd
import select
import struct
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from config.settings import Settings

logger = logging.getLogger(__name__)

IN_MODIFY = 0x00000002
IN_MOVED_FROM = 0x00000040
IN_MOVED_TO = 0x00000080
IN_CREATE = 0x00000100
IN_DELETE = 0x00000200
IN_DELETE_SELF = 0x00000400
IN_MOVE_SELF = 0x00000800
IN_ISDIR = 0x40000000

_WATCH_MASK = IN_MODIFY | IN_DELETE | IN_MOVED_FROM | IN_CREATE | IN_MOVED_TO | IN_DELETE_SELF | IN_MOVE_SELF
_EVENT_STRUCT = struct.Struct("iIII")
_CRITICAL_WATCH_PATHS: tuple[Path, ...] = (
    Path("/etc"),
    Path("/bin"),
    Path("/sbin"),
    Path("/usr/bin"),
    Path("/usr/sbin"),
    Path("/usr/local/bin"),
    Path("/usr/local/sbin"),
    Path("/usr/lib"),
    Path("/lib"),
    Path("/lib64"),
    Path("/boot"),
    Path("/root"),
)


@dataclass(frozen=True)
class FileDeletionEvent:
    path: Path
    action: str
    is_dir: bool
    watched_root: Path
    user: str | None = None

    @property
    def item_type(self) -> str:
        return "directory" if self.is_dir else "file"

    def raw_line(self) -> str:
        return (
            f"file_deletion action={self.action} item_type={self.item_type} "
            f"path={self.path} watched_root={self.watched_root}"
        )


def _path_ignored(path: Path, ignore_globs: tuple[str, ...]) -> bool:
    s = str(path)
    for pat in ignore_globs:
        if fnmatch.fnmatch(s, pat):
            return True
        if pat.endswith("/*") and fnmatch.fnmatch(s, pat[:-2]):
            return True
    return False


def _owner_name(path: Path) -> str | None:
    try:
        uid = path.stat().st_uid
    except OSError:
        return None
    try:
        return pwd.getpwuid(uid).pw_name
    except KeyError:
        return str(uid)


def default_watch_paths() -> tuple[Path, ...]:
    return _CRITICAL_WATCH_PATHS


class _Inotify:
    def __init__(self) -> None:
        libc = ctypes.CDLL("libc.so.6", use_errno=True)
        self._libc = libc
        self._libc.inotify_init.restype = ctypes.c_int
        self._libc.inotify_add_watch.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_uint32]
        self._libc.inotify_add_watch.restype = ctypes.c_int
        self.fd = self._libc.inotify_init()
        if self.fd < 0:
            err = ctypes.get_errno()
            raise OSError(err, os.strerror(err))
        os.set_blocking(self.fd, False)

    def close(self) -> None:
        try:
            os.close(self.fd)
        except OSError:
            pass

    def add_watch(self, path: Path) -> int:
        wd = self._libc.inotify_add_watch(
            self.fd,
            os.fsencode(path),
            ctypes.c_uint32(_WATCH_MASK),
        )
        if wd < 0:
            err = ctypes.get_errno()
            raise OSError(err, os.strerror(err), str(path))
        return int(wd)


class _RecursiveDeleteWatcher:
    def __init__(
        self,
        roots: tuple[Path, ...],
        *,
        recursive: bool,
        include_moves: bool,
        cooldown_seconds: float,
        ignore_globs: tuple[str, ...],
        max_watch_dirs: int,
    ) -> None:
        self.roots = roots
        self.recursive = recursive
        self.include_moves = include_moves
        self.cooldown_seconds = cooldown_seconds
        self.ignore_globs = ignore_globs
        self.max_watch_dirs = max_watch_dirs
        self._ino = _Inotify()
        self._wd_paths: dict[int, Path] = {}
        self._wd_roots: dict[int, Path] = {}
        self._root_users: dict[Path, str | None] = {}
        self._last_emit: dict[tuple[str, str], float] = {}
        self._limit_warned = False

    @property
    def fd(self) -> int:
        return self._ino.fd

    def close(self) -> None:
        self._ino.close()

    def add_initial_watches(self) -> int:
        count = 0
        seen: set[Path] = set()
        for root in self.roots:
            root = root.expanduser().resolve()
            if root in seen:
                continue
            seen.add(root)
            if not root.is_dir():
                logger.warning("File deletion watch path is not a directory: %s", root)
                continue
            self._root_users[root] = _owner_name(root)
            count += self._add_tree(root, root)
        return count

    def _add_watch(self, path: Path, root: Path) -> bool:
        if len(self._wd_paths) >= self.max_watch_dirs:
            self._warn_limit_once()
            return False
        if _path_ignored(path, self.ignore_globs):
            return False
        try:
            wd = self._ino.add_watch(path)
        except OSError as e:
            logger.debug("Cannot watch %s: %s", path, e)
            return False
        self._wd_paths[wd] = path
        self._wd_roots[wd] = root
        return True

    def _warn_limit_once(self) -> None:
        if self._limit_warned:
            return
        logger.warning(
            "File deletion watch limit reached (%s directories); coverage is partial",
            self.max_watch_dirs,
        )
        self._limit_warned = True

    def _add_tree(self, root: Path, watched_root: Path) -> int:
        count = 0
        if self._add_watch(root, watched_root):
            count += 1
        if len(self._wd_paths) >= self.max_watch_dirs:
            self._warn_limit_once()
            return count
        if not self.recursive:
            return count
        for dirpath, dirnames, _filenames in os.walk(root):
            if len(self._wd_paths) >= self.max_watch_dirs:
                self._warn_limit_once()
                dirnames[:] = []
                break
            base = Path(dirpath)
            dirnames[:] = [
                d
                for d in dirnames
                if not _path_ignored(base / d, self.ignore_globs)
            ]
            if base == root:
                continue
            if self._add_watch(base, watched_root):
                count += 1
            if len(self._wd_paths) >= self.max_watch_dirs:
                self._warn_limit_once()
                dirnames[:] = []
                break
        return count

    def _should_emit(self, action: str, path: Path) -> bool:
        if self.cooldown_seconds <= 0:
            return True
        key = (action, str(path))
        now = time.monotonic()
        last = self._last_emit.get(key, 0.0)
        if now - last < self.cooldown_seconds:
            return False
        self._last_emit[key] = now
        return True

    def read_events(self) -> list[FileDeletionEvent]:
        try:
            raw = os.read(self.fd, 65536)
        except BlockingIOError:
            return []
        except OSError as e:
            logger.warning("File deletion watch read error: %s", e)
            return []

        out: list[FileDeletionEvent] = []
        offset = 0
        while offset + _EVENT_STRUCT.size <= len(raw):
            wd, mask, _cookie, name_len = _EVENT_STRUCT.unpack_from(raw, offset)
            offset += _EVENT_STRUCT.size
            name_raw = raw[offset : offset + name_len]
            offset += name_len
            parent = self._wd_paths.get(wd)
            watched_root = self._wd_roots.get(wd)
            if parent is None or watched_root is None:
                continue
            name = name_raw.split(b"\0", 1)[0].decode(errors="replace")
            path = parent / name if name else parent
            is_dir = bool(mask & IN_ISDIR)

            if is_dir and self.recursive and mask & (IN_CREATE | IN_MOVED_TO):
                self._add_tree(path, watched_root)

            action: str | None = None
            if mask & IN_DELETE:
                action = "deleted"
            elif self.include_moves and mask & IN_MOVED_FROM:
                action = "moved_from"
            elif not is_dir and mask & IN_MODIFY:
                action = "modified"

            if action and not _path_ignored(path, self.ignore_globs) and self._should_emit(action, path):
                out.append(
                    FileDeletionEvent(
                        path=path,
                        action=action,
                        is_dir=is_dir,
                        watched_root=watched_root,
                        user=self._root_users.get(watched_root),
                    ),
                )

            if mask & (IN_DELETE_SELF | IN_MOVE_SELF):
                self._wd_paths.pop(wd, None)
                self._wd_roots.pop(wd, None)

        return out


def run_file_delete_watch(
    settings: Settings,
    stop_event: threading.Event,
    on_event: Callable[[FileDeletionEvent], None],
    *,
    ready_event: threading.Event | None = None,
) -> None:
    cfg = settings.file_deletion
    if not cfg.enabled:
        return
    roots = cfg.paths or default_watch_paths()
    watcher: _RecursiveDeleteWatcher | None = None
    try:
        watcher = _RecursiveDeleteWatcher(
            roots,
            recursive=cfg.recursive,
            include_moves=cfg.include_moves,
            cooldown_seconds=cfg.cooldown_seconds,
            ignore_globs=cfg.ignore_globs,
            max_watch_dirs=cfg.max_watch_dirs,
        )
        count = watcher.add_initial_watches()
        if count <= 0:
            logger.warning("File deletion monitoring has no active watch directories")
            return
        logger.info(
            "File deletion monitor active (%d directories): %s",
            count,
            ", ".join(str(p) for p in roots),
        )
        if ready_event is not None:
            ready_event.set()
        while not stop_event.is_set():
            try:
                r, _, _ = select.select([watcher.fd], [], [], 1.0)
            except (OSError, ValueError):
                if stop_event.wait(timeout=1.0):
                    return
                continue
            if not r:
                continue
            for ev in watcher.read_events():
                on_event(ev)
    except OSError as e:
        logger.warning("File deletion monitoring unavailable: %s", e)
    finally:
        if ready_event is not None:
            ready_event.set()
        if watcher is not None:
            watcher.close()
