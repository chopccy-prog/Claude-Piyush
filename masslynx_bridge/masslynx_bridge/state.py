"""Persistent per-collector cursor state.

The bridge must never send the same audit record twice and must survive a PC
reboot without re-uploading everything. We track, per collector and per source
file, how far we have already processed:

* ``offset``  - byte offset already consumed (for append-only text files)
* ``inode``   - a signature of the file (size + mtime + first-line hash) so that
                a rotated/replaced file with the same name is detected and its
                offset reset instead of silently skipping new content.
* ``sent_ids``- a bounded set of recently delivered record fingerprints, a
                second safety net against duplicates across restarts.

State is written atomically (write temp file, then ``os.replace``) so a crash
mid-write cannot corrupt it.
"""
from __future__ import annotations

import json
import os
import tempfile
import threading
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Dict


@dataclass
class FileCursor:
    offset: int = 0
    signature: str = ""


@dataclass
class CollectorState:
    files: Dict[str, FileCursor] = field(default_factory=dict)
    # Bounded FIFO of recently sent record fingerprints (most recent last).
    recent_ids: list[str] = field(default_factory=list)


class StateStore:
    """Thread-safe JSON-backed store of collector cursors."""

    MAX_RECENT_IDS = 5000

    def __init__(self, path: str):
        self._path = Path(path)
        self._lock = threading.Lock()
        self._data: Dict[str, CollectorState] = {}
        self._load()

    def _load(self) -> None:
        if not self._path.is_file():
            return
        try:
            raw = json.loads(self._path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            # Corrupt state is treated as empty; better to risk a re-scan than
            # to crash. The signature check limits duplicate uploads.
            return
        for name, cs in raw.items():
            files = {
                fn: FileCursor(**fc) for fn, fc in cs.get("files", {}).items()
            }
            self._data[name] = CollectorState(
                files=files, recent_ids=cs.get("recent_ids", [])
            )

    def _flush_locked(self) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        serializable = {
            name: {
                "files": {fn: asdict(fc) for fn, fc in cs.files.items()},
                "recent_ids": cs.recent_ids,
            }
            for name, cs in self._data.items()
        }
        fd, tmp = tempfile.mkstemp(
            dir=str(self._path.parent), prefix=".state-", suffix=".tmp"
        )
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(serializable, fh, indent=2, sort_keys=True)
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp, self._path)
        finally:
            if os.path.exists(tmp):
                os.unlink(tmp)

    def get_collector(self, name: str) -> CollectorState:
        with self._lock:
            return self._data.setdefault(name, CollectorState())

    def get_cursor(self, collector: str, filename: str) -> FileCursor:
        cs = self.get_collector(collector)
        with self._lock:
            return cs.files.setdefault(filename, FileCursor())

    def update_cursor(
        self, collector: str, filename: str, offset: int, signature: str
    ) -> None:
        cs = self.get_collector(collector)
        with self._lock:
            cs.files[filename] = FileCursor(offset=offset, signature=signature)
            self._flush_locked()

    def already_sent(self, collector: str, fingerprint: str) -> bool:
        cs = self.get_collector(collector)
        with self._lock:
            return fingerprint in cs.recent_ids

    def mark_sent(self, collector: str, fingerprints: list[str]) -> None:
        if not fingerprints:
            return
        cs = self.get_collector(collector)
        with self._lock:
            cs.recent_ids.extend(fingerprints)
            if len(cs.recent_ids) > self.MAX_RECENT_IDS:
                cs.recent_ids = cs.recent_ids[-self.MAX_RECENT_IDS:]
            self._flush_locked()
