"""FolderCollector - watches one export folder and streams new records.

Design notes
------------
* MassLynx export files are treated as append-only text. On each poll we open
  each matching file, seek to the byte offset we last consumed, read the
  remainder, parse whole lines only, and advance the offset by the number of
  bytes that formed complete lines. A partial trailing line (still being
  written by MassLynx) is left for the next poll.
* Each file carries a *signature* (size is allowed to grow; the signature is
  based on the first line + creation-ish markers). If a file with a known name
  reappears smaller than our offset, or its signature changed, we treat it as a
  new/rotated file and restart from offset 0.
* The header row is re-read every poll from offset 0 so parsing works even when
  we start mid-file; parsers themselves locate the header.
* Records are enveloped (instrument_id + ingest_time), de-duplicated against the
  persistent ``recent_ids`` set, batched, and handed to the sink. Only after the
  sink accepts a batch do we advance the file offset and mark ids as sent, so a
  crash results in re-delivery (at-least-once), never loss.
"""
from __future__ import annotations

import hashlib
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List

from ..config import CollectorConfig
from ..parsers import get_parser
from ..sinks.base import Sink
from ..state import StateStore
from ..util.backoff import retry

log = logging.getLogger("masslynx_bridge.collector")


def _file_signature(path: Path, header_bytes: bytes) -> str:
    h = hashlib.sha256()
    h.update(header_bytes)
    try:
        h.update(str(int(path.stat().st_ctime)).encode())
    except OSError:
        pass
    return h.hexdigest()[:16]


class FolderCollector:
    def __init__(
        self,
        cfg: CollectorConfig,
        sink: Sink,
        state: StateStore,
        instrument_id: str,
    ):
        self.cfg = cfg
        self.sink = sink
        self.state = state
        self.instrument_id = instrument_id
        self.parser = get_parser(cfg.kind)

    # -- helpers ----------------------------------------------------------
    def _envelope(self, rec: Dict) -> Dict:
        rec = dict(rec)
        rec["instrument_id"] = self.instrument_id
        rec["ingest_time"] = datetime.now(timezone.utc).isoformat()
        rec["collector"] = self.cfg.name
        return rec

    def _deliver(self, records: List[Dict]) -> None:
        """Batch, de-dupe, and send. Marks fingerprints as sent on success."""
        batch: List[Dict] = []
        fps: List[str] = []
        for rec in records:
            fp = rec.get("record_fingerprint", "")
            if fp and self.state.already_sent(self.cfg.name, fp):
                continue
            batch.append(self._envelope(rec))
            fps.append(fp)
            if len(batch) >= self.sink.batch_size:
                self._send_batch(batch, fps)
                batch, fps = [], []
        if batch:
            self._send_batch(batch, fps)

    def _send_batch(self, batch: List[Dict], fps: List[str]) -> None:
        retry(
            lambda: self.sink.send(batch),
            attempts=5,
            base_delay=2.0,
            max_delay=60.0,
            on_error=lambda n, exc, delay: log.warning(
                "sink send failed (attempt %d) for %s: %s; retrying in %.1fs",
                n, self.cfg.name, exc, delay,
            ),
        )
        self.state.mark_sent(self.cfg.name, [f for f in fps if f])
        log.info("%s: delivered %d records", self.cfg.name, len(batch))

    # -- main entry -------------------------------------------------------
    def poll_once(self) -> int:
        """Scan the watch folder once. Returns number of records delivered."""
        watch = Path(self.cfg.watch_dir)
        if not watch.is_dir():
            log.warning("%s: watch_dir does not exist: %s",
                        self.cfg.name, watch)
            return 0

        delivered = 0
        for path in sorted(watch.glob(self.cfg.file_glob)):
            if not path.is_file():
                continue
            try:
                delivered += self._process_file(path)
            except Exception:  # noqa: BLE001 - keep other files alive
                log.exception("%s: error processing %s",
                              self.cfg.name, path.name)
        return delivered

    def _process_file(self, path: Path) -> int:
        cursor = self.state.get_cursor(self.cfg.name, path.name)
        size = path.stat().st_size

        with path.open("rb") as fh:
            header_bytes = fh.readline()
            signature = _file_signature(path, header_bytes)

            # Detect rotation/replacement: signature changed, or file shrank
            # below our recorded offset.
            offset = cursor.offset
            if cursor.signature and cursor.signature != signature:
                log.info("%s: %s changed signature; restarting from 0",
                         self.cfg.name, path.name)
                offset = 0
            if offset > size:
                offset = 0

            if offset >= size:
                # Nothing new; still persist signature if first time seen.
                if cursor.signature != signature:
                    self.state.update_cursor(
                        self.cfg.name, path.name, offset, signature
                    )
                return 0

            fh.seek(offset)
            chunk = fh.read()

        # Only consume up to the last newline so a half-written final line is
        # retried next poll.
        last_nl = chunk.rfind(b"\n")
        if last_nl == -1:
            return 0
        consumable = chunk[: last_nl + 1]
        new_offset = offset + len(consumable)

        text = consumable.decode(self.cfg.encoding, errors="replace")
        # When starting mid-file we prepend the header line so the parser sees
        # column names.
        if offset > 0:
            text = header_bytes.decode(self.cfg.encoding, errors="replace") \
                + text

        records = self.parser(text, self.cfg.name)
        if records:
            self._deliver(records)

        self.state.update_cursor(
            self.cfg.name, path.name, new_offset, signature
        )
        return len(records)
