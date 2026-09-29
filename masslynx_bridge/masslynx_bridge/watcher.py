"""The service loop: build sink + collectors, poll on an interval, run forever.

This is a deliberately simple polling loop rather than an OS filesystem-watch,
because on the MassLynx acquisition PC a poll every few seconds is robust
against network shares, antivirus locks, and MassLynx writing files in bursts -
all of which trip up inotify/ReadDirectoryChangesW style watchers.
"""
from __future__ import annotations

import logging
import signal
import time
from typing import List

from .collectors.base import FolderCollector
from .config import Config
from .sinks import build_sink
from .state import StateStore

log = logging.getLogger("masslynx_bridge.watcher")


class Bridge:
    def __init__(self, cfg: Config):
        self.cfg = cfg
        self.state = StateStore(cfg.state_path)
        self.sink = build_sink(cfg.sink)
        self.collectors: List[FolderCollector] = [
            FolderCollector(c, self.sink, self.state, cfg.instrument_id)
            for c in cfg.collectors
            if c.enabled
        ]
        self._stop = False

    def request_stop(self, *_: object) -> None:
        log.info("shutdown requested; finishing current cycle")
        self._stop = True

    def run(self) -> None:
        if not self.collectors:
            log.warning("no enabled collectors configured; nothing to do")
        signal.signal(signal.SIGINT, self.request_stop)
        signal.signal(signal.SIGTERM, self.request_stop)

        log.info(
            "MassLynx bridge starting: instrument=%s, %d collector(s), "
            "sink=%s, poll=%.1fs",
            self.cfg.instrument_id,
            len(self.collectors),
            self.cfg.sink.type,
            self.cfg.poll_interval_seconds,
        )
        try:
            while not self._stop:
                cycle_start = time.monotonic()
                total = 0
                for collector in self.collectors:
                    if self._stop:
                        break
                    try:
                        total += collector.poll_once()
                    except Exception:  # noqa: BLE001
                        log.exception("collector %s crashed in poll",
                                      collector.cfg.name)
                if total:
                    log.info("cycle delivered %d record(s)", total)
                # Sleep the remainder of the interval, in short slices so a
                # stop signal is honored promptly.
                elapsed = time.monotonic() - cycle_start
                remaining = max(0.0, self.cfg.poll_interval_seconds - elapsed)
                slept = 0.0
                while slept < remaining and not self._stop:
                    step = min(0.5, remaining - slept)
                    time.sleep(step)
                    slept += step
        finally:
            try:
                self.sink.close()
            except Exception:  # noqa: BLE001
                pass
            log.info("MassLynx bridge stopped")
