"""Sinks deliver batches of records to a destination."""
from __future__ import annotations

from ..config import SinkConfig
from .base import Sink


def build_sink(cfg: SinkConfig) -> Sink:
    if cfg.type == "https":
        from .https_sink import HttpsSink
        return HttpsSink(cfg)
    if cfg.type == "sqldb":
        from .sqldb_sink import SqlDbSink
        return SqlDbSink(cfg)
    if cfg.type == "stdout":
        from .stdout_sink import StdoutSink
        return StdoutSink(cfg)
    raise ValueError(
        f"unknown sink type {cfg.type!r}; expected https, sqldb, or stdout"
    )
