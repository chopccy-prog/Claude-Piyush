"""Sink interface.

A sink is the pluggable delivery layer. Implement ``send`` to push a batch of
already-enveloped record dicts to a destination. It must be idempotent-friendly:
the caller guarantees each record carries a stable ``record_fingerprint`` the
destination can use to de-duplicate.

``send`` should raise on failure so the retry/backoff layer can react; it must
NOT swallow errors silently, or records would be lost.
"""
from __future__ import annotations

import abc
from typing import Dict, List

from ..config import SinkConfig


class Sink(abc.ABC):
    def __init__(self, cfg: SinkConfig):
        self.cfg = cfg

    @property
    def batch_size(self) -> int:
        return max(1, int(self.cfg.batch_size))

    @abc.abstractmethod
    def send(self, records: List[Dict]) -> None:
        """Deliver a batch. Raise on any failure."""

    def close(self) -> None:  # pragma: no cover - optional override
        """Release resources (connections, sessions)."""
