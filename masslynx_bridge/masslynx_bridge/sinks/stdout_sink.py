"""Stdout sink - prints batches as JSON lines. For dry-run testing only."""
from __future__ import annotations

import json
from typing import Dict, List

from .base import Sink


class StdoutSink(Sink):
    def send(self, records: List[Dict]) -> None:
        for rec in records:
            print(json.dumps(rec, ensure_ascii=False, default=str))
