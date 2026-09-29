"""Parsers turn a raw MassLynx export file into normalized record dicts."""
from __future__ import annotations

import hashlib
import json
from typing import Callable, Dict, List

# A parser takes the decoded text of one export file and the collector name and
# returns a list of record dicts. Each record MUST contain a stable
# "record_fingerprint" so duplicates can be detected across restarts.
Parser = Callable[[str, str], List[Dict]]


def fingerprint(record: Dict) -> str:
    """Deterministic fingerprint of a record's payload fields.

    Excludes envelope metadata added later (instrument_id, ingest_time) so the
    same underlying event always hashes the same way.
    """
    payload = {k: v for k, v in record.items()
               if k not in ("instrument_id", "ingest_time",
                            "record_fingerprint")}
    blob = json.dumps(payload, sort_keys=True, ensure_ascii=False,
                      default=str)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def get_parser(kind: str) -> Parser:
    from .audit_csv import parse_audit_trail
    from .results_csv import parse_results

    parsers: Dict[str, Parser] = {
        "audit_trail": parse_audit_trail,
        "results": parse_results,
    }
    if kind not in parsers:
        raise ValueError(
            f"unknown collector kind {kind!r}; expected one of "
            f"{sorted(parsers)}"
        )
    return parsers[kind]
