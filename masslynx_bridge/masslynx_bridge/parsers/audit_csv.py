"""Parser for MassLynx Security / LogLynx audit-trail exports.

LogLynx (the MassLynx Security viewer) exports the audit trail to a delimited
text file. The exact column set varies with MassLynx version and locale, so
this parser is column-name driven rather than positional: it reads the header
row and maps recognized columns onto normalized field names, keeping any
unrecognized columns under an ``extra`` object so no information is lost.

If your site's export uses different column headings, extend ``COLUMN_ALIASES``
below - that is the only change needed.
"""
from __future__ import annotations

import csv
import io
from typing import Dict, List

from . import fingerprint

# Map many possible source header spellings onto one normalized field name.
COLUMN_ALIASES: Dict[str, str] = {
    # timestamp
    "date/time": "event_time",
    "date time": "event_time",
    "datetime": "event_time",
    "timestamp": "event_time",
    "date": "event_date",
    "time": "event_time_only",
    # who
    "user": "user",
    "user name": "user",
    "username": "user",
    "operator": "user",
    "full name": "user_full_name",
    # what
    "event": "event_type",
    "event type": "event_type",
    "action": "event_type",
    "activity": "event_type",
    "description": "description",
    "details": "description",
    "message": "description",
    "reason": "reason",
    "comment": "reason",
    # where / context
    "application": "application",
    "program": "application",
    "computer": "computer",
    "machine": "computer",
    "workstation": "computer",
    "project": "project",
    "item": "item",
    "object": "item",
}


def _normalize_header(h: str) -> str:
    return h.strip().strip('"').lower()


def parse_audit_trail(text: str, collector: str) -> List[Dict]:
    """Parse the decoded text of one audit-trail export into records."""
    # Sniff the delimiter from the first non-empty line; fall back to tab then
    # comma, which are the two LogLynx uses in practice.
    sample = "\n".join(
        line for line in text.splitlines()[:20] if line.strip()
    )
    delimiter = ","
    if sample:
        try:
            delimiter = csv.Sniffer().sniff(
                sample, delimiters=",\t;|"
            ).delimiter
        except csv.Error:
            delimiter = "\t" if "\t" in sample else ","

    reader = csv.reader(io.StringIO(text), delimiter=delimiter)
    rows = [r for r in reader if any(c.strip() for c in r)]
    if not rows:
        return []

    header = [_normalize_header(c) for c in rows[0]]
    mapped = [COLUMN_ALIASES.get(h, None) for h in header]

    records: List[Dict] = []
    for raw in rows[1:]:
        if len(raw) == 1 and not raw[0].strip():
            continue
        rec: Dict[str, object] = {"record_type": "audit_trail"}
        extra: Dict[str, str] = {}
        for i, value in enumerate(raw):
            value = value.strip()
            if i >= len(header):
                extra[f"col{i}"] = value
                continue
            target = mapped[i]
            if target is None:
                if header[i]:
                    extra[header[i]] = value
            else:
                # If two source columns map to the same target, keep the first
                # non-empty one and stash the rest in extra.
                if rec.get(target):
                    if value:
                        extra[f"{header[i]}"] = value
                else:
                    rec[target] = value
        if extra:
            rec["extra"] = extra
        rec["record_fingerprint"] = fingerprint(rec)
        records.append(rec)
    return records
