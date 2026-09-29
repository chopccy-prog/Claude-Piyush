"""Parser for MassLynx sample-result / OpenLynx exports.

MassLynx result exports (sample list summaries, OpenLynx browser exports,
quantitation reports) are delimited text with one row per sample or per
compound-in-sample. As with the audit parser this is header-driven so it
tolerates version and method differences; unrecognized columns are preserved
under ``extra``.
"""
from __future__ import annotations

import csv
import io
from typing import Dict, List

from . import fingerprint

COLUMN_ALIASES: Dict[str, str] = {
    "sample name": "sample_name",
    "samplename": "sample_name",
    "name": "sample_name",
    "sample id": "sample_id",
    "sampleid": "sample_id",
    "sample text": "sample_text",
    "vial": "vial",
    "injection": "injection",
    "inj": "injection",
    "file name": "raw_file",
    "filename": "raw_file",
    "data file": "raw_file",
    "acquired": "acquired_time",
    "acquired time": "acquired_time",
    "date": "acquired_time",
    "compound": "compound",
    "analyte": "compound",
    "component name": "compound",
    "rt": "retention_time",
    "retention time": "retention_time",
    "area": "area",
    "height": "height",
    "conc": "concentration",
    "concentration": "concentration",
    "calculated conc": "concentration",
    "amount": "concentration",
    "units": "units",
    "user": "user",
    "operator": "user",
    "instrument": "instrument",
    "method": "method",
    "ms method": "ms_method",
    "inlet method": "inlet_method",
}


def _normalize_header(h: str) -> str:
    return h.strip().strip('"').lower()


def parse_results(text: str, collector: str) -> List[Dict]:
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
        rec: Dict[str, object] = {"record_type": "result"}
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
            elif rec.get(target):
                if value:
                    extra[header[i]] = value
            else:
                rec[target] = value
        if extra:
            rec["extra"] = extra
        rec["record_fingerprint"] = fingerprint(rec)
        records.append(rec)
    return records
