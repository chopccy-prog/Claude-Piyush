"""Convert extractor JSON output to Excel-friendly CSV.

The Access-database extractors (AuditTrailExtractor) write one JSON file per
table. Clients want CSV for cross-checking in Excel. This converts any such JSON
(a list of flat record objects) to CSV. It also handles a whole output folder at
once.

Usage
-----
    # one file
    python3 json_to_csv.py out_audit/AuditTrail.json out_audit/AuditTrail.csv

    # a whole folder (every *.json -> *.csv beside it)
    python3 json_to_csv.py --dir out_all

CSV is written UTF-8 with a BOM so Excel opens non-ASCII text correctly. The
column set is the union of all record keys, in first-seen order; nested values
(lists/objects) are JSON-encoded into the cell so nothing is lost.
"""
from __future__ import annotations

import argparse
import csv
import glob
import json
import os
import sys


def _flatten_value(v):
    if v is None or isinstance(v, (str, int, float, bool)):
        return v
    return json.dumps(v, ensure_ascii=False)


def convert_records(records: list, out_path: str) -> int:
    # Union of keys, preserving first-seen order.
    fieldnames: list[str] = []
    seen = set()
    for rec in records:
        if not isinstance(rec, dict):
            rec = {"value": rec}
        for k in rec.keys():
            if k not in seen:
                seen.add(k)
                fieldnames.append(k)
    if not fieldnames:
        fieldnames = ["value"]

    with open(out_path, "w", encoding="utf-8-sig", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        w.writeheader()
        for rec in records:
            if not isinstance(rec, dict):
                rec = {"value": rec}
            w.writerow({k: _flatten_value(v) for k, v in rec.items()})
    return len(records)


def convert_file(in_path: str, out_path: str | None = None) -> str:
    with open(in_path, "r", encoding="utf-8") as f:
        data = json.load(f)
    if isinstance(data, dict):
        # A single object, or a wrapper; treat a dict of records or wrap it.
        records = data.get("records") if "records" in data else [data]
    else:
        records = data
    if out_path is None:
        out_path = os.path.splitext(in_path)[0] + ".csv"
    n = convert_records(records, out_path)
    print("wrote %d rows -> %s" % (n, out_path))
    return out_path


def convert_dir(dir_path: str) -> int:
    files = sorted(glob.glob(os.path.join(dir_path, "*.json")))
    files = [f for f in files if not os.path.basename(f).startswith("_")]
    for f in files:
        try:
            convert_file(f)
        except (json.JSONDecodeError, OSError) as e:
            print("skip %s: %s" % (f, e), file=sys.stderr)
    return len(files)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Convert extractor JSON to CSV.")
    ap.add_argument("input", nargs="?", help="input .json file")
    ap.add_argument("output", nargs="?", help="output .csv (default: alongside)")
    ap.add_argument("--dir", help="convert every *.json in this folder")
    args = ap.parse_args(argv)

    if args.dir:
        n = convert_dir(args.dir)
        print("converted %d file(s) in %s" % (n, args.dir))
        return 0
    if not args.input:
        ap.error("give an input .json file or --dir FOLDER")
    convert_file(args.input, args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
