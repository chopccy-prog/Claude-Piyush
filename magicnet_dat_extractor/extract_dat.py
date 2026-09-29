#!/usr/bin/env python3
"""Extract data from a Metrohm MagIC Net database folder (FastObjects ``objects.dat``).

Same workflow and flags as the Access-database extractor used for the other
instruments (``extract.py --db-dir . --res-dir out --from-date ... --to-date ...``),
but for the MagIC Net database directory:

    <db>/objects.dat     object pages (the determinations, samples, results)
    <db>/objects.idx     index pages
    <db>/DBInfo          Java-properties text: DBVersion=33, ProgID=200
    <db>/eventlog/*.ptd  engine event log (plain binary, fully parsed here)
    <db>/recovery/*.rcy  recovery / transaction area

Modes
-----
salvage  (default; needs only the database folder)
    * EventLog.csv        every event-log record (database open/close, engine
                          start, counters) filtered by --from-date/--to-date
    * Strings.csv         every readable string in objects.dat with page and
                          offset (ASCII and UTF-16LE)
    * _inspect_report.json, strings_top.csv, class_candidates.csv,
      keyword_hits.csv    the forensic report from fo_inspect
    * _extract_summary.json
decode   (needs a *.fospec.json describing the page/object layout)
    * <Class>.csv and <Class>.json per class (or --table Class), filtered by
      the class's date field; _extract_summary.json with row counts
inspect
    * only the forensic report

Usage
-----
    python3 extract_dat.py --db-dir "C:\\ProgramData\\Metrohm\\MagIC Net\\Data\\IC_Determination\\Magic Net 2025" --res-dir out
    python3 extract_dat.py --db-dir . --res-dir out --mode decode --all --from-date 2025-04-01 --to-date 2025-07-31
"""
from __future__ import annotations

import argparse
import csv
import datetime as dt
import glob
import json
import mmap
import os
import re
import sys

import fo_decode
import fo_eventlog
import fo_inspect

DT_FORMATS = ("%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S.%f",
              "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d")
ASCII_RUN = re.compile(rb"[\x20-\x7e]{6,}")
UTF16_RUN = re.compile(rb"(?:[\x20-\x7e]\x00){6,}")


def parse_datetime(value):
    if isinstance(value, dt.datetime):
        return value
    if isinstance(value, str):
        s = value.strip()
        for fmt in DT_FORMATS:
            try:
                return dt.datetime.strptime(s, fmt)
            except ValueError:
                continue
    return None


def parse_bound(value, end=False):
    if value is None:
        return None
    d = parse_datetime(value)
    if d is None:
        raise ValueError("could not parse date bound: %r" % value)
    if end and len(value.strip()) == 10:
        d = d.replace(hour=23, minute=59, second=59, microsecond=999999)
    return d


def in_range(value, start, end) -> bool:
    d = parse_datetime(value)
    if d is None:
        return start is None and end is None
    if start is not None and d < start:
        return False
    if end is not None and d > end:
        return False
    return True


def write_csv(path, fieldnames, rows):
    with open(path, "w", encoding="utf-8-sig", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        w.writeheader()
        for r in rows:
            w.writerow(r)


def write_json(obj, path, indent=2):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, indent=indent, ensure_ascii=False, default=str)


def safe_name(name: str) -> str:
    out = "".join(ch if (ch.isalnum() or ch in "-_.") else "_" for ch in name)
    return out or "table"


# --------------------------------------------------------------------------
# salvage
# --------------------------------------------------------------------------
def salvage_eventlog(db_dir, res_dir, start, end) -> dict:
    logs = sorted(glob.glob(os.path.join(db_dir, "eventlog", "*.ptd")))
    rows = []
    infos = []
    for lg in logs:
        hdr, recs = fo_eventlog.parse(lg)
        hdr["file"] = os.path.relpath(lg, db_dir)
        infos.append(hdr)
        for r in recs:
            if r.kind == "fileinfo" or in_range(r.timestamp, start, end):
                d = r.__dict__.copy()
                d["counter"] = "" if d["counter"] is None else d["counter"]
                d["source_file"] = hdr["file"]
                rows.append(d)
    write_csv(os.path.join(res_dir, "EventLog.csv"), fo_eventlog.CSV_FIELDS + ["source_file"], rows)
    meta = {"table": "EventLog", "files": infos, "row_count": len(rows),
            "date_range": {"from": start.isoformat() if start else None,
                           "to": end.isoformat() if end else None}}
    write_json(meta, os.path.join(res_dir, "EventLog.meta.json"))
    return meta


def salvage_strings(objects_dat, res_dir, page_size, min_len=6) -> dict:
    size = os.path.getsize(objects_dat)
    out = os.path.join(res_dir, "Strings.csv")
    n = 0
    with open(objects_dat, "rb") as f, mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm, \
            open(out, "w", encoding="utf-8-sig", newline="") as fo:
        w = csv.writer(fo)
        w.writerow(["page", "offset", "encoding", "length", "text"])
        chunk = 8 << 20
        overlap = 1024
        pos = 0
        while pos < size:
            buf = bytes(mm[pos:min(size, pos + chunk + overlap)])
            found = []
            for m in ASCII_RUN.finditer(buf):
                if m.start() >= chunk:
                    break
                found.append((m.start(), "ascii", m.group().decode("ascii")))
            for m in UTF16_RUN.finditer(buf):
                if m.start() >= chunk:
                    break
                found.append((m.start(), "utf16", m.group().decode("utf-16-le")))
            found.sort()
            for off, enc, text in found:
                if len(text) < min_len:
                    continue
                abs_off = pos + off
                w.writerow([abs_off // page_size, abs_off, enc, len(text), text])
                n += 1
            pos += chunk
    return {"table": "Strings", "row_count": n, "page_size": page_size, "source": os.path.basename(objects_dat)}


def run_inspect(db_dir, res_dir, page_size) -> dict:
    targets = [os.path.join(db_dir, n) for n in fo_inspect.DB_FILES if os.path.isfile(os.path.join(db_dir, n))]
    reports = [fo_inspect.scan_file(t, page_size, None, 5000) for t in targets]
    return fo_inspect.write_outputs(db_dir, reports, res_dir, 5000)


# --------------------------------------------------------------------------
# decode
# --------------------------------------------------------------------------
def decode_tables(db_dir, res_dir, spec_path, table, all_tables, start, end, indent) -> dict:
    spec = fo_decode.load_spec(spec_path)
    objects_dat = os.path.join(db_dir, "objects.dat")
    names = sorted(spec["classes"]) if (all_tables or not table) else [table]
    summary = {"spec": os.path.basename(spec_path), "page_size": spec["page_size"],
               "date_range": {"from": start.isoformat() if start else None,
                              "to": end.isoformat() if end else None},
               "tables": {}}
    total = 0
    for name in names:
        err = None
        rows = []
        try:
            rows = fo_decode.decode_class(objects_dat, spec, name)
        except (fo_decode.SpecError, OSError, ValueError) as e:
            err = "%s: %s" % (type(e).__name__, e)
        date_field = spec["classes"][name].get("date_field")
        filtered = False
        if err is None and date_field and (start or end):
            rows = [r for r in rows if in_range(r.get(date_field), start, end)]
            filtered = True
        fields = ["_page", "_offset", "_class"] + [f["name"] for f in spec["classes"][name].get("fields", [])]
        write_csv(os.path.join(res_dir, safe_name(name) + ".csv"), fields, rows)
        write_json(rows, os.path.join(res_dir, safe_name(name) + ".json"), indent)
        summary["tables"][name] = {"rows": len(rows), "date_column": date_field,
                                   "filtered": filtered, "error": err}
        total += len(rows)
        print("wrote %d rows -> %s" % (len(rows), os.path.join(res_dir, safe_name(name) + ".csv")))
    summary["table_count"] = len(names)
    summary["total_rows"] = total
    return summary


NO_SPEC_HELP = """\
decode mode needs a *.fospec.json describing the FastObjects page/object layout,
and none was found in --db-dir (or given with --spec).

The MagIC Net database is a Versant FastObjects 10 object store. It is not
encrypted, but the object layout is proprietary and has to be mapped from the
real objects.dat first. Steps:
  1. run:  python3 extract_dat.py --db-dir <db> --res-dir out        (salvage)
  2. send out/_inspect_report.json, out/strings_top.csv and
     out/class_candidates.csv for analysis; the layout mapping becomes a
     magicnet.fospec.json (see magicnet.fospec.json.example)
  3. put the fospec next to objects.dat and re-run with --mode decode
Until then, the supported route is MagIC Net's own CSV/XML result export (see README).
"""


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Extract data from a MagIC Net (FastObjects) database folder.")
    ap.add_argument("--db-dir", required=True, help="database folder (holds objects.dat), or any file in it")
    ap.add_argument("--res-dir", required=True, help="output folder")
    ap.add_argument("--from-date", default=None, help="inclusive lower bound (YYYY-MM-DD)")
    ap.add_argument("--to-date", default=None, help="inclusive upper bound (YYYY-MM-DD)")
    ap.add_argument("--mode", default="salvage", choices=("salvage", "decode", "inspect"))
    ap.add_argument("--all", action="store_true", help="decode: every class in the fospec")
    ap.add_argument("--table", default=None, help="decode: one class name from the fospec")
    ap.add_argument("--spec", default=None, help="decode: fospec path (default: auto-discover *.fospec.json in --db-dir)")
    ap.add_argument("--page-size", type=int, default=None, help="override detected page size")
    ap.add_argument("--no-strings", action="store_true", help="salvage: skip Strings.csv (large)")
    ap.add_argument("--indent", type=int, default=2, help="JSON indent")
    args = ap.parse_args(argv)

    try:
        db_dir = fo_inspect.find_db_dir(args.db_dir)
        start = parse_bound(args.from_date, end=False)
        end = parse_bound(args.to_date, end=True)
    except ValueError as e:
        print("error: " + str(e), file=sys.stderr)
        return 2
    os.makedirs(args.res_dir, exist_ok=True)
    dbinfo = fo_inspect.read_dbinfo(db_dir)
    print("db dir  : " + db_dir)
    print("DBInfo  : %s" % ({k: v for k, v in dbinfo.items() if k != "comments"} or "(missing)"))
    print("mode    : " + args.mode)
    print("range   : %s .. %s" % (args.from_date or "-inf", args.to_date or "+inf"))

    summary = {"db_dir": os.path.abspath(db_dir), "dbinfo": dbinfo, "mode": args.mode,
               "date_range": {"from": start.isoformat() if start else None,
                              "to": end.isoformat() if end else None}}

    if args.mode == "decode":
        spec_path = args.spec or fo_decode.find_spec(db_dir)
        if not spec_path:
            print(NO_SPEC_HELP, file=sys.stderr)
            summary["error"] = "no fospec"
            write_json(summary, os.path.join(args.res_dir, "_extract_summary.json"), args.indent)
            return 3
        try:
            summary.update(decode_tables(db_dir, args.res_dir, spec_path, args.table, args.all, start, end, args.indent))
        except fo_decode.SpecError as e:
            print("error: " + str(e), file=sys.stderr)
            return 3
        write_json(summary, os.path.join(args.res_dir, "_extract_summary.json"), args.indent)
        print("summary -> " + os.path.join(args.res_dir, "_extract_summary.json"))
        return 0

    report = run_inspect(db_dir, args.res_dir, args.page_size)
    files = {f["file"]: f for f in report["files"]}
    dat = files.get("objects.dat", {})
    page_size = args.page_size or dat.get("page_size_used") or 4096
    summary["inspect"] = {"page_size": page_size,
                          "objects_dat_bytes": dat.get("bytes"),
                          "verdict": dat.get("verdict"),
                          "keyword_hits": dat.get("keyword_hits")}
    print("verdict : %s" % dat.get("verdict"))
    if args.mode == "inspect":
        write_json(summary, os.path.join(args.res_dir, "_extract_summary.json"), args.indent)
        return 0

    tables = {}
    if os.path.isdir(os.path.join(db_dir, "eventlog")):
        meta = salvage_eventlog(db_dir, args.res_dir, start, end)
        tables["EventLog"] = {"rows": meta["row_count"], "date_column": "timestamp", "filtered": bool(start or end)}
        print("wrote %d rows -> %s" % (meta["row_count"], os.path.join(args.res_dir, "EventLog.csv")))
    if not args.no_strings and os.path.isfile(os.path.join(db_dir, "objects.dat")):
        meta = salvage_strings(os.path.join(db_dir, "objects.dat"), args.res_dir, page_size)
        tables["Strings"] = {"rows": meta["row_count"], "date_column": None, "filtered": False}
        print("wrote %d rows -> %s" % (meta["row_count"], os.path.join(args.res_dir, "Strings.csv")))
    summary["tables"] = tables
    summary["next_step"] = ("send _inspect_report.json, strings_top.csv and class_candidates.csv "
                            "to map the object layout into a fospec, then run --mode decode")
    write_json(summary, os.path.join(args.res_dir, "_extract_summary.json"), args.indent)
    print("summary -> " + os.path.join(args.res_dir, "_extract_summary.json"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
