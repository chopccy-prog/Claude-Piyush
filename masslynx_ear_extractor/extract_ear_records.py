"""Extract audit records from a MassLynx .EAR, with date-range and condition
filters, to CSV/JSON and/or straight to a server. Same workflow as the
Access-database extractor.

    python3 extract_ear_records.py --src Backup_18102025.ear --res-dir out \
        --from-date 2025-10-01 --to-date 2025-10-31 \
        --where user=sachingade type=Permission outcome=DENIED \
        --format csv

This is a COMPLETE pipeline except for ONE plug-in: the body cipher. The .ear
record bodies are encrypted, and this tool decrypts each record through a
keyspec (see ear_crypto.py) before parsing its fields. Until a correct keyspec
is supplied it runs in --plan mode: it parses the container, reports the record
inventory, and shows exactly what it will do once the key is in place, without
inventing data.

Pipeline per record:
    raw chunk  --(decrypt via keyspec)-->  plaintext bytes
               --(parse_record)-->          {type,time,user,...}
               --(date + where filters)-->  kept rows
               --(writer / server push)-->  CSV / JSON / HTTPS / DB

The field schema mirrors the LogLynx audit report (type, time, description,
outcome, user, machine, domain, file_information, client_time, event_id, index,
size). `parse_record` is written to read those fields out of the decrypted
bytes; the exact byte offsets are finalized against a real decrypted sample (a
one-time calibration once decryption is available), which is why it is isolated
in one small function.
"""
from __future__ import annotations

import argparse
import csv
import datetime as dt
import json
import os
import re
import sys

import ear_format
import ear_crypto

# Field order for output.
FIELDS = [
    "type", "time", "description", "outcome", "user", "machine", "domain",
    "file_information", "client_time", "event_id", "index", "size",
]

# Known plaintext vocabulary (from the LogLynx report) used by the calibrated
# parser and to VERIFY a candidate decryption is correct.
KNOWN_TYPES = ("Log in", "Log out", "Permission", "Audit", "Security",
               "Configuration", "System", "Report")
KNOWN_OUTCOMES = ("Allowed", "DENIED", "Succeeded", "Failed", "Denied")
DT_TEXT = re.compile(rb"\d{2}-\d{2}-\d{4} \d{2}:\d{2}:\d{2}")


# --------------------------------------------------------------------------
# Field parser (runs on DECRYPTED record bytes)
# --------------------------------------------------------------------------
DT = r"\d{2}-\d{2}-\d{4} \d{2}:\d{2}:\d{2}"
TYPES_RE = (
    r"(?:Log in|Log out|Permission|Audit|Configuration|Report|System|Security|"
    r"Instrument|Sample|Method|Backup|Restore|Data|File|Print|Sign[A-Za-z]*|"
    r"Error|Warning|Information|Event)"
)
RECORD_RE = re.compile(rf"({TYPES_RE}) ({DT}) (.*?) ({DT}) (\d+) (\d+) (\d+)")


def parse_record(plain: bytes, machine_hint: str = "MASSLYNX-PC") -> dict | None:
    """Parse one DECRYPTED record's bytes into the field dict.

    The decrypted record carries the same LogLynx schema seen in the audit
    report, so this reuses the report's field logic: anchor on the two
    ``DD-MM-YYYY HH:MM:SS`` timestamps and the trailing id/index/size integers,
    split Description/Outcome/User off the machine/domain anchor. Returns None
    if the bytes do not decode to a valid record (e.g. the key is wrong), so a
    bad key never produces fake rows.
    """
    text = plain.decode("latin-1", "replace")
    text = re.sub(r"\s+", " ", text).strip()
    m = RECORD_RE.search(text)
    if not m:
        # Fall back: a lone timestamp is not enough to trust; reject.
        return None
    typ, time, mid, ctime, idv, index, size = m.groups()
    rec = {k: "" for k in FIELDS}
    rec.update(type=typ, time=time, client_time=ctime, event_id=idv,
               index=index, size=size)
    am = re.search(rf"(.*?) ({re.escape(machine_hint)}) (\S+)(.*)$", mid)
    if am:
        left, rec["machine"], rec["domain"], rec["file_information"] = (
            am.group(1), am.group(2), am.group(3), am.group(4).strip())
        toks = left.split(" ")
        oi = next((i for i in range(len(toks) - 1, -1, -1)
                   if toks[i] in KNOWN_OUTCOMES), None)
        if oi is not None:
            rec["description"] = " ".join(toks[:oi])
            rec["outcome"] = toks[oi]
            rec["user"] = " ".join(toks[oi + 1:])
        else:
            rec["description"] = left
    else:
        rec["description"] = mid
    return rec


# --------------------------------------------------------------------------
# Filters
# --------------------------------------------------------------------------
def parse_date(s: str) -> dt.date | None:
    if not s:
        return None
    for fmt in ("%Y-%m-%d", "%d-%m-%Y"):
        try:
            return dt.datetime.strptime(s, fmt).date()
        except ValueError:
            continue
    raise ValueError("bad date (use YYYY-MM-DD): " + s)


def record_date(rec: dict) -> dt.date | None:
    m = re.match(r"(\d{2})-(\d{2})-(\d{4})", rec.get("time", ""))
    if not m:
        return None
    dd, mm, yy = map(int, m.groups())
    try:
        return dt.date(yy, mm, dd)
    except ValueError:
        return None


def in_range(rec: dict, start, end) -> bool:
    d = record_date(rec)
    if d is None:
        return start is None and end is None
    if start and d < start:
        return False
    if end and d > end:
        return False
    return True


def match_where(rec: dict, conds: dict) -> bool:
    for k, v in conds.items():
        if str(rec.get(k, "")).lower() != v.lower():
            return False
    return True


def parse_where(items: list[str]) -> dict:
    conds = {}
    for it in items or []:
        if "=" not in it:
            raise ValueError("bad --where clause (use field=value): " + it)
        k, v = it.split("=", 1)
        conds[k.strip()] = v.strip()
    return conds


# --------------------------------------------------------------------------
# Writers / server push
# --------------------------------------------------------------------------
def write_csv(rows, path):
    with open(path, "w", newline="", encoding="utf-8-sig") as fh:
        w = csv.DictWriter(fh, fieldnames=FIELDS, extrasaction="ignore")
        w.writeheader()
        w.writerows(rows)


def write_json(rows, path):
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(rows, fh, indent=2, ensure_ascii=False)


def push_to_server(rows, config_path):
    """Send rows to the central server using the masslynx_bridge sink layer."""
    bridge_dir = os.path.join(os.path.dirname(__file__), "..", "masslynx_bridge")
    sys.path.insert(0, os.path.abspath(bridge_dir))
    from masslynx_bridge.config import load_config          # noqa: E402
    from masslynx_bridge.sinks import build_sink            # noqa: E402
    cfg = load_config(config_path)
    sink = build_sink(cfg.sink)
    for i in range(0, len(rows), sink.batch_size):
        sink.send(rows[i:i + sink.batch_size])
    sink.close()


# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------
def find_ear(src):
    if os.path.isfile(src):
        return src
    import glob
    for pat in ("*.ear", "*.EAR"):
        f = sorted(glob.glob(os.path.join(src, pat)))
        if f:
            return f[0]
    raise ValueError("no .ear found at " + src)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Extract audit records from a "
                                 ".ear with date/condition filters.")
    ap.add_argument("--src", required=True, help=".ear file or its folder")
    ap.add_argument("--res-dir", default="out", help="output directory")
    ap.add_argument("--from-date", default=None, help="inclusive YYYY-MM-DD")
    ap.add_argument("--to-date", default=None, help="inclusive YYYY-MM-DD")
    ap.add_argument("--where", nargs="*", default=[],
                    help="field=value filters, e.g. user=sachingade "
                         "type=Permission outcome=DENIED")
    ap.add_argument("--format", choices=("csv", "json"), default="csv")
    ap.add_argument("--keyspec", default=None,
                    help="*.earkey.json with the body cipher/key "
                         "(default: auto-discover next to the .ear)")
    ap.add_argument("--push-config", default=None,
                    help="masslynx_bridge YAML config to push rows to a server")
    args = ap.parse_args(argv)

    ear = find_ear(args.src)
    start = parse_date(args.from_date)
    end = parse_date(args.to_date)
    conds = parse_where(args.where)
    os.makedirs(args.res_dir, exist_ok=True)

    with open(ear, "rb") as f:
        data = f.read()
    chunks = ear_format.split_chunks(data)

    keyspec_path = args.keyspec or ear_crypto.find_keyspec(ear)
    if not keyspec_path:
        # PLAN MODE: no body cipher yet. Report what will happen; invent nothing.
        report = ear_format.analyze(data)
        plan = {
            "status": "DECRYPTION KEY NOT AVAILABLE - plan only",
            "source": os.path.basename(ear),
            "records_in_container": len(chunks),
            "filters": {
                "from": args.from_date, "to": args.to_date, "where": conds,
            },
            "note": (
                "The .ear record bodies are encrypted. Supply a keyspec "
                "(*.earkey.json) with the body cipher/key to extract records. "
                "This tool will then decrypt each record, parse the fields, "
                "apply the date/where filters, and write %s (and optionally "
                "push to the server)." % args.format
            ),
        }
        with open(os.path.join(args.res_dir, "_plan.json"), "w",
                  encoding="utf-8") as fh:
            json.dump(plan, fh, indent=2)
        print("No keyspec found -> PLAN MODE (no records written).")
        print(json.dumps(plan, indent=2))
        return 4

    # DECODE: keyspec present -> decrypt, parse, filter, write, push.
    spec = ear_crypto.load_keyspec(keyspec_path)
    rows = []
    for c in chunks:
        raw = data[c.offset:c.offset + c.length]
        plain = ear_crypto.decrypt_bytes(spec, raw)
        rec = parse_record(plain)
        if rec is None:
            continue
        if not in_range(rec, start, end):
            continue
        if not match_where(rec, conds):
            continue
        rows.append(rec)

    if not rows:
        print("keyspec applied but no records parsed - the key is likely "
              "wrong (decrypted bytes had no valid timestamps).",
              file=sys.stderr)
        return 3

    out = os.path.join(args.res_dir, "ear_records." + args.format)
    (write_csv if args.format == "csv" else write_json)(rows, out)
    print("wrote %d records -> %s" % (len(rows), out))

    if args.push_config:
        push_to_server(rows, args.push_config)
        print("pushed %d records to server" % len(rows))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
