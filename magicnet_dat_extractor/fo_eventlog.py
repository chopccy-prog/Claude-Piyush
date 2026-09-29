"""Parser for the FastObjects database event log (``eventlog/f0000000.ptd``).

Every MagIC Net database directory (``objects.dat`` + ``objects.idx`` +
``DBInfo``) carries an ``eventlog`` folder written by the embedded
**Versant FastObjects Core 10.0.9** engine. The log is plain binary, *not*
encrypted, and its framing was worked out from four real MagIC Net 3.3 logs
(IC_Determination "Magic Net 2025", IC_Config/ConfigDB and two $$Backup# copies).

File layout (all integers little-endian)
----------------------------------------
    file header (16 bytes)
        u32 magic        = 1234 (0x04D2)
        u32 header_len   = 16
        u32 used_bytes   = number of valid bytes in the file
        u32 used_bytes   (repeated)
    records, back to back, from offset 16 up to used_bytes:
        u64 tag          top byte 0x20 for event records, 0x00 for the first
                         (file-info) record; the low bytes look like a hash /
                         thread cookie and are kept verbatim as ``tag``
        u32 length       total record length incl. this header and trailer
        u32 self_offset  file offset of the record (used to validate framing)
        ... payload ...
        u32 length       trailer, equal to ``length``

    record 0 payload (file-info record):
        string           full Windows path of this .ptd file
        u8   0xFF
        date7            creation timestamp

    event record payload:
        date7            u16 year, u8 month, day, hour, minute, second
        u32 seq          1-based running number
        then ONE of
          * u16 event_code               (0x11, 0x12, 0x13, 0x16 seen)
          * date7 + string + string      startup banner: runtime DLL path and
                                          "FastObjects Core 10.0.9.200.0 ..."
          * string + u32 0               message, e.g.
                                          "Open database with enabled storage
                                          clustering. (0-2930818#0)"
          * date7 + date7                a time range (rare)

    string:  u32 L, then (L - 4) bytes of text, then u8 0x00, then u8 0xFF

A backup copy of a log may have stale bytes after ``used_bytes`` (the backup
truncates the counter, not the file); ``parse`` stops at ``used_bytes`` unless
``include_stale=True``.

Usage
-----
    python3 fo_eventlog.py path/to/eventlog/f0000000.ptd -o eventlog.csv
"""
from __future__ import annotations

import argparse
import csv
import datetime as dt
import os
import re
import struct
import sys
from dataclasses import dataclass, asdict
from typing import Iterator, Optional

MAGIC = 1234
HEADER_LEN = 16
DATE7 = struct.Struct("<HBBBBB")
STRING_TERMINATOR = b"\x00\xff"

# Event codes. The names are working labels inferred from where the codes occur
# (0x13/0x16 once at database creation, 0x11/0x12 in pairs around sessions);
# the FastObjects source is not public, so treat them as labels, not facts.
EVENT_CODE_LABELS = {
    0x11: "session_begin",
    0x12: "session_end",
    0x13: "database_created",
    0x16: "database_initialised",
}

OPEN_MSG = re.compile(r"Open database .*\((\d+)-(\d+)#(\d+)\)")


@dataclass
class EventRecord:
    offset: int
    seq: int
    timestamp: str          # ISO "YYYY-MM-DD HH:MM:SS" from the record
    kind: str               # code | banner | message | range | fileinfo | unknown
    event_code: str         # hex, only for kind == code
    event_label: str
    message: str            # message text / banner version / path
    detail: str             # second string / second date / counter
    counter: Optional[int]  # the N in "(0-N#0)" of "Open database" messages
    tag: str                # u64 tag as hex
    length: int
    stale: bool = False     # record lies past used_bytes (backup leftovers)


class EventLogError(ValueError):
    pass


def _date7(b: bytes) -> str:
    y, mo, d, h, mi, s = DATE7.unpack_from(b, 0)
    try:
        return dt.datetime(y, mo, d, h, mi, s).strftime("%Y-%m-%d %H:%M:%S")
    except ValueError:
        return "invalid(%d-%d-%d %d:%d:%d)" % (y, mo, d, h, mi, s)


def looks_like_date7(b: bytes) -> bool:
    if len(b) < 7:
        return False
    y, mo, d, h, mi, s = DATE7.unpack_from(b, 0)
    return 1990 <= y <= 2100 and 1 <= mo <= 12 and 1 <= d <= 31 and h < 24 and mi < 60 and s < 61


def _read_string(buf: bytes, pos: int) -> tuple[str, int]:
    """Read a FastObjects log string at ``pos``; return (text, next_pos)."""
    if pos + 4 > len(buf):
        raise EventLogError("truncated string length at %d" % pos)
    (length,) = struct.unpack_from("<I", buf, pos)
    if length < 4 or pos + length + 2 > len(buf):
        raise EventLogError("bad string length %d at %d" % (length, pos))
    text = buf[pos + 4: pos + length]
    end = pos + length
    if buf[end:end + 2] != STRING_TERMINATOR:
        raise EventLogError("string terminator missing at %d" % end)
    return text.decode("latin-1"), end + 2


def _decode_payload(rec: EventRecord, payload: bytes) -> None:
    if len(payload) == 2:
        (code,) = struct.unpack("<H", payload)
        rec.kind = "code"
        rec.event_code = "0x%02x" % code
        rec.event_label = EVENT_CODE_LABELS.get(code, "code_0x%02x" % code)
        return
    if len(payload) == 14 and looks_like_date7(payload) and looks_like_date7(payload[7:]):
        rec.kind = "range"
        rec.event_label = "time_range"
        rec.message = _date7(payload)
        rec.detail = _date7(payload[7:])
        return
    pos = 0
    if len(payload) >= 7 + 4 and looks_like_date7(payload):
        # startup banner: date7 + runtime path + engine version
        rec.kind = "banner"
        rec.event_label = "engine_start"
        pos = 7
        try:
            path, pos = _read_string(payload, pos)
            version, pos = _read_string(payload, pos)
        except EventLogError:
            rec.kind = "unknown"
            rec.message = payload.hex()
            return
        rec.message = version
        rec.detail = path
        return
    try:
        text, pos = _read_string(payload, 0)
    except EventLogError:
        rec.kind = "unknown"
        rec.message = payload.hex()
        return
    rec.kind = "message"
    rec.event_label = "message"
    rec.message = text
    m = OPEN_MSG.search(text)
    if m:
        rec.event_label = "database_open"
        rec.counter = int(m.group(2))
        rec.detail = "%s-%s#%s" % m.groups()
    if pos < len(payload):
        rest = payload[pos:]
        if rest != b"\x00" * len(rest):
            rec.detail = (rec.detail + " " if rec.detail else "") + "extra=" + rest.hex()


def read_header(data: bytes) -> dict:
    if len(data) < HEADER_LEN:
        raise EventLogError("file shorter than 16-byte header")
    magic, hdr, used, used2 = struct.unpack_from("<IIII", data, 0)
    if magic != MAGIC or hdr != HEADER_LEN:
        raise EventLogError("not a FastObjects eventlog (magic %d, header %d)" % (magic, hdr))
    return {"magic": magic, "header_len": hdr, "used_bytes": used,
            "used_bytes_copy": used2, "file_bytes": len(data),
            "stale_bytes": max(0, len(data) - used)}


def iter_records(data: bytes, include_stale: bool = False) -> Iterator[EventRecord]:
    hdr = read_header(data)
    limit = hdr["used_bytes"] if not include_stale else len(data)
    pos = HEADER_LEN
    first = True
    while pos + 20 <= limit:
        tag, length, self_off = struct.unpack_from("<QII", data, pos)
        if self_off != pos or length < 20 or pos + length > len(data):
            if pos >= hdr["used_bytes"]:
                # stale region: resynchronise on the next plausible record
                nxt = _resync(data, pos + 1, limit)
                if nxt is None:
                    return
                pos = nxt
                continue
            raise EventLogError("record framing broken at offset %d" % pos)
        (trailer,) = struct.unpack_from("<I", data, pos + length - 4)
        if trailer != length:
            raise EventLogError("record trailer mismatch at offset %d" % pos)
        body = data[pos + 16: pos + length - 4]
        rec = EventRecord(offset=pos, seq=0, timestamp="", kind="unknown",
                          event_code="", event_label="", message="", detail="",
                          counter=None, tag="0x%016x" % tag, length=length,
                          stale=pos >= hdr["used_bytes"])
        if first:
            first = False
            rec.kind = "fileinfo"
            rec.event_label = "log_created"
            try:
                path, p2 = _read_string(body, 0)
                rec.message = path
                if looks_like_date7(body[p2:]):       # creation date follows the string
                    rec.timestamp = _date7(body[p2:])
            except EventLogError:
                rec.message = body.hex()
        elif len(body) >= 11:
            rec.timestamp = _date7(body)
            (rec.seq,) = struct.unpack_from("<I", body, 7)
            _decode_payload(rec, body[11:])
        else:
            rec.message = body.hex()
        yield rec
        pos += length


def _resync(data: bytes, start: int, limit: int) -> Optional[int]:
    """Find the next offset p where a record header says self_offset == p."""
    p = start
    while p + 16 <= limit:
        _tag, length, self_off = struct.unpack_from("<QII", data, p)
        if self_off == p and 20 <= length <= 1 << 20 and p + length <= len(data):
            (trailer,) = struct.unpack_from("<I", data, p + length - 4)
            if trailer == length:
                return p
        p += 1
    return None


def parse(path: str, include_stale: bool = False) -> tuple[dict, list[EventRecord]]:
    with open(path, "rb") as f:
        data = f.read()
    hdr = read_header(data)
    recs = list(iter_records(data, include_stale=include_stale))
    hdr["record_count"] = len(recs)
    dated = [r.timestamp for r in recs if r.timestamp and not r.timestamp.startswith("invalid")]
    hdr["first_timestamp"] = min(dated) if dated else None
    hdr["last_timestamp"] = max(dated) if dated else None
    counters = [r.counter for r in recs if r.counter is not None]
    hdr["last_open_counter"] = counters[-1] if counters else None
    banners = sorted({r.message for r in recs if r.kind == "banner"})
    hdr["engine_versions"] = banners
    hdr["source_path_in_log"] = recs[0].message if recs and recs[0].kind == "fileinfo" else None
    return hdr, recs


CSV_FIELDS = ["seq", "timestamp", "kind", "event_label", "event_code", "message",
              "detail", "counter", "offset", "length", "tag", "stale"]


def write_csv(recs: list[EventRecord], out_path: str) -> None:
    with open(out_path, "w", encoding="utf-8-sig", newline="") as f:
        w = csv.DictWriter(f, fieldnames=CSV_FIELDS, extrasaction="ignore")
        w.writeheader()
        for r in recs:
            d = asdict(r)
            d["counter"] = "" if d["counter"] is None else d["counter"]
            w.writerow(d)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Parse a FastObjects eventlog (.ptd) to CSV.")
    ap.add_argument("path", help="eventlog/f0000000.ptd")
    ap.add_argument("-o", "--out", default=None, help="CSV path (default: <name>.csv next to input)")
    ap.add_argument("--include-stale", action="store_true",
                    help="also parse records past used_bytes (backup leftovers)")
    args = ap.parse_args(argv)
    try:
        hdr, recs = parse(args.path, include_stale=args.include_stale)
    except (EventLogError, OSError) as e:
        print("error: " + str(e), file=sys.stderr)
        return 2
    out = args.out or os.path.splitext(args.path)[0] + ".csv"
    write_csv(recs, out)
    for k, v in hdr.items():
        print("%-20s: %s" % (k, v))
    print("wrote %d records -> %s" % (len(recs), out))
    return 0


if __name__ == "__main__":
    sys.exit(main())
