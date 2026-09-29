"""Heuristic tokenizer for FastObjects record bodies (MagIC Net 3.3 objects.dat).

Field encodings observed in the real database:

    string   u16 L, tag (fd 01 = UTF-16LE, 01 01 = 8-bit), L-4 bytes, 00 ff
    java     u32 n+4, u32 n, n bytes of a Java serialization stream (enums)
    ref      u32 0, u64 oid, u16 class_id   (14 bytes; all zero = null)
    date     i64 milliseconds since 1970 (Java time), UTC
    f64 / i32 / i16 / u8 by fallback

`tokenize(body)` returns a list of (kind, offset, size, value) and is used by
fo_layout to learn a class layout from many instances, and by the extractor
to render rows.
"""
from __future__ import annotations

import datetime as dt
import struct
from typing import Optional

import fo_javaser as J

TAG_UTF16 = b"\xfd\x01"
TAG_LATIN = b"\x01\x01"
TAG_NULL = b"\xfd\xfe"
STR_END = b"\x00\xff"
JAVA_MAGIC = b"\xac\xed\x00\x05"

MS_MIN = 946684800000          # 2000-01-01
MS_MAX = 2051222400000         # 2035-01-01


def read_string(b: bytes, pos: int) -> Optional[tuple]:
    if pos + 4 > len(b):
        return None
    L = struct.unpack_from("<H", b, pos)[0]
    if L < 4 or pos + 2 + L > len(b):
        return None
    tag = b[pos + 2:pos + 4]
    if tag not in (TAG_UTF16, TAG_LATIN, TAG_NULL):
        return None
    end = pos + 2 + L
    if b[end - 2:end] != STR_END:
        return None
    raw = b[pos + 4:end - 2]
    if tag == TAG_NULL:
        return (None if not raw else raw.hex()), end
    if tag == TAG_UTF16:
        if len(raw) % 2:
            return None
        try:
            s = raw.decode("utf-16-le")
        except UnicodeDecodeError:
            return None
    else:
        s = raw.decode("latin-1")
    return s, end


def read_java(b: bytes, pos: int) -> Optional[tuple]:
    if pos + 12 > len(b):
        return None
    a, n = struct.unpack_from("<II", b, pos)
    if n != a - 4 or n < 4 or pos + 8 + n > len(b) or b[pos + 8:pos + 12] != JAVA_MAGIC:
        return None
    blob = b[pos + 8:pos + 8 + n]
    try:
        val, _ = J.loads(blob)
    except J.JavaSerError:
        val = None
    return val, blob, pos + 8 + n


def read_ref(b: bytes, pos: int, max_oid: int, class_ids: set) -> Optional[tuple]:
    """Reference = u32 recid (often 0), u64 objnum, u16 class_id. All zero = null.

    Returns ((objnum, class_id, recid), next_pos)."""
    if pos + 14 > len(b):
        return None
    recid, objnum, cid = struct.unpack_from("<IQH", b, pos)
    if objnum == 0 and cid == 0 and recid == 0:
        return (None, None, 0), pos + 14
    if 0 < objnum <= max_oid and recid <= max_oid and cid and cid in class_ids:
        return (objnum, cid, recid), pos + 14
    return None


def read_date(b: bytes, pos: int) -> Optional[tuple]:
    if pos + 8 > len(b):
        return None
    v = struct.unpack_from("<q", b, pos)[0]
    if MS_MIN <= v <= MS_MAX and (v & 0xFFFFFFFF) not in (0, 1) and (v >> 32) != (v & 0xFFFFFFFF):
        return dt.datetime.fromtimestamp(v / 1000.0, tz=dt.timezone.utc).replace(tzinfo=None).isoformat(sep=" ", timespec="milliseconds"), pos + 8
    return None


def java_value(v):
    if isinstance(v, J.JEnum):
        return "%s.%s" % (v.classname.rsplit(".", 1)[-1], v.name)
    return J.to_plain(v)


def tokenize(body: bytes, max_oid: int, class_ids: set, allow_dates: bool = True) -> list:
    """Greedy left-to-right tokenization. Returns [(kind, offset, size, value), ...]."""
    out = []
    pos = 0
    n = len(body)
    raw_start = None

    def flush_raw(upto):
        nonlocal raw_start
        if raw_start is not None and upto > raw_start:
            out.append(("raw", raw_start, upto - raw_start, body[raw_start:upto]))
        raw_start = None

    while pos < n:
        r = read_string(body, pos)
        if r:
            flush_raw(pos)
            out.append(("str", pos, r[1] - pos, r[0]))
            pos = r[1]
            continue
        r = read_java(body, pos)
        if r:
            flush_raw(pos)
            out.append(("java", pos, r[2] - pos, java_value(r[0]) if r[0] is not None else None))
            pos = r[2]
            continue
        r = read_ref(body, pos, max_oid, class_ids)
        if r:
            flush_raw(pos)
            out.append(("ref", pos, 14, r[0]))
            pos = r[1]
            continue
        if allow_dates:
            r = read_date(body, pos)
            if r:
                flush_raw(pos)
                out.append(("date", pos, 8, r[0]))
                pos = r[1]
                continue
        if raw_start is None:
            raw_start = pos
        pos += 1
    flush_raw(pos)
    return out


def describe(tokens: list, maxlen: int = 60) -> str:
    parts = []
    for kind, off, size, val in tokens:
        if kind == "raw":
            parts.append("raw%d[%s]" % (size, val.hex()[:2 * min(size, 24)] + ("…" if size > 24 else "")))
        elif kind == "str":
            parts.append("str(%r)" % (val[:maxlen],))
        elif kind == "ref":
            parts.append("ref(%s)" % ("null" if val[0] is None else "%d:%d" % (val[0], val[1])))
        elif kind == "java":
            parts.append("java(%s)" % (val,))
        elif kind == "date":
            parts.append("date(%s)" % val)
    return " ".join(parts)
