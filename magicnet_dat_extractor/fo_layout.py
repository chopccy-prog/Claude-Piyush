"""Generic decoder for FastObjects record bodies (MagIC Net 3.3).

Body layout (established on the real database, see docs/FINDINGS.md):

    [offset table]  k x u32: byte offsets (relative to the body start) of the
                    variable-length members, ending with the body length.
                    The first entry is where the variable part starts.
    [fixed part]    typed values back to back: references (14 bytes),
                    i64 Java-time dates, doubles, ints, bools
    [variable part] members in table order, each one of
                    string     u16 L, tag (fd01 UTF-16LE | 0101 8-bit), chars, 00 ff
                    blob       u32 n+4, u32 n, n bytes  (Java-serialized enum, or
                               gzip'ed curve data)
                    ref array  u32 count, count x 14-byte references
                    other      raw bytes

``NN<digits>`` strings are doubles: the digits are the IEEE-754 bit pattern.
"""
from __future__ import annotations

import gzip
import struct
from dataclasses import dataclass, field
from typing import Optional

import fo_fields as F
import fo_javaser as J


@dataclass
class Body:
    table: list
    fixed: bytes
    fixed_tokens: list          # (kind, offset, size, value) over the fixed part
    members: list               # decoded variable members, in table order
    raw_members: list           # raw bytes of each member


def nn_number(s):
    """'NN4607182418800017408' -> 1.0 ; returns the input unchanged otherwise."""
    if isinstance(s, str) and s.startswith("NN") and s[2:].lstrip("-").isdigit():
        bits = int(s[2:])
        if bits < 0:
            bits &= (1 << 64) - 1
        try:
            return struct.unpack("<d", struct.pack("<Q", bits))[0]
        except struct.error:
            return s
    return s


def parse_table(body: bytes) -> list:
    n = len(body)
    table = []
    pos = 0
    prev = -1
    first = None
    while pos + 4 <= n:
        v = struct.unpack_from("<I", body, pos)[0]
        if first is None:
            if v > n or v < 4:
                break
            first = v
        else:
            if v < prev or v > n:
                break
        table.append(v)
        prev = v
        pos += 4
        if len(table) * 4 > first:      # table cannot run into the variable part
            break
        if v == n and len(table) >= 1 and pos >= first:
            break
    # The table must end at exactly the body length when the object has variable
    # members; trim trailing entries beyond the first that reaches n.
    if table:
        try:
            k = table.index(n)
            table = table[:k + 1]
        except ValueError:
            pass
    return table


def decode_member(raw: bytes, max_oid: int, class_ids: set):
    if not raw:
        return ("empty", None)
    r = F.read_string(raw, 0)
    if r and r[1] == len(raw):
        return ("str", nn_number(r[0]))
    if len(raw) >= 8:
        a, n = struct.unpack_from("<II", raw, 0)
        if n == a - 4 and 8 + n == len(raw):
            data = raw[8:]
            if data[:4] == F.JAVA_MAGIC:
                try:
                    val, _ = J.loads(data)
                    return ("java", F.java_value(val))
                except J.JavaSerError:
                    return ("blob", data)
            if data[:2] == b"\x1f\x8b":
                try:
                    return ("gzip", gzip.decompress(data))
                except Exception:
                    return ("blob", data)
            return ("blob", data)
    if len(raw) >= 4:
        cnt = struct.unpack_from("<I", raw, 0)[0]
        if 4 + cnt * 14 == len(raw):
            refs = []
            ok = True
            for i in range(cnt):
                recid, objnum, cid = struct.unpack_from("<IQH", raw, 4 + i * 14)
                if recid > max_oid or objnum > max_oid or (objnum and (not cid or cid not in class_ids)):
                    ok = False
                    break
                refs.append((objnum, cid, recid) if objnum else None)
            if ok:
                return ("refs", refs)
        # array of strings: u32 count then strings back to back
        pos = 4
        items = []
        ok = cnt < 100000
        for _ in range(cnt if ok else 0):
            r = F.read_string(raw, pos)
            if not r:
                ok = False
                break
            items.append(nn_number(r[0]))
            pos = r[1]
        if ok and pos == len(raw) and cnt > 0:
            return ("strs", items)
        if 4 + cnt * 8 == len(raw) and cnt > 0:
            return ("f64s", list(struct.unpack_from("<%dd" % cnt, raw, 4)))
    return ("raw", raw)


def parse_body(body: bytes, max_oid: int, class_ids: set) -> Body:
    table = parse_table(body)
    if table:
        first = table[0]
        fixed = body[len(table) * 4:first]
        raw_members = [body[table[i]:table[i + 1]] for i in range(len(table) - 1)]
    else:
        fixed = body
        raw_members = []
    fixed_tokens = F.tokenize(fixed, max_oid, class_ids)
    members = [decode_member(m, max_oid, class_ids) for m in raw_members]
    return Body(table, fixed, fixed_tokens, members, raw_members)


def fixed_refs(b: Body) -> list:
    return [v for k, o, s, v in b.fixed_tokens if k == "ref"]


def describe(b: Body, maxlen: int = 50) -> str:
    parts = ["T%s" % b.table[:1] + ("+%d" % (len(b.table) - 1) if len(b.table) > 1 else "")]
    parts.append("FIXED{" + F.describe(b.fixed_tokens, maxlen) + "}")
    for kind, val in b.members:
        if kind == "str":
            parts.append("str(%r)" % (val if not isinstance(val, str) else val[:maxlen],))
        elif kind == "refs":
            parts.append("refs[%d](%s)" % (len(val), ",".join("null" if r is None else "%d:%d" % (r[0], r[1]) for r in val[:6]) + ("…" if len(val) > 6 else "")))
        elif kind == "strs":
            parts.append("strs%r" % ([v if not isinstance(v, str) else v[:20] for v in val[:6]],))
        elif kind == "java":
            parts.append("java(%s)" % val)
        elif kind == "gzip":
            parts.append("gzip(%d bytes -> %d)" % (0, len(val)))
        elif kind == "blob":
            parts.append("blob(%d)" % len(val))
        elif kind == "f64s":
            parts.append("f64s%r" % (val[:4],))
        elif kind == "empty":
            parts.append("empty")
        else:
            parts.append("raw(%s)" % val[:16].hex())
    return " ".join(parts)
