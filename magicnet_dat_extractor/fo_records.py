"""Record walker for FastObjects ``objects.dat`` pages as written by MagIC Net 3.3.

Layout established from the real file (docs/FINDINGS.md, section 8). Every
record starts on a 16-byte boundary:

    offset  size  field
    0       8     recid      record id (u64 LE; high dword is 0); unique, grows
    8       4     len        record length counted from offset 14 (total = 14 + len)
    12      2     check      low byte varies, high byte is always 0x54
    14      4     objnum     object number: this is what references point to
    18      2     zero
    20      2     class_id   FastObjects class identifier in the schema dictionary
    22      2     version    class version (0, 1 or 2 seen)
    24      2     zero
    26      ...   body       the object's fields, class-specific (see fo_fields)

The bytes between a record end and the next 16-byte boundary are fill letters
'A'..'P'. The complete 432 MB determination database walks with this rule:
2,921,283 records, every one accounted for.
"""
from __future__ import annotations

import mmap
import os
import struct
from dataclasses import dataclass
from typing import Iterator, Optional

HEADER = struct.Struct("<QIHIHHHH")
HEADER_LEN = 26
BODY_START = 26
CHECK_HI = 0x54


@dataclass
class Record:
    offset: int
    oid: int            # recid (bytes 0..7)
    length: int
    check: int
    objnum: int         # object number (bytes 14..17), the reference target
    zero: int
    class_id: int
    version: int
    body: bytes

    @property
    def end(self) -> int:
        return self.offset + 14 + self.length

    @property
    def body_len(self) -> int:
        return self.length - 12


def parse_header(buf, pos: int) -> Optional[tuple]:
    if pos + HEADER_LEN > len(buf):
        return None
    oid, ln, chk, objnum, z1, cid, ver, z2 = HEADER.unpack_from(buf, pos)
    if (chk >> 8) != CHECK_HI or z2 != 0 or z1 != 0 or ln < 12 or ln > (1 << 24) or (oid >> 32):
        return None
    return oid, ln, chk, objnum, z1, cid, ver


def iter_records(path: str, start: int = 0, end: Optional[int] = None,
                 chunk: int = 32 << 20, want_body: bool = True,
                 class_ids: Optional[set] = None) -> Iterator[Record]:
    """Yield every record in ``path`` between ``start`` and ``end`` (file offsets)."""
    size = os.path.getsize(path)
    end = size if end is None else min(end, size)
    overlap = 1 << 20
    with open(path, "rb") as f, mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
        pos = start - (start % 16)
        while pos < end:
            limit = min(chunk, end - pos)
            buf = mm[pos:min(size, pos + limit + overlap)]
            local = 0
            while local < limit:
                if buf[local + 13:local + 14] != b"\x54":
                    local += 16
                    continue
                h = parse_header(buf, local)
                if h is None:
                    local += 16
                    continue
                oid, ln, chk, objnum, z1, cid, ver = h
                rec_end = local + 14 + ln
                if rec_end > len(buf):
                    local += 16
                    continue
                if class_ids is None or cid in class_ids:
                    body = bytes(buf[local + BODY_START:rec_end]) if want_body else b""
                    yield Record(pos + local, oid, ln, chk, objnum, z1, cid, ver, body)
                local = rec_end + ((16 - rec_end % 16) % 16)
            pos += local
