"""Spec-driven record decoder for FastObjects ``objects.dat`` pages.

FastObjects (Versant / POET) stores objects in fixed-size pages with a
proprietary, undocumented layout. The layout is **not encrypted** (see
docs/FINDINGS.md), so once the page and object structure of one MagIC Net
class has been mapped from real bytes, it can be described in a small JSON
"fospec" and this module turns the pages into rows. This is the same idea as
the ``*.keymap.json`` used by the Access extractors: the format knowledge lives
in a data file next to the database, the code stays generic.

fospec format (``<dbname>.fospec.json`` or ``magicnet.fospec.json`` in --db-dir)
--------------------------------------------------------------------------------
{
  "format": "magicnet-extractor/fospec",
  "page_size": 4096,
  "data_start": 0,                       # first byte of the first data page
  "string_encoding": "utf-16-le",        # default for type "utf16z"
  "classes": {
    "Determination": {
      "signature": {"offset": 0, "hex": "0100"},   # bytes that start a record
      "record_length": 128,                        # or null when "length_field" is given
      "length_field": null,                        # {"offset": 4, "type": "u32"} for variable records
      "fields": [
        {"name": "ident",        "offset": 8,  "type": "lstring"},
        {"name": "sample_pos",   "offset": 40, "type": "u16"},
        {"name": "started",      "offset": 48, "type": "date7"},
        {"name": "result_value", "offset": 56, "type": "f64"}
      ],
      "date_field": "started"                      # used by --from-date/--to-date
    }
  }
}

Field types: u8 u16 u32 u64 i8 i16 i32 i64 f32 f64 date7 java_millis filetime
cstring (NUL-terminated latin-1) lstring (u32 length prefix, bytes as latin-1)
utf16z (NUL-terminated UTF-16LE) hex:<n> (n raw bytes as hex).

Everything decoded is tagged with the page number and offset it came from so
that every row can be cross-checked against the MagIC Net UI.
"""
from __future__ import annotations

import datetime as dt
import json
import mmap
import os
import struct
from typing import Iterator, Optional

FOSPEC_FORMAT = "magicnet-extractor/fospec"
DATE7 = struct.Struct("<HBBBBB")
_SIMPLE = {"u8": "<B", "u16": "<H", "u32": "<I", "u64": "<Q", "i8": "<b", "i16": "<h",
           "i32": "<i", "i64": "<q", "f32": "<f", "f64": "<d"}


class SpecError(ValueError):
    pass


def load_spec(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        spec = json.load(f)
    if spec.get("format") != FOSPEC_FORMAT:
        raise SpecError("not a fospec file (format field missing or wrong): " + path)
    if not isinstance(spec.get("page_size"), int) or spec["page_size"] <= 0:
        raise SpecError("fospec needs an integer page_size")
    if not spec.get("classes"):
        raise SpecError("fospec has no classes")
    for name, cls in spec["classes"].items():
        sig = cls.get("signature") or {}
        if "hex" not in sig:
            raise SpecError("class %s: signature.hex is required" % name)
        if not cls.get("record_length") and not cls.get("length_field"):
            raise SpecError("class %s: record_length or length_field is required" % name)
        for fld in cls.get("fields", []):
            t = fld.get("type", "")
            if t not in _SIMPLE and t not in ("date7", "java_millis", "filetime", "cstring",
                                              "lstring", "utf16z") and not t.startswith("hex:"):
                raise SpecError("class %s field %s: unknown type %r" % (name, fld.get("name"), t))
    return spec


def find_spec(db_dir: str) -> Optional[str]:
    cands = []
    for fn in sorted(os.listdir(db_dir)):
        if fn.lower().endswith(".fospec.json"):
            cands.append(os.path.join(db_dir, fn))
    return cands[0] if cands else None


def _date7(b: bytes) -> Optional[str]:
    if len(b) < 7:
        return None
    y, mo, d, h, mi, s = DATE7.unpack_from(b, 0)
    try:
        return dt.datetime(y, mo, d, h, mi, s).isoformat(sep=" ")
    except ValueError:
        return None


def read_field(buf: bytes, off: int, ftype: str, encoding: str) -> object:
    if ftype in _SIMPLE:
        st = struct.Struct(_SIMPLE[ftype])
        if off + st.size > len(buf):
            return None
        return st.unpack_from(buf, off)[0]
    if ftype == "date7":
        return _date7(buf[off:off + 7])
    if ftype == "java_millis":
        if off + 8 > len(buf):
            return None
        (v,) = struct.unpack_from("<q", buf, off)
        try:
            return dt.datetime.fromtimestamp(v / 1000.0, tz=dt.timezone.utc).replace(tzinfo=None).isoformat(sep=" ")
        except (OverflowError, OSError, ValueError):
            return None
    if ftype == "filetime":
        if off + 8 > len(buf):
            return None
        (v,) = struct.unpack_from("<q", buf, off)
        try:
            return (dt.datetime(1601, 1, 1) + dt.timedelta(microseconds=v / 10)).isoformat(sep=" ")
        except (OverflowError, ValueError):
            return None
    if ftype == "cstring":
        end = buf.find(b"\x00", off)
        end = len(buf) if end < 0 else end
        return buf[off:end].decode("latin-1", "replace")
    if ftype == "lstring":
        if off + 4 > len(buf):
            return None
        (n,) = struct.unpack_from("<I", buf, off)
        if n > len(buf) - off - 4:
            return None
        return buf[off + 4: off + 4 + n].decode("latin-1", "replace")
    if ftype == "utf16z":
        end = off
        while end + 1 < len(buf) and buf[end:end + 2] != b"\x00\x00":
            end += 2
        return buf[off:end].decode(encoding, "replace")
    if ftype.startswith("hex:"):
        n = int(ftype[4:])
        return buf[off:off + n].hex()
    raise SpecError("unknown field type " + ftype)


def iter_records(mm, size: int, spec: dict, class_name: str) -> Iterator[dict]:
    cls = spec["classes"][class_name]
    ps = spec["page_size"]
    start = spec.get("data_start", 0)
    sig = bytes.fromhex(cls["signature"]["hex"])
    sig_off = int(cls["signature"].get("offset", 0))
    enc = spec.get("string_encoding", "utf-16-le")
    fixed_len = cls.get("record_length")
    len_field = cls.get("length_field")
    fields = cls.get("fields", [])
    page_no = start // ps if ps else 0
    for off in range(start, size - ps + 1, ps):
        page = bytes(mm[off:off + ps])
        pos = 0
        while True:
            i = page.find(sig, pos)
            if i < 0:
                break
            rec_start = i - sig_off
            if rec_start < 0:
                pos = i + 1
                continue
            if fixed_len:
                rec_len = int(fixed_len)
            else:
                rec_len = read_field(page, rec_start + int(len_field["offset"]), len_field["type"], enc)
                if not isinstance(rec_len, int) or rec_len <= 0:
                    pos = i + 1
                    continue
            rec = page[rec_start: rec_start + rec_len]
            if len(rec) < rec_len:
                break            # record runs past the page: not a record of this class
            row = {"_page": page_no, "_offset": off + rec_start, "_class": class_name}
            for fld in fields:
                row[fld["name"]] = read_field(rec, int(fld["offset"]), fld["type"], enc)
            yield row
            pos = rec_start + rec_len
        page_no += 1


def decode_class(objects_dat: str, spec: dict, class_name: str) -> list[dict]:
    if class_name not in spec["classes"]:
        raise SpecError("class %r not in fospec; available: %s" % (class_name, sorted(spec["classes"])))
    size = os.path.getsize(objects_dat)
    with open(objects_dat, "rb") as f, mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
        return list(iter_records(mm, size, spec, class_name))
