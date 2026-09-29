"""Parser for the Java Object Serialization Stream Protocol (java.io.ObjectOutputStream).

MagIC Net stores its attribute values inside the FastObjects pages as Java
serialized objects (the inspector found `java.lang.Enum`, `mnet.*Enum`,
`DBICSample$SampleType` ... with Java's UTF length prefix in front). The
serialization format is public (Java Object Serialization Specification,
chapter 6), so those blobs can be decoded without the FastObjects schema.

This module is a standard-library, dependency-free reader that turns a
serialized stream into plain Python values:

    java object   -> JObject(classname, fields={...}, annotations=[...])
    enum constant -> JEnum(classname, name)
    String        -> str
    arrays        -> list          primitives -> int / float / bool / str
    null          -> None          class      -> JClass(name)

Custom `writeObject` data (SC_WRITE_METHOD) is kept: primitive block data is
returned as bytes, objects written in it are decoded, and the whole list lands
in `JObject.annotations`. Well-known JDK collections (ArrayList, HashMap,
HashSet, LinkedList, Date, ...) are additionally unpacked into Python lists,
dicts and ISO timestamps.

Also provides `scan(buf)` to find every stream (magic AC ED 00 05) inside a
larger byte buffer such as a FastObjects page file, and `parse_class_desc`
based recovery for blobs stored without the stream header.
"""
from __future__ import annotations

import datetime as dt
import struct
from dataclasses import dataclass, field
from typing import Any, Iterator, Optional

STREAM_MAGIC = b"\xac\xed"
STREAM_VERSION = 5
MAGIC_BYTES = b"\xac\xed\x00\x05"

TC_NULL = 0x70
TC_REFERENCE = 0x71
TC_CLASSDESC = 0x72
TC_OBJECT = 0x73
TC_STRING = 0x74
TC_ARRAY = 0x75
TC_CLASS = 0x76
TC_BLOCKDATA = 0x77
TC_ENDBLOCKDATA = 0x78
TC_RESET = 0x79
TC_BLOCKDATALONG = 0x7A
TC_EXCEPTION = 0x7B
TC_LONGSTRING = 0x7C
TC_PROXYCLASSDESC = 0x7D
TC_ENUM = 0x7E
BASE_WIRE_HANDLE = 0x7E0000

SC_WRITE_METHOD = 0x01
SC_BLOCK_DATA = 0x08
SC_SERIALIZABLE = 0x02
SC_EXTERNALIZABLE = 0x04
SC_ENUM = 0x10

PRIM = {"B": ("b", 1), "C": ("H", 2), "D": ("d", 8), "F": ("f", 4),
        "I": ("i", 4), "J": ("q", 8), "S": ("h", 2), "Z": ("?", 1)}


class JavaSerError(ValueError):
    pass


@dataclass
class JField:
    name: str
    typecode: str
    classname: Optional[str] = None      # for L and [ types


@dataclass
class JClassDesc:
    name: str
    serial_version_uid: int
    flags: int
    fields: list[JField]
    annotations: list = field(default_factory=list)
    super_desc: Optional["JClassDesc"] = None
    proxy_interfaces: Optional[list[str]] = None

    @property
    def is_enum(self) -> bool:
        return bool(self.flags & SC_ENUM)

    @property
    def has_write_method(self) -> bool:
        return bool(self.flags & SC_WRITE_METHOD)

    @property
    def is_externalizable(self) -> bool:
        return bool(self.flags & SC_EXTERNALIZABLE)

    @property
    def chain(self) -> list["JClassDesc"]:
        out = []
        d: Optional[JClassDesc] = self
        while d is not None:
            out.append(d)
            d = d.super_desc
        return list(reversed(out))         # root superclass first


@dataclass
class JClass:
    name: str


@dataclass
class JEnum:
    classname: str
    name: str

    def __str__(self) -> str:
        return self.name


@dataclass
class JObject:
    classname: str
    fields: dict = field(default_factory=dict)
    annotations: list = field(default_factory=list)   # custom writeObject data per class
    desc: Optional[JClassDesc] = None
    value: Any = None            # unpacked Python value for known JDK types

    def get(self, name, default=None):
        return self.fields.get(name, default)


@dataclass
class JArray:
    classname: str
    items: list


class Reader:
    def __init__(self, buf: bytes, pos: int = 0):
        self.buf = buf
        self.pos = pos
        self.handles: list = []

    # --- primitives ------------------------------------------------------
    def need(self, n: int) -> None:
        if self.pos + n > len(self.buf):
            raise JavaSerError("truncated at %d (need %d bytes)" % (self.pos, n))

    def u8(self) -> int:
        self.need(1)
        v = self.buf[self.pos]
        self.pos += 1
        return v

    def u16(self) -> int:
        self.need(2)
        v = struct.unpack_from(">H", self.buf, self.pos)[0]
        self.pos += 2
        return v

    def i32(self) -> int:
        self.need(4)
        v = struct.unpack_from(">i", self.buf, self.pos)[0]
        self.pos += 4
        return v

    def i64(self) -> int:
        self.need(8)
        v = struct.unpack_from(">q", self.buf, self.pos)[0]
        self.pos += 8
        return v

    def raw(self, n: int) -> bytes:
        self.need(n)
        v = self.buf[self.pos:self.pos + n]
        self.pos += n
        return v

    def utf(self) -> str:
        n = self.u16()
        return _decode_mutf8(self.raw(n))

    def long_utf(self) -> str:
        n = self.i64()
        if n < 0 or n > len(self.buf):
            raise JavaSerError("bad long string length %d" % n)
        return _decode_mutf8(self.raw(n))

    def prim(self, code: str):
        fmt, size = PRIM[code]
        self.need(size)
        v = struct.unpack_from(">" + fmt, self.buf, self.pos)[0]
        self.pos += size
        if code == "C":
            return chr(v)
        return v

    # --- handles ----------------------------------------------------------
    def new_handle(self, obj) -> int:
        self.handles.append(obj)
        return BASE_WIRE_HANDLE + len(self.handles) - 1

    def deref(self, handle: int):
        i = handle - BASE_WIRE_HANDLE
        if i < 0 or i >= len(self.handles):
            raise JavaSerError("bad handle 0x%x at %d" % (handle, self.pos))
        return self.handles[i]

    # --- stream ----------------------------------------------------------
    def stream_header(self) -> None:
        if self.raw(2) != STREAM_MAGIC:
            raise JavaSerError("no stream magic")
        if self.u16() != STREAM_VERSION:
            raise JavaSerError("unsupported stream version")

    def content(self, tc: Optional[int] = None):
        """Read one content element (object / string / array / blockdata ...)."""
        if tc is None:
            tc = self.u8()
        if tc == TC_NULL:
            return None
        if tc == TC_REFERENCE:
            return self.deref(self.i32())
        if tc == TC_STRING:
            s = self.utf()
            self.new_handle(s)
            return s
        if tc == TC_LONGSTRING:
            s = self.long_utf()
            self.new_handle(s)
            return s
        if tc == TC_OBJECT:
            return self.object()
        if tc == TC_ARRAY:
            return self.array()
        if tc == TC_ENUM:
            return self.enum()
        if tc == TC_CLASS:
            desc = self.class_desc()
            c = JClass(desc.name if desc else "?")
            self.new_handle(c)
            return c
        if tc in (TC_CLASSDESC, TC_PROXYCLASSDESC):
            return self.class_desc(tc)
        if tc == TC_BLOCKDATA:
            n = self.u8()
            return self.raw(n)
        if tc == TC_BLOCKDATALONG:
            n = self.i32()
            if n < 0:
                raise JavaSerError("negative block length")
            return self.raw(n)
        if tc == TC_RESET:
            self.handles = []
            return self.content()
        if tc == TC_EXCEPTION:
            self.handles = []
            exc = self.content()
            self.handles = []
            raise JavaSerError("stream contains TC_EXCEPTION: %r" % (exc,))
        if tc == TC_ENDBLOCKDATA:
            raise JavaSerError("unexpected TC_ENDBLOCKDATA at %d" % (self.pos - 1))
        raise JavaSerError("unknown type code 0x%02x at %d" % (tc, self.pos - 1))

    def class_desc(self, tc: Optional[int] = None) -> Optional[JClassDesc]:
        if tc is None:
            tc = self.u8()
        if tc == TC_NULL:
            return None
        if tc == TC_REFERENCE:
            d = self.deref(self.i32())
            if not isinstance(d, JClassDesc):
                raise JavaSerError("class-desc reference to non-class at %d" % self.pos)
            return d
        if tc == TC_PROXYCLASSDESC:
            n = self.i32()
            ifaces = [self.utf() for _ in range(n)]
            desc = JClassDesc(name="$Proxy", serial_version_uid=0, flags=SC_SERIALIZABLE,
                              fields=[], proxy_interfaces=ifaces)
            self.new_handle(desc)
            desc.annotations = self.annotation()
            desc.super_desc = self.class_desc()
            return desc
        if tc != TC_CLASSDESC:
            raise JavaSerError("expected class desc, got 0x%02x at %d" % (tc, self.pos - 1))
        name = self.utf()
        suid = self.i64()
        desc = JClassDesc(name=name, serial_version_uid=suid, flags=0, fields=[])
        self.new_handle(desc)
        desc.flags = self.u8()
        nfields = self.u16()
        for _ in range(nfields):
            code = chr(self.u8())
            fname = self.utf()
            cname = None
            if code in ("L", "["):
                cname = self.content()          # TC_STRING or TC_REFERENCE
                if not isinstance(cname, str):
                    raise JavaSerError("field class name not a string")
            elif code not in PRIM:
                raise JavaSerError("bad field type code %r" % code)
            desc.fields.append(JField(fname, code, cname))
        desc.annotations = self.annotation()
        desc.super_desc = self.class_desc()
        return desc

    def annotation(self) -> list:
        out = []
        while True:
            tc = self.u8()
            if tc == TC_ENDBLOCKDATA:
                return out
            out.append(self.content(tc))

    def object(self) -> JObject:
        desc = self.class_desc()
        if desc is None:
            raise JavaSerError("object with null class desc")
        obj = JObject(classname=desc.name, desc=desc)
        self.new_handle(obj)
        if desc.is_externalizable:
            if desc.flags & SC_BLOCK_DATA:
                obj.annotations.append(self.annotation())
            else:
                raise JavaSerError("externalizable protocol v1 not supported (%s)" % desc.name)
            _unpack_known(obj)
            return obj
        for d in desc.chain:
            for f in d.fields:
                if f.typecode in PRIM:
                    obj.fields[f.name] = self.prim(f.typecode)
                else:
                    obj.fields[f.name] = self.content()
            if d.has_write_method:
                obj.annotations.append(self.annotation())
        _unpack_known(obj)
        return obj

    def array(self) -> list:
        desc = self.class_desc()
        if desc is None:
            raise JavaSerError("array with null class desc")
        n = self.i32()
        if n < 0:
            raise JavaSerError("negative array length")
        arr = JArray(desc.name, [])
        self.new_handle(arr)
        code = desc.name[1] if desc.name.startswith("[") and len(desc.name) > 1 else "L"
        if code in PRIM:
            fmt, size = PRIM[code]
            self.need(n * size)
            vals = list(struct.unpack_from(">%d%s" % (n, fmt), self.buf, self.pos))
            self.pos += n * size
            if code == "C":
                vals = [chr(v) for v in vals]
            arr.items = vals
        else:
            arr.items = [self.content() for _ in range(n)]
        return arr.items if code in PRIM or True else arr

    def enum(self) -> JEnum:
        desc = self.class_desc()
        e = JEnum(desc.name if desc else "?", "")
        self.new_handle(e)
        name = self.content()
        if not isinstance(name, str):
            raise JavaSerError("enum constant name not a string")
        e.name = name
        return e


def _decode_mutf8(b: bytes) -> str:
    try:
        return b.decode("utf-8")
    except UnicodeDecodeError:
        # modified UTF-8: NUL as C0 80 and surrogates encoded separately
        return b.replace(b"\xc0\x80", b"\x00").decode("utf-8", "replace")


# ---------------------------------------------------------------------------
# unpacking of well-known JDK classes
# ---------------------------------------------------------------------------
def _unpack_known(obj: JObject) -> None:
    n = obj.classname
    ann = obj.annotations
    try:
        if n in ("java.util.ArrayList", "java.util.LinkedList", "java.util.Vector",
                 "java.util.ArrayDeque", "java.util.concurrent.CopyOnWriteArrayList"):
            items = [x for x in ann[-1] if not isinstance(x, bytes)] if ann else []
            if n == "java.util.Vector":
                items = obj.fields.get("elementData") or []
                items = items[: obj.fields.get("elementCount", len(items))]
            obj.value = items
        elif n in ("java.util.HashSet", "java.util.LinkedHashSet", "java.util.TreeSet"):
            obj.value = [x for x in ann[-1] if not isinstance(x, bytes)] if ann else []
        elif n in ("java.util.HashMap", "java.util.LinkedHashMap", "java.util.Hashtable",
                   "java.util.TreeMap", "java.util.concurrent.ConcurrentHashMap",
                   "java.util.Properties"):
            objs = [x for x in ann[-1] if not isinstance(x, bytes)] if ann else []
            obj.value = {_key(objs[i]): objs[i + 1] for i in range(0, len(objs) - 1, 2)}
        elif n in ("java.util.Date", "java.sql.Timestamp", "java.sql.Date"):
            blocks = [x for x in ann[-1] if isinstance(x, bytes)] if ann else []
            if blocks and len(blocks[0]) >= 8:
                ms = struct.unpack(">q", blocks[0][:8])[0]
                obj.value = dt.datetime.fromtimestamp(ms / 1000.0, tz=dt.timezone.utc).replace(tzinfo=None).isoformat(sep=" ", timespec="milliseconds")
        elif n in ("java.lang.Integer", "java.lang.Long", "java.lang.Short", "java.lang.Byte",
                   "java.lang.Double", "java.lang.Float", "java.lang.Boolean", "java.lang.Character"):
            obj.value = obj.fields.get("value")
        elif n == "java.lang.String":
            obj.value = obj.fields.get("value")
        elif n == "java.math.BigDecimal":
            iv = obj.fields.get("intVal")
            scale = obj.fields.get("scale", 0)
            mag = iv.fields.get("magnitude") if isinstance(iv, JObject) else None
            if isinstance(mag, list):
                num = int.from_bytes(bytes((x & 0xFF) for x in mag), "big", signed=False)
                if isinstance(iv, JObject) and iv.fields.get("signum", 1) < 0:
                    num = -num
                obj.value = num / (10 ** scale) if scale else num
        elif n == "java.math.BigInteger":
            mag = obj.fields.get("magnitude")
            if isinstance(mag, list):
                num = int.from_bytes(bytes((x & 0xFF) for x in mag), "big", signed=False)
                obj.value = -num if obj.fields.get("signum", 1) < 0 else num
        elif n == "java.util.UUID":
            obj.value = "%016x%016x" % (obj.fields.get("mostSigBits", 0) & (2**64 - 1),
                                        obj.fields.get("leastSigBits", 0) & (2**64 - 1))
    except Exception:   # unpacking is best effort; raw fields stay available
        obj.value = None


def _key(k):
    if isinstance(k, JEnum):
        return k.name
    if isinstance(k, JObject) and k.value is not None and not isinstance(k.value, (list, dict)):
        return k.value
    if isinstance(k, (str, int, float, bool)) or k is None:
        return k
    return repr(k)


# ---------------------------------------------------------------------------
# public API
# ---------------------------------------------------------------------------
def loads(buf: bytes, pos: int = 0, all_contents: bool = False):
    """Parse one serialized stream starting at ``pos`` (expects the AC ED 00 05 header).

    Returns (value, end_pos). With all_contents=True returns (list_of_values, end_pos)
    reading contents until the buffer ends or a parse error occurs after the first.
    """
    r = Reader(buf, pos)
    r.stream_header()
    first = r.content()
    if not all_contents:
        return first, r.pos
    vals = [first]
    while r.pos < len(buf):
        save = r.pos
        try:
            vals.append(r.content())
        except JavaSerError:
            r.pos = save
            break
    return vals, r.pos


def scan(buf: bytes, start: int = 0, limit: Optional[int] = None) -> Iterator[tuple[int, int, Any, Optional[str]]]:
    """Yield (offset, end, value_or_None, error) for every stream magic found in ``buf``."""
    pos = start
    end_limit = len(buf) if limit is None else limit
    while True:
        i = buf.find(MAGIC_BYTES, pos, end_limit)
        if i < 0:
            return
        try:
            val, end = loads(buf, i)
            yield i, end, val, None
            pos = max(end, i + 4)
        except JavaSerError as e:
            yield i, i + 4, None, str(e)
            pos = i + 4


def to_plain(v, depth: int = 0, max_depth: int = 40):
    """Convert parsed values into JSON-friendly Python (dicts/lists/str/num)."""
    if depth > max_depth:
        return "<max depth>"
    if v is None or isinstance(v, (bool, int, float, str)):
        return v
    if isinstance(v, bytes):
        return {"__bytes_hex__": v.hex()}
    if isinstance(v, JEnum):
        return v.name
    if isinstance(v, JClass):
        return {"__class__": v.name}
    if isinstance(v, JClassDesc):
        return {"__classdesc__": v.name}
    if isinstance(v, list):
        return [to_plain(x, depth + 1, max_depth) for x in v]
    if isinstance(v, dict):
        return {str(k): to_plain(x, depth + 1, max_depth) for k, x in v.items()}
    if isinstance(v, JArray):
        return [to_plain(x, depth + 1, max_depth) for x in v.items]
    if isinstance(v, JObject):
        if v.value is not None:
            return to_plain(v.value, depth + 1, max_depth)
        out = {"__class__": v.classname}
        for k, x in v.fields.items():
            out[k] = to_plain(x, depth + 1, max_depth)
        if v.annotations:
            ann = [to_plain(a, depth + 1, max_depth) for a in v.annotations]
            if any(a for a in ann):
                out["__writeObject__"] = ann
        return out
    return repr(v)
