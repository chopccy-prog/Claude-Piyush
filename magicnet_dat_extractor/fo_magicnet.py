"""MagIC Net 3.3 determination database decoder (built-in layout, no dictionary needed).

Object model of the IC_Determination database, mapped from the real file
(class ids are the FastObjects schema ids of MagIC Net 3.3; see FINDINGS.md):

    226 Determination      one record per determination VERSION (0 = acquired,
                           1 = evaluated, 2 = re-integrated/reviewed); strings:
                           guid, ..., program version, client ip, database name,
                           client pc, user login, user full name, user group;
                           refs: 133 timing, 135 sample, 134 statement results,
                           111 device list, 180 method info, 164 modification
                           entry; member ref arrays: analyses (210), reviews (236)
    180 Method info        name, guid, author login/full name, 3 comment lines, saved date
    135 Sample             ident + 4 strings; refs to 138 sample properties
    138 Sample property    value, display value, name (POSITION, VOLUME, DILUTION,
                           AMOUNT, INFO1, ...), unit
    133 Timing             two NN numbers (run time in minutes as stored/displayed)
    210 Analysis           name (e.g. PHOSPHATE BINDING CAPACITY, PRESSURE); refs:
                           189 curve, 115 calibration/method link; member: result sets
    234 Result set         code, name (analysis.component); refs: 130 peak link, 242 results
    242 Result             value, display value, low limit, high limit, unit,
                           variable name (RS.<analysis>.<component>.<quantity>), flags
    130 -> 219 Peak        peak metrics and 9 (time, signal) points (class 110)
    164 History entry      date, user login, full name, action, description, program
    236 Review entry       date, user login, full name, pc, category, action
    189 Curve              units, scaling, gzip'ed big-endian sample stream

Numbers are stored as strings "NN<ieee754 bits>" and decoded to floats.
"""
from __future__ import annotations

import array
import datetime as dt
import mmap
import os
import struct
from typing import Iterator, Optional

import fo_fields as F
import fo_layout as L
import fo_records as R

CLASS = {
    "determination": 226, "method": 180, "sample": 135, "sample_prop": 138, "timing": 133,
    "analysis": 210, "result_set": 234, "result": 242, "peak_link": 130, "peak": 219,
    "point": 110, "history": 164, "review": 236, "curve": 189, "statement_results": 134,
    "statement_result": 125, "devices": 111,
}


def _strs(body: L.Body) -> list:
    return [v for k, v in body.members if k == "str"]


def _members_of_kind(body: L.Body, kind: str) -> list:
    return [v for k, v in body.members if k == kind]


def _fixed_refs(body: L.Body) -> list:
    return [v for k, o, s, v in body.fixed_tokens if k == "ref" and v[0]]


def _u32(b: bytes, off: int) -> Optional[int]:
    return struct.unpack_from("<I", b, off)[0] if off + 4 <= len(b) else None


def _f64(b: bytes, off: int) -> Optional[float]:
    return struct.unpack_from("<d", b, off)[0] if off + 8 <= len(b) else None


def _date(b: bytes, off: int) -> Optional[str]:
    r = F.read_date(b, off)
    return r[0] if r else None


def _ref_at(db, b: bytes, off: int, want_cid: Optional[int] = None) -> Optional[int]:
    """Read the reference at a known offset; None when null or not of the wanted class."""
    if off + 14 > len(b):
        return None
    recid, objnum, cid = struct.unpack_from("<IQH", b, off)
    if objnum == 0 or objnum > db.max_objnum:
        return None
    if want_cid is not None and cid != want_cid:
        return None
    if db.class_of(objnum) != cid:
        return None
    return objnum


def _refs_at(db, b: bytes, off: int, count: int) -> list:
    out = []
    for i in range(count):
        o = off + 14 * i
        if o + 14 > len(b):
            break
        recid, objnum, cid = struct.unpack_from("<IQH", b, o)
        out.append((objnum, cid) if objnum and db.class_of(objnum) == cid else None)
    return out


class MagicNetDB:
    """Random access to the objects of one MagIC Net database folder."""

    def __init__(self, objects_dat: str):
        self.path = objects_dat
        self.size = os.path.getsize(objects_dat)
        self._f = open(objects_dat, "rb")
        self.mm = mmap.mmap(self._f.fileno(), 0, access=mmap.ACCESS_READ)
        self.class_counts: dict = {}
        self.max_objnum = 0
        self.max_recid = 0
        entries = []
        for r in R.iter_records(objects_dat, want_body=False):
            entries.append((r.objnum, r.class_id, r.offset))
            self.class_counts[r.class_id] = self.class_counts.get(r.class_id, 0) + 1
            if r.objnum > self.max_objnum:
                self.max_objnum = r.objnum
            if r.oid > self.max_recid:
                self.max_recid = r.oid
        self.class_ids = set(self.class_counts)
        self.obj_cid = array.array("H", bytes(2 * (self.max_objnum + 1)))
        self.obj_off = array.array("Q", bytes(8 * (self.max_objnum + 1)))
        for objnum, cid, off in entries:
            self.obj_cid[objnum] = cid
            self.obj_off[objnum] = off
        self.record_count = len(entries)
        self._limit = max(self.max_objnum, self.max_recid)
        self._cache: dict = {}

    def close(self):
        self.mm.close()
        self._f.close()

    def record(self, objnum: int) -> Optional[R.Record]:
        if objnum <= 0 or objnum > self.max_objnum or self.obj_cid[objnum] == 0:
            return None
        off = self.obj_off[objnum]
        h = R.parse_header(self.mm, off)
        if h is None:
            return None
        oid, ln, chk, on, z1, cid, ver = h
        return R.Record(off, oid, ln, chk, on, z1, cid, ver, bytes(self.mm[off + 26:off + 14 + ln]))

    def body(self, objnum: int) -> Optional[L.Body]:
        if objnum in self._cache:
            return self._cache[objnum]
        r = self.record(objnum)
        b = L.parse_body(r.body, self._limit, self.class_ids) if r else None
        if len(self._cache) > 200000:
            self._cache.clear()
        self._cache[objnum] = b
        return b

    def class_of(self, objnum: int) -> int:
        return self.obj_cid[objnum] if 0 < objnum <= self.max_objnum else 0

    def iter_class(self, class_id: int) -> Iterator[R.Record]:
        return R.iter_records(self.path, class_ids={class_id})

    def child(self, body: L.Body, class_id: int) -> Optional[int]:
        for objnum, cid, recid in _fixed_refs(body):
            if cid == class_id:
                return objnum
        return None

    def children(self, body: L.Body, class_id: int) -> list:
        out = [objnum for objnum, cid, recid in _fixed_refs(body) if cid == class_id]
        for refs in _members_of_kind(body, "refs"):
            out += [x[0] for x in refs if x and x[1] == class_id]
        return out


# ----------------------------------------------------------------------------
# decoders per class
# ----------------------------------------------------------------------------
def decode_method(db: MagicNetDB, objnum: Optional[int]) -> dict:
    out = {"method_name": None, "method_guid": None, "method_author_login": None,
           "method_author_name": None, "method_comment": None, "method_saved": None}
    if not objnum:
        return out
    b = db.body(objnum)
    if not b:
        return out
    s = _strs(b)
    out["method_name"] = s[0] if len(s) > 0 else None
    out["method_guid"] = s[1] if len(s) > 1 else None
    out["method_author_login"] = s[2] if len(s) > 2 else None
    out["method_author_name"] = s[3] if len(s) > 3 else None
    out["method_comment"] = " | ".join(x for x in s[4:7] if x) if len(s) > 4 else None
    out["method_saved"] = _date(b.fixed, 14)
    return out


def decode_sample(db: MagicNetDB, objnum: Optional[int]) -> tuple:
    """Returns (sample dict, properties list of dicts)."""
    out = {"sample_ident": None, "sample_str2": None, "sample_str3": None,
           "sample_str4": None, "sample_str5": None}
    props = []
    if not objnum:
        return out, props
    b = db.body(objnum)
    if not b:
        return out, props
    s = _strs(b)
    for i, key in enumerate(("sample_ident", "sample_str2", "sample_str3", "sample_str4", "sample_str5")):
        out[key] = s[i] if i < len(s) else None
    prop_refs = [x[0] for x in _refs_at(db, b.fixed, 26, 13) if x and x[1] == CLASS["sample_prop"]]
    if not prop_refs:
        prop_refs = db.children(b, CLASS["sample_prop"])
    for pn in prop_refs:
        pb = db.body(pn)
        if not pb:
            continue
        ps = _strs(pb)
        props.append({"name": ps[2] if len(ps) > 2 else None,
                      "value": ps[0] if len(ps) > 0 else None,
                      "display": ps[1] if len(ps) > 1 else None,
                      "unit": ps[3] if len(ps) > 3 else None,
                      "objnum": pn})
    return out, props


def decode_timing(db: MagicNetDB, objnum: Optional[int]) -> dict:
    out = {"run_time_value": None, "run_time_display": None}
    if objnum:
        b = db.body(objnum)
        if b:
            s = _strs(b)
            out["run_time_value"] = s[0] if s else None
            out["run_time_display"] = s[1] if len(s) > 1 else None
    return out


def decode_result(db: MagicNetDB, objnum: int) -> Optional[dict]:
    b = db.body(objnum)
    if not b:
        return None
    s = _strs(b)
    fx = b.fixed
    return {"result_objnum": objnum,
            "variable": s[5] if len(s) > 5 else None,
            "value": s[0] if len(s) > 0 else None,
            "display_value": s[1] if len(s) > 1 else None,
            "unit": s[4] if len(s) > 4 else None,
            "limit_low": s[2] if len(s) > 2 else None,
            "limit_high": s[3] if len(s) > 3 else None,
            "flag1": s[6] if len(s) > 6 else None,
            "flag2": s[7] if len(s) > 7 else None,
            "flag3": s[8] if len(s) > 8 else None,
            "decimals": _u32(fx, 4), "type_code": _u32(fx, 8)}


def decode_peak(db: MagicNetDB, link_objnum: int) -> Optional[dict]:
    lb = db.body(link_objnum)
    if not lb:
        return None
    pk = db.child(lb, CLASS["peak"])
    if not pk:
        return None
    b = db.body(pk)
    if not b:
        return None
    fx = b.fixed
    out = {"peak_objnum": pk, "u32_a": _u32(fx, 0), "u32_b": _u32(fx, 4), "d1": _f64(fx, 8),
           "u32_c": _u32(fx, 16), "d2": _f64(fx, 20), "d3": _f64(fx, 28), "d4": _f64(fx, 36)}
    pts = []
    point_refs = [x[0] for x in _refs_at(db, fx, 44, 9) if x and x[1] == CLASS["point"]]
    if not point_refs:
        point_refs = [objnum for objnum, cid, recid in _fixed_refs(b) if cid == CLASS["point"]]
    for objnum in point_refs:
        pb = db.body(objnum)
        if pb and len(pb.fixed) >= 16:
            pts.append((_f64(pb.fixed, 0), _f64(pb.fixed, 8)))
    for i, (x, y) in enumerate(pts, 1):
        out["p%d_x" % i] = x
        out["p%d_y" % i] = y
    out["points"] = len(pts)
    return out


def decode_history(db: MagicNetDB, objnum: int, kind: str) -> Optional[dict]:
    b = db.body(objnum)
    if not b:
        return None
    s = _strs(b)
    if kind == "history":
        return {"timestamp": _date(b.fixed, 0), "user_login": s[0] if s else None,
                "user_fullname": s[1] if len(s) > 1 else None, "client_pc": None,
                "category": s[3] if len(s) > 3 else None, "action": s[2] if len(s) > 2 else None,
                "program_version": s[4] if len(s) > 4 else None, "entry_objnum": objnum}
    return {"timestamp": _date(b.fixed, 0), "user_login": s[0] if s else None,
            "user_fullname": s[1] if len(s) > 1 else None, "client_pc": s[2] if len(s) > 2 else None,
            "category": s[3] if len(s) > 3 else None, "action": s[4] if len(s) > 4 else None,
            "program_version": None, "entry_objnum": objnum}


def decode_determination(db: MagicNetDB, rec: R.Record) -> dict:
    b = L.parse_body(rec.body, db._limit, db.class_ids)
    fx = b.fixed
    s = _strs(b)
    refs = {x[1]: x[0] for x in _refs_at(db, fx, 60, 8) if x}
    if not refs:
        refs = {cid: objnum for objnum, cid, recid in _fixed_refs(b)}
    det = {
        "det_objnum": rec.objnum,
        "det_recid": rec.oid,
        "determination_number": _u32(fx, 16),
        "version": _u32(fx, 28),
        "is_latest": None,
        "status_code": _u32(fx, 12),
        "method_version_id": _u32(fx, 20),
        "field24": _u32(fx, 24),
        "start_time": _date(fx, 48),
        "guid": s[0] if s else None,
        "parent_guid": s[2] if len(s) > 2 else None,
        "database_id": s[3] if len(s) > 3 else None,
        "program_version": s[6] if len(s) > 6 else None,
        "client_ip": s[8] if len(s) > 8 else None,
        "database": s[9] if len(s) > 9 else None,
        "client_pc": s[10] if len(s) > 10 else None,
        "user_login": s[11] if len(s) > 11 else None,
        "user_fullname": s[12] if len(s) > 12 else None,
        "user_group": s[14] if len(s) > 14 else None,
        "comment": s[13] if len(s) > 13 else None,
    }
    det.update(decode_method(db, refs.get(CLASS["method"])))
    sample, props = decode_sample(db, refs.get(CLASS["sample"]))
    det.update(sample)
    det.update(decode_timing(db, refs.get(CLASS["timing"])))
    det["_props"] = props
    det["_analyses"] = []
    det["_history"] = []
    for objnum in db.children(b, CLASS["analysis"]):
        ab = db.body(objnum)
        if not ab:
            continue
        a_refs = {x[1]: x[0] for x in _refs_at(db, ab.fixed, 18, 8) if x}
        a = {"analysis_objnum": objnum, "analysis": (_strs(ab) or [None])[0],
             "curve_objnum": a_refs.get(CLASS["curve"]) or db.child(ab, CLASS["curve"]), "result_sets": []}
        for rs in db.children(ab, CLASS["result_set"]):
            rb = db.body(rs)
            if not rb:
                continue
            rss = _strs(rb)
            rset = {"result_set_objnum": rs, "result_set_code": rss[0] if rss else None,
                    "result_set": rss[1] if len(rss) > 1 else None,
                    "results": [], "peak": None}
            rs_refs = [x for x in _refs_at(db, rb.fixed, 0, len(rb.fixed) // 14) if x]
            if not rs_refs:
                rs_refs = [(objnum2, cid) for objnum2, cid, recid in _fixed_refs(rb)]
            for objnum2, cid in rs_refs:
                if cid == CLASS["result"]:
                    rr = decode_result(db, objnum2)
                    if rr:
                        rset["results"].append(rr)
                elif cid == CLASS["peak_link"]:
                    rset["peak"] = decode_peak(db, objnum2)
            a["result_sets"].append(rset)
        det["_analyses"].append(a)
    if refs.get(CLASS["history"]):
        h = decode_history(db, refs[CLASS["history"]], "history")
        if h:
            det["_history"].append(h)
    for objnum in db.children(b, CLASS["review"]):
        h = decode_history(db, objnum, "review")
        if h:
            det["_history"].append(h)
    det["analyses"] = "; ".join(a["analysis"] or "" for a in det["_analyses"])
    det["result_count"] = sum(len(r["results"]) for a in det["_analyses"] for r in a["result_sets"])
    return det


def iter_determinations(db: MagicNetDB) -> Iterator[dict]:
    for rec in db.iter_class(CLASS["determination"]):
        yield decode_determination(db, rec)


def mark_latest(dets: list) -> None:
    best: dict = {}
    for d in dets:
        key = d["guid"] or d["determination_number"]
        v = d["version"] or 0
        if key not in best or v > best[key][0] or (v == best[key][0] and d["det_recid"] > best[key][1]):
            best[key] = (v, d["det_recid"])
    for d in dets:
        key = d["guid"] or d["determination_number"]
        d["is_latest"] = (d["version"] or 0, d["det_recid"]) == best[key]


# ----------------------------------------------------------------------------
# flat tables
# ----------------------------------------------------------------------------
DET_KEY_FIELDS = ("det_objnum", "determination_number", "version", "is_latest", "guid",
                  "start_time", "method_name", "sample_ident", "user_login")


def tables(dets: list) -> dict:
    """Flatten decoded determinations into row lists per table."""
    det_rows, sample_rows, result_rows, peak_rows, hist_rows, analysis_rows = [], [], [], [], [], []
    for d in dets:
        key = {k: d[k] for k in DET_KEY_FIELDS}
        row = {k: v for k, v in d.items() if not k.startswith("_")}
        for p in d["_props"]:
            if p["name"]:
                row["prop_" + p["name"]] = p["value"]
        det_rows.append(row)
        srow = dict(key)
        srow.update({k: d[k] for k in ("sample_ident", "sample_str2", "sample_str3", "sample_str4", "sample_str5")})
        for p in d["_props"]:
            if p["name"]:
                srow[p["name"]] = p["value"]
                srow[p["name"] + "_display"] = p["display"]
        sample_rows.append(srow)
        for a in d["_analyses"]:
            analysis_rows.append(dict(key, analysis_objnum=a["analysis_objnum"], analysis=a["analysis"],
                                      curve_objnum=a["curve_objnum"], result_sets=len(a["result_sets"]),
                                      results=sum(len(r["results"]) for r in a["result_sets"])))
            for rs in a["result_sets"]:
                for r in rs["results"]:
                    rr = dict(key, analysis=a["analysis"], result_set_code=rs["result_set_code"],
                              result_set=rs["result_set"])
                    rr.update(r)
                    result_rows.append(rr)
                if rs["peak"]:
                    pr = dict(key, analysis=a["analysis"], result_set=rs["result_set"])
                    pr.update(rs["peak"])
                    peak_rows.append(pr)
        for h in d["_history"]:
            hr = dict(key)
            hr.update(h)
            hist_rows.append(hr)
    return {"Determinations": det_rows, "Samples": sample_rows, "Analyses": analysis_rows,
            "Results": result_rows, "Peaks": peak_rows, "History": hist_rows}


def methods_table(dets: list) -> list:
    seen = {}
    for d in dets:
        g = d.get("method_guid")
        if g and g not in seen:
            seen[g] = {k: d[k] for k in ("method_name", "method_guid", "method_author_login",
                                         "method_author_name", "method_comment", "method_saved")}
            seen[g]["determinations"] = 0
        if g:
            seen[g]["determinations"] += 1
    return list(seen.values())
