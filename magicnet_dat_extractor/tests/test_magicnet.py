"""Regression tests for the MagIC Net decoder on a synthetic database written in the
real FastObjects record layout (header, offset table, string/ref/blob encodings)."""
import json
import os
import struct

import extract_dat
import fo_layout
import fo_magicnet as M
import fo_records

HERE = os.path.dirname(os.path.abspath(__file__))


def s16(text):
    if text is None:
        return b"\x04\x00\xfd\xfe\x00\xff"
    raw = text.encode("utf-16-le")
    return struct.pack("<H", len(raw) + 4) + b"\xfd\x01" + raw + b"\x00\xff"


def nn(x):
    return "NN%d" % struct.unpack("<Q", struct.pack("<d", x))[0]


def ref(objnum, cid, recid=0):
    return struct.pack("<IQH", recid, objnum, cid) if objnum else b"\x00" * 14


def refs(items):
    return struct.pack("<I", len(items)) + b"".join(ref(o, c) for o, c in items)


def body_of(fixed, members):
    k = len(members) + 1
    off = 4 * k + len(fixed)
    table = []
    for m in members:
        table.append(off)
        off += len(m)
    table.append(off)
    return b"".join(struct.pack("<I", t) for t in table) + fixed + b"".join(members)


class Builder:
    def __init__(self):
        self.out = bytearray()
        self.next_obj = 100
        self.next_rec = 1000

    def add(self, cid, body, version=1):
        objnum = self.next_obj
        self.next_obj += 1
        recid = self.next_rec
        self.next_rec += 3
        ln = len(body) + 12
        hdr = struct.pack("<QIHIHHHH", recid, ln, 0x5400 | (objnum & 0xFF), objnum, 0, cid, version, 0)
        rec = hdr + body
        pad = (16 - len(rec) % 16) % 16
        self.out += rec + b"F" * pad
        return objnum


def build_db(tmp_path):
    b = Builder()
    ms = lambda d: struct.pack("<q", d)
    T0 = 1735981895713          # 2025-01-04 09:11:35.713 UTC
    p_pos = b.add(138, body_of(b"\xe8\x03\x00\x00" + b"\x00" * 17, [s16("TTRA1"), s16("TTRA1"), s16("POSITION"), s16(None)]))
    p_vol = b.add(138, body_of(b"\xe8\x03\x00\x00" + b"\x00" * 17, [s16(nn(20.0)), s16(nn(20.0)), s16("VOLUME"), s16(None)]))
    sample = b.add(135, body_of(b"\x01" + ref(0, 0) + b"\x00" * 11 + ref(p_pos, 138) + ref(p_vol, 138) + ref(0, 0) * 11,
                                [s16("STANDARD1_1"), s16("ASN1230018"), s16(""), s16(""), s16("")]))
    timing = b.add(133, body_of(b"\x00" * 17, [s16(nn(13.266666666666667)), s16(nn(13.3))]))
    method = b.add(180, body_of(ref(0, 0) + ms(T0 - 100000) + b"\x00" * 9 + ref(0, 0),
                                [s16("PHOSPHATE METHOD"), s16("m-guid-1"), s16("author"), s16("Author Name"),
                                 s16("comment A"), s16("comment B"), s16(""), refs([])]))
    r1 = b.add(242, body_of(b"\xe8\x03\x00\x00\x02\x00\x00\x00\x0b\x00\x00\x00" + b"\x00" * 5 + b"\xff\xff\xff\xff",
                            [s16(nn(5.131666)), s16(nn(5.13)), s16(None), s16(None), s16("min"),
                             s16("RS.PHOSPHATE.PHOSPHATE.START"), s16("$"), s16("!!"), s16("!!"), refs([])]))
    r2 = b.add(242, body_of(b"\xe8\x03\x00\x00\x00\x00\x00\x00\x0b\x00\x00\x00" + b"\x00" * 5 + b"\xff\xff\xff\xff",
                            [s16(nn(12.5)), s16(nn(12.5)), s16(None), s16(None), s16("mg/L"),
                             s16("RS.PHOSPHATE.PHOSPHATE.CONC"), s16("$"), s16("!!"), s16("!!"), refs([])]))
    pts = [b.add(110, struct.pack("<dd", 1.0 * i, 10.0 * i)) for i in range(1, 10)]
    peak = b.add(219, struct.pack("<II", 3263, 3078) + struct.pack("<d", 3587255.0) + struct.pack("<I", 4047)
                 + struct.pack("<ddd", 1.5, 2.5, 3.5) + struct.pack("<I", 0) + b"".join(ref(p, 110) for p in pts) + b"\x01")
    link = b.add(130, b"\x00\x00\x00\x00" + ref(peak, 219))
    rset = b.add(234, body_of(ref(link, 130) + ref(r1, 242) + ref(r2, 242) + ref(0, 0) * 3,
                              [s16("BB"), s16("PHOSPHATE.PHOSPHATE"), s16(""), refs([])]))
    analysis = b.add(210, body_of(b"\x01" + b"\x00" * 17 + ref(0, 0) * 8, [s16("PHOSPHATE"), refs([(rset, 234)])]))
    hist = b.add(164, body_of(ms(T0 + 3 * 86400000), [s16("aman"), s16("Aman M"), s16("INTEGRATION DONE"),
                                                       s16("Determination modified"), s16("MagIC Net 3.3 - 130")]))
    review = b.add(236, body_of(ms(T0 + 4 * 86400000) + b"\xc0\x1f\x2e\x01\x01\x00",
                                [s16("suraj"), s16("Suraj R"), s16("PC01"), s16("Review"), s16("DATA REVIEWED")]))

    def det(version, guid):
        fixed = struct.pack("<8I", 0, 3, 1000, 3 if version == 0 else 0, 8000, 796, 1, version) + b"\x00" * 16 \
            + ms(T0) + struct.pack("<I", 65536)
        fixed += ref(timing, 133) + ref(sample, 135) + ref(0, 0) + ref(0, 0) + ref(0, 0) + ref(method, 180) \
            + (ref(hist, 164) if version == 2 else ref(0, 0)) + ref(0, 0)
        members = [s16(guid), s16(None), s16(guid), s16("628660"), s16(guid), s16(None), s16("MagIC Net 3.3 - 130"),
                   s16(None), s16("127.0.0.1"), s16("Magic Net 2025"), s16("PC01"), s16("aman"), s16("Aman M"),
                   s16(""), s16("Main group"), refs([(analysis, 210)]),
                   refs([]), refs([]), refs([]), refs([]), refs([(review, 236)] if version == 2 else []),
                   refs([]), refs([])]
        return b.add(226, body_of(fixed, members), version=4)

    d0 = det(0, "guid-A")
    d2 = det(2, "guid-A")
    d1 = det(1, "guid-B")
    db_dir = tmp_path / "Magic Net Test"
    db_dir.mkdir()
    (db_dir / "objects.dat").write_bytes(bytes(b.out) + b"\x00" * 4096)
    (db_dir / "DBInfo").write_text("DBVersion=33\nProgID=200\n")
    return db_dir, {"d0": d0, "d2": d2, "d1": d1, "sample": sample, "r1": r1}


def test_record_walker_and_layout(tmp_path):
    db_dir, ids = build_db(tmp_path)
    recs = list(fo_records.iter_records(str(db_dir / "objects.dat")))
    assert len(recs) == 25
    assert {r.class_id for r in recs} >= {226, 180, 135, 138, 210, 234, 242, 219, 110, 130, 164, 236, 133}
    det = [r for r in recs if r.objnum == ids["d2"]][0]
    body = fo_layout.parse_body(det.body, 10000, {r.class_id for r in recs})
    assert body.table[0] == 4 * 24 + 48 + 8 + 4 + 14 * 8
    strs = [v for k, v in body.members if k == "str"]
    assert strs[0] == "guid-A" and strs[11] == "aman" and strs[1] is None
    kinds = [k for k, v in body.members]
    assert kinds.count("refs") == 8
    assert fo_layout.nn_number(nn(13.3)) == 13.3


def test_decoder_tables(tmp_path):
    db_dir, ids = build_db(tmp_path)
    db = M.MagicNetDB(str(db_dir / "objects.dat"))
    assert db.record_count == 25 and db.class_counts[226] == 3
    dets = list(M.iter_determinations(db))
    M.mark_latest(dets)
    assert len(dets) == 3
    latest = {d["guid"]: d for d in dets if d["is_latest"]}
    assert set(latest) == {"guid-A", "guid-B"}
    a = latest["guid-A"]
    assert a["version"] == 2 and a["determination_number"] == 8000
    assert a["start_time"] == "2025-01-04 09:11:35.713"
    assert a["method_name"] == "PHOSPHATE METHOD" and a["method_author_login"] == "author"
    assert a["sample_ident"] == "STANDARD1_1" and a["sample_str2"] == "ASN1230018"
    assert a["run_time_display"] == 13.3
    assert {p["name"]: p["value"] for p in a["_props"]} == {"POSITION": "TTRA1", "VOLUME": 20.0}
    assert a["analyses"] == "PHOSPHATE" and a["result_count"] == 2
    t = M.tables(dets)
    res = [r for r in t["Results"] if r["det_objnum"] == a["det_objnum"]]
    assert [r["variable"] for r in res] == ["RS.PHOSPHATE.PHOSPHATE.START", "RS.PHOSPHATE.PHOSPHATE.CONC"]
    assert abs(res[0]["value"] - 5.131666) < 1e-9 and res[0]["unit"] == "min" and res[0]["decimals"] == 2
    assert res[1]["unit"] == "mg/L" and res[1]["display_value"] == 12.5
    pk = [p for p in t["Peaks"] if p["det_objnum"] == a["det_objnum"]][0]
    assert pk["points"] == 9 and pk["p3_x"] == 3.0 and pk["p9_y"] == 90.0 and pk["u32_a"] == 3263
    hist = [h for h in t["History"] if h["det_objnum"] == a["det_objnum"]]
    assert [h["action"] for h in hist] == ["INTEGRATION DONE", "DATA REVIEWED"]
    assert hist[1]["client_pc"] == "PC01" and hist[0]["timestamp"].startswith("2025-01-07")
    assert t["Samples"][0]["POSITION"] == "TTRA1"
    assert M.methods_table(dets)[0]["determinations"] == 3
    db.close()


def test_cli_decode_and_filters(tmp_path):
    db_dir, ids = build_db(tmp_path)
    res = tmp_path / "out"
    rc = extract_dat.main(["--db-dir", str(db_dir), "--res-dir", str(res)])
    assert rc == 0
    for name in ("Determinations", "Samples", "Analyses", "Results", "Peaks", "History", "Methods"):
        assert (res / (name + ".csv")).exists() and (res / (name + ".json")).exists()
    summary = json.loads((res / "_extract_summary.json").read_text())
    assert summary["tables"]["Determinations"]["rows"] == 3 and summary["tables"]["Results"]["rows"] == 6
    rc = extract_dat.main(["--db-dir", str(db_dir), "--res-dir", str(tmp_path / "o2"), "--latest-only",
                           "--from-date", "2025-01-01", "--to-date", "2025-01-31", "--table", "Results"])
    assert rc == 0
    rows = json.loads((tmp_path / "o2" / "Results.json").read_text())
    assert len(rows) == 4 and all(r["is_latest"] for r in rows)
    rc = extract_dat.main(["--db-dir", str(db_dir), "--res-dir", str(tmp_path / "o3"), "--from-date", "2026-01-01"])
    assert rc == 0
    assert json.loads((tmp_path / "o3" / "_extract_summary.json").read_text())["determinations_exported"] == 0
