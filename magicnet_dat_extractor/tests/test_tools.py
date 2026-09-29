"""Tests for the MagIC Net (FastObjects) extractor.

The eventlog tests run against a REAL log copied from a MagIC Net 3.3
installation (samples/eventlog_sample.ptd, IC_Config/ConfigDB backup copy).
The objects.dat tests use a synthetic paged file because the real one is
432 MB and proprietary.
"""
import json
import os
import random
import struct

import extract_dat
import fo_decode
import fo_eventlog
import fo_inspect

HERE = os.path.dirname(os.path.abspath(__file__))
SAMPLE_LOG = os.path.join(os.path.dirname(HERE), "samples", "eventlog_sample.ptd")
PS = 4096


def _fake_db(tmp_path, pages=120, with_spec=False):
    db = tmp_path / "Magic Net 2025"
    (db / "eventlog").mkdir(parents=True)
    (db / "recovery").mkdir()
    rnd = random.Random(7)
    words = ["Determination", "Sample", "Chloride", "Metrohm", "com.metrohm.ic.PeakResult"]
    out = bytearray()
    for i in range(pages):
        if i % 6 == 0:
            out += b"\x00" * PS
            continue
        body = bytearray(b"\x01\x00\x07\x00" + struct.pack("<I", i))
        while len(body) < PS - 64:
            w = rnd.choice(words)
            body += struct.pack("<I", len(w)) + w.encode() + b"\x00"
            body += w.encode("utf-16-le") + b"\x00\x00"
            body += struct.pack("<d", rnd.uniform(0.1, 100.0))
            body += struct.pack("<HBBBBB", 2025, 3, 1 + i % 27, 9, 15, 0)
            body += bytes(rnd.getrandbits(8) for _ in range(12))
        out += (body[:PS - 8] + b"\x00" * PS)[:PS]
    (db / "objects.dat").write_bytes(bytes(out))
    (db / "objects.idx").write_bytes(bytes(rnd.getrandbits(8) for _ in range(16 * 1024)))
    (db / "recovery" / "data0000.rcy").write_bytes(b"\x00" * 4096)
    (db / "DBInfo").write_text("#DBVersion\n#Tue Oct 14 10:25:32 IST 2025\nDBVersion=33\nProgID=200\n")
    with open(SAMPLE_LOG, "rb") as f:
        (db / "eventlog" / "f0000000.ptd").write_bytes(f.read())
    if with_spec:
        spec = {"format": fo_decode.FOSPEC_FORMAT, "page_size": PS,
                "classes": {"Page": {"signature": {"offset": 0, "hex": "01000700"},
                                     "record_length": 8,
                                     "fields": [{"name": "index", "offset": 4, "type": "u32"}]}}}
        (db / "magicnet.fospec.json").write_text(json.dumps(spec))
    return db


# ---------------------------------------------------------------- eventlog

def test_eventlog_real_sample_parses_completely():
    hdr, recs = fo_eventlog.parse(SAMPLE_LOG)
    assert hdr["magic"] == 1234
    assert hdr["record_count"] == 2069
    assert hdr["stale_bytes"] == 134          # backup copy: counter truncated, bytes left
    assert recs[0].kind == "fileinfo"
    assert recs[0].message.endswith(r"IC_Config\ConfigDB\eventlog\f0000000.ptd")
    assert recs[0].timestamp == "2020-09-30 11:46:19"
    kinds = {r.kind for r in recs}
    assert "unknown" not in kinds
    assert hdr["engine_versions"] == ["FastObjects Core 10.0.9.200.0  (Feb 15 2010), MS Visual C++ 8.0 1400"]
    assert hdr["first_timestamp"] == "2020-09-30 11:46:19"
    assert hdr["last_timestamp"] == "2024-06-24 09:00:05"
    opens = [r for r in recs if r.event_label == "database_open"]
    assert opens and opens[-1].counter == 7186214
    # sequence numbers are contiguous
    seqs = [r.seq for r in recs[1:]]
    assert seqs == list(range(1, len(seqs) + 1))


def test_eventlog_include_stale_finds_leftover_records():
    _hdr, recs = fo_eventlog.parse(SAMPLE_LOG, include_stale=True)
    stale = [r for r in recs if r.stale]
    assert len(stale) == 2 and all(r.timestamp for r in stale)


def test_eventlog_csv_roundtrip(tmp_path):
    _hdr, recs = fo_eventlog.parse(SAMPLE_LOG)
    out = tmp_path / "log.csv"
    fo_eventlog.write_csv(recs, str(out))
    text = out.read_text(encoding="utf-8-sig").splitlines()
    assert text[0].split(",")[:4] == ["seq", "timestamp", "kind", "event_label"]
    assert len(text) == len(recs) + 1


def test_eventlog_rejects_other_files(tmp_path):
    p = tmp_path / "x.ptd"
    p.write_bytes(b"\x00" * 64)
    try:
        fo_eventlog.parse(str(p))
    except fo_eventlog.EventLogError:
        return
    raise AssertionError("expected EventLogError")


# ---------------------------------------------------------------- inspector

def test_inspector_detects_page_size_and_plaintext(tmp_path):
    db = _fake_db(tmp_path)
    rep = fo_inspect.scan_file(str(db / "objects.dat"), None, None, 100)
    assert rep["page_size_detection"]["page_size_guess"] == PS
    assert rep["pages_all_zero"] == 20
    assert rep["keyword_hits"]["Chloride"] > 0 and rep["keyword_hits"]["Metrohm"] > 0
    out = fo_inspect.write_outputs(str(db), [rep], str(tmp_path / "insp"), 100)
    f = out["files"][0]
    assert f["verdict"].startswith("PLAINTEXT")
    assert out["dbinfo"]["DBVersion"] == "33"
    classes = (tmp_path / "insp" / "class_candidates.csv").read_text(encoding="utf-8-sig")
    assert "com.metrohm.ic.PeakResult" in classes


def test_inspector_flags_random_index_as_not_plaintext(tmp_path):
    db = _fake_db(tmp_path)
    rep = fo_inspect.scan_file(str(db / "objects.idx"), 4096, None, 100)
    assert rep["sampled_entropy"] > 7.5
    assert not fo_inspect.verdict(rep).startswith("PLAINTEXT")


# ---------------------------------------------------------------- CLI

def test_salvage_mode_writes_eventlog_and_strings(tmp_path):
    db = _fake_db(tmp_path)
    res = tmp_path / "out"
    rc = extract_dat.main(["--db-dir", str(db), "--res-dir", str(res),
                           "--from-date", "2024-01-01", "--to-date", "2024-12-31"])
    assert rc == 0
    for name in ("EventLog.csv", "EventLog.meta.json", "Strings.csv", "_inspect_report.json",
                 "strings_top.csv", "class_candidates.csv", "_extract_summary.json"):
        assert (res / name).exists(), name
    summary = json.loads((res / "_extract_summary.json").read_text())
    assert summary["tables"]["EventLog"]["rows"] > 0
    assert summary["tables"]["Strings"]["rows"] > 0
    # date filter applied: every dated event row is in 2024 (fileinfo row is kept)
    rows = (res / "EventLog.csv").read_text(encoding="utf-8-sig").splitlines()[1:]
    dated = [r.split(",")[1] for r in rows if r.split(",")[2] != "fileinfo"]
    assert dated and all(d.startswith("2024-") for d in dated)


def test_decode_without_spec_explains_and_fails(tmp_path, capsys):
    db = _fake_db(tmp_path)
    rc = extract_dat.main(["--db-dir", str(db), "--res-dir", str(tmp_path / "o"), "--mode", "decode", "--all"])
    assert rc == 3
    assert "fospec" in capsys.readouterr().err


def test_decode_with_spec(tmp_path):
    db = _fake_db(tmp_path, with_spec=True)
    res = tmp_path / "o"
    rc = extract_dat.main(["--db-dir", str(db / "objects.dat"), "--res-dir", str(res), "--mode", "decode", "--all"])
    assert rc == 0
    rows = json.loads((res / "Page.json").read_text())
    assert len(rows) == 100                       # 120 pages minus 20 zero pages
    assert rows[0]["index"] == 1 and rows[0]["_page"] == 1
    assert (res / "Page.csv").exists()
    summary = json.loads((res / "_extract_summary.json").read_text())
    assert summary["tables"]["Page"]["rows"] == 100


def test_spec_validation():
    bad = {"format": fo_decode.FOSPEC_FORMAT, "page_size": 4096,
           "classes": {"X": {"signature": {"hex": "00"}, "record_length": 8,
                             "fields": [{"name": "a", "offset": 0, "type": "nope"}]}}}
    import tempfile
    with tempfile.NamedTemporaryFile("w", suffix=".fospec.json", delete=False) as f:
        json.dump(bad, f)
    try:
        fo_decode.load_spec(f.name)
    except fo_decode.SpecError as e:
        assert "unknown type" in str(e)
    else:
        raise AssertionError("expected SpecError")
    finally:
        os.unlink(f.name)


def test_read_field_types():
    buf = struct.pack("<HBBBBB", 2025, 10, 14, 10, 25, 32) + b"\x00" + struct.pack("<d", 12.5) \
        + struct.pack("<I", 3) + b"abc" + b"h\x00i\x00\x00\x00"
    assert fo_decode.read_field(buf, 0, "date7", "utf-16-le") == "2025-10-14 10:25:32"
    assert fo_decode.read_field(buf, 8, "f64", "utf-16-le") == 12.5
    assert fo_decode.read_field(buf, 16, "lstring", "utf-16-le") == "abc"
    assert fo_decode.read_field(buf, 23, "utf16z", "utf-16-le") == "hi"
    assert fo_decode.read_field(buf, 16, "hex:4", "utf-16-le") == "03000000"
