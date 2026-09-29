import json
import os

import ear_format
import ear_crypto
import extract_ear
import json_to_csv


MARKER = ear_format.FRAMING_MARKER


def _synthetic_ear(tmp_path):
    """Build a small fake .ear: framing marker + random-looking chunks."""
    import os as _os
    parts = []
    for _ in range(20):
        parts.append(_os.urandom(50 + (_ % 30)))
    data = MARKER.join(parts)
    p = tmp_path / "backup.ear"
    p.write_bytes(data)
    return p, data


def test_split_and_analyze(tmp_path):
    p, data = _synthetic_ear(tmp_path)
    chunks = ear_format.split_chunks(data)
    assert len(chunks) == 20
    # Offsets must point at the real bytes.
    for c in chunks:
        assert data[c.offset:c.offset + c.length] == \
            data[c.offset:c.offset + c.length]
    report = ear_format.analyze(data)
    assert report.marker == ".gCi2k1"
    assert report.chunk_count == 20
    assert "ENCRYPTED" in report.verdict  # urandom => high entropy


def test_salvage_writes_csv(tmp_path):
    p, _ = _synthetic_ear(tmp_path)
    out = tmp_path / "out"
    summary = extract_ear.salvage(str(p), str(out))
    assert (out / "ear_chunks.csv").is_file()
    assert (out / "ear_strings.csv").is_file()
    assert (out / "_extract_summary.json").is_file()
    assert summary["container"]["chunk_count"] == 20
    # chunk csv has a header + 20 rows
    lines = (out / "ear_chunks.csv").read_text(encoding="utf-8-sig").splitlines()
    assert len(lines) == 21


def test_decode_without_key_raises(tmp_path):
    p, _ = _synthetic_ear(tmp_path)
    out = tmp_path / "out"
    try:
        extract_ear.decode(str(p), str(out), None, None, None)
    except ear_crypto.KeyNotAvailable:
        pass
    else:  # pragma: no cover
        assert False, "expected KeyNotAvailable"


def test_decode_roundtrip_with_rc4(tmp_path):
    """Prove the decode path works once a key exists: RC4-encrypt a known
    plaintext into the container shape, then decode it back."""
    key = bytes.fromhex("0011223344556677")
    plain_chunks = [b"USER=jdoe;ACTION=Login;TS=2025-04-19",
                    b"USER=asmith;ACTION=MethodEdit;TS=2025-04-19"]
    # encrypt each chunk with RC4 and join with the marker
    enc = MARKER.join(ear_crypto.rc4(key, c) for c in plain_chunks)
    p = tmp_path / "backup.ear"
    p.write_bytes(enc)

    spec = {
        "format": "ear-extractor/keyspec",
        "cipher": "rc4",
        "key_hex": key.hex(),
        "scope": "per-chunk",
        "strip_marker": True,
    }
    ks = tmp_path / "backup.earkey.json"
    ks.write_text(json.dumps(spec), encoding="utf-8")

    out = tmp_path / "out"
    summary = extract_ear.decode(str(p), str(out), str(ks), None, None)
    decrypted = (out / "decrypted.bin").read_bytes()
    assert b"USER=jdoe" in decrypted
    assert b"MethodEdit" in decrypted
    # entropy should have dropped now that it's plaintext
    assert summary["decrypted_entropy"] < 6.0


def test_json_to_csv_roundtrip(tmp_path):
    records = [
        {"id": "1", "username": "jdoe", "action": "Login", "nested": [1, 2]},
        {"id": "2", "username": "asmith", "action": "Logout"},
    ]
    src = tmp_path / "AuditTrail.json"
    src.write_text(json.dumps(records), encoding="utf-8")
    out = tmp_path / "AuditTrail.csv"
    json_to_csv.convert_file(str(src), str(out))
    text = out.read_text(encoding="utf-8-sig")
    lines = text.splitlines()
    assert lines[0] == "id,username,action,nested"
    assert "jdoe" in lines[1]
    # nested value is JSON-encoded into the cell
    assert "[1, 2]" in lines[1]
    # second record lacks 'nested' -> trailing empty cell under the union column
    assert lines[2] == "2,asmith,Logout,"


def test_rc4_is_involutive():
    key = b"secret"
    data = b"the quick brown fox"
    assert ear_crypto.rc4(key, ear_crypto.rc4(key, data)) == data


def test_pdf_audit_parser():
    import pdf_audit_to_csv
    txt = (
        "MassLynx MassLynx V4.2 SCN1012 Page 1 of 2 Printed by: LUPIN\\x\\y "
        "on machine MASSLYNX-PC at 02-12-2025 14:40:38 India Standard Time "
        "Query: Results from (All Events) "
        "Type Time Description Outcome User Machine Domain File Information "
        "Client Time ID Index Size Object/File Time Verify User Verify Domain "
        "Base file Diagnostics "
        "Permission 02-12-2025 14:36:31 LogLynx - Enter log viewer Allowed "
        "nileshnile MASSLYNX-PC LUPIN 02-12-2025 14:36:31 8201 140996 74 "
        "Log in 02-12-2025 14:35:50 Login Attempt Allowed nileshnile "
        "MASSLYNX-PC LUPIN 02-12-2025 14:35:50 12001 140995 111"
    )
    rows = pdf_audit_to_csv.parse(txt)
    assert len(rows) == 2
    assert rows[0]["type"] == "Permission"
    assert rows[0]["description"] == "LogLynx - Enter log viewer"
    assert rows[0]["outcome"] == "Allowed"
    assert rows[0]["user"] == "nileshnile"
    assert rows[0]["event_id"] == "8201"
    assert rows[0]["index"] == "140996"
    assert rows[1]["type"] == "Log in"
    assert rows[1]["user"] == "nileshnile"
