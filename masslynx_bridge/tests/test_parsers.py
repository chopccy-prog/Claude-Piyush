from masslynx_bridge.parsers import get_parser, fingerprint
from masslynx_bridge.parsers.audit_csv import parse_audit_trail
from masslynx_bridge.parsers.results_csv import parse_results


def test_audit_trail_tab_delimited():
    text = (
        "Date/Time\tUser\tEvent\tDescription\tComputer\n"
        "2025-10-18 09:12:33\tjdoe\tLogin\tUser logged in\tLCMS-PC1\n"
        "2025-10-18 09:15:01\tjdoe\tMethod Edit\tChanged gradient\tLCMS-PC1\n"
    )
    recs = parse_audit_trail(text, "audit")
    assert len(recs) == 2
    assert recs[0]["event_time"] == "2025-10-18 09:12:33"
    assert recs[0]["user"] == "jdoe"
    assert recs[0]["event_type"] == "Login"
    assert recs[0]["computer"] == "LCMS-PC1"
    assert recs[0]["record_type"] == "audit_trail"
    assert len(recs[0]["record_fingerprint"]) == 64


def test_audit_trail_comma_with_unknown_columns():
    text = (
        "Date,User,Action,WeirdCol\n"
        "2025-10-18,alice,Delete,xyz\n"
    )
    recs = parse_audit_trail(text, "audit")
    assert len(recs) == 1
    assert recs[0]["event_date"] == "2025-10-18"
    assert recs[0]["user"] == "alice"
    assert recs[0]["event_type"] == "Delete"
    # Unknown column preserved
    assert recs[0]["extra"]["weirdcol"] == "xyz"


def test_results_parser():
    text = (
        "Sample Name,Compound,RT,Area,Calculated Conc,Units,File Name\n"
        "STD_1,Caffeine,3.42,10543,5.01,ug/mL,std1.raw\n"
        "STD_1,Theobromine,2.10,8412,4.88,ug/mL,std1.raw\n"
    )
    recs = parse_results(text, "results")
    assert len(recs) == 2
    assert recs[0]["sample_name"] == "STD_1"
    assert recs[0]["compound"] == "Caffeine"
    assert recs[0]["retention_time"] == "3.42"
    assert recs[0]["concentration"] == "5.01"
    assert recs[0]["raw_file"] == "std1.raw"
    assert recs[0]["record_type"] == "result"


def test_get_parser_dispatch_and_unknown():
    assert get_parser("audit_trail") is parse_audit_trail
    assert get_parser("results") is parse_results
    try:
        get_parser("nope")
    except ValueError:
        pass
    else:  # pragma: no cover
        assert False, "expected ValueError"


def test_fingerprint_is_stable_and_ignores_envelope():
    a = {"user": "x", "event_type": "Login", "instrument_id": "A",
         "ingest_time": "t1"}
    b = {"user": "x", "event_type": "Login", "instrument_id": "B",
         "ingest_time": "t2"}
    assert fingerprint(a) == fingerprint(b)


def test_empty_input():
    assert parse_audit_trail("", "audit") == []
    assert parse_results("\n\n", "results") == []
