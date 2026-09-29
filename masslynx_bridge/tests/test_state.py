from masslynx_bridge.state import StateStore


def test_cursor_roundtrip_and_persistence(tmp_path):
    p = tmp_path / "state.json"
    s = StateStore(str(p))
    s.update_cursor("audit", "file1.txt", 128, "sig1")
    s.mark_sent("audit", ["fp1", "fp2"])

    # Reload from disk
    s2 = StateStore(str(p))
    cur = s2.get_cursor("audit", "file1.txt")
    assert cur.offset == 128
    assert cur.signature == "sig1"
    assert s2.already_sent("audit", "fp1")
    assert not s2.already_sent("audit", "nope")


def test_recent_ids_bounded(tmp_path):
    p = tmp_path / "state.json"
    s = StateStore(str(p))
    s.MAX_RECENT_IDS = 10
    s.mark_sent("c", [f"fp{i}" for i in range(25)])
    cs = s.get_collector("c")
    assert len(cs.recent_ids) == 10
    # Most recent retained
    assert "fp24" in cs.recent_ids
    assert "fp0" not in cs.recent_ids


def test_corrupt_state_is_ignored(tmp_path):
    p = tmp_path / "state.json"
    p.write_text("{ not json", encoding="utf-8")
    s = StateStore(str(p))  # should not raise
    assert s.get_cursor("x", "y").offset == 0
