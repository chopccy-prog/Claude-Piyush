from typing import Dict, List

from masslynx_bridge.collectors.base import FolderCollector
from masslynx_bridge.config import CollectorConfig, SinkConfig
from masslynx_bridge.sinks.base import Sink
from masslynx_bridge.state import StateStore


class MemorySink(Sink):
    def __init__(self):
        super().__init__(SinkConfig(type="stdout", batch_size=100))
        self.sent: List[Dict] = []
        self.fail_times = 0

    def send(self, records):
        if self.fail_times > 0:
            self.fail_times -= 1
            raise RuntimeError("simulated network error")
        self.sent.extend(records)


def _make(tmp_path, sink):
    watch = tmp_path / "exports"
    watch.mkdir()
    cfg = CollectorConfig(
        name="audit", kind="audit_trail", watch_dir=str(watch),
        file_glob="*.txt", encoding="latin-1",
    )
    state = StateStore(str(tmp_path / "state.json"))
    coll = FolderCollector(cfg, sink, state, "INSTR-1")
    return coll, watch, state


HEADER = "Date/Time\tUser\tEvent\tDescription\n"


def test_incremental_append_no_duplicates(tmp_path):
    sink = MemorySink()
    coll, watch, _ = _make(tmp_path, sink)
    f = watch / "audit.txt"
    f.write_text(HEADER + "2025-10-18 09:00:00\tbob\tLogin\tin\n",
                 encoding="latin-1")

    assert coll.poll_once() == 1
    assert len(sink.sent) == 1
    assert sink.sent[0]["user"] == "bob"
    assert sink.sent[0]["instrument_id"] == "INSTR-1"

    # No new data -> nothing delivered
    assert coll.poll_once() == 0
    assert len(sink.sent) == 1

    # Append one more line
    with f.open("a", encoding="latin-1") as fh:
        fh.write("2025-10-18 09:05:00\tbob\tLogout\tout\n")
    assert coll.poll_once() == 1
    assert len(sink.sent) == 2
    assert sink.sent[1]["event_type"] == "Logout"


def test_partial_line_waits(tmp_path):
    sink = MemorySink()
    coll, watch, _ = _make(tmp_path, sink)
    f = watch / "audit.txt"
    # Header + a complete line + a partial line with no trailing newline
    f.write_text(HEADER + "2025-10-18 09:00:00\tbob\tLogin\tin\n"
                 "2025-10-18 09:06:00\tbob\tPartial", encoding="latin-1")
    assert coll.poll_once() == 1
    assert len(sink.sent) == 1

    # Complete the partial line
    with f.open("a", encoding="latin-1") as fh:
        fh.write("\tfinished\n")
    assert coll.poll_once() == 1
    assert sink.sent[1]["description"] == "finished"


def test_retry_then_success(tmp_path):
    sink = MemorySink()
    sink.fail_times = 2  # first two sends raise, third succeeds
    coll, watch, _ = _make(tmp_path, sink)
    f = watch / "audit.txt"
    f.write_text(HEADER + "2025-10-18 09:00:00\tbob\tLogin\tin\n",
                 encoding="latin-1")

    # Patch retry sleep so the test is fast
    import masslynx_bridge.collectors.base as base
    orig = base.retry

    def fast_retry(func, **kw):
        kw["sleep"] = lambda *_: None
        kw["base_delay"] = 0
        return orig(func, **kw)

    base.retry = fast_retry
    try:
        assert coll.poll_once() == 1
    finally:
        base.retry = orig
    assert len(sink.sent) == 1


def test_persistence_across_restart(tmp_path):
    sink = MemorySink()
    coll, watch, _ = _make(tmp_path, sink)
    f = watch / "audit.txt"
    f.write_text(HEADER + "2025-10-18 09:00:00\tbob\tLogin\tin\n",
                 encoding="latin-1")
    coll.poll_once()
    assert len(sink.sent) == 1

    # New collector instance sharing the same state file: should NOT resend.
    sink2 = MemorySink()
    cfg = coll.cfg
    state2 = StateStore(str(tmp_path / "state.json"))
    coll2 = FolderCollector(cfg, sink2, state2, "INSTR-1")
    assert coll2.poll_once() == 0
    assert len(sink2.sent) == 0
