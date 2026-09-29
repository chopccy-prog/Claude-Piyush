# MassLynx → ERP Bridge

Continuously ship **Waters MassLynx** audit-trail and sample-result exports from
an LC-MS instrument PC to a central ERP / LIMS server.

> **About the `.EAR` file first.** If you came here to "decrypt" a MassLynx
> `.ear` backup, read **[docs/EAR_FORMAT_ANALYSIS.md](docs/EAR_FORMAT_ANALYSIS.md)**.
> Short version: the `.ear` is a proprietary, encrypted Waters backup blob
> (measured entropy 7.93 / 8.0, no readable structure). It is not meant to be
> parsed, and building an ERP feed on a reverse-engineered guess would be
> fragile and would break your audit-trail integrity. The supported, reliable
> way to get that same data is MassLynx's own exports — which is what this bridge
> consumes.

## What this does

```
MassLynx PC                                   Central server
┌──────────────────────────┐                 ┌───────────────────┐
│ LogLynx  → audit export ─┐│    this         │                   │
│ OpenLynx → result export─┼┼──► bridge ──────►  HTTPS API  or DB │
│           (CSV/TXT folders)│   (Python)      │                   │
└──────────────────────────┘                 └───────────────────┘
```

- **Watches** one or more export folders that MassLynx / LogLynx / OpenLynx
  write into.
- **Parses** the delimited exports with version-tolerant, column-name-driven
  parsers (unknown columns are preserved, never dropped).
- **De-duplicates** using a per-record fingerprint plus a persistent byte-offset
  cursor, so a restart never re-sends or loses data (at-least-once delivery).
- **Delivers** in batches to a pluggable sink: **HTTPS JSON** (default), **SQL
  database**, or **stdout** (for testing).
- **Retries** with exponential backoff on network failures.
- Runs as a simple, robust **poll loop** suitable for Windows Task Scheduler,
  NSSM, or Linux systemd.

## Quick start

```bash
pip install -r requirements.txt
cp config.example.yaml config.yaml      # then edit watch_dir and sink.url
python -m masslynx_bridge --config config.yaml --check    # validate
python -m masslynx_bridge --config config.yaml --once     # single pass
python -m masslynx_bridge --config config.yaml            # run forever
```

### Try it end to end with no real instrument

Terminal 1 — a mock ERP endpoint:

```bash
python tools/mock_erp_server.py --port 8080
```

Terminal 2 — point the bridge at the sample files and the mock server:

```bash
mkdir -p /tmp/ml/audit /tmp/ml/results
cp samples/sample_audit_trail.txt /tmp/ml/audit/
cp samples/sample_results.csv     /tmp/ml/results/
cat > /tmp/ml/config.yaml <<'YAML'
state_path: /tmp/ml/state/state.json
instrument_id: DEMO-01
sink:
  type: https
  url: http://localhost:8080/ingest
  verify_tls: false
collectors:
  - {name: audit_trail, kind: audit_trail, watch_dir: /tmp/ml/audit,   file_glob: "*.txt", delimiter: "\t"}
  - {name: results,     kind: results,     watch_dir: /tmp/ml/results, file_glob: "*.csv"}
YAML
python -m masslynx_bridge --config /tmp/ml/config.yaml --once
```

You will see the mock server print the received audit and result records, and a
second `--once` sends nothing (dedup works).

## Configuration

See [`config.example.yaml`](config.example.yaml) for every option with comments.
Key points:

- **Secrets via environment, not the file.** The API token comes from
  `MASSLYNX_BRIDGE_SINK_TOKEN`; the DB URL from `MASSLYNX_BRIDGE_SINK_DB_URL`.
  Any config field can be overridden by `MASSLYNX_BRIDGE_<FIELD>` (nested sink
  fields use `MASSLYNX_BRIDGE_SINK_<FIELD>`).
- **`instrument_id`** stamps every record so the server knows the source PC.
- **Collectors** — one block per export folder. `kind` is `audit_trail` or
  `results`, selecting the parser.

## Adapting the parser to your export columns

The parsers map source column headers onto normalized fields via an alias table.
If your MassLynx export uses different headings, add them to `COLUMN_ALIASES` in:

- `masslynx_bridge/parsers/audit_csv.py`
- `masslynx_bridge/parsers/results_csv.py`

Unrecognized columns are automatically preserved under an `extra` object, so you
never silently lose data while tuning the aliases.

## Deploying

- **Windows (the MassLynx PC):** [docs/SETUP_WINDOWS.md](docs/SETUP_WINDOWS.md)
- **Linux gateway:** [systemd/masslynx-bridge.service](systemd/masslynx-bridge.service)

## Safety

- The bridge only ever **reads** export files. It never writes to or modifies
  MassLynx data or the acquisition system.
- It is designed for a **dedicated export folder** that LogLynx/OpenLynx write
  to on a schedule — not for MassLynx's internal data directories.

## Tests

```bash
pip install pytest
python -m pytest
```

## Project layout

```
masslynx_bridge/
├── masslynx_bridge/          # the package
│   ├── __main__.py           # CLI entry point
│   ├── config.py             # YAML + env config
│   ├── state.py              # persistent per-file cursors + dedup
│   ├── watcher.py            # the poll loop / service
│   ├── collectors/base.py    # folder watcher, incremental read, delivery
│   ├── parsers/              # audit_trail + results parsers
│   └── sinks/                # https / sqldb / stdout
├── tools/
│   ├── inspect_ear.py        # forensic entropy report on a .ear file
│   └── mock_erp_server.py    # local test receiver
├── docs/
│   ├── EAR_FORMAT_ANALYSIS.md
│   └── SETUP_WINDOWS.md
├── systemd/masslynx-bridge.service
├── samples/                  # example export files
└── tests/
```
