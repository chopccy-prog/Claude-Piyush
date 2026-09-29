# MassLynx .EAR Extractor

Extracts data from a Waters **MassLynx** `.ear` audit-trail backup to CSV, in the
same workflow as the Access-database `AuditTrailExtractor` used for the other
instruments.

> **Read this first.** The `.ear` payload is **encrypted**, proven by five
> measurements on your file (see [docs/FINDINGS.md](docs/FINDINGS.md)). Unlike the
> Access machines — where a **keymap** (the decryption keys) let the extractor
> read the tables — no key is available for the `.ear`. So this tool has two
> modes: a **salvage** mode that works today with only the `.ear` and gives you
> evidence CSVs to cross-check, and a **decode** mode that produces full record
> CSVs the moment a key/spec exists.

## Setup

```bash
python3 -m pip install -r requirements.txt   # needs Python 3.9+
```

Salvage mode and JSON→CSV use only the standard library. The optional AES decode
path needs `cryptography`; RC4 and XOR are built in.

## Run — salvage (works today, only the .ear needed)

```bash
python3 extract_ear.py --src-dir . --res-dir out
```

Writes into `out/`:

- **`ear_chunks.csv`** — one row per payload chunk: `offset`, `length`,
  `entropy_bits_per_byte`, `printable_ratio`, `preview_hex`, `preview_ascii`.
  This is the record-by-record inventory of the container.
- **`ear_strings.csv`** — every *word-like* readable run found (>=4 consecutive
  letters), with offset and length. On an encrypted `.ear` these come out as
  gibberish (no `User`, `Method`, dates, etc.), which is the evidence that the
  records are encrypted.
- **`_extract_summary.json`** — the container report and the verdict.

Quick look without writing files:

```bash
python3 ear_inspect.py Backup_18102025.ear
```

## Run — decode (works once a key/spec is available)

```bash
python3 extract_ear.py --src-dir . --res-dir out --mode decode \
    --from-date 2025-04-01 --to-date 2025-07-31
```

Decode needs a **keyspec** file describing the cipher and key. Copy
`backup.earkey.json.example` to `<yourfile>.earkey.json`, fill in the real values,
and put it next to the `.ear`. The tool auto-discovers `*.earkey.json`. Supported
ciphers: `rc4`, `xor` (built in), `aes-cbc`, `aes-ecb` (need `cryptography`). See
[`ear_crypto.py`](ear_crypto.py) for the keyspec format.

If no keyspec is present, decode mode explains exactly what is missing and points
to the supported-export route — it never pretends to have decoded anything.

## Getting a key/spec, or records another way

- **Ask Waters** for the audit-trail export key/algorithm, or obtain it the same
  way your Access `*.keymap.json` was obtained, then use decode mode.
- **Or use the supported export** (needs the instrument PC): LogLynx exports the
  audit trail and OpenLynx exports results to readable CSV/text. The
  `masslynx_bridge` project in this repository consumes those and forwards them
  to your ERP continuously.

## Run directly on any .ear (date range + conditions + server push)

`extract_ear_records.py` is the deployable extractor, same shape as the
Access-database tool: it reads any `.ear`, decrypts each record through a
keyspec, parses the fields, filters by date range and conditions, and writes CSV
or JSON and/or pushes to the server. No PDF step.

```bash
python3 extract_ear_records.py --src Backup_18102025.ear --res-dir out \
    --from-date 2025-10-01 --to-date 2025-10-31 \
    --where user=sachingade type=Permission outcome=DENIED \
    --format csv \
    --push-config ../masslynx_bridge/config.yaml   # optional: send to server
```

- Filters: `--from-date` / `--to-date` (YYYY-MM-DD) and repeatable `--where
  field=value` over any output field.
- Output: `--format csv|json`; `--push-config` sends rows to your server via the
  `masslynx_bridge` sink layer (HTTPS/DB).
- **The one required input is the body cipher.** Drop a `*.earkey.json` keyspec
  (see `ear_crypto.py`) next to the `.ear`. Without it the tool runs in **plan
  mode**: it reports the container and exactly what it will extract, and writes
  no invented data. With a wrong key it writes nothing (the parser rejects
  bytes that are not a valid record), so it never emits garbage.

Once a correct keyspec exists, this produces the same clean schema as the audit
report, straight from the `.ear`, repeatably, with no PDF.

**Status of the body cipher:** the record *header* keystream is recovered (it
decrypts a fixed zero field); the record *body* key is not yet solved. The
LogLynx report you exported is the known-plaintext needed to solve it — see
`docs/FINDINGS.md` and the decryption brief. Recovering that key is
cryptanalysis that must be done in an environment permitting it; this tool then
applies it.

## LogLynx audit PDF → clean CSV (recommended, no key needed)

MassLynx's own LogLynx viewer can print/export the audit trail to a PDF report.
That report is the readable, validatable audit data, and it needs no decryption.
Convert it to one clean CSV row per event:

```bash
# 1) dump the PDF text (any one of these)
pdftotext -layout "LCMS Audit.pdf" audit_full.txt
python3 -c "import pdfplumber; print('\n'.join((p.extract_text() or '') \
    for p in pdfplumber.open('LCMS Audit.pdf').pages))" > audit_full.txt

# 2) parse to CSV
python3 pdf_audit_to_csv.py audit_full.txt audit.csv
```

Columns: `type, time, description, outcome, user, machine, domain,
file_information, client_time, event_id, index, size`. The `index` field is the
sequential audit record number, so it de-duplicates and orders the whole trail.
This is the fastest route to give a client cross-checkable records, and the same
CSV doubles as known-plaintext reference for any `.ear` decoding work.

## JSON → CSV for cross-checking

The Access extractors write one JSON per table. Clients cross-check in Excel, so
convert to CSV (UTF-8 with BOM, opens cleanly in Excel):

```bash
# one file
python3 json_to_csv.py out_audit/AuditTrail.json out_audit/AuditTrail.csv

# a whole folder (every *.json -> *.csv beside it)
python3 json_to_csv.py --dir out_all
```

This works on the existing Access outputs (`AuditTrail.json`, `Readings.json`,
`Users.json`, …) and on any future decoded `.ear` output, so the client gets the
same CSV shape for every machine.

## Files

```
masslynx_ear_extractor/
├── extract_ear.py       # main CLI: salvage (default) + decode modes -> CSV
├── ear_format.py        # container framing + entropy analysis
├── ear_crypto.py        # pluggable decryption (rc4/xor/aes) via keyspec
├── ear_inspect.py       # quick forensic report on a .ear
├── json_to_csv.py       # extractor JSON -> Excel CSV
├── backup.earkey.json.example
├── requirements.txt
├── docs/FINDINGS.md     # the measured evidence that the payload is encrypted
├── samples/
└── tests/
```

## Tests

```bash
python3 -m pytest        # 6 tests, incl. an RC4 decode round-trip
```
