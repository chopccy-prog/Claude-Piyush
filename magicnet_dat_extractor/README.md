# MagIC Net `.dat` Extractor (Metrohm IC, FastObjects database)

Decodes a **Metrohm MagIC Net 3.3** determination database folder
(`objects.dat` + `objects.idx` + `DBInfo` + `eventlog/` + `recovery/`) into
CSV and JSON tables for the central ERP server, in the same workflow as the
Access `extract.py` used for the other instruments.

> **What the `.dat` is.** Not an encrypted export and not one file per run: it
> is the data file of an embedded **Versant FastObjects 10.0.9** object
> database. There is no key. The record framing, the object layout and the
> MagIC Net object model were mapped from the real database and are built into
> this tool, so it needs no dictionary, no Metrohm software and no key file.
> [docs/FINDINGS.md](docs/FINDINGS.md) has the evidence and the format.

Verified on the real `Magic Net 2025` database (432 MB): 2,921,281 records in
148 classes, every one framed; 1,289 determination records (501 determinations
in up to three versions), 159,726 results, 3,914 peaks, 904 history entries,
decoded in about 30 seconds. Python 3.9+, standard library only.

## Run

```bash
# everything, same flags as the Access extractor
python extract_dat.py --db-dir "C:\ProgramData\Metrohm\MagIC Net\Data\IC_Determination\Magic Net 2025" --res-dir out

# only the newest version of each determination, for a date range
python extract_dat.py --db-dir . --res-dir out --latest-only --from-date 2025-04-01 --to-date 2025-07-31

# one table
python extract_dat.py --db-dir . --res-dir out --table Results
```

`--db-dir` is the folder that holds `objects.dat` (or any file in it). Every
run is read-only.

## Output (one CSV + one JSON per table, UTF-8 with BOM for Excel)

| table | one row per | key columns |
|---|---|---|
| `Determinations` | determination **version** | `determination_number`, `version` (0 acquired, 1 evaluated, 2 re-integrated/reviewed), `is_latest`, `guid`, `start_time`, `user_login`, `user_fullname`, `client_pc`, `program_version`, `method_name`, `method_guid`, `method_author_*`, `sample_ident`, `run_time_display`, `analyses`, `result_count`, `prop_POSITION`, `prop_VOLUME`, `prop_DILUTION`, `prop_AMOUNT`, `prop_INFO1` ... |
| `Samples` | determination version | `sample_ident`, `sample_str2..5`, every sample property with value and display value |
| `Analyses` | analysis of a determination (e.g. `PHOSPHATE BINDING CAPACITY`, `PRESSURE`) | `analysis`, `result_sets`, `results`, `curve_objnum` |
| `Results` | result variable | `variable` = `RS.<analysis>.<component>.<quantity>` (RET, AREA, HGT, CONC, CONC%, START, END, FWHM, ASY, PLA, RES, CAL... ), `value`, `display_value`, `unit`, `limit_low`, `limit_high`, `decimals` |
| `Peaks` | identified peak | peak metrics (`u32_a..d4`, meaning not yet named) and 9 `(p*_x, p*_y)` time/signal points |
| `History` | modification / review / release entry | `timestamp`, `user_login`, `user_fullname`, `client_pc`, `category` (`Determination modified`, `Review`, `Release`), `action` (`INTEGRATION DONE`, `SUBMITTED FOR REVIEW`, `DATA REVIEWED`, ...) |
| `Methods` | distinct method GUID | name, author, comments, saved date, determination count |
| `EventLog` | engine event | database create/open/close, engine version, counters |

Every child row carries the determination key columns (`det_objnum`,
`determination_number`, `version`, `is_latest`, `guid`, `start_time`,
`method_name`, `sample_ident`, `user_login`) so the ERP can join without
lookups. `--from-date/--to-date` filter on `start_time` (inclusive days);
`--latest-only` keeps `is_latest` rows.

Numbers are decoded from MagIC Net's `NN<ieee754-bits>` strings to exact
doubles; `display_value` is the rounded value as shown in the software. A
text value such as `ZN` in `CONC` is what MagIC Net stores (not calculated).

## Other modes

- `--mode salvage`: forensic report + `EventLog.csv` + `Strings.csv` without
  decoding objects (`fo_inspect.py` alone gives just the report).
- `--mode spec --spec x.fospec.json`: generic layout-driven decoder for
  another FastObjects database (see `magicnet.fospec.json.example`).
- `fo_carve.py`: lists and decodes every Java-serialized blob (enums) in a file.
- `split_dat.py`: split/join a big file into 9 MB parts with checksums.

## Files

```
magicnet_dat_extractor/
├── extract_dat.py      # CLI: decode (default) / salvage / inspect / spec
├── fo_magicnet.py      # MagIC Net 3.3 object model: determinations, samples, results, peaks, history
├── fo_records.py       # FastObjects record walker (26-byte header, 16-byte alignment)
├── fo_layout.py        # record body: offset table, fixed part, members (strings/refs/blobs)
├── fo_fields.py        # field encodings: UTF-16/8-bit strings, references, Java blobs, dates
├── fo_javaser.py       # Java Object Serialization Stream parser (standard library)
├── fo_carve.py         # carve Java streams out of a file
├── fo_eventlog.py      # eventlog/*.ptd parser
├── fo_inspect.py       # forensic inspector (page size, entropy, strings, dictionary search)
├── fo_decode.py        # fospec-driven generic decoder
├── split_dat.py        # split / join large files
├── docs/FINDINGS.md    # the format, class map and evidence
├── samples/            # real event log, JDK-generated Java streams, real inspector report
└── tests/              # 16 tests: real event log, synthetic FastObjects DB in the real layout, JDK streams
```

```bash
python3 -m pytest -q tests
```

## Known gaps

- Peak metric fields in `Peaks.csv` are exported but not named (`u32_a`, `d1`...).
- Chromatogram curves (class 189, gzip'ed big-endian sample stream with the
  scaling factors in the fixed part) are located but not exported yet.
- The ConfigDB (users, audit trail, methods) uses the same record format but
  its class ids are not mapped; `--mode salvage` works on it today.
- MagIC Net's own export templates (CSV/XML per determination) remain the
  vendor-supported route and can run in parallel.
