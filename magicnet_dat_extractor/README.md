# MagIC Net `.dat` Extractor (Metrohm IC, FastObjects database)

Tools to get data out of a **Metrohm MagIC Net 3.3** database folder
(`objects.dat` + `objects.idx` + `DBInfo` + `eventlog/` + `recovery/`) for the
central ERP server, in the same workflow as the Access `extract.py` used for the
other instruments.

> **Read this first.** The MagIC Net `.dat` is not an encrypted export and it is
> not one file per run. It is the data file of an embedded **Versant FastObjects
> 10.0.9** object database (the engine names itself in `eventlog/*.ptd`). There is
> no key to extract: the pages are plain proprietary structures whose layout has
> to be mapped from the real bytes, and the class schema lives in a separate
> *dictionary* database (`_objects.dat`) that was not in the shared folder.
> [docs/FINDINGS.md](docs/FINDINGS.md) has the evidence and the plan.

## What works today

| tool | input | output | status |
|---|---|---|---|
| `fo_eventlog.py` | `eventlog/f0000000.ptd` | CSV of every engine event (create/open/close, counters, versions) | **complete**, validated on 4 real MagIC Net logs |
| `fo_inspect.py` | database folder | `_inspect_report.json`, `strings_top.csv`, `class_candidates.csv`, `keyword_hits.csv`, dictionary-DB discovery, page-size guess, encryption verdict | **complete**; run it on the instrument PC and send back the report |
| `extract_dat.py --mode salvage` (default) | database folder | `EventLog.csv` (date-filtered), `Strings.csv` (every readable string with page/offset), the inspector report, `_extract_summary.json` | **complete** |
| `extract_dat.py --mode decode` | database folder + `*.fospec.json` | `<Class>.csv` / `<Class>.json` per class, date-filtered | engine done; **needs the layout mapping** (`fospec`) that can only be written from the real `objects.dat` + dictionary |

Python 3.9+, standard library only.

## Run

```bash
# 1) on the instrument PC (or on a copy of the DB folder): inspect + salvage
python extract_dat.py --db-dir "C:\ProgramData\Metrohm\MagIC Net\Data\IC_Determination\Magic Net 2025" --res-dir out

# only the forensic report (fast, small files to send back)
python fo_inspect.py "C:\ProgramData\Metrohm\MagIC Net\Data\IC_Determination\Magic Net 2025" --res-dir inspect_out

# event log alone
python fo_eventlog.py "…\Magic Net 2025\eventlog\f0000000.ptd" -o eventlog.csv

# 2) once magicnet.fospec.json exists next to objects.dat: full decode, same flags as extract.py
python extract_dat.py --db-dir . --res-dir out --mode decode --all --from-date 2025-04-01 --to-date 2025-07-31
python extract_dat.py --db-dir . --res-dir out --mode decode --table Determination
```

Flags mirror the Access extractor: `--db-dir`, `--res-dir`, `--from-date`,
`--to-date` (inclusive, `YYYY-MM-DD`), `--all`, `--table`, `--indent`; plus
`--mode salvage|decode|inspect`, `--spec`, `--page-size`, `--no-strings`.
Everything is read-only.

## What is needed to finish the decoder

The tooling is blocked on data, not on code:

1. **The inspector report from the real database** (`_inspect_report.json`,
   `strings_top.csv`, `class_candidates.csv` from step 1 above). It shows the
   page size, whether strings are readable (= not encrypted), and the class /
   attribute vocabulary. A few MB.
2. **The dictionary database**: a folder containing `_objects.dat` and
   `_objects.idx`, somewhere under `C:\ProgramData\Metrohm\MagIC Net` or
   `C:\Program Files (x86)\Metrohm\MagIC Net 3.3`. `fo_inspect.py` searches
   nearby folders and prints what it finds. Also any `ptserver.cfg` /
   `ptbase.cfg` / `*.cfg` mentioning `schemata` or `dictionary`.
3. **The bytes of `objects.dat`** for offline mapping, if the report alone is
   not enough. The Drive connector caps downloads at 10 MB and the files are
   private; options: share the files as "Anyone with the link", attach them
   to a GitHub release of this repo (up to 2 GB per asset), or split into
   9 MB 7-Zip volumes.

With those, the page/object layout becomes a `magicnet.fospec.json`
(see `magicnet.fospec.json.example`), and `--mode decode` produces
`Determination.csv`, `Sample.csv`, `Result.csv`, … exactly like the Access
`--all` output.

## The supported alternative (recommended in parallel)

MagIC Net has a built-in export designed for LIMS/ERP: **Database ▸ Tools ▸
Templates ▸ Export templates** (`*.csv`, `*.slk`, `*.xml`, `*.cdf`, `*.idet`),
and every method can export automatically at the end of each determination.
The XML export contains the complete `<DeterminationReport>` (sample,
method, analyses, single results, statistics, devices, user). A watcher on
that export folder (like `masslynx_bridge` in this repository) gives the ERP
live, vendor-supported data while the raw-database decoder is completed.

## Files

```
magicnet_dat_extractor/
├── extract_dat.py               # main CLI: salvage (default) / decode / inspect
├── fo_eventlog.py               # eventlog/*.ptd parser -> CSV (fully mapped)
├── fo_inspect.py                # forensic inspector for objects.dat / objects.idx / _objects.dat
├── fo_decode.py                 # fospec-driven record decoder (needs the mapping)
├── magicnet.fospec.json.example # layout description template
├── docs/FINDINGS.md             # evidence: engine, layout, eventlog format, blockers, sources
├── samples/eventlog_sample.ptd  # real MagIC Net event log (ConfigDB backup copy)
└── tests/                       # 11 tests (real eventlog + synthetic paged store)
```

```bash
python3 -m pytest -q
```
