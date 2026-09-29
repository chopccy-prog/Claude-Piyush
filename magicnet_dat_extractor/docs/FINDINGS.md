# MagIC Net `.dat` files: what they are and what was established

Written 2026-09-29 from the files in the shared Drive folder
`MagicNet 3.3 (I-B2-162)` and from public sources. Everything in the
"Measured" sections was read from the real bytes; "Public sources" is what
the vendors publish; "Open" is what still has to be confirmed on the
instrument PC.

## 1. The files are a database directory, not per-run result files

The folder tree (sizes from Drive):

```
MagicNet 3.3 (I-B2-162)/MagicNet 3.3 (I-B2-162)/
├── Magic Net 2025/                      <- IC_Determination database (the results)
│   ├── objects.dat        452,984,832 B  (= 432 x 1 MiB exactly; 27 x 16 MiB)
│   ├── objects.idx         67,108,864 B  (= 64 MiB exactly)
│   ├── DBInfo                      69 B
│   ├── eventlog/f0000000.ptd  434,519 B
│   └── recovery/data0000.rcy   16,777,216 B (= 16 MiB)
└── IC_Config/
    ├── ConfigDB/                        <- configuration database (users, audit trail, methods)
    │   ├── objects.dat        104,857,600 B  (100 MiB)
    │   ├── objects.idx         25,165,824 B  (24 MiB)
    │   ├── DBInfo, eventlog/, recovery/
    ├── $$Backup#1719201237860/          <- ConfigDB backup, 2024-06-24 (Unix ms in the name)
    │   ├── objects.dat  75,079,680 B, DBInfo, eventlog/
    └── $$Backup#1735017882412/          <- ConfigDB backup, 2024-12-24
        ├── objects.dat  61,726,720 B, DBInfo, eventlog/
```

`objects.dat` is **one file for the whole database**, pre-allocated in 16 MiB
extents. There is no "one .dat per determination". Any integration therefore
reads records out of this store (or uses MagIC Net's export) rather than
picking up files per run.

The Windows paths recorded inside the event logs are:

```
C:\ProgramData\Metrohm\MagIC Net\Data\IC_Determination\Magic Net 2025\
C:\ProgramData\Metrohm\MagIC Net\Data\IC_Config\ConfigDB\
```

## 2. Measured: the engine is Versant FastObjects Core 10.0.9

Every event log starts each session with a banner record (read with
`fo_eventlog.py`):

```
FastObjects Core 10.0.9.200.0  (Feb 15 2010), MS Visual C++ 8.0 1400
C:\Windows\WinSxS\x86_microsoft.vc80.crt_...\MSVCR80.dll (VERSION 8.00.50727.9554)
```

So the `.dat` is a **FastObjects** (formerly POET) object database, 32-bit
build, native (C++) core. `DBInfo` is a Java-properties file
(`DBVersion=33`, `ProgID=200`, a timestamp comment) and is Metrohm's own
marker, not a FastObjects file.

## 3. Measured: the event log format (fully parsed)

`eventlog/f0000000.ptd` is plain little-endian binary, parsed record-for-record
with zero unknown records across the four real logs (2,732 + 2,849 + 2,069 +
2,388 records). Layout is documented in `fo_eventlog.py`. Content:

| record kind      | meaning                                                          |
|------------------|------------------------------------------------------------------|
| fileinfo         | path of the log and creation time                                |
| banner           | engine start: FastObjects version + runtime DLL                  |
| code 0x13, 0x16  | once, at database creation                                       |
| code 0x11, 0x12  | in pairs, session begin/end (working labels)                     |
| message          | `Open database with enabled storage clustering. (0-N#0)`         |
| range            | two timestamps (rare)                                            |

The `N` in the open message increases monotonically (2,930,818 on
2025-10-14 for the determination DB; 8,776,250 for ConfigDB) and behaves like
a transaction / object-allocation counter. The determination database was
created 2025-01-02 10:34:11 and last opened 2025-10-14 10:25:28. The
ConfigDB dates back to 2020-09-30.

The log carries no analytical data (no samples, results or users); it is
operational. It matters because it proves two things without touching
`objects.dat`: which engine wrote the store, and that the engine writes
**plain, unencrypted** structures.

## 4. Public sources: what FastObjects is on disk

- A FastObjects database is a directory whose main files are `objects.dat`
  (persistent objects in canonical, platform-independent form) and
  `objects.idx` (indexes). The format is proprietary; the vendor never
  published page or object layouts and no open-source reader exists.
- The **class schema ("dictionary") is a separate FastObjects database**, a
  directory containing `_objects.dat` / `_objects.idx` (leading underscore).
  One dictionary can serve several databases. **It is not in the Drive
  folder.** Without it, even the vendor's own tools cannot name the classes
  and attributes in `objects.dat`.
- `eventlog/*.ptd` = engine event log (confirmed by SCIEX, whose Analyst
  software also embeds FastObjects); `recovery/` = crash-recovery data.
- Encryption is an optional enterprise feature of FastObjects with its own
  guide; nothing indicates Metrohm enabled it. Metrohm's 21 CFR Part 11
  assessment says the live database is "encoded in a format non-readable for
  humans" and that *backup/export files* are "encrypted and provided with a
  checksum". Those are two different statements: proprietary binary versus
  encrypted archive.
- Vendor read routes, all of which need the FastObjects runtime **and the
  dictionary**: `ptxml -export` (XML dump of a class or the whole base),
  FastObjects Developer (GUI browser), FastObjects Connect (ODBC driver) with
  SQL Object Factory. FastObjects 10/11/12/14/15 installers and PDFs still
  exist at Actian but behind a customer login.
- Metrohm: MagIC Net 4.0 and tiamo 3.0 moved to FastObjects 14; 3.3 is on 10.
  MagIC Net exports determinations via **export templates** to `*.csv`,
  `*.slk`, `*.xml`, `*.cdf`, `*.idet`, manually or automatically at the end
  of every determination (set in the method). The XML export is a full
  `<DeterminationReport>` (Determination, Method, Sample, Analyses,
  SingleResults, Statistics, Devices, Columns, System/user).

## 5. Why this is different from the Access `.accdb` machines

For the Autopol/Access databases, the file was a standard Access `.accdb`
whose pages had been RC4-scrambled with per-page keys; recovering the keymap
made an ordinary Access parser work. Here:

| | Access machines | MagIC Net |
|---|---|---|
| container | Microsoft Access, public format | FastObjects 10, proprietary, undocumented |
| protection | per-page RC4, key recoverable | none expected (plain engine structures); schema kept in a separate dictionary DB |
| parser available | `access_parser` (open source) | none; must be written from the bytes |
| what unlocks it | keymap | (1) the bytes of `objects.dat`, (2) the dictionary DB, (3) a mapped page/object layout |

"Key extraction" therefore does not apply. The work is **format mapping**,
and the tooling in this folder is built for exactly that, in the same CLI
shape as the Access extractor so the ERP side sees the same kind of output.

## 6. Blocker on this side: the 10 MB connector limit

The Drive connector available in this session refuses downloads above 10 MB
(`objects.dat` is 432 MB; the smallest backup copy is 61 MB; the recovery file
is 16 MB) and the files are private, so a direct HTTPS download is not possible
either. Everything under 10 MB (DBInfo, all four event logs) was retrieved and
analysed. To go further, one of these is needed:

1. **Run the inspector on the instrument PC** and send back the small report:
   `python fo_inspect.py "C:\ProgramData\Metrohm\MagIC Net\Data\IC_Determination\Magic Net 2025" --res-dir inspect_out`
   then share `inspect_out\_inspect_report.json`, `strings_top.csv`,
   `class_candidates.csv` (a few MB at most). This is the fastest route.
2. Or make the bytes reachable: set the Drive files to "Anyone with the link"
   (then they can be fetched directly), or attach `objects.dat` to a GitHub
   release of this repository (assets up to 2 GB), or split with 7-Zip into
   9 MB volumes and upload the parts to Drive.
3. In all cases also locate and share the **dictionary database**: search
   `C:\ProgramData\Metrohm\MagIC Net` and `C:\Program Files*\Metrohm\MagIC Net*`
   for a folder containing `_objects.dat`, and for `ptserver.cfg` /
   `ptbase.cfg` / `*.cfg` files that mention `[schemata]` or `dictionary`.

## 7. Open questions (to be answered from the real bytes)

- Page size and page header of `objects.dat` (the inspector estimates it).
- Object header / OID layout, class tagging, and the serialization of
  strings (ASCII vs UTF-16), doubles, dates and collections.
- Whether MagIC Net turned on FastObjects encryption (the inspector's
  keyword and entropy test answers this in seconds on the real file).
- Whether a FastObjects 12/14 `ptxml.exe` can open a 10.0.9 database without
  migrating it.
