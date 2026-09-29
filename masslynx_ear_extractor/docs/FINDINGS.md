# What the `.EAR` file is — the measured evidence

This is the analysis behind the extractor. Every number here was measured from
your file `Backup_18102025.ear` (25,539,334 bytes). You can reproduce all of it
by running `python3 extract_ear.py --src-dir . --res-dir out` and reading
`out/_extract_summary.json`, or `python3 ear_inspect.py <file>.ear`.

## The container

The `.ear` is a flat byte stream built from a repeating 7-byte ASCII framing
marker and variable-length payload chunks:

| Property | Value |
|---|---|
| Framing marker | `.gCi2k1` (hex `2e 67 43 69 32 6b 31`) |
| Marker occurrences | 143,462 |
| Payload chunks | 143,463 |
| Chunk length | min 25, mean ~171, max 28,451 bytes |

So the file is roughly 143k small records, each wrapped by the marker.

## The payload is encrypted — five independent checks

| Test | Result | Meaning |
|---|---|---|
| Whole-file entropy | 7.927 / 8.0 | near-maximal randomness |
| Entropy of every region | 7.895 – 7.923 | uniform, no plaintext islands |
| Payload entropy (marker removed) | 7.971 | chunks are essentially random |
| Standard decompression (zlib/gzip/bz2/xz/deflate) | all fail | not a compressed container |
| Repeating-key XOR test (32-byte columns) | every column entropy 7.927 | **not** XOR; a real cipher |
| Readable text (ASCII + UTF-16) | none but the marker | no words survive |
| Keyword scan (MassLynx, User, 2025, Method, .raw, xml, SQL...) | 0 hits | no header, no field names |

The XOR test is the decisive one. If the file were obfuscated with a repeating
key, splitting it into 32 columns would leave each column with a single dominant
byte (low entropy). Instead all 32 columns are uniformly random. That is the
signature of a real stream/block cipher, not obfuscation.

## Conclusion

The chunk payloads are encrypted with a key we do not have. Records cannot be
turned into fields from this file alone. This is by design: MassLynx Security
stores its audit log encrypted so it is tamper-evident, and the `.ear` is the
exported form of that.

## Why the other machine worked and this one does not

The Access-database instruments (e.g. the Autopol polarimeter) were extractable
because your team had a **keymap** — the actual decryption keys, supplied out of
band as `*.keymap.json`. With the keys, `access_parser` reads the tables. The
`.ear` has no equivalent key available, so the analogous `decode` mode here is
ready but inert until a key/spec is supplied.

## The two ways to get real CSV records from MassLynx

1. **A key/spec** (then `decode` mode produces records like the other machines).
   Ask Waters for the audit-trail export key/algorithm, or extract it the same
   way the Access keymap was obtained. Drop a `*.earkey.json` next to the `.ear`.
2. **The supported export** — LogLynx (audit trail) and OpenLynx (results) export
   readable CSV/text directly. That is the reliable, vendor-backed route and is
   what the `masslynx_bridge` project in this repo consumes and forwards to your
   ERP. This needs access to the instrument PC.
