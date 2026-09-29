# The `.EAR` file: what it is, and why you should not try to decrypt it

## Summary

`Backup_18102025.ear` is a **Waters MassLynx Security backup export**. It is a
closed, proprietary, compressed-and-encrypted blob produced by the MassLynx
Security / LogLynx subsystem. It is **not** a document format you can parse, and
you should **not** build your ERP integration on top of trying to crack it.
This document explains the evidence and gives you the correct integration path
instead.

## What we measured on your actual file

Run the inspector yourself: `python tools/inspect_ear.py <yourfile>.ear`

| Property | Value | What it tells us |
|---|---|---|
| Size | 25,539,334 bytes (~25 MB) | A full security-log backup, not a single record |
| Container magic | none recognized | Not ZIP, GZIP, 7z, SQLite, OLE, PDF, or XML |
| First 16 bytes | `20 92 55 b3 21 d5 47 33 09 45 12 80 ad b3 2f 64` | No readable header or version marker |
| Whole-file entropy | **7.927 / 8.000 bits per byte** | Essentially maximal randomness |
| Entropy across blocks | 7.895 – 7.923 everywhere | Uniformly high from start to end |

### Why entropy settles the question

Shannon entropy measures how random the bytes are. As a rule of thumb:

- English text: ~1.0 to 1.5 bits/byte
- XML / CSV / JSON: ~2 to 4 bits/byte
- A database file: ~3 to 6 bits/byte
- Compressed data (ZIP/GZIP): ~7.9+ bits/byte
- Encrypted data: ~7.99 bits/byte

Your file measures **7.927 across every region**. That means the payload is
compressed and/or encrypted end to end. There is no plaintext island to read.
There is a short repeating framing pattern (a 7-byte marker recurs about
143,000 times) that looks like Waters' own record-envelope or obfuscation
scheme wrapped around the encrypted payload, but it carries no readable content.

## Why "decrypt it anyway" is the wrong engineering decision

1. **No key, no spec, by design.** MassLynx Security stores its audit log in a
   proprietary encrypted format (`mlevt`) that Waters documents as readable
   *only* by their own security-log service. The `.EAR` backup is the exported
   form of that. There is no published key or schema, and there is not meant to
   be.
2. **It would break on every MassLynx update.** Even a partial reverse-engineer
   would be an undocumented guess that Waters can change silently in any patch.
   An ERP feed built on a guess corrupts your records the day the vendor ships
   an update, and you would not know until an audit.
3. **It defeats the point of the audit trail.** In a regulated lab (21 CFR
   Part 11 / GxP) the audit trail's value is that it is tamper-evident and can
   only be read through the validated vendor chain. Data pulled out by
   circumventing that protection is not trustworthy evidence. Your QA and any
   auditor would reject it.
4. **You would own a fragile, unsupportable system.** When it breaks, Waters
   support cannot help you, because you are not using a supported interface.

## The correct path: integrate at the supported output layer

MassLynx already emits machine-readable data through documented, validatable
channels. Point the bridge in this repository at those, not at the `.ear`.

### For the audit trail (the data inside your `.EAR`)

- Open **LogLynx** (MassLynx Security's audit viewer):
  `Start > All Programs > MassLynx > LogLynx`.
- Use its **export** function to write the audit trail to a delimited text /
  CSV file (and/or a printable report). This export is the *supported, readable*
  representation of exactly what is locked inside the `.ear`.
- Where available, schedule that export to a folder on a routine so it stays
  current. The bridge's `audit_trail` collector watches that folder.

### For sample / analytical results (what an ERP usually needs)

- **OpenLynx** and the MassLynx sample-list / quantitation reports export to
  CSV / text.
- The **MassLynx Automation (OLE/COM) API** and the **MassLynx SDK** give
  programmatic access to sample lists and results.
- The bridge's `results` collector watches the results-export folder.

### The fully supported, vendor-backed option

Waters sells and documents connectivity for exactly this use case. If this is
going into a production, regulated ERP, ask Waters support for:

> "Supported programmatic export / interface for the MassLynx Security audit
> trail and sample results, for integration with a central LIMS/ERP."

They can point you at NuGenesis / LIMS interfaces, Empower connectivity, or the
MassLynx SDK, all of which come with documentation you can validate against.

## What to send Waters (so you get a fast, useful answer)

- MassLynx version (Help > About).
- That you need a **routine, machine-readable export** of the audit trail and
  of sample results.
- That the destination is a **central ERP/LIMS** and the instrument PC will run
  an unattended collector.
- Ask specifically whether LogLynx audit export can be **scheduled/automated**,
  and what the **column format** is, so the parser aliases can be confirmed.
