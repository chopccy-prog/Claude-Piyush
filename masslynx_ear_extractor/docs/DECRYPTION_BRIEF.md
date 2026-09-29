# Brief: recover the MassLynx `.EAR` body key (known-plaintext now available)

This is the task for an analyst/tool in an environment that permits
cryptanalysis. It recovers the body encryption key for the instrument owner's
own audit backups so `extract_ear_records.py` can read any `.ear` from this
machine directly. A strong known-plaintext resource is now in hand.

## Files to work with

1. `Backup_18102025.ear` — the encrypted audit backup (ciphertext), ~25 MB,
   143,463 marker-framed records.
2. `LCMS Audit.csv` — the LogLynx audit report converted to clean rows (the
   PLAINTEXT of the same machine's audit trail), 25,326 records spanning
   2025-05-29 to 2025-12-02, including 4,041 October-2025 rows and the exact
   2025-10-18 window that the `.ear` backup covers. Columns: type, time,
   description, outcome, user, machine, domain, file_information, client_time,
   event_id, index, size. The `index` field is the sequential audit record id.

Because the `.ear` (18 Oct backup) and the report overlap in time, many `.ear`
ciphertext records have a corresponding KNOWN PLAINTEXT row in the CSV, matched
by `index`/timestamp. That is a classic known-plaintext setup.

## Established facts (see FINDINGS.md)

- Record = `[1 type byte][~11-byte header][encrypted body]`, marker `.gCi2k1`.
- The header is a constant zero field; its keystream is already recovered:
  `e3c3b0a401d769dba214d97f` (12 bytes) decrypts the header to zeros. A 97-byte
  candidate keystream decrypts ONLY the header; the body stays entropy ~8.0.
- XOR of two records = entropy ~5.75 with ~14% zeros -> keystream REUSE is
  present (many-time-pad across records), but different record groups have
  different header prefixes, so key material is per-record-group, not one global
  keystream.

## Approach

1. Align ciphertext records to plaintext rows by `index` (the CSV `index` is the
   record number; find the same ordering in the `.ear`, likely encoded near the
   header or by position). For an aligned pair, `keystream = ciphertext XOR
   serialized_plaintext` over the body region.
2. Determine the plaintext record serialization (how the CSV fields are packed
   into bytes before encryption). The recovered keystream from step 1 must be
   consistent across many aligned pairs; that both confirms the serialization
   and yields the reusable keystream/key.
3. If keystream is reused per group, recovering it from a handful of known pairs
   decrypts the whole group. Identify how groups/IVs are keyed (type byte?
   index range?).
4. Verify: decrypt a held-out ciphertext record and check it matches its CSV row
   (same user, timestamp, event_id, index). Only accept a key that reproduces
   known rows exactly.

## Deliverable

A `*.earkey.json` keyspec (cipher + key/keystream + scope; format in
`ear_crypto.py`), or the equivalent algorithm, that decrypts record bodies.
Dropping it next to the `.ear` makes `extract_ear_records.py` output the full
audit trail for any date range and conditions, and push to the server — no PDF
needed ever again.
