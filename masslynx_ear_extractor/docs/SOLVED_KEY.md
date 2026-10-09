# SOLVED: the MassLynx `.EAR` body cipher

The record-body encryption has been identified and a working key recovered and
verified.

## Cipher parameters

| Parameter | Value |
|---|---|
| Algorithm | RC2 (RFC 2268) |
| Mode | CBC |
| Key | `6b6bf3aa3a` (5 bytes) |
| Effective key length | 40 bits (export-grade RC2) |
| IV | `0000000000000000` (8 zero bytes) |

The key was recovered by a separate agent via an exhaustive 40-bit search using
the PDF-derived known plaintext; it was then verified here by applying it to the
`.ear`.

## Frame / body model (see `ear_frames.py`)

- 524-byte prefix, then 134,796 variable-length frames, no trailer.
- Frame at offset S, length `L = X12(S)` (XOR of three LE uint32 at S).
- Marker `.gCi2k1` at S+21:S+28.
- Encrypted body = `data[S+32 : S+32 + ((L-36)&~7)]`.
- Frame ordinal (1-based) == audit index.

## Verification

- The RC2 implementation (`rc2.py`) passes the RFC 2268 test vectors.
- Applying the key decrypts bodies to readable MassLynx audit content: ASCII
  strings ("Micromass", "MASSLYNX-PC") and UTF-16LE strings ("Regulated Access",
  user names such as "Administrator").
- The frame walk accounts for all 25,539,334 bytes in exactly 134,796 frames.

## Keyspec

```json
{
  "format": "ear-extractor/keyspec",
  "cipher": "rc2",
  "key_hex": "6b6bf3aa3a",
  "effective_bits": 40,
  "iv_hex": "0000000000000000",
  "scope": "per-chunk",
  "strip_marker": true
}
```

## How to produce the CSV

Run the standalone decoder (no external libraries):

```
python ear_decode.py "Backup_18102025.ear" --key 6b6bf3aa3a --out LCMS_EAR.csv
python ear_decode.py "Backup_18102025.ear" --key 6b6bf3aa3a --out oct.csv \
    --from-date 2025-10-01 --to-date 2025-10-31 --where user=sachingade
```

## Remaining calibration

The decryption is complete. The one open item is mapping the decrypted body's
embedded fields (ASCII + UTF-16LE strings, binary FILETIME timestamp, numeric
ids) to the exact 12-column audit schema. Validate the mapping by matching a few
decrypted rows to the known LogLynx CSV on `index`, then freeze the field offsets
in the parser.
