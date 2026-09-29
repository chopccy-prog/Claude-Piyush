#!/usr/bin/env python3
"""Forensic inspector for a MassLynx .EAR backup file.

This does NOT decrypt anything. It reports the statistical fingerprint of the
file so you can confirm for yourself what it is: a compressed/encrypted,
proprietary Waters backup blob that is not meant to be parsed directly.

Run it on your own .ear file:

    python tools/inspect_ear.py /path/to/Backup_18102025.ear

It prints:
  * file size and any recognizable container magic bytes (ZIP/GZIP/SQLite/...)
  * Shannon entropy of the whole file and of several blocks
  * the most common byte values
An entropy near 8.0 bits/byte with no known magic number means the payload is
compressed or encrypted and must be read through Waters' own supported export
tools, not reverse-engineered.
"""
from __future__ import annotations

import argparse
import collections
import math
import sys

MAGICS = {
    b"PK\x03\x04": "ZIP archive",
    b"PK\x05\x06": "ZIP archive (empty)",
    b"\x1f\x8b": "GZIP stream",
    b"BZh": "BZIP2 stream",
    b"\xfd7zXZ\x00": "XZ stream",
    b"7z\xbc\xaf\x27\x1c": "7-Zip archive",
    b"Rar!\x1a\x07": "RAR archive",
    b"SQLite format 3\x00": "SQLite database",
    b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1": "MS OLE / Compound File",
    b"%PDF": "PDF document",
    b"<?xml": "XML text",
}


def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = collections.Counter(data)
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("path", help="path to the .ear file")
    args = ap.parse_args(argv)

    with open(args.path, "rb") as fh:
        data = fh.read()

    print(f"file: {args.path}")
    print(f"size: {len(data):,} bytes")

    head = data[:64]
    found = next((name for magic, name in MAGICS.items()
                  if data.startswith(magic)), None)
    print(f"magic: {found or 'none recognized (raw/proprietary blob)'}")
    print("first 16 bytes: " + " ".join(f"{b:02x}" for b in head[:16]))

    print(f"whole-file entropy: {entropy(data):.4f} bits/byte (max 8.0)")
    block = 65536
    offsets = [0, len(data) // 4, len(data) // 2, max(0, len(data) - block)]
    for off in offsets:
        seg = data[off:off + block]
        print(f"  block @ {off:>12,}: entropy {entropy(seg):.3f}")

    common = collections.Counter(data).most_common(8)
    print("most common bytes: " +
          ", ".join(f"0x{b:02x}={c}" for b, c in common))

    ent = entropy(data)
    print()
    if found in (None,) and ent > 7.5:
        print("VERDICT: high entropy, no known container magic. This is a "
              "compressed or encrypted proprietary blob. Do not attempt to "
              "parse it directly; use MassLynx/LogLynx supported exports "
              "instead (see docs/EAR_FORMAT_ANALYSIS.md).")
    elif found:
        print(f"VERDICT: looks like a {found}; try the matching standard tool.")
    else:
        print("VERDICT: lower entropy than expected for encryption; inspect "
              "the bytes above for structure.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
