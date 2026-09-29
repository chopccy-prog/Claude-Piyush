#!/usr/bin/env python3
"""Quick forensic report on a .ear file (no extraction, no key needed).

    python3 ear_inspect.py Backup_18102025.ear

Prints the container framing, entropy, and the encrypted/compressed verdict. Use
it to confirm for yourself, or show a client, what the file is.
"""
from __future__ import annotations

import argparse
import sys

import ear_format


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("path", help="path to the .ear file")
    args = ap.parse_args(argv)

    with open(args.path, "rb") as f:
        data = f.read()
    r = ear_format.analyze(data)

    print(f"file                : {args.path}")
    print(f"size                : {r.size:,} bytes")
    print(f"framing marker      : {r.marker!r}  x{r.marker_count:,}")
    print(f"payload chunks      : {r.chunk_count:,} "
          f"(len min {r.chunk_len_min}, mean {r.chunk_len_mean}, "
          f"max {r.chunk_len_max})")
    print(f"whole-file entropy  : {r.whole_entropy} / 8.0")
    print(f"payload entropy     : {r.payload_entropy_no_marker} / 8.0")
    print(f"\nverdict: {r.verdict}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
