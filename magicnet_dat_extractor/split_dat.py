#!/usr/bin/env python3
"""Split a big database file into parts small enough to upload (default 9 MB).

    python split_dat.py "B:\\...\\Magic Net 2025\\objects.dat" --out-dir "B:\\DataAnalysis\\parts"

Writes objects.dat.part0001, objects.dat.part0002, ... plus objects.dat.parts.json
(sizes and SHA-256 per part) so the parts can be verified and joined again with:

    python split_dat.py --join "B:\\DataAnalysis\\parts\\objects.dat.parts.json" --out objects.dat

Pure standard library. Read-only on the source file.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys


def split(src: str, out_dir: str, part_mb: float) -> str:
    part_bytes = int(part_mb * 1024 * 1024)
    os.makedirs(out_dir, exist_ok=True)
    base = os.path.basename(src)
    size = os.path.getsize(src)
    parts = []
    whole = hashlib.sha256()
    with open(src, "rb") as f:
        idx = 1
        while True:
            chunk = f.read(part_bytes)
            if not chunk:
                break
            name = "%s.part%04d" % (base, idx)
            with open(os.path.join(out_dir, name), "wb") as o:
                o.write(chunk)
            whole.update(chunk)
            parts.append({"name": name, "offset": (idx - 1) * part_bytes, "bytes": len(chunk),
                          "sha256": hashlib.sha256(chunk).hexdigest()})
            print("wrote %s (%d bytes)" % (name, len(chunk)), flush=True)
            idx += 1
    manifest = {"source": base, "source_bytes": size, "source_sha256": whole.hexdigest(),
                "part_bytes": part_bytes, "parts": parts}
    mpath = os.path.join(out_dir, base + ".parts.json")
    with open(mpath, "w", encoding="utf-8") as m:
        json.dump(manifest, m, indent=2)
    print("%d parts, manifest -> %s" % (len(parts), mpath))
    return mpath


def join(manifest_path: str, out: str) -> None:
    with open(manifest_path, "r", encoding="utf-8") as m:
        manifest = json.load(m)
    d = os.path.dirname(os.path.abspath(manifest_path))
    whole = hashlib.sha256()
    with open(out, "wb") as o:
        for p in manifest["parts"]:
            with open(os.path.join(d, p["name"]), "rb") as f:
                chunk = f.read()
            if hashlib.sha256(chunk).hexdigest() != p["sha256"]:
                raise SystemExit("checksum mismatch in " + p["name"])
            o.write(chunk)
            whole.update(chunk)
    if whole.hexdigest() != manifest["source_sha256"]:
        raise SystemExit("joined file checksum differs from the source")
    print("joined %d parts -> %s (%d bytes, checksum OK)" % (len(manifest["parts"]), out, manifest["source_bytes"]))


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("src", nargs="?", help="file to split (objects.dat, objects.idx, data0000.rcy)")
    ap.add_argument("--out-dir", default="parts", help="folder for the parts (default: parts)")
    ap.add_argument("--part-mb", type=float, default=9.0, help="part size in MB (default 9, under the 10 MB limit)")
    ap.add_argument("--join", default=None, help="manifest (*.parts.json) to join back")
    ap.add_argument("--out", default=None, help="output file for --join")
    args = ap.parse_args(argv)
    if args.join:
        join(args.join, args.out or os.path.basename(args.join).replace(".parts.json", ""))
        return 0
    if not args.src:
        ap.error("give a file to split, or --join")
    split(args.src, args.out_dir, args.part_mb)
    return 0


if __name__ == "__main__":
    sys.exit(main())
