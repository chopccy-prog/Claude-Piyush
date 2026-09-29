#!/usr/bin/env python3
"""Carve Java-serialized objects out of a FastObjects page file (objects.dat, .rcy, parts).

MagIC Net stores its data as Java serialized objects inside the FastObjects
pages. This tool finds every serialization stream (magic AC ED 00 05), decodes
it with fo_javaser and writes:

    <res-dir>/java_streams.csv     one row per stream: offset, end, length,
                                   top-level class, ok/error
    <res-dir>/java_classes.csv     class name -> count of decoded objects,
                                   and the field names seen
    <res-dir>/java_objects.jsonl   one JSON document per decoded stream
                                   (use --max-objects to cap)

It also reports class descriptors found WITHOUT a stream header (blobs written
by a shared ObjectOutputStream), so the layout of those can be worked out next.

    python fo_carve.py objects.dat --res-dir carve_out
    python fo_carve.py parts_dat --res-dir carve_out          # a folder of *.partNNNN files
"""
from __future__ import annotations

import argparse
import collections
import csv
import glob
import json
import mmap
import os
import re
import sys

import fo_javaser as J

CLASSDESC_RE = re.compile(rb"\x72\x00([\x01-\x7f])((?:[a-zA-Z_$][a-zA-Z0-9_$]*\.)+[A-Za-z_$][A-Za-z0-9_$]*)")


def iter_sources(path: str):
    if os.path.isdir(path):
        parts = sorted(glob.glob(os.path.join(path, "*.part[0-9]*")))
        if parts:
            for p in parts:
                yield p
            return
        for name in ("objects.dat",):
            if os.path.isfile(os.path.join(path, name)):
                yield os.path.join(path, name)
        return
    yield path


def part_offset(path: str) -> int:
    """Absolute offset of a *.partNNNN file according to its manifest, else 0."""
    d = os.path.dirname(os.path.abspath(path))
    base = os.path.basename(path)
    m = re.match(r"(.+)\.part(\d+)$", base)
    if not m:
        return 0
    manifest = os.path.join(d, m.group(1) + ".parts.json")
    if os.path.isfile(manifest):
        with open(manifest, "r", encoding="utf-8") as f:
            for p in json.load(f).get("parts", []):
                if p["name"] == base:
                    return int(p["offset"])
    return (int(m.group(2)) - 1) * 9 * 1024 * 1024


def carve(path: str, res_dir: str, max_objects: int, verbose: bool) -> dict:
    os.makedirs(res_dir, exist_ok=True)
    streams_csv = open(os.path.join(res_dir, "java_streams.csv"), "w", encoding="utf-8-sig", newline="")
    sw = csv.writer(streams_csv)
    sw.writerow(["file", "offset", "abs_offset", "end", "length", "top_class", "status", "error"])
    objects_out = open(os.path.join(res_dir, "java_objects.jsonl"), "w", encoding="utf-8")
    class_counts: collections.Counter = collections.Counter()
    class_fields: dict = collections.defaultdict(set)
    headerless: collections.Counter = collections.Counter()
    n_streams = n_ok = n_err = n_written = 0
    for src in iter_sources(path):
        base_off = part_offset(src)
        with open(src, "rb") as f, mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
            buf = bytes(mm)
        # 1) full streams
        for off, end, val, err in J.scan(buf):
            n_streams += 1
            top = _top_class(val)
            if err:
                n_err += 1
                sw.writerow([os.path.basename(src), off, base_off + off, end, end - off, top, "error", err])
                continue
            n_ok += 1
            sw.writerow([os.path.basename(src), off, base_off + off, end, end - off, top, "ok", ""])
            _collect(val, class_counts, class_fields)
            if n_written < max_objects:
                objects_out.write(json.dumps({"file": os.path.basename(src), "abs_offset": base_off + off,
                                              "value": J.to_plain(val)}, ensure_ascii=False, default=str) + "\n")
                n_written += 1
        # 2) class descriptors without stream header (0x72 + UTF length + dotted name)
        for m in CLASSDESC_RE.finditer(buf):
            headerless[m.group(2).decode("ascii")] += 1
        if verbose:
            print("%s: %d streams so far (%d ok)" % (os.path.basename(src), n_streams, n_ok), flush=True)
    streams_csv.close()
    objects_out.close()
    with open(os.path.join(res_dir, "java_classes.csv"), "w", encoding="utf-8-sig", newline="") as f:
        w = csv.writer(f)
        w.writerow(["class", "objects_decoded", "fields"])
        for c, n in class_counts.most_common():
            w.writerow([c, n, " ".join(sorted(class_fields.get(c, [])))])
    with open(os.path.join(res_dir, "java_classdesc_without_header.csv"), "w", encoding="utf-8-sig", newline="") as f:
        w = csv.writer(f)
        w.writerow(["class", "descriptors_found"])
        for c, n in headerless.most_common():
            w.writerow([c, n])
    summary = {"source": path, "streams_found": n_streams, "streams_decoded": n_ok, "streams_failed": n_err,
               "objects_written": n_written, "distinct_classes": len(class_counts),
               "classdesc_without_header": sum(headerless.values()),
               "top_classes": class_counts.most_common(30)}
    with open(os.path.join(res_dir, "_carve_summary.json"), "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2, ensure_ascii=False)
    return summary


def _top_class(val) -> str:
    if isinstance(val, J.JObject):
        return val.classname
    if isinstance(val, J.JEnum):
        return val.classname
    if val is None:
        return ""
    return type(val).__name__


def _collect(val, counts, fields, depth=0):
    if depth > 60:
        return
    if isinstance(val, J.JObject):
        counts[val.classname] += 1
        fields[val.classname].update(val.fields.keys())
        for v in val.fields.values():
            _collect(v, counts, fields, depth + 1)
        for ann in val.annotations:
            for v in ann:
                _collect(v, counts, fields, depth + 1)
        if isinstance(val.value, (list, dict)):
            _collect(val.value, counts, fields, depth + 1)
    elif isinstance(val, J.JEnum):
        counts[val.classname] += 1
    elif isinstance(val, list):
        for v in val:
            _collect(v, counts, fields, depth + 1)
    elif isinstance(val, dict):
        for v in val.values():
            _collect(v, counts, fields, depth + 1)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("path", help="objects.dat / data0000.rcy / a folder of *.partNNNN files")
    ap.add_argument("--res-dir", default="carve_out")
    ap.add_argument("--max-objects", type=int, default=200000, help="cap on java_objects.jsonl rows")
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args(argv)
    s = carve(args.path, args.res_dir, args.max_objects, args.verbose)
    print(json.dumps({k: v for k, v in s.items() if k != "top_classes"}, indent=2))
    print("top classes:")
    for c, n in s["top_classes"]:
        print("  %8d  %s" % (n, c))
    return 0


if __name__ == "__main__":
    sys.exit(main())
