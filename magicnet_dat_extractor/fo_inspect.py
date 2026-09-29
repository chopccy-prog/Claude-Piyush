#!/usr/bin/env python3
"""Forensic inspector for a FastObjects database directory (MagIC Net ``objects.dat``).

Run it on the instrument PC (or on a copy of the database folder). It reads the
files **read-only**, never opens them through the database engine, and writes a
small report you can send for analysis without moving hundreds of megabytes:

    python3 fo_inspect.py "C:\\ProgramData\\Metrohm\\MagIC Net\\Data\\IC_Determination\\Magic Net 2025" --res-dir inspect_out

Outputs in ``--res-dir``:

    _inspect_report.json   sizes, header bytes, page-size guess, entropy
                           histogram, string statistics, keyword hits, date
                           and number sniffing, encryption verdict
    strings_top.csv        the most frequent readable strings with counts and
                           first offset (ASCII and UTF-16LE), word-like only
    class_candidates.csv   identifier-looking strings (CamelCase / dotted
                           package names) that are likely schema class or
                           attribute names
    keyword_hits.csv       offsets of the first hits of each MagIC Net keyword
    pages.csv              (with --pages-csv) one row per page: offset,
                           entropy, printable ratio, first 16 bytes hex

Nothing here needs the FastObjects runtime, a dictionary, or a key. It is the
first step of mapping the object layout, in the same spirit as ``ear_inspect``
for the MassLynx container.
"""
from __future__ import annotations

import argparse
import collections
import csv
import json
import math
import mmap
import os
import re
import struct
import sys
from typing import Iterable

DB_FILES = ("objects.dat", "objects.idx")
PAGE_CANDIDATES = (512, 1024, 2048, 4096, 8192, 16384, 32768, 65536)
ASCII_RUN = re.compile(rb"[\x20-\x7e]{6,}")
UTF16_RUN = re.compile(rb"(?:[\x20-\x7e]\x00){6,}")
WORD_LIKE = re.compile(r"[A-Za-z]{4,}")
# Runs of one repeated byte (FastObjects fill/tag bytes 0x41..0x50 print as A..P)
# and strings made of at most two distinct characters are storage noise, not text.
NOISE = re.compile(r"^(.)\1{4,}.?$")
IDENTIFIER = re.compile(r"^(?:[a-z][a-z0-9_]*\.)+[A-Za-z_][A-Za-z0-9_]*$|^[A-Z][a-z0-9]+(?:[A-Z][a-z0-9]+)+$")
DATE7 = struct.Struct("<HBBBBB")

# Words that MUST show up somewhere in a MagIC Net determination database if it
# is stored in clear (schema names, common analytes, UI vocabulary).
KEYWORDS = (
    "Metrohm", "MagIC", "Determination", "Sample", "Method", "Chromatogram",
    "Anion", "Cation", "Conductivity", "Peak", "Result", "Calibration",
    "Fluoride", "Chloride", "Nitrate", "Sulfate", "Sulphate", "Phosphate",
    "Sodium", "Potassium", "Calcium", "Magnesium", "Ammonium",
    "User", "Audit", "Signature", "Column", "Eluent", "Suppressor",
    "Batch", "Position", "Volume", "Dilution", "Ident", "Remark",
)

HISTOGRAM_BINS = ((0.0, 0.5, "zero_or_constant"), (0.5, 3.0, "very_low"),
                  (3.0, 5.0, "low_structured"), (5.0, 6.5, "mixed_text_binary"),
                  (6.5, 7.6, "dense_binary"), (7.6, 8.01, "random_like"))


def entropy(b: bytes) -> float:
    if not b:
        return 0.0
    counts = collections.Counter(b)
    n = len(b)
    return round(-sum(c / n * math.log2(c / n) for c in counts.values()), 3)


def printable_ratio(b: bytes) -> float:
    if not b:
        return 0.0
    return round(sum(1 for c in b if 32 <= c < 127) / len(b), 3)


def _bin_name(e: float) -> str:
    for lo, hi, name in HISTOGRAM_BINS:
        if lo <= e < hi:
            return name
    return "random_like"


def find_db_dir(path: str) -> str:
    """Accept the DB directory, or any file inside it, and return the directory."""
    if os.path.isfile(path):
        path = os.path.dirname(os.path.abspath(path))
    if not os.path.isdir(path):
        raise ValueError("path not found: " + path)
    if os.path.isfile(os.path.join(path, "objects.dat")):
        return path
    # maybe the parent folder that holds several databases: pick the first with objects.dat
    for name in sorted(os.listdir(path)):
        sub = os.path.join(path, name)
        if os.path.isfile(os.path.join(sub, "objects.dat")):
            return sub
    raise ValueError("no objects.dat in " + path)


def read_dbinfo(db_dir: str) -> dict:
    p = os.path.join(db_dir, "DBInfo")
    out = {}
    if os.path.isfile(p):
        with open(p, "r", encoding="latin-1") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    if line.startswith("#") and "=" not in line and len(line) > 2:
                        out.setdefault("comments", []).append(line[1:])
                    continue
                k, _, v = line.partition("=")
                out[k.strip()] = v.strip()
    return out


def guess_page_size(mm, size: int, sample_pages: int = 4000) -> dict:
    """Score candidate page sizes by how repetitive the bytes at page boundaries are.

    A paged store repeats a small vocabulary of header bytes at every page
    start (page type, flags). Random offsets do not. For each candidate we take
    the first 4 bytes at up to ``sample_pages`` boundaries and measure how
    concentrated their distribution is (top-3 share) and how many boundaries
    start an all-zero page.
    """
    scores = {}
    for ps in PAGE_CANDIDATES:
        n = size // ps
        if n < 8:
            continue
        step = max(1, n // sample_pages)
        heads = collections.Counter()
        zero_pages = 0
        taken = 0
        for i in range(0, n, step):
            off = i * ps
            head = bytes(mm[off:off + 4])
            heads[head] += 1
            taken += 1
            if head == b"\x00\x00\x00\x00" and bytes(mm[off:off + 64]) == b"\x00" * 64:
                zero_pages += 1
        top3 = sum(c for _, c in heads.most_common(3)) / max(1, taken)
        scores[ps] = {"boundaries_sampled": taken, "top3_header_share": round(top3, 3),
                      "distinct_headers": len(heads),
                      "zero_page_share": round(zero_pages / max(1, taken), 3),
                      "top_headers": [(h.hex(), c) for h, c in heads.most_common(5)]}
    # Every multiple of the true page size scores as well as the true size
    # (its boundaries are a subset), while sub-multiples score worse (half of
    # their boundaries fall mid-page). So take the SMALLEST candidate whose
    # top-3 share is within 0.05 of the best.
    if not scores:
        return {"page_size_guess": None, "scores": scores}
    best = max(s["top3_header_share"] for s in scores.values())
    cands = [ps for ps, s in scores.items() if s["top3_header_share"] >= best - 0.05]
    return {"page_size_guess": min(cands), "best_top3_share": best, "scores": scores}


def scan_file(path: str, page_size: int | None, pages_csv: str | None,
              max_strings: int, sample_bytes_for_entropy: int = 1 << 20) -> dict:
    size = os.path.getsize(path)
    rep: dict = {"file": os.path.basename(path), "bytes": size,
                 "mib": round(size / 1048576, 3), "exact_mib_multiple": size % 1048576 == 0}
    if size == 0:
        rep["empty"] = True
        return rep
    with open(path, "rb") as f, mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
        rep["header_hex_256"] = bytes(mm[:256]).hex()
        rep["header_ascii_256"] = "".join(chr(c) if 32 <= c < 127 else "." for c in mm[:256])
        # whole-file entropy from evenly spread 1 MiB worth of 4 KiB samples
        samples = bytearray()
        n_samples = max(1, min(256, size // 4096))
        for i in range(n_samples):
            off = (size // n_samples) * i
            samples += mm[off:off + 4096]
        rep["sampled_entropy"] = entropy(bytes(samples))
        rep["sampled_printable_ratio"] = printable_ratio(bytes(samples))
        # last non-zero byte -> how much of the pre-allocated file is used
        last = size
        probe = 1 << 16
        while last > 0:
            chunk = mm[max(0, last - probe):last]
            stripped = chunk.rstrip(b"\x00")
            if stripped:
                last = max(0, last - probe) + len(stripped)
                break
            last -= len(chunk)
        rep["last_nonzero_offset"] = last
        rep["trailing_zero_bytes"] = size - last

        pg = guess_page_size(mm, size)
        rep["page_size_detection"] = pg
        ps = page_size or pg.get("page_size_guess") or 4096
        rep["page_size_used"] = ps

        # per-page entropy histogram (every page, streaming)
        hist = collections.Counter()
        n_pages = size // ps
        zero_pages = 0
        writer = None
        fh = None
        if pages_csv:
            fh = open(pages_csv, "w", encoding="utf-8-sig", newline="")
            writer = csv.writer(fh)
            writer.writerow(["page", "offset", "entropy", "printable_ratio", "head16_hex"])
        for i in range(n_pages):
            off = i * ps
            page = bytes(mm[off:off + ps])
            if page == b"\x00" * ps:
                zero_pages += 1
                e = 0.0
                pr = 0.0
            else:
                e = entropy(page)
                pr = printable_ratio(page)
            hist[_bin_name(e)] += 1
            if writer:
                writer.writerow([i, off, e, pr, page[:16].hex()])
        if fh:
            fh.close()
        rep["pages_total"] = n_pages
        rep["pages_all_zero"] = zero_pages
        rep["page_entropy_histogram"] = dict(hist)

        # strings (ASCII + UTF-16LE), counted, word-like only for the inventory
        ascii_counts: collections.Counter = collections.Counter()
        ascii_first: dict = {}
        utf16_counts: collections.Counter = collections.Counter()
        utf16_first: dict = {}
        total_ascii_runs = 0
        total_utf16_runs = 0
        chunk = 8 << 20
        overlap = 512
        pos = 0
        while pos < size:
            buf = bytes(mm[pos:min(size, pos + chunk + overlap)])
            for m in ASCII_RUN.finditer(buf):
                if m.start() >= chunk:
                    break
                total_ascii_runs += 1
                s = m.group().decode("ascii")
                if WORD_LIKE.search(s) and not NOISE.match(s) and len(set(s)) > 2:
                    ascii_counts[s] += 1
                    ascii_first.setdefault(s, pos + m.start())
            for m in UTF16_RUN.finditer(buf):
                if m.start() >= chunk:
                    break
                total_utf16_runs += 1
                s = m.group().decode("utf-16-le")
                if WORD_LIKE.search(s) and not NOISE.match(s) and len(set(s)) > 2:
                    utf16_counts[s] += 1
                    utf16_first.setdefault(s, pos + m.start())
            pos += chunk
        rep["ascii_runs_total"] = total_ascii_runs
        rep["ascii_wordlike_distinct"] = len(ascii_counts)
        rep["utf16le_runs_total"] = total_utf16_runs
        rep["utf16le_wordlike_distinct"] = len(utf16_counts)
        rep["_strings"] = {"ascii": (ascii_counts, ascii_first), "utf16": (utf16_counts, utf16_first)}

        # keyword hits
        hits = {}
        for kw in KEYWORDS:
            offs = []
            for pat in (kw.encode("ascii"), kw.encode("utf-16-le")):
                start = 0
                while len(offs) < 5:
                    i = mm.find(pat, start)
                    if i < 0:
                        break
                    offs.append((i, "utf16" if pat != kw.encode("ascii") else "ascii"))
                    start = i + 1
            if offs:
                hits[kw] = offs
        rep["keyword_hits"] = {k: len(v) for k, v in hits.items()}
        rep["_keyword_offsets"] = hits

        # date / number sniffing on the sampled bytes (cheap, indicative)
        d7 = 0
        for i in range(0, len(samples) - 7):
            y, mo, d, h, mi, s = DATE7.unpack_from(samples, i)
            if 2000 <= y <= 2035 and 1 <= mo <= 12 and 1 <= d <= 31 and h < 24 and mi < 60 and s < 60:
                d7 += 1
        millis = 0
        doubles = 0
        for i in range(0, len(samples) - 8, 8):
            (v,) = struct.unpack_from("<q", samples, i)
            if 946684800000 <= v <= 2051222400000:      # 2000..2035 in Java epoch ms
                millis += 1
            (x,) = struct.unpack_from("<d", samples, i)
            if x == x and 1e-6 < abs(x) < 1e9 and x not in (0.0,):
                doubles += 1
        rep["sniff_on_sampled_bytes"] = {
            "sample_bytes": len(samples), "date7_like": d7,
            "java_epoch_millis_like": millis, "plausible_doubles_8aligned": doubles}
    return rep


def verdict(rep: dict) -> str:
    e = rep.get("sampled_entropy", 0)
    words = rep.get("ascii_wordlike_distinct", 0) + rep.get("utf16le_wordlike_distinct", 0)
    kws = len(rep.get("keyword_hits", {}))
    if (kws >= 3 and words >= 10) or words > 200:
        return ("PLAINTEXT object store: schema/analyte vocabulary is readable "
                "(%d keywords, %d distinct word-like strings). Not encrypted; decoding "
                "means mapping the FastObjects page/object layout." % (kws, words))
    if e > 7.6 and words < 20:
        return ("ENCRYPTED or compressed: near-random bytes and no readable vocabulary "
                "(entropy %.2f, %d word-like strings)." % (e, words))
    return ("UNDETERMINED: entropy %.2f, %d word-like strings, %d keyword hits. "
            "Inspect strings_top.csv." % (e, words, kws))


def write_outputs(db_dir: str, reports: list[dict], res_dir: str, max_strings: int) -> dict:
    os.makedirs(res_dir, exist_ok=True)
    # strings_top.csv and class_candidates.csv across all files
    rows = []
    classes = []
    kw_rows = []
    for rep in reports:
        strings = rep.pop("_strings", None)
        kwo = rep.pop("_keyword_offsets", {})
        for kw, offs in kwo.items():
            for off, enc in offs:
                kw_rows.append({"file": rep["file"], "keyword": kw, "offset": off, "encoding": enc})
        if not strings:
            continue
        for enc, (counts, first) in strings.items():
            for s, c in counts.most_common(max_strings):
                rows.append({"file": rep["file"], "encoding": enc, "count": c,
                             "first_offset": first[s], "length": len(s), "text": s})
                if IDENTIFIER.match(s.strip()):
                    classes.append({"file": rep["file"], "encoding": enc, "count": c,
                                    "first_offset": first[s], "identifier": s.strip()})
        rep["top_strings_preview"] = [s for s, _ in strings["ascii"][0].most_common(25)] + \
                                     [s for s, _ in strings["utf16"][0].most_common(25)]
        rep["class_candidates_count"] = sum(1 for r in classes if r["file"] == rep["file"])
        rep["verdict"] = verdict(rep)
    rows.sort(key=lambda r: -r["count"])
    with open(os.path.join(res_dir, "strings_top.csv"), "w", encoding="utf-8-sig", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["file", "encoding", "count", "first_offset", "length", "text"])
        w.writeheader()
        w.writerows(rows)
    classes.sort(key=lambda r: -r["count"])
    with open(os.path.join(res_dir, "class_candidates.csv"), "w", encoding="utf-8-sig", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["file", "encoding", "count", "first_offset", "identifier"])
        w.writeheader()
        w.writerows(classes)
    with open(os.path.join(res_dir, "keyword_hits.csv"), "w", encoding="utf-8-sig", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["file", "keyword", "offset", "encoding"])
        w.writeheader()
        w.writerows(kw_rows)
    report = {"db_dir": os.path.abspath(db_dir), "dbinfo": read_dbinfo(db_dir),
              "files": reports,
              "dictionary_candidates": find_dictionaries(db_dir),
              "directory_listing": sorted(_listing(db_dir))}
    with open(os.path.join(res_dir, "_inspect_report.json"), "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)
    return report


def find_dictionaries(db_dir: str, depth: int = 3) -> list[str]:
    """Look near ``db_dir`` for FastObjects *dictionary* databases.

    The class schema of a FastObjects database is itself a database directory
    holding ``_objects.dat`` / ``_objects.idx`` (note the underscore) and is
    usually a sibling or a parent-level folder. Without it no tool, vendor or
    otherwise, can name the classes and attributes stored in ``objects.dat``,
    so it is the first thing to locate on the instrument PC.
    """
    found = []
    root = os.path.abspath(db_dir)
    for _ in range(depth):
        root = os.path.dirname(root)
        if not root or root == os.path.dirname(root):
            break
        for cur, dirs, files in os.walk(root):
            if "_objects.dat" in files:
                found.append(cur)
            # do not descend more than two levels below each root
            if cur[len(root):].count(os.sep) >= 2:
                dirs[:] = []
        if found:
            break
    return sorted(set(found))


def _listing(db_dir: str) -> Iterable[str]:
    for root, _dirs, files in os.walk(db_dir):
        for fn in files:
            p = os.path.join(root, fn)
            yield "%s (%d bytes)" % (os.path.relpath(p, db_dir), os.path.getsize(p))


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("db_dir", help="MagIC Net database folder (holds objects.dat, objects.idx, DBInfo)")
    ap.add_argument("--res-dir", default="inspect_out", help="output folder (default inspect_out)")
    ap.add_argument("--page-size", type=int, default=None, help="force a page size instead of guessing")
    ap.add_argument("--pages-csv", action="store_true", help="also write per-page pages_<file>.csv (large)")
    ap.add_argument("--max-strings", type=int, default=5000, help="rows per encoding in strings_top.csv")
    ap.add_argument("--files", nargs="*", default=None,
                    help="files to scan (default: objects.dat objects.idx and recovery/*.rcy)")
    args = ap.parse_args(argv)
    try:
        db_dir = find_db_dir(args.db_dir)
    except ValueError as e:
        print("error: " + str(e), file=sys.stderr)
        return 2
    targets = args.files
    if not targets:
        targets = [os.path.join(db_dir, n) for n in DB_FILES if os.path.isfile(os.path.join(db_dir, n))]
        rec = os.path.join(db_dir, "recovery")
        if os.path.isdir(rec):
            targets += [os.path.join(rec, n) for n in sorted(os.listdir(rec)) if n.lower().endswith(".rcy")]
        for d in find_dictionaries(db_dir):
            targets.append(os.path.join(d, "_objects.dat"))
    os.makedirs(args.res_dir, exist_ok=True)
    reports = []
    for t in targets:
        print("scanning %s (%d bytes) ..." % (t, os.path.getsize(t)), flush=True)
        pages_csv = os.path.join(args.res_dir, "pages_%s.csv" % os.path.basename(t)) if args.pages_csv else None
        reports.append(scan_file(t, args.page_size, pages_csv, args.max_strings))
    report = write_outputs(db_dir, reports, args.res_dir, args.max_strings)
    for rep in report["files"]:
        print("\n%s: %s bytes, page size guess %s, sampled entropy %s" %
              (rep["file"], rep["bytes"], rep.get("page_size_used"), rep.get("sampled_entropy")))
        print("  entropy histogram : %s" % rep.get("page_entropy_histogram"))
        print("  keyword hits      : %s" % rep.get("keyword_hits"))
        print("  verdict           : %s" % rep.get("verdict"))
    dicts = report.get("dictionary_candidates") or []
    print("\ndictionary databases (_objects.dat) found nearby: %s" % (dicts or "NONE - please locate them"))
    print("report -> %s" % os.path.join(args.res_dir, "_inspect_report.json"))
    print("send _inspect_report.json, strings_top.csv and class_candidates.csv for analysis.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
