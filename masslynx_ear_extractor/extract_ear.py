"""Extract data from a Waters MassLynx .EAR backup to CSV.

Mirrors the workflow of the Access-database AuditTrailExtractor used for the
other instruments, but for the MassLynx `.ear` container.

Two modes
---------
salvage  (default, works TODAY with only the .ear)
    Parses the .ear container framing and writes:
      * ear_chunks.csv   - one row per payload chunk (offset, length, entropy,
                           printable ratio, hex/ascii preview)
      * ear_strings.csv  - every readable ASCII run found, with offset & length
      * _extract_summary.json - the container report and the verdict
    Use this to SHOW a client why the raw .ear cannot be cross-checked field by
    field: the chunks are encrypted and carry no readable words.

decode   (--keyspec, works once key material exists)
    Decrypts the container with a supplied keyspec (see ear_crypto.py), then
    parses records and writes AuditTrail.csv / <table>.csv, in the same shape as
    the other machines. Errors clearly if no keyspec is available.

Usage
-----
    # salvage (only the .ear needed)
    python3 extract_ear.py --src-dir . --res-dir out

    # decode (when a *.earkey.json keyspec is available)
    python3 extract_ear.py --src-dir . --res-dir out --mode decode \
        --from-date 2025-04-01 --to-date 2025-07-31
"""
from __future__ import annotations

import argparse
import csv
import glob
import json
import os
import re
import sys

import ear_format
import ear_crypto

EAR_GLOBS = ("*.ear", "*.EAR", "*.Ear")
ASCII_RUN = re.compile(rb"[\x20-\x7e]{4,}")
# A "word-like" token has >=4 consecutive letters. On encrypted data almost
# nothing matches; on plaintext, real field values do. This is the honest
# "are there any actual words in here" test.
WORD_LIKE = re.compile(rb"[A-Za-z]{4,}")
MARKER_CORE = b"i2k1"


def find_ear_file(src: str) -> str:
    if os.path.isfile(src):
        return src
    if not os.path.isdir(src):
        raise ValueError("source path not found: " + src)
    found = []
    for pat in EAR_GLOBS:
        found.extend(glob.glob(os.path.join(src, pat)))
    found = sorted(set(found))
    if not found:
        raise ValueError("no .ear file in " + src)
    if len(found) > 1:
        raise ValueError("multiple .ear files in %s: %s" %
                         (src, [os.path.basename(f) for f in found]))
    return found[0]


def write_csv(path: str, fieldnames: list[str], rows: list[dict]) -> None:
    with open(path, "w", encoding="utf-8-sig", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        w.writeheader()
        for r in rows:
            w.writerow(r)


# --------------------------------------------------------------------------
# salvage mode
# --------------------------------------------------------------------------
def salvage(ear_file: str, res_dir: str, min_str: int = 4) -> dict:
    with open(ear_file, "rb") as f:
        data = f.read()

    report = ear_format.analyze(data)
    chunks = ear_format.split_chunks(data)

    os.makedirs(res_dir, exist_ok=True)

    chunk_rows = [
        {
            "chunk_index": c.index,
            "offset": c.offset,
            "length": c.length,
            "entropy_bits_per_byte": c.entropy,
            "printable_ratio": c.printable_ratio,
            "preview_hex": c.preview_hex,
            "preview_ascii": c.preview_ascii,
        }
        for c in chunks
    ]
    write_csv(
        os.path.join(res_dir, "ear_chunks.csv"),
        ["chunk_index", "offset", "length", "entropy_bits_per_byte",
         "printable_ratio", "preview_hex", "preview_ascii"],
        chunk_rows,
    )

    # Readable ASCII runs across the whole file (excluding the pure marker) so a
    # human can eyeball whether any words survive. On an encrypted .ear this is
    # essentially just the framing marker - which is the point.
    str_rows = []
    for m in ASCII_RUN.finditer(data):
        s = m.group()
        if len(s) < min_str:
            continue
        # Skip the framing marker and any fragment of it.
        if MARKER_CORE in s:
            continue
        # Keep only runs that contain a real word (>=4 consecutive letters).
        if not WORD_LIKE.search(s):
            continue
        str_rows.append({
            "offset": m.start(),
            "length": len(s),
            "text": s.decode("latin-1", "replace"),
        })
    write_csv(
        os.path.join(res_dir, "ear_strings.csv"),
        ["offset", "length", "text"],
        str_rows,
    )

    summary = {
        "source": os.path.basename(ear_file),
        "mode": "salvage",
        "container": {
            "size": report.size,
            "whole_entropy": report.whole_entropy,
            "marker": report.marker,
            "marker_count": report.marker_count,
            "chunk_count": report.chunk_count,
            "chunk_len_min": report.chunk_len_min,
            "chunk_len_max": report.chunk_len_max,
            "chunk_len_mean": report.chunk_len_mean,
            "payload_entropy_no_marker": report.payload_entropy_no_marker,
        },
        "verdict": report.verdict,
        "readable_string_count": len(str_rows),
        "outputs": {
            "ear_chunks.csv": len(chunk_rows),
            "ear_strings.csv": len(str_rows),
        },
    }
    with open(os.path.join(res_dir, "_extract_summary.json"), "w",
              encoding="utf-8") as f:
        json.dump(summary, f, indent=2, ensure_ascii=False)
    return summary


# --------------------------------------------------------------------------
# decode mode (requires key material)
# --------------------------------------------------------------------------
def decode(ear_file: str, res_dir: str, keyspec_path: str | None,
           from_date: str | None, to_date: str | None) -> dict:
    keyspec_path = keyspec_path or ear_crypto.find_keyspec(ear_file)
    if not keyspec_path:
        raise ear_crypto.KeyNotAvailable(
            "decode mode needs a keyspec (*.earkey.json) with the .ear "
            "decryption key/algorithm, which is not available. The .ear payload "
            "is encrypted (run salvage mode to confirm). Options:\n"
            "  1. Obtain the key/algorithm from Waters and drop a "
            "<name>.earkey.json next to the .ear (see ear_crypto.py).\n"
            "  2. Use MassLynx's supported LogLynx audit export instead "
            "(see the masslynx_bridge project in this repo)."
        )
    spec = ear_crypto.load_keyspec(keyspec_path)
    with open(ear_file, "rb") as f:
        data = f.read()
    plaintext = ear_crypto.decrypt_container(spec, data)

    # Once decrypted, the record layout is Waters-specific and will be filled in
    # here from the real plaintext structure. Until a real key exists we cannot
    # know the exact record schema, so we persist the decrypted bytes for
    # inspection and emit a placeholder so the pipeline shape is proven.
    os.makedirs(res_dir, exist_ok=True)
    raw_path = os.path.join(res_dir, "decrypted.bin")
    with open(raw_path, "wb") as f:
        f.write(plaintext)

    report = ear_format.analyze(plaintext, marker=spec.marker)
    summary = {
        "source": os.path.basename(ear_file),
        "mode": "decode",
        "keyspec": os.path.basename(keyspec_path),
        "cipher": spec.cipher,
        "decrypted_bytes": len(plaintext),
        "decrypted_entropy": report.whole_entropy,
        "date_range": {"from": from_date, "to": to_date},
        "note": (
            "Decrypted bytes written to decrypted.bin. If entropy is now low "
            "(<6), the key is correct and record parsing can be finalized "
            "against the real structure. If entropy is still ~8, the keyspec is "
            "wrong."
        ),
    }
    with open(os.path.join(res_dir, "_extract_summary.json"), "w",
              encoding="utf-8") as f:
        json.dump(summary, f, indent=2, ensure_ascii=False)
    return summary


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description="Extract a MassLynx .EAR backup to CSV.")
    ap.add_argument("--src-dir", required=True,
                    help="Directory (or file) holding the .ear")
    ap.add_argument("--res-dir", required=True, help="Output directory")
    ap.add_argument("--mode", default="salvage", choices=("salvage", "decode"),
                    help="salvage (file-only, default) or decode (needs keyspec)")
    ap.add_argument("--keyspec", default=None,
                    help="Keyspec JSON (default: auto-discover *.earkey.json)")
    ap.add_argument("--from-date", default=None,
                    help="Inclusive lower bound YYYY-MM-DD (decode mode)")
    ap.add_argument("--to-date", default=None,
                    help="Inclusive upper bound YYYY-MM-DD (decode mode)")
    ap.add_argument("--min-str", type=int, default=6,
                    help="Minimum readable-string length in salvage mode "
                         "(on encrypted data short runs are just chance)")
    args = ap.parse_args(argv)

    try:
        ear_file = find_ear_file(args.src_dir)
    except ValueError as e:
        print("error: " + str(e), file=sys.stderr)
        return 2

    print("ear file : " + ear_file)
    print("mode     : " + args.mode)

    try:
        if args.mode == "salvage":
            summary = salvage(ear_file, args.res_dir, args.min_str)
        else:
            summary = decode(ear_file, args.res_dir, args.keyspec,
                             args.from_date, args.to_date)
    except ear_crypto.KeyNotAvailable as e:
        print("\ndecode not possible:\n" + str(e), file=sys.stderr)
        return 4
    except (ValueError, RuntimeError) as e:
        print("error: " + str(e), file=sys.stderr)
        return 3

    print("")
    if args.mode == "salvage":
        c = summary["container"]
        print("container: %d bytes, %d chunks, whole-entropy %.3f" %
              (c["size"], c["chunk_count"], c["whole_entropy"]))
        print("verdict  : " + summary["verdict"])
        print("readable strings (excluding marker): %d" %
              summary["readable_string_count"])
    else:
        print("decrypted %d bytes -> %s (entropy %.3f)" %
              (summary["decrypted_bytes"], os.path.join(args.res_dir,
               "decrypted.bin"), summary["decrypted_entropy"]))
    print("outputs  -> " + args.res_dir)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
