"""Convert a MassLynx LogLynx audit-trail report (PDF text) into clean CSV.

LogLynx can print/export the audit trail to PDF. This turns that report into one
CSV row per audit event, with the columns a reviewer/client needs:

    type, time, description, outcome, user, machine, domain,
    file_information, client_time, event_id, index, size

It works on the extracted TEXT of the PDF (use `pdftotext report.pdf out.txt`,
or pdfplumber/pypdf/pymupdf to dump text first), because that keeps this tool
dependency-free. The parser is anchored on the fixed fields (the two
DD-MM-YYYY HH:MM:SS timestamps, the machine/domain tokens, the trailing
event_id/index/size integers), so it tolerates the free-text description and
optional File Information column.

Usage
-----
    # 1) get the report text (any one of):
    pdftotext -layout "LCMS Audit.pdf" audit_full.txt
    python3 -c "import pdfplumber,sys; \
        print('\\n'.join((p.extract_text() or '') for p in \
        pdfplumber.open('LCMS Audit.pdf').pages))" > audit_full.txt

    # 2) convert to CSV
    python3 pdf_audit_to_csv.py audit_full.txt audit.csv
"""
from __future__ import annotations

import argparse
import csv
import re
import sys

DT = r"\d{2}-\d{2}-\d{4} \d{2}:\d{2}:\d{2}"

# Known event "Type" values. Multi-word types first so the regex prefers them.
TYPES = (
    r"(?:Log in|Log out|Permission|Audit|Configuration|Report|System|Security|"
    r"Instrument|Sample|Method|Backup|Restore|Data|File|Print|Sign[A-Za-z]*|"
    r"Error|Warning|Information|Event)"
)

OUTCOMES = {
    "Allowed", "DENIED", "Denied", "Succeeded", "Success", "Failed", "Failure",
    "Aborted", "Cancelled", "Canceled",
}

FIELDNAMES = [
    "type", "time", "description", "outcome", "user", "machine", "domain",
    "file_information", "client_time", "event_id", "index", "size",
]


def clean_text(txt: str) -> str:
    """Strip repeated page banners and header rows, collapse whitespace."""
    txt = re.sub(
        r"MassLynx MassLynx V4\.2 SCN\d+ Page \d+ of \d+ Printed by:.*?"
        r"Query: Results from \([^)]*\)",
        " ", txt,
    )
    txt = re.sub(
        r"Type Time Description Outcome User Machine Domain File Information "
        r"Client Time ID Index Size Object/File Time Verify User Verify Domain "
        r"Base file Diagnostics",
        " ", txt,
    )
    return re.sub(r"\s+", " ", txt).strip()


def parse(txt: str, machine_hint: str = "MASSLYNX-PC") -> list[dict]:
    txt = clean_text(txt)
    rec_re = re.compile(
        rf"({TYPES}) ({DT}) (.*?) ({DT}) (\d+) (\d+) (\d+)"
    )
    rows = []
    for m in rec_re.finditer(txt):
        typ, time, mid, ctime, idv, index, size = m.groups()
        desc = out = user = machine = domain = fileinfo = ""
        # Anchor on "<machine> <domain>" to split Description/Outcome/User from
        # the optional File Information that follows.
        am = re.search(rf"(.*?) ({re.escape(machine_hint)}) (\S+)(.*)$", mid)
        if am:
            left, machine, domain, fileinfo = (
                am.group(1), am.group(2), am.group(3), am.group(4).strip()
            )
            toks = left.split(" ")
            oi = next((i for i in range(len(toks) - 1, -1, -1)
                       if toks[i] in OUTCOMES), None)
            if oi is not None:
                desc = " ".join(toks[:oi])
                out = toks[oi]
                user = " ".join(toks[oi + 1:])
            else:
                desc = left
        else:
            desc = mid
        rows.append({
            "type": typ, "time": time, "description": desc, "outcome": out,
            "user": user, "machine": machine, "domain": domain,
            "file_information": fileinfo, "client_time": ctime,
            "event_id": idv, "index": index, "size": size,
        })
    return rows


def write_csv(rows: list[dict], out_path: str) -> None:
    with open(out_path, "w", newline="", encoding="utf-8-sig") as fh:
        w = csv.DictWriter(fh, fieldnames=FIELDNAMES, extrasaction="ignore")
        w.writeheader()
        w.writerows(rows)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("input", help="extracted PDF text file")
    ap.add_argument("output", nargs="?", help="output CSV (default: alongside)")
    ap.add_argument("--machine", default="MASSLYNX-PC",
                    help="machine name anchor (default MASSLYNX-PC)")
    args = ap.parse_args(argv)

    with open(args.input, "r", encoding="utf-8", errors="replace") as fh:
        txt = fh.read()
    rows = parse(txt, args.machine)
    if not rows:
        print("no records parsed; check the input text", file=sys.stderr)
        return 1
    out = args.output or (args.input.rsplit(".", 1)[0] + ".csv")
    write_csv(rows, out)
    idxs = [int(r["index"]) for r in rows if r["index"].isdigit()]
    print("parsed %d records (index %d..%d) -> %s" %
          (len(rows), min(idxs), max(idxs), out))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
