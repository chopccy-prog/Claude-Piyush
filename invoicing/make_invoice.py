#!/usr/bin/env python3
"""Generate premium, consistent PDF invoices from small JSON files.

Layout
------
  data/seller.json            who is billing (name, address, PAN, bank, ...)
  data/clients/<id>.json      who is billed (one file per client)
  data/invoices/<no>.json     one file per invoice (items, advances, notes)
  templates/invoice.html.j2   the single shared design
  output/                     generated HTML + PDF, plus register.csv

Usage
-----
  python make_invoice.py data/invoices/SKS-2026-27-001.json
  python make_invoice.py --all                 # every invoice in data/invoices
  python make_invoice.py --new proventech      # scaffold the next invoice number
  python make_invoice.py --data examples ...   # use another data folder

PDF rendering uses Chromium via Playwright (Python package if installed,
otherwise Node's `playwright`). Without either, open the HTML in Chrome and
"Print -> Save as PDF" (A4, margins: none, background graphics: on).
"""
from __future__ import annotations

import argparse
import base64
import csv
import datetime as dt
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, StrictUndefined

ROOT = Path(__file__).resolve().parent
PLACEHOLDER = re.compile(r"\[(?:ADD|TBD)[^\]]*\]")

# --------------------------------------------------------------------------
# Indian number formatting and amount-in-words
# --------------------------------------------------------------------------
ONES = ("", "One", "Two", "Three", "Four", "Five", "Six", "Seven", "Eight",
        "Nine", "Ten", "Eleven", "Twelve", "Thirteen", "Fourteen", "Fifteen",
        "Sixteen", "Seventeen", "Eighteen", "Nineteen")
TENS = ("", "", "Twenty", "Thirty", "Forty", "Fifty", "Sixty", "Seventy",
        "Eighty", "Ninety")


def _two(n: int) -> str:
    return ONES[n] if n < 20 else (TENS[n // 10] + (" " + ONES[n % 10] if n % 10 else ""))


def _three(n: int) -> str:
    h, r = divmod(n, 100)
    parts = []
    if h:
        parts.append(ONES[h] + " Hundred")
    if r:
        parts.append(_two(r))
    return " ".join(parts)


def words_inr(amount: float) -> str:
    rupees = int(round(amount * 100)) // 100
    paise = int(round(amount * 100)) % 100
    if rupees == 0:
        text = "Zero"
    else:
        parts = []
        crore, rem = divmod(rupees, 10_000_000)
        lakh, rem = divmod(rem, 100_000)
        thousand, rem = divmod(rem, 1000)
        if crore:
            parts.append(words_inr(crore).replace("Rupees ", "").replace(" Only", "") + " Crore")
        if lakh:
            parts.append(_two(lakh) + " Lakh")
        if thousand:
            parts.append(_two(thousand) + " Thousand")
        if rem:
            parts.append(_three(rem))
        text = " ".join(parts)
    out = "Rupees " + text
    if paise:
        out += " and " + _two(paise) + " Paise"
    return out + " Only"


def inr(amount: float, symbol: bool = True) -> str:
    neg = amount < 0
    amount = abs(amount)
    whole, frac = f"{amount:.2f}".split(".")
    if len(whole) > 3:
        head, tail = whole[:-3], whole[-3:]
        head = re.sub(r"(\d)(?=(\d{2})+$)", r"\1,", head)
        whole = head + "," + tail
    s = f"{whole}.{frac}"
    if symbol:
        s = "₹" + s
    return ("−" if neg else "") + s


def fmt_date(value: str) -> str:
    return dt.date.fromisoformat(value).strftime("%d %b %Y")


# --------------------------------------------------------------------------
def load(path: Path) -> dict:
    with path.open(encoding="utf-8") as fh:
        return json.load(fh)


def build_context(inv_path: Path, data_dir: Path) -> dict:
    inv = load(inv_path)
    seller = load(data_dir / "seller.json")
    client = load(data_dir / "clients" / f"{inv['client']}.json")

    issue = dt.date.fromisoformat(inv["date"])
    terms = inv.get("payment_terms_days", seller.get("default_payment_terms_days", 15))
    due = dt.date.fromisoformat(inv["due_date"]) if inv.get("due_date") else issue + dt.timedelta(days=terms)

    items = []
    subtotal = 0.0
    for it in inv["items"]:
        qty = float(it.get("qty", 1))
        rate = float(it["rate"])
        amt = round(qty * rate, 2)
        subtotal += amt
        items.append({**it, "qty": qty, "rate": rate, "amount": amt})

    taxes = []
    gst = seller.get("gst", {})
    if gst.get("registered"):
        same_state = gst.get("state_code") == client.get("state_code")
        rate = float(inv.get("gst_rate", gst.get("rate", 18)))
        if same_state:
            taxes = [("CGST", rate / 2), ("SGST", rate / 2)]
        else:
            taxes = [("IGST", rate)]
        taxes = [{"label": f"{n} @ {r:g}%", "amount": round(subtotal * r / 100, 2)} for n, r in taxes]
    total = round(subtotal + sum(t["amount"] for t in taxes), 2)

    adjustments = []
    for adj in inv.get("adjustments", []):
        adjustments.append({**adj, "amount": float(adj["amount"])})
    balance = round(total - sum(a["amount"] for a in adjustments), 2)

    signature_src = ""
    sig = seller.get("signature_image")
    if sig:
        sig_path = (ROOT / sig) if not Path(sig).is_absolute() else Path(sig)
        if sig_path.exists():
            mime = "image/png" if sig_path.suffix.lower() == ".png" else "image/jpeg"
            signature_src = f"data:{mime};base64," + base64.b64encode(sig_path.read_bytes()).decode()
        else:
            signature_src = sig  # URL

    return {
        "signature_src": signature_src,
        "seller": seller,
        "client": client,
        "inv": inv,
        "issue_date": fmt_date(inv["date"]),
        "due_date": due.strftime("%d %b %Y"),
        "items": items,
        "subtotal": subtotal,
        "taxes": taxes,
        "total": total,
        "adjustments": adjustments,
        "balance": balance,
        "balance_words": words_inr(balance),
        "fmt_date": fmt_date,
    }


def render_html(ctx: dict) -> str:
    env = Environment(loader=FileSystemLoader(ROOT / "templates"),
                      undefined=StrictUndefined, autoescape=True)
    env.filters["inr"] = inr
    env.filters["num"] = lambda v: inr(v, symbol=False)
    env.filters["date"] = fmt_date
    env.filters["ph"] = highlight_placeholder
    return env.get_template("invoice.html.j2").render(**ctx)


def highlight_placeholder(value):
    from markupsafe import Markup, escape
    text = str(escape(value))
    return Markup(PLACEHOLDER.sub(lambda m: f'<span class="ph">{m.group(0)}</span>', text))


def html_to_pdf(html_path: Path, pdf_path: Path) -> bool:
    try:
        from playwright.sync_api import sync_playwright  # type: ignore
        with sync_playwright() as p:
            b = p.chromium.launch()
            pg = b.new_page()
            pg.goto(html_path.as_uri())
            pg.wait_for_load_state("networkidle")
            pg.pdf(path=str(pdf_path), format="A4", print_background=True,
                   margin={"top": "0", "right": "0", "bottom": "0", "left": "0"})
            b.close()
        return True
    except ImportError:
        pass
    if shutil.which("node"):
        r = subprocess.run(["node", str(ROOT / "render_pdf.js"), str(html_path), str(pdf_path)],
                           capture_output=True, text=True)
        if r.returncode == 0:
            return True
        print(r.stderr.strip(), file=sys.stderr)
    return False


def update_register(out_dir: Path, ctx: dict) -> None:
    reg = out_dir / "register.csv"
    rows = []
    if reg.exists():
        with reg.open(newline="", encoding="utf-8") as fh:
            rows = [r for r in csv.DictReader(fh) if r["invoice_no"] != ctx["inv"]["number"]]
    rows.append({
        "invoice_no": ctx["inv"]["number"],
        "date": ctx["inv"]["date"],
        "client": ctx["client"]["name"],
        "title": ctx["inv"]["title"],
        "invoice_value": f"{ctx['total']:.2f}",
        "adjusted": f"{sum(a['amount'] for a in ctx['adjustments']):.2f}",
        "balance_due": f"{ctx['balance']:.2f}",
        "status": ctx["inv"].get("status", "Issued"),
    })
    rows.sort(key=lambda r: r["invoice_no"])
    with reg.open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)


def generate(inv_path: Path, data_dir: Path, out_dir: Path) -> None:
    ctx = build_context(inv_path, data_dir)
    html = render_html(ctx)
    out_dir.mkdir(parents=True, exist_ok=True)
    stem = ctx["inv"]["number"].replace("/", "-")
    html_path = out_dir / f"{stem}.html"
    pdf_path = out_dir / f"{stem}.pdf"
    html_path.write_text(html, encoding="utf-8")
    ok = html_to_pdf(html_path, pdf_path)
    update_register(out_dir, ctx)
    missing = sorted(set(PLACEHOLDER.findall(html)))
    print(f"{ctx['inv']['number']}: balance {inr(ctx['balance'])} -> "
          f"{pdf_path if ok else html_path}")
    if missing:
        print(f"  ! still contains placeholders: {', '.join(missing)}")


def next_number(data_dir: Path, seller: dict, date: dt.date) -> str:
    fy_start = date.year if date.month >= 4 else date.year - 1
    fy = f"{fy_start}-{str(fy_start + 1)[-2:]}"
    prefix = f"{seller['invoice_prefix']}/{fy}/"
    seen = [0]
    for p in (data_dir / "invoices").glob("*.json"):
        n = load(p).get("number", "")
        if n.startswith(prefix):
            seen.append(int(n.rsplit("/", 1)[1]))
    return f"{prefix}{max(seen) + 1:03d}"


def scaffold(data_dir: Path, client_id: str) -> None:
    seller = load(data_dir / "seller.json")
    today = dt.date.today()
    number = next_number(data_dir, seller, today)
    path = data_dir / "invoices" / f"{number.replace('/', '-')}.json"
    path.write_text(json.dumps({
        "number": number,
        "date": today.isoformat(),
        "client": client_id,
        "title": "[ADD assignment title]",
        "reference": "Independent Contractor Service Agreement",
        "items": [{"description": "[ADD description]", "details": [], "sac": "998313",
                   "qty": 1, "unit": "Assignment", "rate": 0}],
        "adjustments": [],
        "notes": []
    }, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"created {path}")


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("invoices", nargs="*", type=Path)
    ap.add_argument("--all", action="store_true")
    ap.add_argument("--new", metavar="CLIENT_ID")
    ap.add_argument("--data", type=Path, default=ROOT / "data")
    ap.add_argument("--out", type=Path, default=ROOT / "output")
    a = ap.parse_args()
    if a.new:
        return scaffold(a.data, a.new)
    paths = sorted((a.data / "invoices").glob("*.json")) if a.all else a.invoices
    if not paths:
        ap.error("give invoice JSON files, --all, or --new CLIENT_ID")
    for p in paths:
        generate(p, a.data, a.out)


if __name__ == "__main__":
    main()
