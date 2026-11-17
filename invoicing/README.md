# Invoicing

Makes invoices from small JSON files using one shared design. Every invoice
comes out with the same layout, numbering and terms.

```
invoicing/
  make_invoice.py            generator (HTML -> PDF via Chromium/Playwright)
  render_pdf.js              Node fallback for PDF rendering
  templates/invoice.html.j2  the design (edit once, applies to all invoices)
  examples/                  dummy data showing the file formats
  data/      (git-ignored)   real data: seller.json, clients/*.json, invoices/*.json
  output/    (git-ignored)   generated .html/.pdf + register.csv
```

`data/` and `output/` are git-ignored because this repository is public and
those files hold PAN, bank details and client amounts. Back them up somewhere
private, such as Google Drive.

## Raising the next invoice

```bash
pip install jinja2
python make_invoice.py --new proventech          # creates data/invoices/SKS-2026-27-003.json
# edit that file: title, items, rate, adjustments (advances), notes
python make_invoice.py data/invoices/SKS-2026-27-003.json
```

* **Numbering:** `<prefix>/<financial year>/<serial>`, e.g. `SKS/2026-27/001`.
  The serial restarts each April.
* **Advances:** list them under `adjustments`. They are subtracted from the
  invoice value to give the balance due.
* **GST:** set `seller.gst.registered` to `true` and fill in `gstin` and
  `state_code`. The title then changes to "Tax Invoice". CGST+SGST is used when
  the client is in the same state, and IGST otherwise.
* **Signature:** set `seller.signature_image` to the path or URL of a
  transparent PNG.
* **Placeholders:** text like `[ADD PAN]` shows up highlighted in yellow, and
  the script warns you until you replace it.
* **Register:** `output/register.csv` keeps a list of every invoice you
  generate. Change an invoice's `status`, e.g. to `"Paid"`, and generate it
  again to update the list.

You need Chromium to get a PDF, through the Python `playwright` package or
Node's `playwright`. Without either, the script still writes the HTML. Open it
in Chrome and use Print → Save as PDF, with A4, margins None and Background
graphics on.
