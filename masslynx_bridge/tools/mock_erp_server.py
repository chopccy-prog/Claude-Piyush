#!/usr/bin/env python3
"""A tiny mock ERP ingest endpoint for testing the HTTPS sink locally.

It accepts POSTed batches, de-duplicates on record_fingerprint, and prints a
running count. Uses only the standard library so it needs no dependencies.

    python tools/mock_erp_server.py --port 8080

Then set your config sink to:
    type: "https"
    url: "http://localhost:8080/ingest"
    verify_tls: false
"""
from __future__ import annotations

import argparse
import json
from http.server import BaseHTTPRequestHandler, HTTPServer

_seen: set[str] = set()
_total = 0


class Handler(BaseHTTPRequestHandler):
    def do_POST(self):  # noqa: N802
        global _total
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length)
        try:
            payload = json.loads(body)
        except json.JSONDecodeError:
            self.send_response(400)
            self.end_headers()
            return
        new = 0
        for rec in payload.get("records", []):
            fp = rec.get("record_fingerprint")
            if fp and fp in _seen:
                continue
            if fp:
                _seen.add(fp)
            new += 1
            _total += 1
            print(f"[{_total}] {rec.get('record_type')} "
                  f"{rec.get('collector')}: "
                  f"{rec.get('sample_name') or rec.get('event_type')}")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps({"accepted": new,
                                     "duplicates_ignored":
                                     len(payload.get('records', [])) - new})
                         .encode())

    def log_message(self, *args):  # silence default logging
        pass


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8080)
    args = ap.parse_args()
    print(f"mock ERP listening on http://localhost:{args.port}/ingest")
    HTTPServer(("0.0.0.0", args.port), Handler).serve_forever()


if __name__ == "__main__":
    main()
