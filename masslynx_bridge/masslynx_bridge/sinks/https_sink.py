"""HTTPS JSON sink - POSTs record batches to a central ERP endpoint.

Payload shape (one POST per batch):

    {
      "instrument_id": "MASSLYNX-01",
      "count": 3,
      "records": [ {...}, {...}, {...} ]
    }

The endpoint is expected to be idempotent on ``record_fingerprint`` so that a
retried batch after a network blip does not create duplicates server-side.
"""
from __future__ import annotations

import json
import logging
from typing import Dict, List

import requests

from ..config import SinkConfig
from .base import Sink

log = logging.getLogger("masslynx_bridge.sink.https")


class HttpsSink(Sink):
    def __init__(self, cfg: SinkConfig):
        super().__init__(cfg)
        if not cfg.url:
            raise ValueError("https sink requires 'url' to be set")
        self._session = requests.Session()
        headers = {"Content-Type": "application/json"}
        if cfg.token:
            scheme = f"{cfg.auth_scheme} " if cfg.auth_scheme else ""
            headers[cfg.auth_header] = f"{scheme}{cfg.token}"
        self._session.headers.update(headers)
        # TLS verification: True, or a path to a private CA bundle.
        self._verify: object = cfg.ca_bundle or cfg.verify_tls

    def send(self, records: List[Dict]) -> None:
        payload = {
            "count": len(records),
            "records": records,
        }
        resp = self._session.post(
            self.cfg.url,
            data=json.dumps(payload, ensure_ascii=False).encode("utf-8"),
            timeout=self.cfg.timeout_seconds,
            verify=self._verify,
        )
        # Treat any non-2xx as a retryable failure; the server should return
        # 2xx even when it de-duplicates, so a 4xx here is a real problem.
        if not (200 <= resp.status_code < 300):
            snippet = resp.text[:500]
            raise RuntimeError(
                f"sink POST failed: HTTP {resp.status_code}: {snippet}"
            )
        log.debug("delivered %d records, HTTP %d", len(records),
                  resp.status_code)

    def close(self) -> None:
        self._session.close()
