"""SQL database sink - inserts records into a central table via SQLAlchemy.

Records are stored with the payload as a JSON column plus a few promoted
columns for indexing/query. The ``record_fingerprint`` column is UNIQUE so a
retried batch is de-duplicated by the database itself (insert-or-ignore).

SQLAlchemy is imported lazily so sites using only the HTTPS sink do not need it.
"""
from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Dict, List

from ..config import SinkConfig
from .base import Sink

log = logging.getLogger("masslynx_bridge.sink.sqldb")


class SqlDbSink(Sink):
    def __init__(self, cfg: SinkConfig):
        super().__init__(cfg)
        if not cfg.db_url:
            raise ValueError("sqldb sink requires 'db_url' to be set")
        try:
            import sqlalchemy as sa
        except ImportError as exc:  # pragma: no cover
            raise RuntimeError(
                "the sqldb sink requires SQLAlchemy: pip install sqlalchemy"
            ) from exc

        self._sa = sa
        self._engine = sa.create_engine(cfg.db_url, pool_pre_ping=True)
        self._metadata = sa.MetaData()
        self._table = sa.Table(
            cfg.db_table,
            self._metadata,
            sa.Column("record_fingerprint", sa.String(64), primary_key=True),
            sa.Column("instrument_id", sa.String(128), index=True),
            sa.Column("record_type", sa.String(64), index=True),
            sa.Column("ingest_time", sa.DateTime(timezone=True)),
            sa.Column("payload", sa.Text),
        )
        self._metadata.create_all(self._engine)

    def send(self, records: List[Dict]) -> None:
        sa = self._sa
        rows = []
        for rec in records:
            rows.append(
                {
                    "record_fingerprint": rec.get("record_fingerprint"),
                    "instrument_id": rec.get("instrument_id"),
                    "record_type": rec.get("record_type"),
                    "ingest_time": datetime.now(timezone.utc),
                    "payload": json.dumps(rec, ensure_ascii=False,
                                          default=str),
                }
            )
        dialect = self._engine.dialect.name
        with self._engine.begin() as conn:
            if dialect in ("postgresql", "sqlite"):
                from sqlalchemy.dialects import postgresql, sqlite

                insert = (postgresql.insert if dialect == "postgresql"
                          else sqlite.insert)(self._table)
                stmt = insert.on_conflict_do_nothing(
                    index_elements=["record_fingerprint"]
                )
                conn.execute(stmt, rows)
            else:
                # Generic path: insert one at a time, ignoring duplicates.
                for row in rows:
                    try:
                        conn.execute(sa.insert(self._table), [row])
                    except sa.exc.IntegrityError:
                        pass
        log.debug("inserted/ignored %d rows", len(rows))

    def close(self) -> None:
        self._engine.dispose()
