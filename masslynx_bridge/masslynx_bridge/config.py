"""Configuration loading for the MassLynx bridge.

Config is read from a YAML file whose path is given on the command line or via
the ``MASSLYNX_BRIDGE_CONFIG`` environment variable. Every value can also be
overridden by an environment variable so that secrets (API tokens, DB
passwords) never have to live on disk. Environment variables win over the file.

The precedence for any single setting is:

    explicit environment variable  >  value in the YAML file  >  built-in default
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field, fields, is_dataclass
from pathlib import Path
from typing import Any, Dict, Optional

try:
    import yaml
except ImportError:  # pragma: no cover - yaml is a declared dependency
    yaml = None


ENV_PREFIX = "MASSLYNX_BRIDGE_"


@dataclass
class SinkConfig:
    """Where collected records are delivered."""

    # One of: "https", "sqldb", "stdout". "stdout" is for dry-run testing.
    type: str = "https"

    # --- HTTPS sink ---
    url: str = ""
    # Auth token is read from env MASSLYNX_BRIDGE_SINK_TOKEN by preference.
    token: str = ""
    # Header the token is sent in. "Authorization" -> "Bearer <token>".
    auth_header: str = "Authorization"
    auth_scheme: str = "Bearer"
    verify_tls: bool = True
    # Optional path to a custom CA bundle for a private/internal CA.
    ca_bundle: str = ""
    timeout_seconds: float = 30.0
    # Records are POSTed in batches of this size.
    batch_size: int = 200

    # --- SQL DB sink ---
    # SQLAlchemy-style URL, e.g. postgresql+psycopg://user:pass@host/db
    # Prefer setting the password via MASSLYNX_BRIDGE_SINK_DB_URL env var.
    db_url: str = ""
    db_table: str = "instrument_records"


@dataclass
class CollectorConfig:
    """One folder-watching collector."""

    # Human-readable name; also used as the state-file key. Must be unique.
    name: str
    # Kind of data: "audit_trail" or "results". Selects the parser.
    kind: str
    # Folder that MassLynx / LogLynx writes exports into.
    watch_dir: str
    # Glob for the files to pick up inside watch_dir.
    file_glob: str = "*.csv"
    # Character encoding of the export files. MassLynx commonly uses latin-1.
    encoding: str = "latin-1"
    # CSV delimiter. LogLynx audit exports are often tab-delimited.
    delimiter: str = ","
    # Skip this many header lines before the column header row (banner lines).
    preamble_lines: int = 0
    # Enable/disable without deleting the block.
    enabled: bool = True


@dataclass
class Config:
    # How often to rescan the watch folders, in seconds.
    poll_interval_seconds: float = 15.0
    # Where the per-collector cursor state is persisted.
    state_path: str = "state/bridge_state.json"
    log_level: str = "INFO"
    # A stable identifier for this instrument/PC, attached to every record so
    # the central server knows which machine a record came from.
    instrument_id: str = "MASSLYNX-01"
    sink: SinkConfig = field(default_factory=SinkConfig)
    collectors: list[CollectorConfig] = field(default_factory=list)


def _coerce(dc_type: Any, value: Any) -> Any:
    """Best-effort conversion of a scalar to the dataclass field type."""
    if value is None:
        return None
    if dc_type is bool and isinstance(value, str):
        return value.strip().lower() in ("1", "true", "yes", "on")
    try:
        return dc_type(value)
    except (TypeError, ValueError):
        return value


def _apply_env_overrides(obj: Any, prefix: str) -> None:
    """Override dataclass fields from environment variables in place.

    A field ``token`` on the sink is overridable via
    ``MASSLYNX_BRIDGE_SINK_TOKEN``. Nested dataclasses extend the prefix.
    """
    if not is_dataclass(obj):
        return
    for f in fields(obj):
        current = getattr(obj, f.name)
        if is_dataclass(current):
            _apply_env_overrides(current, f"{prefix}{f.name.upper()}_")
            continue
        env_key = f"{prefix}{f.name.upper()}"
        if env_key in os.environ:
            setattr(obj, f.name, _coerce(type(current), os.environ[env_key]))


def load_config(path: Optional[str] = None) -> Config:
    """Load configuration from a YAML file plus environment overrides."""
    path = path or os.environ.get(f"{ENV_PREFIX}CONFIG")
    data: Dict[str, Any] = {}
    if path:
        p = Path(path)
        if not p.is_file():
            raise FileNotFoundError(f"config file not found: {p}")
        if yaml is None:
            raise RuntimeError("PyYAML is required to read the config file")
        with p.open("r", encoding="utf-8") as fh:
            data = yaml.safe_load(fh) or {}

    sink_data = data.get("sink", {}) or {}
    sink = SinkConfig(**{k: v for k, v in sink_data.items()
                         if k in {f.name for f in fields(SinkConfig)}})

    collectors = []
    for c in data.get("collectors", []) or []:
        allowed = {f.name for f in fields(CollectorConfig)}
        collectors.append(CollectorConfig(**{k: v for k, v in c.items()
                                             if k in allowed}))

    top = {k: v for k, v in data.items()
           if k in {f.name for f in fields(Config)}
           and k not in ("sink", "collectors")}
    cfg = Config(sink=sink, collectors=collectors, **top)

    # Environment overrides for the top-level and nested sink config.
    _apply_env_overrides(cfg, ENV_PREFIX)
    # Special-case the DB url env so a full connection string with a password
    # can be supplied without any of it touching the YAML file.
    if f"{ENV_PREFIX}SINK_DB_URL" in os.environ:
        cfg.sink.db_url = os.environ[f"{ENV_PREFIX}SINK_DB_URL"]

    return cfg
