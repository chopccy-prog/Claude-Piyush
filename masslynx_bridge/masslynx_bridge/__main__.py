"""Command-line entry point.

Usage:
    python -m masslynx_bridge --config config.yaml
    python -m masslynx_bridge --config config.yaml --once   # single cycle
    python -m masslynx_bridge --config config.yaml --check  # validate & exit
"""
from __future__ import annotations

import argparse
import sys

from .config import load_config
from .util.logging_setup import setup_logging
from .watcher import Bridge


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="masslynx_bridge",
        description="Ship MassLynx audit-trail and result exports to a "
                    "central ERP/LIMS server.",
    )
    parser.add_argument(
        "--config", "-c", help="Path to YAML config (or set "
        "MASSLYNX_BRIDGE_CONFIG).")
    parser.add_argument(
        "--once", action="store_true",
        help="Run a single poll cycle and exit (useful for cron/testing).")
    parser.add_argument(
        "--check", action="store_true",
        help="Load config, build sink and collectors, then exit. "
             "Validates setup without sending anything.")
    args = parser.parse_args(argv)

    try:
        cfg = load_config(args.config)
    except (FileNotFoundError, RuntimeError, ValueError) as exc:
        print(f"config error: {exc}", file=sys.stderr)
        return 2

    setup_logging(cfg.log_level)
    bridge = Bridge(cfg)

    if args.check:
        print(
            f"OK: instrument={cfg.instrument_id}, "
            f"{len(bridge.collectors)} collector(s), sink={cfg.sink.type}"
        )
        return 0

    if args.once:
        total = 0
        for collector in bridge.collectors:
            total += collector.poll_once()
        print(f"single cycle delivered {total} record(s)")
        return 0

    bridge.run()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
