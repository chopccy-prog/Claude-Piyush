"""MassLynx .EAR container format analysis and framing.

This module contains everything we could establish about the `.ear` backup file
by measuring the file itself (see docs/FINDINGS.md for the evidence). It is used
by both the salvage path (works today, file-only) and the decode path (works
once key material is supplied).

What we know about the container
--------------------------------
* The file is a flat byte stream with a repeating 7-byte ASCII framing marker
  ``.gCi2k1`` (hex ``2e 67 43 69 32 6b 31``) that separates variable-length
  payload chunks (~143,000 of them; mean ~171 bytes).
* Whole-file entropy is ~7.93/8.0 and is uniform across the file and across a
  32-byte column split, i.e. the payload chunks are ENCRYPTED, not merely
  compressed and not a repeating-key XOR. No readable text (ASCII or UTF-16)
  survives except the marker itself.

Therefore this module can reliably do container-level work (split into chunks,
measure them, inventory them) but it cannot turn chunk bytes into fields without
the decryption key/spec, which is what the decode path plugs in.
"""
from __future__ import annotations

import collections
import math
from dataclasses import dataclass
from typing import List

# The literal framing marker observed in the container.
FRAMING_MARKER = b".gCi2k1"


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = collections.Counter(data)
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


@dataclass
class Chunk:
    index: int
    offset: int          # byte offset in the file where this chunk starts
    length: int          # payload length (marker not included)
    entropy: float
    printable_ratio: float
    preview_hex: str     # first 16 bytes as hex
    preview_ascii: str   # first 32 bytes, non-printables shown as '.'


def _printable_ratio(data: bytes) -> float:
    if not data:
        return 0.0
    printable = sum(1 for b in data if 0x20 <= b < 0x7F)
    return printable / len(data)


def _ascii_preview(data: bytes, n: int = 32) -> str:
    return "".join(chr(b) if 0x20 <= b < 0x7F else "." for b in data[:n])


def split_chunks(data: bytes, marker: bytes = FRAMING_MARKER) -> List[Chunk]:
    """Split the container on the framing marker into payload chunks.

    Offsets are the position of the chunk payload's first byte in the original
    file (the marker that precedes it is not part of the chunk).
    """
    chunks: List[Chunk] = []
    parts = data.split(marker)
    pos = 0
    for i, part in enumerate(parts):
        # The first part starts at 0; every later part is preceded by a marker.
        start = pos if i == 0 else pos + len(marker)
        if part:
            chunks.append(
                Chunk(
                    index=i,
                    offset=start,
                    length=len(part),
                    entropy=round(shannon_entropy(part), 4),
                    printable_ratio=round(_printable_ratio(part), 4),
                    preview_hex=part[:16].hex(),
                    preview_ascii=_ascii_preview(part),
                )
            )
        pos = start + len(part)
    return chunks


@dataclass
class ContainerReport:
    size: int
    whole_entropy: float
    marker: str
    marker_count: int
    chunk_count: int
    chunk_len_min: int
    chunk_len_max: int
    chunk_len_mean: int
    payload_entropy_no_marker: float
    verdict: str


def analyze(data: bytes, marker: bytes = FRAMING_MARKER) -> ContainerReport:
    marker_count = data.count(marker)
    chunks = split_chunks(data, marker)
    lens = [c.length for c in chunks] or [0]
    payload = data.replace(marker, b"")
    payload_entropy = shannon_entropy(payload)
    whole = shannon_entropy(data)

    if whole > 7.5 and payload_entropy > 7.5:
        verdict = (
            "ENCRYPTED payload. Chunks between the framing marker have "
            "near-maximal, uniform entropy: they are encrypted, not compressed "
            "or XOR-obfuscated. Records cannot be recovered from this file "
            "without the decryption key/spec (see README: decode mode + keymap)."
        )
    elif whole > 7.5:
        verdict = (
            "High-entropy blob. Likely compressed or encrypted; no readable "
            "structure recovered."
        )
    else:
        verdict = (
            "Lower entropy than expected for encryption; inspect chunk previews "
            "for structure."
        )

    return ContainerReport(
        size=len(data),
        whole_entropy=round(whole, 4),
        marker=marker.decode("latin-1", "replace"),
        marker_count=marker_count,
        chunk_count=len(chunks),
        chunk_len_min=min(lens),
        chunk_len_max=max(lens),
        chunk_len_mean=sum(lens) // len(lens),
        payload_entropy_no_marker=round(payload_entropy, 4),
        verdict=verdict,
    )
