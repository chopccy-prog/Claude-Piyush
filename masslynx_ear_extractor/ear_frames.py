"""Confirmed MassLynx .EAR frame walker.

Layout: a 524-byte prefix, then variable-length frames, no trailer. For a frame
at offset S with length L = X12(S), where X12(p) is the XOR of three consecutive
little-endian uint32 at p. The marker '.gCi2k1' sits at S+21:S+28. The encrypted
body is data[S+32 : S+32 + ((L-36)&~7)]. Frame ordinal (1-based) equals the audit
index. Verified: exactly 134,796 frames on Backup_18102025.ear, first frame at
offset 524 length 145, accounting for every byte.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass

MARKER = b".gCi2k1"
PREFIX_LEN = 524


@dataclass
class Frame:
    ordinal: int   # 1-based; equals the audit index
    offset: int
    length: int

    def body_range(self) -> tuple[int, int]:
        blen = (self.length - 36) & ~7
        return self.offset + 32, self.offset + 32 + blen


def walk(data: bytes) -> list[Frame]:
    def u32(p: int) -> int:
        return struct.unpack_from("<I", data, p)[0]

    def x12(p: int) -> int:
        return u32(p) ^ u32(p + 4) ^ u32(p + 8)

    S = PREFIX_LEN
    frames: list[Frame] = []
    n = 0
    while S + 12 <= len(data):
        L = x12(S)
        if L < 36 or S + L > len(data) or data[S + 21:S + 28] != MARKER:
            break
        n += 1
        frames.append(Frame(n, S, L))
        S += L
    return frames


def body_bytes(data: bytes, f: Frame) -> bytes:
    a, b = f.body_range()
    return data[a:b]
