"""Pluggable decryption for the .EAR decode path.

The `.ear` payload is encrypted (see docs/FINDINGS.md). We do NOT have the key.
This module mirrors the structure of the working Access-database extractor, which
decrypts with a *keymap file* supplied out of band. When Waters (or whoever holds
the key/algorithm) provides the cipher and key, drop a keyspec JSON next to the
`.ear` and the decode path uses it.

Keyspec JSON format (``*.earkey.json``)
---------------------------------------
    {
      "format": "ear-extractor/keyspec",
      "cipher": "rc4" | "aes-cbc" | "aes-ecb" | "xor",
      "key_hex": "....",              # required for all ciphers
      "iv_hex": "....",               # aes-cbc only
      "marker": ".gCi2k1",            # framing marker (default)
      "scope": "per-chunk" | "whole", # decrypt each chunk, or the whole payload
      "strip_marker": true             # remove the framing marker before decrypt
    }

``rc4`` and ``xor`` are implemented in pure Python. ``aes-*`` requires the
optional ``cryptography`` package. This is deliberately a small, auditable set:
the point is to make the decoder ready, not to guess Waters' scheme.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Optional


@dataclass
class KeySpec:
    cipher: str
    key: bytes
    iv: bytes = b""
    marker: bytes = b".gCi2k1"
    scope: str = "per-chunk"
    strip_marker: bool = True


class KeyNotAvailable(Exception):
    """Raised when decode is requested but no keyspec is present."""


def load_keyspec(path: str) -> KeySpec:
    with open(path, "r", encoding="utf-8") as f:
        d = json.load(f)
    if d.get("format") != "ear-extractor/keyspec":
        raise ValueError(f"not a valid keyspec file: {path}")
    return KeySpec(
        cipher=d["cipher"].lower(),
        key=bytes.fromhex(d["key_hex"]),
        iv=bytes.fromhex(d["iv_hex"]) if d.get("iv_hex") else b"",
        marker=(d.get("marker", ".gCi2k1")).encode("latin-1"),
        scope=d.get("scope", "per-chunk"),
        strip_marker=bool(d.get("strip_marker", True)),
    )


def rc4(key: bytes, data: bytes) -> bytes:
    s = list(range(256))
    j = 0
    klen = len(key)
    for i in range(256):
        j = (j + s[i] + key[i % klen]) & 0xFF
        s[i], s[j] = s[j], s[i]
    out = bytearray(len(data))
    i = j = 0
    for n, b in enumerate(data):
        i = (i + 1) & 0xFF
        j = (j + s[i]) & 0xFF
        s[i], s[j] = s[j], s[i]
        out[n] = b ^ s[(s[i] + s[j]) & 0xFF]
    return bytes(out)


def xor(key: bytes, data: bytes) -> bytes:
    klen = len(key)
    return bytes(b ^ key[i % klen] for i, b in enumerate(data))


def _aes(spec: KeySpec, data: bytes) -> bytes:
    try:
        from cryptography.hazmat.primitives.ciphers import (
            Cipher, algorithms, modes,
        )
    except ImportError as exc:  # pragma: no cover
        raise RuntimeError(
            "aes ciphers need the 'cryptography' package: pip install cryptography"
        ) from exc
    if spec.cipher == "aes-cbc":
        mode = modes.CBC(spec.iv)
    else:
        mode = modes.ECB()
    dec = Cipher(algorithms.AES(spec.key), mode).decryptor()
    return dec.update(data) + dec.finalize()


def decrypt_bytes(spec: KeySpec, data: bytes) -> bytes:
    if spec.cipher == "rc4":
        return rc4(spec.key, data)
    if spec.cipher == "xor":
        return xor(spec.key, data)
    if spec.cipher in ("aes-cbc", "aes-ecb"):
        return _aes(spec, data)
    raise ValueError(f"unsupported cipher: {spec.cipher!r}")


def decrypt_container(spec: KeySpec, data: bytes) -> bytes:
    """Decrypt the whole container per the keyspec's scope."""
    if spec.scope == "whole":
        payload = data.replace(spec.marker, b"") if spec.strip_marker else data
        return decrypt_bytes(spec, payload)
    # per-chunk: decrypt each framed chunk independently and concatenate
    from ear_format import split_chunks

    out = bytearray()
    for chunk in split_chunks(data, spec.marker):
        block = data[chunk.offset:chunk.offset + chunk.length]
        out += decrypt_bytes(spec, block)
    return bytes(out)


def find_keyspec(src_file: str) -> Optional[str]:
    p = Path(src_file)
    base = p.with_suffix("")
    for cand in (
        p.parent / (base.name + ".earkey.json"),
        p.parent / (p.name + ".earkey.json"),
    ):
        if cand.is_file():
            return str(cand)
    generic = sorted(p.parent.glob("*.earkey.json"))
    return str(generic[0]) if generic else None
