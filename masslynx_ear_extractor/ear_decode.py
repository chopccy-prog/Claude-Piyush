"""
MassLynx .EAR decoder -> CSV, with date-range and condition filters.
CONFIRMED cipher: RC2-CBC, 5-byte key, 40-bit effective, IV = 8 zero bytes.
Frame model: 524-byte prefix, then variable frames; per frame at offset S with
length L = X12(S) (XOR of three LE uint32 at S); marker '.gCi2k1' at S+21:S+28;
encrypted body = data[S+32 : S+32 + ((L-36)&~7)]. Frame ordinal (1-based) = audit
index.

Standalone (no external libraries). Run on any .ear from this machine:
    python ear_decode.py "Backup_18102025.ear" --key 6b6bf3aa3a --out LCMS_EAR.csv
    python ear_decode.py "Backup_18102025.ear" --key 6b6bf3aa3a --out oct.csv \
        --from-date 2025-10-01 --to-date 2025-10-31 --where user=sachingade

Output columns: index, filetime_utc, strings_ascii, strings_utf16, body_hex.
The ASCII/UTF-16 strings hold user, machine, domain, description, etc.; match a
few rows to the known LogLynx CSV on `index` to lock the exact column mapping.
"""
import argparse
import csv
import datetime as dt
import re
import struct

PITABLE = bytes([
0xd9,0x78,0xf9,0xc4,0x19,0xdd,0xb5,0xed,0x28,0xe9,0xfd,0x79,0x4a,0xa0,0xd8,0x9d,
0xc6,0x7e,0x37,0x83,0x2b,0x76,0x53,0x8e,0x62,0x4c,0x64,0x88,0x44,0x8b,0xfb,0xa2,
0x17,0x9a,0x59,0xf5,0x87,0xb3,0x4f,0x13,0x61,0x45,0x6d,0x8d,0x09,0x81,0x7d,0x32,
0xbd,0x8f,0x40,0xeb,0x86,0xb7,0x7b,0x0b,0xf0,0x95,0x21,0x22,0x5c,0x6b,0x4e,0x82,
0x54,0xd6,0x65,0x93,0xce,0x60,0xb2,0x1c,0x73,0x56,0xc0,0x14,0xa7,0x8c,0xf1,0xdc,
0x12,0x75,0xca,0x1f,0x3b,0xbe,0xe4,0xd1,0x42,0x3d,0xd4,0x30,0xa3,0x3c,0xb6,0x26,
0x6f,0xbf,0x0e,0xda,0x46,0x69,0x07,0x57,0x27,0xf2,0x1d,0x9b,0xbc,0x94,0x43,0x03,
0xf8,0x11,0xc7,0xf6,0x90,0xef,0x3e,0xe7,0x06,0xc3,0xd5,0x2f,0xc8,0x66,0x1e,0xd7,
0x08,0xe8,0xea,0xde,0x80,0x52,0xee,0xf7,0x84,0xaa,0x72,0xac,0x35,0x4d,0x6a,0x2a,
0x96,0x1a,0xd2,0x71,0x5a,0x15,0x49,0x74,0x4b,0x9f,0xd0,0x5e,0x04,0x18,0xa4,0xec,
0xc2,0xe0,0x41,0x6e,0x0f,0x51,0xcb,0xcc,0x24,0x91,0xaf,0x50,0xa1,0xf4,0x70,0x39,
0x99,0x7c,0x3a,0x85,0x23,0xb8,0xb4,0x7a,0xfc,0x02,0x36,0x5b,0x25,0x55,0x97,0x31,
0x2d,0x5d,0xfa,0x98,0xe3,0x8a,0x92,0xae,0x05,0xdf,0x29,0x10,0x67,0x6c,0xba,0xc9,
0xd3,0x00,0xe6,0xcf,0xe1,0x9e,0xa8,0x2c,0x63,0x16,0x01,0x3f,0x58,0xe2,0x89,0xa9,
0x0d,0x38,0x34,0x1b,0xab,0x33,0xff,0xb0,0xbb,0x48,0x0c,0x5f,0xb9,0xb1,0xcd,0x2e,
0xc5,0xf3,0xdb,0x47,0xe5,0xa5,0x9c,0x77,0x0a,0xa6,0x20,0x68,0xfe,0x7f,0xc1,0xad])


def expand_key(key, eff):
    L = list(key) + [0] * (128 - len(key))
    T = len(key)
    T8 = (eff + 7) // 8
    TM = 0xFF >> ((8 - (eff % 8)) % 8)
    for i in range(T, 128):
        L[i] = PITABLE[(L[i - 1] + L[i - T]) & 0xFF]
    L[128 - T8] = PITABLE[L[128 - T8] & TM]
    for i in range(127 - T8, -1, -1):
        L[i] = PITABLE[L[i + 1] ^ L[i + T8]]
    return [L[2 * i] | (L[2 * i + 1] << 8) for i in range(64)]


def _dec_block(ct, K):
    R = [ct[0] | (ct[1] << 8), ct[2] | (ct[3] << 8),
         ct[4] | (ct[5] << 8), ct[6] | (ct[7] << 8)]
    ror = lambda x, n: ((x >> n) | (x << (16 - n))) & 0xFFFF
    j = 63
    for rnd in range(16):
        R[3] = ror(R[3], 5); R[3] = (R[3]-K[j]-(R[2]&R[1])-((~R[2]&0xFFFF)&R[0]))&0xFFFF; j-=1
        R[2] = ror(R[2], 3); R[2] = (R[2]-K[j]-(R[1]&R[0])-((~R[1]&0xFFFF)&R[3]))&0xFFFF; j-=1
        R[1] = ror(R[1], 2); R[1] = (R[1]-K[j]-(R[0]&R[3])-((~R[0]&0xFFFF)&R[2]))&0xFFFF; j-=1
        R[0] = ror(R[0], 1); R[0] = (R[0]-K[j]-(R[3]&R[2])-((~R[3]&0xFFFF)&R[1]))&0xFFFF; j-=1
        if rnd in (4, 10):
            for k in range(3, -1, -1):
                R[k] = (R[k] - K[R[(k - 1) % 4] & 63]) & 0xFFFF
    o = bytearray(8)
    for i in range(4):
        o[2 * i] = R[i] & 0xFF
        o[2 * i + 1] = (R[i] >> 8) & 0xFF
    return bytes(o)


def rc2_decrypt_cbc(data, key, eff, iv=b"\x00" * 8):
    K = expand_key(key, eff)
    out = bytearray()
    prev = iv
    for i in range(0, len(data) - 7, 8):
        blk = data[i:i + 8]
        d = _dec_block(blk, K)
        out += bytes(a ^ b for a, b in zip(d, prev))
        prev = blk
    return bytes(out)


def walk_frames(data):
    u32 = lambda p: struct.unpack_from("<I", data, p)[0]
    X12 = lambda p: u32(p) ^ u32(p + 4) ^ u32(p + 8)
    S = 524
    frames = []
    while S + 12 <= len(data):
        L = X12(S)
        if L < 36 or S + L > len(data) or data[S + 21:S + 28] != b".gCi2k1":
            break
        frames.append((S, L))
        S += L
    return frames


ASCII = re.compile(rb"[\x20-\x7e]{2,}")
UTF16 = re.compile(rb"(?:[\x20-\x7e]\x00){2,}")


def ascii_strs(b):
    return [m.group().decode("latin-1") for m in ASCII.finditer(b)]


def utf16_strs(b):
    return [m.group().decode("utf-16le") for m in UTF16.finditer(b)]


def find_filetime(b):
    lo = int((dt.datetime(2015, 1, 1) - dt.datetime(1601, 1, 1)).total_seconds() * 1e7)
    hi = int((dt.datetime(2030, 1, 1) - dt.datetime(1601, 1, 1)).total_seconds() * 1e7)
    for off in range(0, len(b) - 7):
        v = struct.unpack_from("<Q", b, off)[0]
        if lo <= v <= hi:
            return dt.datetime(1601, 1, 1) + dt.timedelta(microseconds=v / 10), off
    return None, None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("ear")
    ap.add_argument("--key", required=True)
    ap.add_argument("--eff", type=int, default=40)
    ap.add_argument("--out", default="LCMS_EAR.csv")
    ap.add_argument("--from-date")
    ap.add_argument("--to-date")
    ap.add_argument("--where", nargs="*", default=[])
    a = ap.parse_args()
    key = bytes.fromhex(a.key)
    data = open(a.ear, "rb").read()
    frames = walk_frames(data)
    print("frames:", len(frames))

    def pdate(s):
        return dt.datetime.strptime(s, "%Y-%m-%d").date() if s else None

    fd, td = pdate(a.from_date), pdate(a.to_date)
    conds = dict(w.split("=", 1) for w in a.where)
    rows = []
    for i, (S, L) in enumerate(frames, 1):
        blen = (L - 36) & ~7
        body = rc2_decrypt_cbc(data[S + 32:S + 32 + blen], key, a.eff)
        ft, _ = find_filetime(body)
        row = {
            "index": i,
            "filetime_utc": ft.strftime("%Y-%m-%d %H:%M:%S") if ft else "",
            "strings_ascii": " | ".join(ascii_strs(body)),
            "strings_utf16": " | ".join(utf16_strs(body)),
            "body_hex": body.hex(),
        }
        if fd or td:
            if not ft:
                continue
            d = ft.date()
            if fd and d < fd:
                continue
            if td and d > td:
                continue
        if conds:
            blob = (row["strings_ascii"] + " " + row["strings_utf16"]).lower()
            if not all(v.lower() in blob for v in conds.values()):
                continue
        rows.append(row)
    with open(a.out, "w", newline="", encoding="utf-8-sig") as f:
        w = csv.DictWriter(f, fieldnames=["index", "filetime_utc",
                           "strings_ascii", "strings_utf16", "body_hex"])
        w.writeheader()
        w.writerows(rows)
    print("wrote", len(rows), "rows ->", a.out)


if __name__ == "__main__":
    main()
