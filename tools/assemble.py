#!/usr/bin/env python3
"""assemble.py -- stitch four decoded pages into the 32-byte flag and check it.

  python assemble.py <page4hex> <page5hex> <page6hex> <page7hex> <crc32hex>

The badge computed that CRC over the bytes it actually read, before they ever
became pixels. If it matches, the photo pipeline is proven end to end. If it
does not, reshoot; do not hand-patch a nibble because it "looks close".
"""
import sys, zlib

pages, expect = sys.argv[1:5], int(sys.argv[5], 16)
flag = b"".join(bytes.fromhex(p) for p in pages)
got = zlib.crc32(flag) & 0xFFFFFFFF

print("flag  =", flag.hex())
print(f"crc32 = 0x{got:08x}   on-chip = 0x{expect:08x}")
print("VERIFIED" if got == expect else "MISMATCH: reshoot the pages")

if flag == bytes(32):
    print("all zeros: the keystore denied the read. You were in S-mode, not U-mode.")
