#!/usr/bin/env python3
"""verify_ko.py -- check the four decoded pages really are Ko, and read page 1.

  python verify_ko.py <p4> <p5> <p6> <p7> --diag <page1hex>

The oracle is not ours. bunnie left sha256(k0)[0:4] in his own source at
dc34-vault/src/main.rs:42, where the badge uses it to check its own key.
Either the prefix is dca9ea49 or you do not have Ko. There is no middle.
"""
import hashlib, sys, zlib

SPI_FLASH_IDS = [0x1820c2, 0x3825c2, 0x17600b, 0x1732ba, 0x172085]

args = sys.argv[1:]
diag = None
if "--diag" in args:
    i = args.index("--diag"); diag = args[i+1]; args = args[:i]

k0 = b"".join(bytes.fromhex(p) for p in args[:4])
h  = hashlib.sha256(k0).hexdigest()
print("k0     =", k0.hex())
print("sha256 =", h)
print("oracle = dca9ea49 ->", "MATCH, this is Ko" if h.startswith("dca9ea49")
                              else "NO MATCH, this is not Ko")
print(f"crc32  = 0x{zlib.crc32(k0) & 0xFFFFFFFF:08x}  (compare with page 3)")

if diag:
    d = bytes.fromhex(diag)
    id_spi = int.from_bytes(d[0:3], "big")
    id_qpi = int.from_bytes(d[4:7], "big")
    f = d[7]
    print("\npage 1 diagnostics")
    print(f"  id_spi    = 0x{id_spi:06x}   valid: {id_spi in SPI_FLASH_IDS}")
    print(f"  status reg= 0x{d[3]:02x}")
    print(f"  id_qpi    = 0x{id_qpi:06x}   valid: {id_qpi in SPI_FLASH_IDS}")
    print(f"  SCD @ 0x403000 (baosec-lite) : {bool(f & 0x01)}")
    print(f"  SCD @ 0x404000 (4 MiB build) : {bool(f & 0x02)}")
    print(f"  AES-KWP AIV passed           : {bool(f & 0x40)}"
          "   <- this also confirms the master key")
    if id_spi not in SPI_FLASH_IDS:
        print("\n  The flash never answered. If you see 0xffffff here, you almost")
        print("  certainly forgot fl.mem_qpi_mode(true) before the first mem_read.")
