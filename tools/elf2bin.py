#!/usr/bin/env python3
"""elf2bin.py -- flatten the payload ELF, and refuse to produce one that bricks.

  python elf2bin.py target/riscv32imac-unknown-none-elf/release/dc34-payload payload.bin

There is no objcopy in this toolchain install, and there does not need to be:
the loadable segments are all we want. The two asserts are the point of the file.
"""
import struct, sys

KERNEL_START = 0x60099000    # offsets/common.rs:13 -- xous.img begins here
ENTRY        = 0x60090000

src, dst = sys.argv[1], sys.argv[2]
d = open(src, 'rb').read()
assert d[:4] == b'\x7fELF' and d[4] == 1, "not a 32-bit ELF"
entry, phoff = struct.unpack_from('<II', d, 24)
phentsize, phnum = struct.unpack_from('<HH', d, 42)

segs = []
for i in range(phnum):
    o = phoff + i * phentsize
    typ, off, vaddr, paddr, filesz, memsz, flags, align = struct.unpack_from('<8I', d, o)
    if typ == 1 and filesz > 0:          # PT_LOAD with real bytes.
        segs.append((vaddr, off, filesz))   # a filesz of 0 is .bss: it lives in RAM,
                                            # and including it would inflate the image
                                            # by the whole RAM origin offset.
base = min(s[0] for s in segs)
top  = max(s[0] + s[2] for s in segs)
out = bytearray(top - base)
for vaddr, off, filesz in segs:
    out[vaddr - base:vaddr - base + filesz] = d[off:off + filesz]

print(f"entry=0x{entry:08x} base=0x{base:08x} end=0x{top:08x} size={len(out)}")
assert entry == ENTRY and base == ENTRY, "payload must start exactly at 0x60090000"
assert top < KERNEL_START, (
    f"payload ends at 0x{top:08x}, at or past KERNEL_START 0x{KERNEL_START:08x}. "
    "Writing this would overwrite xous.img and brick the badge.")
open(dst, 'wb').write(out)
print(f"OK: {KERNEL_START - top} bytes of headroom below KERNEL_START")
