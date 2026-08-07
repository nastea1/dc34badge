#!/usr/bin/env python3
"""uf2send.py -- write RRAM through boot1's update-mode `uf2` command.

  uf2send.py word <addr-hex> <value-hex>     one 32-bit little-endian word
  uf2send.py file <addr-hex> <path>          a binary blob, chunked
  uf2send.py --dry ...                       print records, send nothing

The guards below are not paranoia. boot1 itself lives at 0x60000000-0x6005FFFF,
and update mode is inside boot1. Corrupt that and there is no way back in:
it is the single unrecoverable action in this whole exercise.
"""
import base64, glob, struct, sys, time
import serial

FAMILY   = 0xA7D76373
RRAM     = 0x60000000
MIN_ADDR = 0x60060000          # LOADER_START. Never write below this.
MAX_ADDR = RRAM + 0x3DA000     # HW_RERAM_MEM + RRAM_STORAGE_LEN
KERNEL   = 0x60099000          # KERNEL_START: xous.img. Never reach this.
CHUNK    = 256                 # bytes per record (max 476)

def uf2(addr, payload, blkno, nblk):
    b = struct.pack('<8I', 0x0A324655, 0x9E5D5157, 0x00002000, addr,
                    len(payload), blkno, nblk, FAMILY)
    b += payload + b'\x00' * (476 - len(payload))
    return b + struct.pack('<I', 0x0AB16F30)

def check(addr, n):
    if addr % 4:
        sys.exit(f"REFUSING: {addr:#x} is not 4-byte aligned")
    if addr < MIN_ADDR:
        sys.exit(f"REFUSING: {addr:#x} is below LOADER_START. That is boot0/boot1, "
                 "and corrupting it is unrecoverable: update mode lives there.")
    if addr < KERNEL <= addr + n:
        sys.exit(f"REFUSING: {addr:#x}+{n} crosses KERNEL_START {KERNEL:#x}. "
                 "That would overwrite xous.img and brick the badge.")
    if addr + n > MAX_ADDR:
        sys.exit(f"REFUSING: {addr:#x}+{n} exceeds RRAM storage {MAX_ADDR:#x}")

args = [a for a in sys.argv[1:] if a != "--dry"]
DRY  = "--dry" in sys.argv
if len(args) != 3:
    sys.exit(__doc__)
mode, addr_s, val = args
addr = int(addr_s, 16)
if mode == "word":
    data = struct.pack('<I', int(val, 16))
elif mode == "file":
    data = open(val, 'rb').read()
    if len(data) % 4:
        data += b'\x00' * (4 - len(data) % 4)
else:
    sys.exit(__doc__)

check(addr, len(data))
nblk = (len(data) + CHUNK - 1) // CHUNK
recs = [uf2(addr + i*CHUNK, data[i*CHUNK:(i+1)*CHUNK], i, nblk) for i in range(nblk)]
print(f"[plan] {len(data)} bytes -> {nblk} record(s), {addr:#x}..{addr+len(data):#x}")
if DRY:
    for r in recs:
        print("uf2 " + base64.b64encode(r).decode())
    sys.exit(0)

ports = sorted(glob.glob("/dev/cu.usbmodem*"))
if not ports:
    sys.exit("no serial port found")
s = serial.Serial(ports[0], 115200, timeout=3)
s.write(b"\r\n"); time.sleep(0.3); s.reset_input_buffer()

acked = 0
for i, r in enumerate(recs):
    s.write(b"uf2 " + base64.b64encode(r) + b"\r\n")
    deadline = time.time() + 3
    while time.time() < deadline:            # scan for the ack; log lines share this stream
        line = s.readline().decode(errors="replace")
        if "OK" in line or "ok" in line:
            acked += 1
            break
    print(f"\r  {i+1}/{nblk} acked={acked}", end="", flush=True)
print(f"\n[done] {acked}/{nblk} records acknowledged")
if acked != nblk:
    sys.exit("NOT every record was acknowledged. Do not power cycle. Retry the write.")
