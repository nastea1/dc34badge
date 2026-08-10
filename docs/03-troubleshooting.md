# Troubleshooting

Every entry here cost at least one boot cycle, and a boot cycle is about five
minutes of pulling batteries and waiting.

## Symptoms

| What you see | What is wrong | Fix |
|---|---|---|
| Screen blank, badge seems dead | boot1 leaves `medeleg`/`mideleg` at `0xFFFFFFFF` (`irq.rs:50-51`) and never restores them, so your own `ecall` is delivered to an uninitialised `stvec` | Clear both before `mret` |
| Variables contain nonsense | No C runtime on this path, so `.bss` is never zeroed and your "empty" statics hold old SRAM | Zero `__sbss` to `__ebss` in `_start` |
| Screen looks like a photo negative | `clear()` fills all ones, so a **0 bit is lit** | Invert your rendering |
| Keystore reads all zero, no error | Denied. It fails silently. | Always read a known value alongside |
| Control page decodes fine, flag still zeros | You are in S-mode, not U-mode | `MPP = 00`, not `01` |
| Pages flicker too fast to photograph | `spin(30_000_000)` is about 0.09 s | `spin(400_000_000)`, about 3 s |
| Decode looks plausible but is subtly wrong | Sampling grid off by one whole cell, which silently inserts a byte | Measure your offset search in cells, not pixels, and trust only a CRC match |
| Every flash read is `0xff` | Missing `mem_qpi_mode(true)` before the first `mem_read` | See [02-ko.md](02-ko.md) |
| Badge dark forever during flash work | You called `identify_flash_reset_qpi()` and `flash_ensure_qe()` is spinning on a `0xff` bus | Use the read-only sequence in `payload/src/bin/ko.rs` |
| Button held at cold boot, still boots normally | `warm_boot` is still set | Take both AA cells out and wait |
| `uf2send.py` refuses an address | Working as designed | Read the message. It is stopping you from bricking the badge. |

## The two that are worth internalising

**Denied reads and dead buses both look like your own bug.** A protected keystore
slot returns zeros without faulting. A misconfigured SPI bus returns `0xff`
without erroring. Neither is distinguishable from a broken toolchain, and both
produced confident, written-down, wrong conclusions in this project. The only
defence is a known-value control read in the same breath, every run.

**A control must be in the same permission class as your claim.** The UUID slot is
`PartitionAccess::Open`, which `coreuser.rs` turns into "readable by every
coreuser id". Passing it proves your user-mode context exists. It proves nothing
whatsoever about `Fw0` slots. I validated against it, generalised, and was
wrong for a day. If your control is easier to satisfy than your claim, it is not
a control.

## Recovery

**Payload written, jump retargeted, and something is wrong.** Cold boot back to
update mode and restore the header:

```sh
python3 tools/uf2send.py word 0x60060000 3000006F
```

Update mode lives in boot1, which you never touched, so this always works.

**The one unrecoverable action** is writing below `0x60060000`, which is boot0 and
boot1 themselves, or at or above `0x60099000`, which is `xous.img`. The first
destroys the way back in. The second bricks the OS. `uf2send.py` and `elf2bin.py`
both refuse, and neither guard should be removed.

**Developer mode** is not a recovery path. It is the failure state. It erases the
secrets you are trying to read.
