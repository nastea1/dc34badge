<picture>
  <source media="(prefers-color-scheme: dark)" srcset="img/grid-dark.svg">
  <img src="img/grid-light.svg" width="96" alt="eight bytes as an 8x8 bit grid">
</picture>

# THE_FLAG_1

A 32-byte value in keystore slot 260, behind hardware access control, on a badge
that never leaves its Sealed state. There is a styled version of this page at
[flag1.html](flag1.html) with the complete source inline.

## What you are dealing with

The badge is a small computer built around **Baochip-1x**, a **RISC-V** processor.
Four things to know:

**Boot chain.** Power on runs four programs in sequence: boot0, then boot1, then
the loader, then the Xous operating system. Each verifies the next before running it.

**Signature check.** That verification is a digital signature, like a wax seal.
The manufacturer fingerprints the program and signs it. The badge recomputes the
fingerprint and checks. Change one byte and it fails.

**Privilege modes.** RISC-V code runs at one of three trust levels: **M-mode**
(machine, unrestricted), **S-mode** (supervisor, for a kernel), **U-mode** (user,
for apps). This distinction is the whole trick.

**RRAM.** The chip's 4 MB of built-in permanent storage, holding all four boot
programs, addressed from `0x6000_0000`.

The keystore is 2048 slots of 32 bytes each starting at `0x603E_0000`. Slot 260
is named `THE_FLAG_1`. Hardware refuses to let the wrong code read protected
slots, and it refuses *silently*: the read returns zeros.

## The flaw

The loader's signature covers bytes 132 onward. The first 132 bytes are excluded
because that space holds the signature. But byte 0 of that unsigned region is a
jump instruction, and it is the first thing executed once the check passes.

The badge carefully verifies the book, then follows a table of contents that is
not part of the book it verified.

| Source | What it shows |
|---|---|
| `bao1x-hal/src/sigcheck.rs:186-192` | Hashing starts at `img_offset + UNSIGNED_LEN`, and `UNSIGNED_LEN` is 132 |
| `bao1x-hal/src/sigcheck.rs:309` | Returns `jump_target = img_offset ^ tag` |
| `bao1x-hal/src/sigcheck.rs:563-564` | `jump_to` does `xor t0,t1,t0; jr t0`, landing on the unhashed byte 0 |
| `boot1/src/repl.rs:137-172` | The `uf2` command, no signature check on write |
| `bao1x-hal/src/rram.rs:343-345` | Read-modify-write on the 32-byte block, so a 4-byte poke leaves the signature intact |

Two facts make it work. You can write those bytes, because boot1's `uf2` command
performs no check at write time. And you only need to write four of them, because
the 32-byte read-modify-write leaves the signature bytes beside them untouched.

## The part that stumped us for a day

Machine mode is total control, so you would expect to read slot 260 and be done.
You cannot. The guard does not care how privileged you are. It cares which
*identity* is asking, and derives that from the paging setup.

`boot1/src/secboot.rs:17` says `protect()` inverts the mm sense, so "you must
enter a virtual memory **user** state to access sealed keys."

We read "user" as "not machine mode" and tested S-mode exhaustively. It returned
zeros every time, and we concluded the protection had held. In RISC-V, S-mode is
*supervisor*. "User" means **U-mode** specifically, and it has to be U-mode at
**ASID 3**, because that is the identity the badge's own keystore service runs
under.

You are not breaking the guard. You are using machine mode to construct exactly
the user-mode context the guard is built to trust.

## Procedure

### 1. Pin the source to your badge

```sh
git -C xous-core worktree add ../xous-BADGE <your-badge-commit>
```

Read your badge's version banner first. The flaw is fixed upstream, so current
code describes a badge that does not exist.

### 2. Build

```sh
cd payload
cargo build --release --bin flag1
python3 ../tools/elf2bin.py target/riscv32imac-unknown-none-elf/release/flag1 flag1.bin
```

The payload goes at `0x6009_0000`, free space between the loader and the OS.
`KERNEL_START` is `0x6009_9000` (`offsets/common.rs:13`). Reaching it overwrites
`xous.img` and bricks the badge. `elf2bin.py` asserts this, so do not bypass it.

### 3. Enter boot1 update mode

Both AA cells out, USB unplugged about 30 seconds, hold a face button while
replugging. The cells must come out: `warm_boot`
(`bao1x-api/src/lib.rs:71-77`) is set on every OS start and clears only on full
power loss, and while set `boot1/src/main.rs:180` ignores your button.

Confirm the badge enumerates as `Baochip_1x`, not `Baosec_lite`. Type
`echo hello` and expect `hello` back.

### 4. Upload

```sh
python3 ../tools/uf2send.py file 0x60090000 flag1.bin
```

### 5. Redirect the jump

```sh
python3 ../tools/uf2send.py word 0x60060000 0003006F
```

`0x0003006F` is `j +0x30000`, exactly the distance from the loader's start to
your payload.

**Optional proof, worth doing once.** Write a bare `j .` (infinite loop) instead.
The badge goes completely dark with no USB. That proves your code ran: a failed
signature would have printed "Image did not validate" and dropped back to the
update prompt, because `try_boot()` is called with `or_die = false`
(`boot1/src/main.rs:182`). Silence means the check passed *and* your instruction
executed.

### 6. Power cycle, no button

boot0, boot1, signature verified, `jr t0` into your code, machine mode, sealed badge.

### 7. What the payload does

Builds an Sv32 identity map with the user bit set, points `satp` at it with
ASID 3, clears `mstatus.MPP` to `00`, and `mret`s into user mode. Reads 32 bytes
at `0x603E_2080`, CRCs them on-chip, then `ecall`s back to machine mode to drive
the display.

```rust
for i in 0..1024 { pt[i] = (i << 20) | 0xDF; }   // 0xDF sets D|A|U|X|W|R|V

csrw mtvec, {trap}
csrw medeleg, zero          // not optional. see 03-troubleshooting.md.
csrw mideleg, zero
csrw stvec, {trap}
sfence.vma
csrw satp, {satp}           // Sv32 | ASID 3 | table address
sfence.vma
li   t0, 0x1800
csrc mstatus, t0            // MPP = 00 is U-mode. 01 is S-mode and reads zeros.
csrw mepc, {u_phase}
mret
```

### 8. Photograph and decode

Six pages, about 3 seconds each.

| Page | Contents |
|---|---|
| 1 | CRC32 of the flag, its first 3 bytes, the fault latch |
| 2 | **Your control.** Eight bytes of the UUID slot. |
| 3 to 6 | The 32 flag bytes |

```sh
python3 tools/decode.py page*.jpg
python3 tools/assemble.py <p3> <p4> <p5> <p6> <crc-from-page-1>
```

If page 1's CRC is `190a55ad`, the flag read back as all zeros and the keystore
denied you. Almost always that means S-mode instead of U-mode.

Set `CONTROL_PAGE2` in `tools/decode.py` to your own badge's value first.
It is unique per badge, so there is no constant we can ship. Without it, the
decoder still runs but cannot tell you when a photo set is untrustworthy, which
is the entire point of a control.

### 9. Restore

```sh
python3 tools/uf2send.py word 0x60060000 3000006F
```

`0x3000006F` is what the build system originally generated there. Next power
cycle the badge boots normally. Nothing in the PDDB was touched, so saved data
and any custom splash survive.

## What this does to your badge

Read only, except the 4-byte jump redirect and the payload in free space, both
reverted in step 9. No writes to the access-control memory, the one-way counters,
or the SPI flash. The badge stays Sealed: Paranoid 0/0, Possible attacks 0, gene
and counters intact across a dozen deploy and restore cycles. Developer mode is
never involved, so the secret-erasing policy never fires.

Next: [02-ko.md](02-ko.md), which picks up from here.
