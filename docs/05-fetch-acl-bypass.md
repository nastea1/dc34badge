<picture>
  <source media="(prefers-color-scheme: dark)" srcset="img/grid-dark.svg">
  <img src="img/grid-light.svg" width="96" alt="eight bytes as an 8x8 bit grid">
</picture>

# Finding: instruction fetches read RRAM with no access control

A second, independent vulnerability found during this work, in **silicon** rather than
firmware. Styled version with the complete payload source: [05-fetch-acl-bypass.html](05-fetch-acl-bypass.html).

> [!IMPORTANT]
> Unpatched at time of writing and disclosed privately to the chip author. Same embargo as
> the rest of this repo. See the [README](../README.md).

## The mechanism

Every access-control term in the RRAM controller is ANDed with `data_op`, and `data_op` is
always zero during an instruction fetch.

| Location | Code | Effect |
|---|---|---|
| `rrc.sv:679` | `assign data_op = !axprot_reg[2];` | "is this a data access" |
| `VexRiscv_CramSoC.sv:7508` | `assign iBusAxi_ar_payload_prot = 3'b110;` | AxPROT[2]=1 on every fetch, so `data_op = 0` |
| `rrc.sv:717` | `key_access_error_pre = (...) & data_op & keysel` | collapses to 0 |
| `rrc.sv:726` | `data_access_error_pre = (...) & data_op & datasel` | collapses to 0 |
| `rrc.sv:782` | `info_access_error_pre = (...) & axi_info & data_op` | collapses to 0 |
| `rrc.sv:819` | `cfg_access_error_pre = (...) & data_op` | collapses to 0 |

The only `inst_op` check (`rrc.sv:770`) additionally requires
`codesel = haddr[31:12] < 20'h603DA` (`:686`, `:644`). The keystore is `0x603F`, the data
slots `0x603E`, the IFR `0x60400`: all above that border, so it never fires. It is also gated
on the CPU-writable `rrccr[12]` (`:778`, `:274`).

The data path cannot substitute: `dbus_axi_arw_payload_prot = 3'b010` is hardwired
(`VexRiscv_CramSoC.sv:7591`).

## This is not the documented limitation

`secboot.rs` notes that an arbitrary-exec primitive can forge the ASID and work around
coreuser. That is acknowledged and fair. This is different: **nothing is forged.** `satp` is
never touched, U-mode is not required, ASID 3 is irrelevant. The check is structurally absent
for those address ranges.

## Confirmed on hardware

IFR data reads return zeros in **every** privilege mode (M-mode and U-mode both tested; the
U-mode read returned CRC `c2a8fa9d`, which is CRC32 of 128 zero bytes, with no fault). Fetches
of the same region return the real contents, matching `blobs/pubkey-block-ifr-0x1a0.bin` at
its exact offsets.

## Measured scope

The bypass reaches the **RRAM array**: main array, IFR, and the key/data apertures. It does
**not** reach ACRAM/cfg at `0x603D_C000`, a separate SRAM on its own port (`rrc.sv:342-347`).
Measured with controls placed inside that region (`0x603D_C010` expecting `02 00 f0 00`, and
`0x603D_C410` expecting `0x00400000`): both read zero while the mechanism control passed in
the same run.

## Reading safely

Fetched bytes execute if they decode legally. Run the fetch in U-mode under a page table
mapping only the target pages **execute-only** (PTE flags `0xD9` = D|A|U|X|V, no R, no W):

- no readable or writable mapping exists, so every load and store faults before reaching
  MMIO, which makes `suicide_start` (`rrc.sv:307`) unreachable by construction
- CSR access, `mret`, `sret`, `wfi`, `ecall` and `ebreak` all trap from U-mode
- a jump outside the mapped pages takes an instruction page fault

Recover each word from `mtval` on the illegal-instruction trap, fetching at every halfword
offset so the reads overlap.

> [!WARNING]
> A `mtval`-based read **cannot distinguish "blocked" from "zero"**, because a blocked fetch
> returns `0x0000`, which is itself a defined-illegal RVC encoding trapping with `mtval = 0`.
> Any "all zeros" verdict is void unless a known-nonzero value from the **same aperture** was
> recovered in the same pass. A control in your own payload page proves the technique, not
> the reach.

## Suggested fix

The `data_op` gating reads as "only data accesses need checking", which holds only if
instruction fetches can never reach protected regions. They can. Either apply the ACL terms
regardless of `data_op` for the key, data and info apertures, or extend `codesel` to cover
everything above `0x603DA`.
