<picture>
  <source media="(prefers-color-scheme: dark)" srcset="img/grid-dark.svg">
  <img src="img/grid-light.svg" width="96" alt="eight bytes as an 8x8 bit grid">
</picture>

# Upstream status

Checked 2026-08-07 against `betrusted-io/xous-core` branch `dev` at `5d5bbbfa9`
(2026-08-03), which is **197 commits ahead** of the badge's own `8964027ff`.

## The unsigned header is still there

Every link is unchanged, and one of them is byte-identical.

| Element | Badge `8964027ff` | Upstream `dev` `5d5bbbfa9` |
|---|---|---|
| `UNSIGNED_LEN` | 132 | 132, `SignatureInFlash::sealed_data_offset()` |
| Hash start | `img_offset + UNSIGNED_LEN` | unchanged, `sigcheck.rs:173-175` |
| `jump_target` | `(img_offset as u32) ^ tag` | **identical**, `sigcheck.rs:435` |
| `jump_to` | `xor t0,t1,t0; jr t0` | unchanged, `sigcheck.rs:865-866` |
| `uf2` write window | `[BAREMETAL_START, HW_RERAM_MEM + RRAM_STORAGE_LEN)`, no signature check at write time | unchanged |

This is not a bug sitting in a forgotten corner. `sigcheck.rs` gained roughly 330 lines and
`boot1/src/repl.rs` roughly 439 over those 197 commits, including post-quantum signature
support added to the very function that computes `jump_target`. The surrounding code was
actively worked on. The jump target was not touched.

The fix is still the one in the original report: `SIGBLOCK_LEN` is a constant, so `jump_to`
could target `img_offset + SIGBLOCK_LEN` and drop `_jal_instruction` from the control path
entirely.

## The Ko chain also still holds

| Step | Upstream status |
|---|---|
| U-mode ASID 3 reaches `Fw0` slots | `coreuser.rs` unchanged |
| `ROOT_SEED` slot 256, nuisance 8..128 and 1920..2048, chaff 128..256 | unchanged, all still `Fw0` |
| `KEK = HKDF-SHA256(salt, ikm)`, info `"sec"` | unchanged |
| Master key used raw as the AES-KW KEK (`Kek::from`) | unchanged |
| `StaticCryptoData`, `SCD_VERSION = 2` | `pddb/src/backend/hw.rs` unchanged |
| `sha256(k0)[..4] == dca9ea49` oracle | still present in `dc34-vault/src/main.rs:42` |

`store.rs` gained about 400 lines, but all of it is swap encryption (`get_swap_key`,
`ensure_swap_encryption`). The derivation is untouched; even the length assertion is the
same logic, written generically as `(nk_len + 1 + 1) * KEY_LEN` rather than the literal 8000.

## Reaching Fw0 from U-mode is NOT a vulnerability

Upstream added a comment to `secboot.rs` after this badge shipped that states the design
position directly:

> "this does not offer unbreakable security. Rather, it prevents someone with an arbitrary
> read primitive from accessing secret keys. **An arbitrary-exec primitive can, of course,
> forge the ASID and work around the coreuser mechanism.**"

So the ASID 3 technique in [01-flag1.md](01-flag1.md) is working as designed, and the vendor
documents it as such. Coreuser is scoped to defend against read primitives only, and against
that threat model it holds.

Everything in this repo therefore rests on **one** break: the unsigned header handing you
machine mode. Every step after it is the documented consequence of arbitrary execution, not
a separate flaw. That makes the finding narrower and stronger at the same time, because it
points at a single fixable line rather than a diffuse chain.

## Why this matters for the embargo

A patched bug is a war story. This one is live in shipping code, which is why nothing in this
repo may be published until the badge author says otherwise. See the notice in the
[README](../README.md).
