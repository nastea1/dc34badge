//! Shared plumbing: the OLED output channel, and a CRC so the badge can tell you
//! whether your photo decode was right.
//!
//! Output is a screen because nothing else is available. UART is not broken out on
//! the carrier, the BIO FIFOs are cleared at boot, and USB is shut down before the
//! loader runs (boot1/src/main.rs:390-392).

pub const CLKTOP_HZ: u32 = 700_000_000;

/// Eight bytes as an 8x8 grid: 12 px cells on a 14 px pitch, inset 8 px, MSB leftmost.
/// Plus a 2 px lit border (so a decoder can find the corners in a handheld photo) and
/// `tag` blobs in the top margin (so you know which page you photographed).
///
/// Polarity is inverted on this panel: clear() fills 0xFFFF_FFFF, so a 0 bit is LIT.
pub fn draw_page8(fb: &mut [u32], eight: &[u8], tag: usize) {
    for w in fb.iter_mut() {
        *w = 0xFFFF_FFFF;
    }
    let mut lit = |x: usize, y: usize| {
        if x < 128 && y < 128 {
            let b = x + y * 128;
            fb[b / 32] &= !(1u32 << (b % 32));
        }
    };
    for i in 0..128usize {
        for t in 0..2usize {
            lit(i, t);
            lit(i, 127 - t);
            lit(t, i);
            lit(127 - t, i);
        }
    }
    for k in 0..tag.min(8) {
        for dy in 3..7usize {
            for dx in 0..6usize {
                lit(20 + k * 11 + dx, dy);
            }
        }
    }
    for (row, &byte) in eight.iter().enumerate() {
        for bit in 0..8usize {
            if (byte >> (7 - bit)) & 1 == 0 {
                continue;
            }
            for dy in 0..12usize {
                for dx in 0..12usize {
                    lit(8 + bit * 14 + dx, 8 + row * 14 + dy);
                }
            }
        }
    }
}

/// About 3 seconds at 400_000_000. Our first attempt used 30_000_000, which is
/// roughly 0.09 s: the pages flickered at 6 Hz and were unphotographable.
pub fn spin(n: u32) {
    for _ in 0..n {
        core::hint::spin_loop();
    }
}

pub fn crc32(d: &[u8]) -> u32 {
    let mut c: u32 = 0xFFFF_FFFF;
    for &b in d {
        c ^= b as u32;
        for _ in 0..8 {
            let m = (c & 1).wrapping_neg();
            c = (c >> 1) ^ (0xEDB8_8320 & m);
        }
    }
    !c
}

pub fn open_oled<'a>(
    iox: &'a bao1x_hal::iox::Iox,
    udma: &'a bao1x_hal::udma::GlobalConfig,
) -> bao1x_hal::sh1107::Oled128x128<'a> {
    use bao1x_hal::sh1107::{MainThreadToken, Oled128x128};
    use utralib::*;
    let sysctrl = CSR::new(utra::sysctrl::HW_SYSCTRL_BASE as *mut u32);
    let fd = sysctrl.r(utra::sysctrl::SFR_CGUFDPER) & 0xFF;
    let perclk = bao1x_hal::clocks::divide_by_fd(fd, CLKTOP_HZ) / 2;
    let mut o = Oled128x128::new(MainThreadToken::new(), perclk, iox, udma);
    o.init().ok();
    o
}

// bao1x-hal pulls in `alloc`, so a bare-metal binary linking it needs a global
// allocator even though the payloads never intentionally allocate. A bump
// allocator that never frees is exactly right here: the payload runs once and
// the badge is power cycled.
pub struct Bump;
static mut ARENA: [u8; 8192] = [0; 8192];
static mut NEXT: usize = 0;

unsafe impl core::alloc::GlobalAlloc for Bump {
    unsafe fn alloc(&self, l: core::alloc::Layout) -> *mut u8 {
        unsafe {
            let base = core::ptr::addr_of_mut!(ARENA) as usize;
            let start = (base + NEXT + l.align() - 1) & !(l.align() - 1);
            let end = start - base + l.size();
            if end > 8192 {
                return core::ptr::null_mut();
            }
            NEXT = end;
            start as *mut u8
        }
    }
    unsafe fn dealloc(&self, _p: *mut u8, _l: core::alloc::Layout) {}
}
