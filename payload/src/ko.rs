//! Ko extraction crypto: AES-KWP unwrap, AES-GCM-SIV decrypt-without-verify.
//!
//! Verification is deliberately skipped: POLYVAL is unnecessary because in GCM-SIV
//! the stored tag *is* the CTR seed (RFC 8452 §4), and we have a far better oracle
//! than the tag: `sha256(k0)[..4] == dca9ea49`, published in the vendor's own
//! source at dc34-vault/src/main.rs:42. Skipping the tag also retires every
//! AAD-byte-order risk (basis name, PDDB_VERSION, DNA endianness).

use aes::Aes256;
use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit};

/// RFC 5649 AES-KWP unwrap of a 40-byte blob to 32 bytes.
///
/// The AIV check is 64 bits wide, so a pass is strong evidence the KEK is right.
/// That makes this the master key's first real correctness oracle. The UUID slot
/// never was one, because `PartitionAccess::Open` is readable by every coreuser id.
pub fn kwp_unwrap(kek: &[u8; 32], ct: &[u8; 40], out: &mut [u8; 32]) -> bool {
    let c = Aes256::new(GenericArray::from_slice(kek));
    const N: usize = 4; // 40/8 - 1
    let mut a = [0u8; 8];
    a.copy_from_slice(&ct[0..8]);
    let mut r = [[0u8; 8]; N];
    for i in 0..N {
        r[i].copy_from_slice(&ct[8 + 8 * i..16 + 8 * i]);
    }
    for j in (0..6usize).rev() {
        for i in (1..=N).rev() {
            let t = (N * j + i) as u64;
            let mut blk = [0u8; 16];
            blk[0..8].copy_from_slice(&(u64::from_be_bytes(a) ^ t).to_be_bytes());
            blk[8..16].copy_from_slice(&r[i - 1]);
            let mut g = *GenericArray::from_slice(&blk);
            c.decrypt_block(&mut g);
            a.copy_from_slice(&g[0..8]);
            r[i - 1].copy_from_slice(&g[8..16]);
        }
    }
    for i in 0..N {
        out[8 * i..8 * i + 8].copy_from_slice(&r[i]);
    }
    // KWP AIV = A65959A6 || MLI(be32); MLI must be 32 for a 256-bit key.
    a[0] == 0xA6
        && a[1] == 0x59
        && a[2] == 0x59
        && a[3] == 0xA6
        && u32::from_be_bytes([a[4], a[5], a[6], a[7]]) == 32
}

/// AES-GCM-SIV CTR pass, in place. RFC 8452 §4: derive per-nonce keys, then CTR
/// seeded with the tag, MSB of the last byte forced to 1, counter = LE u32 at [0..4].
pub fn gcm_siv_ctr(key: &[u8; 32], nonce: &[u8; 12], tag: &[u8; 16], data: &mut [u8]) {
    let c = Aes256::new(GenericArray::from_slice(key));
    let mut enc = [0u8; 32];
    for i in 0..6u32 {
        let mut b = [0u8; 16];
        b[0..4].copy_from_slice(&i.to_le_bytes());
        b[4..16].copy_from_slice(nonce);
        let mut g = *GenericArray::from_slice(&b);
        c.encrypt_block(&mut g);
        // blocks 0..1 make the auth key (unused here); 2..5 make the 256-bit enc key
        if i >= 2 {
            let o = (i as usize - 2) * 8;
            enc[o..o + 8].copy_from_slice(&g[0..8]);
        }
    }
    let ec = Aes256::new(GenericArray::from_slice(&enc));
    let mut ctr = *tag;
    ctr[15] |= 0x80;
    let mut off = 0usize;
    while off < data.len() {
        let mut g = *GenericArray::from_slice(&ctr);
        ec.encrypt_block(&mut g);
        let n = core::cmp::min(16, data.len() - off);
        for k in 0..n {
            data[off + k] ^= g[k];
        }
        let v = u32::from_le_bytes([ctr[0], ctr[1], ctr[2], ctr[3]]).wrapping_add(1);
        ctr[0..4].copy_from_slice(&v.to_le_bytes());
        off += 16;
    }
}

/// The published oracle. Returns the offset of the first 32-byte window whose
/// SHA-256 begins dc a9 ea 49, or None.
pub fn find_k0(buf: &[u8]) -> Option<usize> {
    use sha2::{Digest, Sha256};
    if buf.len() < 32 {
        return None;
    }
    let mut w = 0usize;
    while w + 32 <= buf.len() {
        let d = Sha256::digest(&buf[w..w + 32]);
        if d[0] == 0xdc && d[1] == 0xa9 && d[2] == 0xea && d[3] == 0x49 {
            return Some(w);
        }
        w += 4;
    }
    None
}
