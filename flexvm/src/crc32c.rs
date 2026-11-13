//! CRC32C, the checksum of checkpoint pages. With SSE4.2 or the Arm CRC extension a page is
//! three interleaved streams (`crc32`/`crc32cx` have 2-3 cycle latency but issue every cycle)
//! combined with shift tables; the same pass tells whether the page is all zero.

use std::sync::OnceLock;

const POLY: u32 = 0x82F6_3B78;

fn table() -> &'static [u32; 256] {
    static T: OnceLock<[u32; 256]> = OnceLock::new();
    T.get_or_init(|| {
        let mut t = [0u32; 256];
        for (i, e) in t.iter_mut().enumerate() {
            let mut c = i as u32;
            for _ in 0..8 {
                c = if c & 1 != 0 { (c >> 1) ^ POLY } else { c >> 1 };
            }
            *e = c;
        }
        t
    })
}

/// No pre- or post-inversion.
fn update_sw(mut c: u32, bytes: &[u8]) -> u32 {
    let t = table();
    for &b in bytes {
        c = t[((c ^ b as u32) & 0xff) as usize] ^ (c >> 8);
    }
    c
}

pub fn crc32c(bytes: &[u8]) -> u32 {
    #[cfg(target_arch = "x86_64")]
    if std::arch::is_x86_feature_detected!("sse4.2") {
        // SAFETY: the CPU has SSE4.2.
        return !unsafe { hw::update(!0, bytes) };
    }
    #[cfg(target_arch = "aarch64")]
    if std::arch::is_aarch64_feature_detected!("crc") {
        // SAFETY: the CPU has the CRC extension.
        return !unsafe { hw::update(!0, bytes) };
    }
    !update_sw(!0, bytes)
}

#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
const STREAM: usize = crate::util::PAGE_SIZE / 24 * 8;

/// Advance a CRC register over `STREAM` zero bytes, a register byte at a time (it is linear).
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
fn shift_tables() -> &'static [[u32; 256]; 4] {
    static T: OnceLock<[[u32; 256]; 4]> = OnceLock::new();
    T.get_or_init(|| {
        let zeros = [0u8; STREAM];
        let bit: Vec<u32> = (0..32).map(|i| update_sw(1 << i, &zeros)).collect();
        let mut t = [[0u32; 256]; 4];
        for (k, tk) in t.iter_mut().enumerate() {
            for (b, e) in tk.iter_mut().enumerate() {
                *e = (0..8).filter(|i| b & (1 << i) != 0).fold(0, |a, i| a ^ bit[8 * k + i]);
            }
        }
        t
    })
}

#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
fn shift(t: &[[u32; 256]; 4], c: u32) -> u32 {
    t[0][(c & 0xff) as usize] ^ t[1][((c >> 8) & 0xff) as usize] ^ t[2][((c >> 16) & 0xff) as usize] ^ t[3][(c >> 24) as usize]
}

pub fn page(p: &[u8]) -> (u32, bool) {
    debug_assert_eq!(p.len(), crate::util::PAGE_SIZE);
    #[cfg(target_arch = "x86_64")]
    if std::arch::is_x86_feature_detected!("sse4.2") {
        // SAFETY: the CPU has SSE4.2.
        let (c, zero) = unsafe { hw::page(!0, p, shift_tables()) };
        return (!c, zero);
    }
    #[cfg(target_arch = "aarch64")]
    if std::arch::is_aarch64_feature_detected!("crc") {
        // SAFETY: the CPU has the CRC extension.
        let (c, zero) = unsafe { hw::page(!0, p, shift_tables()) };
        return (!c, zero);
    }
    let zero = p.chunks_exact(8).fold(0u64, |a, w| a | u64::from_ne_bytes(w.try_into().unwrap())) == 0;
    (crc32c(p), zero)
}

#[cfg(target_arch = "x86_64")]
mod hw {
    use std::arch::x86_64::{_mm_crc32_u64, _mm_crc32_u8};

    use super::{shift, STREAM};

    #[target_feature(enable = "sse4.2")]
    pub(super) unsafe fn update(mut c: u32, bytes: &[u8]) -> u32 {
        let mut pages = bytes.chunks_exact(4096);
        if bytes.len() >= 4096 {
            let t = super::shift_tables();
            for p in &mut pages {
                c = page(c, p, t).0;
            }
        }
        let bytes = pages.remainder();
        let mut c = c as u64;
        let mut words = bytes.chunks_exact(8);
        for w in &mut words {
            c = _mm_crc32_u64(c, u64::from_le_bytes(w.try_into().unwrap()));
        }
        let mut c = c as u32;
        for &b in words.remainder() {
            c = _mm_crc32_u8(c, b);
        }
        c
    }

    #[target_feature(enable = "sse4.2")]
    pub(super) unsafe fn page(init: u32, p: &[u8], t: &[[u32; 256]; 4]) -> (u32, bool) {
        let word = |w: &[u8]| u64::from_le_bytes(w.try_into().unwrap());
        let (streams, rest) = p.split_at(3 * STREAM);
        let (s0, s12) = streams.split_at(STREAM);
        let (s1, s2) = s12.split_at(STREAM);
        let (mut a, mut b, mut c, mut or) = (init as u64, 0u64, 0u64, 0u64);
        // Fixed-size chunks: no bounds checks in the loop.
        for ((x, y), z) in s0.chunks_exact(8).zip(s1.chunks_exact(8)).zip(s2.chunks_exact(8)) {
            let (x, y, z) = (word(x), word(y), word(z));
            a = _mm_crc32_u64(a, x);
            b = _mm_crc32_u64(b, y);
            c = _mm_crc32_u64(c, z);
            or |= x | y | z;
        }
        // raw(r, X) = shift(r, |X|) ^ raw(0, X): stitch the streams together.
        let mut r = (shift(t, shift(t, a as u32) ^ b as u32) ^ c as u32) as u64;
        for x in rest.chunks_exact(8) {
            let x = word(x);
            r = _mm_crc32_u64(r, x);
            or |= x;
        }
        (r as u32, or == 0)
    }
}

#[cfg(target_arch = "aarch64")]
mod hw {
    use std::arch::aarch64::{__crc32cb, __crc32cd, __crc32cw};

    use super::{shift, STREAM};

    #[target_feature(enable = "crc")]
    pub(super) unsafe fn update(mut c: u32, bytes: &[u8]) -> u32 {
        let mut pages = bytes.chunks_exact(4096);
        if bytes.len() >= 4096 {
            let t = super::shift_tables();
            for p in &mut pages {
                c = page(c, p, t).0;
            }
        }
        let bytes = pages.remainder();
        let mut words = bytes.chunks_exact(8);
        for w in &mut words {
            c = __crc32cd(c, u64::from_le_bytes(w.try_into().unwrap()));
        }
        let mut rest = words.remainder();
        if let Some((w, r)) = rest.split_first_chunk::<4>() {
            c = __crc32cw(c, u32::from_le_bytes(*w));
            rest = r;
        }
        for &b in rest {
            c = __crc32cb(c, b);
        }
        c
    }

    #[target_feature(enable = "crc")]
    pub(super) unsafe fn page(init: u32, p: &[u8], t: &[[u32; 256]; 4]) -> (u32, bool) {
        let word = |w: &[u8]| u64::from_le_bytes(w.try_into().unwrap());
        let (streams, rest) = p.split_at(3 * STREAM);
        let (s0, s12) = streams.split_at(STREAM);
        let (s1, s2) = s12.split_at(STREAM);
        let (mut a, mut b, mut c, mut or) = (init, 0u32, 0u32, 0u64);
        // Fixed-size chunks: no bounds checks in the loop.
        for ((x, y), z) in s0.chunks_exact(8).zip(s1.chunks_exact(8)).zip(s2.chunks_exact(8)) {
            let (x, y, z) = (word(x), word(y), word(z));
            a = __crc32cd(a, x);
            b = __crc32cd(b, y);
            c = __crc32cd(c, z);
            or |= x | y | z;
        }
        // raw(r, X) = shift(r, |X|) ^ raw(0, X): stitch the streams together.
        let mut r = shift(t, shift(t, a) ^ b) ^ c;
        for x in rest.chunks_exact(8) {
            let x = word(x);
            r = __crc32cd(r, x);
            or |= x;
        }
        (r, or == 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::PAGE_SIZE;

    #[test]
    fn known_values() {
        assert_eq!(crc32c(b"123456789"), 0xE306_9283);
        assert_eq!(!update_sw(!0, b"123456789"), 0xE306_9283);
        assert_eq!(crc32c(&[0u8; 32]), 0x8A91_36AA);
    }

    #[test]
    fn page_matches_the_plain_crc() {
        let mut p = vec![0u8; PAGE_SIZE];
        assert_eq!(page(&p), (crc32c(&p), true));
        for seed in 0..64u64 {
            let mut x = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1;
            for b in p.iter_mut() {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                *b = if seed % 4 == 0 { 0 } else { x as u8 };
            }
            p[(seed as usize * 61) % PAGE_SIZE] = seed as u8 | 1;
            assert_eq!(page(&p), (!update_sw(!0, &p), false), "seed {seed}");
        }
    }

    /// The hardware path against the software one, at every offset and every short length
    /// (the word and byte tails), and on buffers of several pages.
    #[test]
    fn hw_matches_sw() {
        let mut x = 0x9E37_79B9_7F4A_7C15u64;
        let buf: Vec<u8> = (0..4 * PAGE_SIZE + 64)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                x as u8
            })
            .collect();
        for off in 0..16 {
            for len in 0..=64 {
                let b = &buf[off..off + len];
                assert_eq!(crc32c(b), !update_sw(!0, b), "offset {off} length {len}");
            }
            for len in [PAGE_SIZE - 1, PAGE_SIZE, PAGE_SIZE + 7, 4 * PAGE_SIZE + 13] {
                let b = &buf[off..off + len];
                assert_eq!(crc32c(b), !update_sw(!0, b), "offset {off} length {len}");
            }
            let p = &buf[off..off + PAGE_SIZE];
            assert_eq!(page(p), (!update_sw(!0, p), false), "offset {off}");
        }
    }

    #[test]
    fn multi_page_matches_sw() {
        let mut x = 0x9E37_79B9_7F4A_7C15u64;
        let buf: Vec<u8> = (0..16384)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                x as u8
            })
            .collect();
        for len in [4096, 4097, 8192, 12345, 16384] {
            let b = &buf[..len];
            assert_eq!(crc32c(b), !update_sw(!0, b), "length {len}");
        }
    }
}
