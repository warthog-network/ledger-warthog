//! `r || s || recid`, matching `warthog-js` signature65 and the C app.
//!
//! recid bit 0 is the Y parity. A high `s` is replaced with `n - s` and bit 0 is flipped.
//! The Rust SDK's `deterministic_sign` only reports Y parity, so recid bit 1 (`r.x > n`)
//! stays clear. That bit is set for a negligible fraction of signatures.

const SECP256K1_N: [u8; 32] = [
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
    0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B, 0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x41,
];

const SECP256K1_N_HALF: [u8; 32] = [
    0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0x5D, 0x57, 0x6E, 0x73, 0x57, 0xA4, 0x50, 0x1D, 0xDF, 0xE9, 0x2F, 0x46, 0x68, 0x1B, 0x20, 0xA0,
];

fn cmp32(left: &[u8; 32], right: &[u8; 32]) -> i8 {
    for i in 0..32 {
        if left[i] != right[i] {
            return if left[i] < right[i] { -1 } else { 1 };
        }
    }
    0
}

fn is_zero(value: &[u8; 32]) -> bool {
    value.iter().fold(0u8, |acc, byte| acc | byte) == 0
}

/// `out = left - right`. Caller guarantees `left >= right`.
fn sub32(out: &mut [u8; 32], left: &[u8; 32], right: &[u8; 32]) {
    let mut borrow = 0i16;
    for i in (0..32).rev() {
        let mut diff = left[i] as i16 - right[i] as i16 - borrow;
        if diff < 0 {
            diff += 256;
            borrow = 1;
        } else {
            borrow = 0;
        }
        out[i] = diff as u8;
    }
}

/// Low-`s` form. Returns false when `r` or `s` is 0 or is not strictly less than `n`.
pub fn signature65_canonicalize(raw: &mut [u8; 65]) -> bool {
    let mut r = [0u8; 32];
    let mut s = [0u8; 32];
    r.copy_from_slice(&raw[..32]);
    s.copy_from_slice(&raw[32..64]);

    if is_zero(&r) || is_zero(&s) || cmp32(&r, &SECP256K1_N) >= 0 || cmp32(&s, &SECP256K1_N) >= 0 {
        return false;
    }
    if cmp32(&s, &SECP256K1_N_HALF) > 0 {
        let mut low = [0u8; 32];
        sub32(&mut low, &SECP256K1_N, &s);
        raw[32..64].copy_from_slice(&low);
        raw[64] ^= 1;
    }
    true
}

/// Decode an ECDSA DER signature into padded 32-byte `r` and `s`.
pub fn der_to_rs(der: &[u8]) -> Option<([u8; 32], [u8; 32])> {
    if der.len() < 8 || der[0] != 0x30 {
        return None;
    }
    // Short-form length only. A secp256k1 DER signature is at most 72 bytes.
    if der[1] & 0x80 != 0 || der[1] as usize != der.len() - 2 {
        return None;
    }
    let mut i = 2;
    let r = read_der_int(der, &mut i)?;
    let s = read_der_int(der, &mut i)?;
    if i != der.len() {
        return None;
    }
    Some((r, s))
}

fn read_der_int(der: &[u8], i: &mut usize) -> Option<[u8; 32]> {
    if *i >= der.len() || der[*i] != 0x02 {
        return None;
    }
    *i += 1;
    if *i >= der.len() {
        return None;
    }
    let len = der[*i] as usize;
    *i += 1;
    if len == 0 || *i + len > der.len() {
        return None;
    }
    let bytes = &der[*i..*i + len];
    *i += len;
    // Drop a single DER sign-padding 0x00, then reject anything that still does not fit.
    let bytes = if bytes.len() > 1 && bytes[0] == 0x00 {
        &bytes[1..]
    } else {
        bytes
    };
    if bytes.is_empty() || bytes.len() > 32 {
        return None;
    }
    let mut out = [0u8; 32];
    out[32 - bytes.len()..].copy_from_slice(bytes);
    Some(out)
}
