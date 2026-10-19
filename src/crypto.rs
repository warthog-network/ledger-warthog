//! Warthog address and signature65.
//!
//! payload = RIPEMD160(SHA256(compressed pubkey))
//! address = payload || SHA256(payload)[0..4]   (24 bytes, 48 hex characters)
//!
//! The signed message is one SHA-256 of the 79-byte transfer body.

use crate::signature65::{der_to_rs, signature65_canonicalize};
use crate::AppSW;
use ledger_device_sdk::ecc::{Secp256k1, SeedDerive};
use ledger_device_sdk::hash::ripemd::Ripemd160;
use ledger_device_sdk::hash::sha2::Sha2_256;
use ledger_device_sdk::hash::HashInit;

pub const WART_ADDRESS_LEN: usize = 24;

fn sha256(input: &[u8]) -> Result<[u8; 32], AppSW> {
    let mut hasher = Sha2_256::new();
    let mut out = [0u8; 32];
    hasher.hash(input, &mut out).map_err(|_| AppSW::IncorrectData)?;
    Ok(out)
}

fn ripemd160(input: &[u8]) -> Result<[u8; 20], AppSW> {
    let mut hasher = Ripemd160::new();
    let mut out = [0u8; 20];
    hasher.hash(input, &mut out).map_err(|_| AppSW::IncorrectData)?;
    Ok(out)
}

/// Address from an uncompressed secp256k1 key (`0x04 || X || Y`).
pub fn address_from_pubkey(public_key: &[u8; 65]) -> Result<[u8; WART_ADDRESS_LEN], AppSW> {
    if public_key[0] != 0x04 {
        return Err(AppSW::IncorrectData);
    }
    let mut compressed = [0u8; 33];
    compressed[0] = if public_key[64] & 1 == 1 { 0x03 } else { 0x02 };
    compressed[1..].copy_from_slice(&public_key[1..33]);
    let hashed = sha256(&compressed)?;
    let payload = ripemd160(&hashed)?;
    address_from_payload(&payload)
}

/// `payload || SHA256(payload)[0..4]`.
pub fn address_from_payload(payload: &[u8; 20]) -> Result<[u8; WART_ADDRESS_LEN], AppSW> {
    let checksum = sha256(payload)?;
    let mut out = [0u8; WART_ADDRESS_LEN];
    out[..20].copy_from_slice(payload);
    out[20..].copy_from_slice(&checksum[..4]);
    Ok(out)
}

/// SHA-256 of `message`, then RFC6979 secp256k1, returned as signature65.
pub fn sign_hash(path: &[u32], message_hash: &[u8]) -> Result<[u8; 65], AppSW> {
    ledger_device_sdk::log::debug!("Signing Warthog message hash");
    let (der, der_len, parity) = Secp256k1::derive_from_path(path)
        .deterministic_sign(message_hash)
        .map_err(|_| AppSW::SecurityIssue)?;
    let der_len = der_len as usize;
    if der_len > der.len() {
        return Err(AppSW::SecurityIssue);
    }
    let (r, s) = der_to_rs(&der[..der_len]).ok_or(AppSW::SecurityIssue)?;
    let mut raw = [0u8; 65];
    raw[..32].copy_from_slice(&r);
    raw[32..64].copy_from_slice(&s);
    if parity != 0 {
        raw[64] |= 1;
    }
    if !signature65_canonicalize(&mut raw) {
        return Err(AppSW::SecurityIssue);
    }
    Ok(raw)
}
