use alloc::vec::Vec;

use crate::tx::wart_path_ok;
use crate::AppSW;
use ledger_device_sdk::ecc::{Secp256k1, SeedDerive};

/// BIP32 derivation path stored as a vector of u32 components.
///
/// Hardened derivation is indicated by setting the high bit (>= 0x80000000).
/// Only the two Warthog paths are accepted: `m/44'/2070'/0'/0/index` and
/// `m/44'/2070'/0/0/index`.
#[derive(Default)]
pub struct Bip32Path(Vec<u32>);

impl AsRef<[u32]> for Bip32Path {
    fn as_ref(&self) -> &[u32] {
        &self.0
    }
}

impl TryFrom<&[u8]> for Bip32Path {
    type Error = AppSW;

    /// APDU encoding: one length byte, then each index as a 4-byte big-endian integer.
    fn try_from(data: &[u8]) -> Result<Self, Self::Error> {
        if data.is_empty() || (data[0] as usize * 4 != data.len() - 1) {
            return Err(AppSW::WrongDataLength);
        }

        let path: Vec<u32> = data[1..]
            .chunks(4)
            .map(|chunk| u32::from_be_bytes(chunk.try_into().unwrap()))
            .collect();
        if !wart_path_ok(&path) {
            return Err(AppSW::IncorrectData);
        }
        Ok(Bip32Path(path))
    }
}

/// Uncompressed secp256k1 public key: `0x04 || X || Y`.
pub fn get_pubkey_from_path(path: &Bip32Path) -> Result<[u8; 65], AppSW> {
    let (k, _) = Secp256k1::derive_from(path.as_ref());
    let pk = k.public_key().map_err(|_| AppSW::IncorrectData)?;
    if pk.pubkey[0] != 0x04 {
        return Err(AppSW::IncorrectData);
    }
    Ok(pk.pubkey)
}
