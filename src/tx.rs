//! Native Warthog transfer: the 79-byte body from the C app's APDU.
//!
//! pin hash (32) || pin height (4) || nonce (4) || 3 zero bytes || fee (8) || to (20) || amount (8)
//! Amounts are E8. 1 WART is 100_000_000.

use alloc::string::String;

pub const NATIVE_TX_LEN: usize = 79;
pub const WART_DECIMALS: u32 = 8;

pub struct NativeTx {
    pub pin_hash: [u8; 32],
    pub pin_height: u32,
    pub nonce: u32,
    pub fee: u64,
    pub to: [u8; 20],
    pub amount: u64,
}

/// Accept `m/44'/2070'/0'/0/index` and `m/44'/2070'/0/0/index`.
/// The address index is not hardened.
pub fn wart_path_ok(path: &[u32]) -> bool {
    const HARDENED: u32 = 0x8000_0000;
    if path.len() != 5 {
        return false;
    }
    path[0] == (HARDENED | 44)
        && path[1] == (HARDENED | 2070)
        && (path[2] == (HARDENED | 0) || path[2] == 0)
        && path[3] == 0
        && (path[4] & HARDENED) == 0
}

pub fn parse_native_tx(raw: &[u8]) -> Option<NativeTx> {
    if raw.len() != NATIVE_TX_LEN {
        return None;
    }
    if raw[40] != 0 || raw[41] != 0 || raw[42] != 0 {
        return None;
    }
    Some(NativeTx {
        pin_hash: raw[0..32].try_into().ok()?,
        pin_height: u32::from_be_bytes(raw[32..36].try_into().ok()?),
        nonce: u32::from_be_bytes(raw[36..40].try_into().ok()?),
        fee: u64::from_be_bytes(raw[43..51].try_into().ok()?),
        to: raw[51..71].try_into().ok()?,
        amount: u64::from_be_bytes(raw[71..79].try_into().ok()?),
    })
}

/// Format an E8 amount the way the C app's `format_fpu64` does, then append ` WART`.
/// Trailing fractional zeros are dropped. `250_000_000` is `2.5 WART`.
pub fn format_wart(value: u64) -> String {
    let scale = 10u64.pow(WART_DECIMALS);
    let whole = value / scale;
    let frac = value % scale;
    if frac == 0 {
        return alloc::format!("{whole} WART");
    }
    let mut digits = [b'0'; 8];
    let mut rest = frac;
    for slot in digits.iter_mut().rev() {
        *slot = b'0' + (rest % 10) as u8;
        rest /= 10;
    }
    let mut end = 8;
    while end > 1 && digits[end - 1] == b'0' {
        end -= 1;
    }
    let frac_str = core::str::from_utf8(&digits[..end]).unwrap_or("0");
    alloc::format!("{whole}.{frac_str} WART")
}
