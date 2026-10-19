use crate::crypto::WART_ADDRESS_LEN;
use crate::tx::{format_wart, NativeTx};
use crate::AppSW;

use ledger_device_sdk::include_gif;
use ledger_device_sdk::io::Comm;
use ledger_device_sdk::nbgl::{Field, NbglGlyph, NbglReview};

use alloc::format;
use alloc::string::String;

/// Review a native WART transfer. Returns true when the user approves it.
pub fn ui_display_tx(
    comm: &mut Comm,
    tx: &NativeTx,
    path: &[u32],
    from: &[u8; WART_ADDRESS_LEN],
    to: &[u8; WART_ADDRESS_LEN],
) -> Result<bool, AppSW> {
    let from_str = hex::encode(from);
    let path_str = format_path(path);
    let amount_str = format_wart(tx.amount);
    let fee_str = format_wart(tx.fee);
    let to_str = hex::encode(to);
    let nonce_str = format!("{}", tx.nonce);
    let pin_height_str = format!("{}", tx.pin_height);
    let pin_hash_str = hex::encode(tx.pin_hash);

    let fields = [
        Field {
            name: "From",
            value: from_str.as_str(),
        },
        Field {
            name: "Path",
            value: path_str.as_str(),
        },
        Field {
            name: "Amount",
            value: amount_str.as_str(),
        },
        Field {
            name: "Fee",
            value: fee_str.as_str(),
        },
        Field {
            name: "To",
            value: to_str.as_str(),
        },
        Field {
            name: "Nonce",
            value: nonce_str.as_str(),
        },
        Field {
            name: "Pin height",
            value: pin_height_str.as_str(),
        },
        Field {
            name: "Pin hash",
            value: pin_hash_str.as_str(),
        },
    ];

    #[cfg(target_os = "apex_p")]
    const WART_ICON: NbglGlyph =
        NbglGlyph::from_include(include_gif!("glyphs/crab_48x48.png", NBGL));
    #[cfg(any(target_os = "stax", target_os = "flex"))]
    const WART_ICON: NbglGlyph =
        NbglGlyph::from_include(include_gif!("glyphs/crab_64x64.gif", NBGL));
    #[cfg(any(target_os = "nanosplus", target_os = "nanox"))]
    const WART_ICON: NbglGlyph =
        NbglGlyph::from_include(include_gif!("icons/crab_14x14.gif", NBGL));

    let review: NbglReview = NbglReview::new()
        .titles(
            "Review transaction\nto send WART",
            "",
            "Sign transaction\nto send WART",
        )
        .glyph(&WART_ICON);

    Ok(review.show(comm, &fields))
}

fn format_path(path: &[u32]) -> String {
    let mut out = String::from("m");
    for value in path {
        let hardened = value & 0x8000_0000 != 0;
        let index = value & 0x7fff_ffff;
        if hardened {
            out.push_str(&format!("/{index}'"));
        } else {
            out.push_str(&format!("/{index}"));
        }
    }
    out
}
