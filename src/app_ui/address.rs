use crate::AppSW;

use ledger_device_sdk::include_gif;
use ledger_device_sdk::io::Comm;
use ledger_device_sdk::nbgl::{NbglAddressReview, NbglGlyph};

pub fn ui_display_pk(comm: &mut Comm, address: &[u8]) -> Result<bool, AppSW> {
    let addr_hex = hex::encode(address);

    #[cfg(target_os = "apex_p")]
    const WART_ICON: NbglGlyph =
        NbglGlyph::from_include(include_gif!("glyphs/crab_48x48.png", NBGL));
    #[cfg(any(target_os = "stax", target_os = "flex"))]
    const WART_ICON: NbglGlyph =
        NbglGlyph::from_include(include_gif!("glyphs/crab_64x64.gif", NBGL));
    #[cfg(any(target_os = "nanosplus", target_os = "nanox"))]
    const WART_ICON: NbglGlyph =
        NbglGlyph::from_include(include_gif!("icons/crab_14x14.gif", NBGL));

    Ok(NbglAddressReview::new()
        .glyph(&WART_ICON)
        .review_title("Verify WART address")
        .show(comm, &addr_hex))
}
