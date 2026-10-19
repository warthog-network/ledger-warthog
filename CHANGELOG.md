# Changelog

## [0.3.0] - 2026-10-19

### Changed

- The app is the Rust port on `ledger_device_sdk` 1.42.0. The APDU matches 0.2.0.
- Release builds cover Nano X, Nano S+, Stax, Flex, and Apex P.
- Exchange signing stays off. A launch from Exchange exits and does not sign.

### Removed

- Original Nano S builds. The Rust SDK has no Nano S target. Those files remain on the v0.2.0 release.

## [0.2.0] - 2026-10-17

C app for Nano S and Nano S+. Native 79-byte WART transfers, signature65, and the eight review rows. That source is the `v0.2.0` tag.
