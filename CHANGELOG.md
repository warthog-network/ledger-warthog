# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0] - 2026-10-17

### Added

- Original Ledger Nano S build (`BOLOS_SDK=$NANOS_SDK`). The same review
  screens are used. The dashboard icon is 16×16. This file is separate from
  the Nano S+ file and targets Nano S OS 2.1.0.
- Native WART transfer signing. The body is 79 bytes: pin hash, pin height,
  nonce, three zero bytes, fee, 20-byte destination, and amount. Amounts are
  E8. The signed message is SHA-256 of that body, and the reply is 65-byte
  `signature65`.
- Clear-sign review rows: From, Path, Amount, Fee, To, Nonce, Pin height, Pin hash.
- Accepted paths: `m/44'/2070'/0'/0/index` and `m/44'/2070'/0/0/index`.
- Device and in-app icons use the Warthog mark.

### Removed

- Token signing (`SIGN_TOKEN_TX`, INS `0x07`) and dynamic token info (`PROVIDE_TOKEN_INFO`, INS `0x22`).
- Blind-sign and token review screens.
- TLV and PKI libraries from the build. Warthog has no CAL token descriptor.

The entries below are the Ledger boilerplate this app was forked from.

## [2.1.0] - 2023-10-06

### Changed

- Improving the settings use case in order to be able to use app settings parameters stored in NVM
- add a NBGL use case choice when a setting switch is toggled

## [2.0.0] - 2023-07-10

### Added

- Stax porting
- Extensive CI, including mandatory `guidelines_enforcer.yml`
- Extensive `README.md` to modify/compile/test the application on most OS (Linux, MacOS, Windows)
- Extensive `Ragger` tests

### Changed

- Simplified `Makefile` (complexity delegated to the SDK's `Makefile.standard_app`)
- Simplified overall code (moved into the SDK)
- Improving several UI flows to fit Ledger UI guidelines
- Removing `TRY`/`CATCH` usage (using `_no_throw` SDK functions)
- Cleaning unnecessary resources (moved into the SDK)

### Fixed

- Multiple minor lint, prototype or misspell fixes

## [1.0.1] - 2021-01-11

### Fix

- Missing header includes

## [1.0.0] - 2020-11-19

### Added

- Initial commit with the brand new Boilerplate application
