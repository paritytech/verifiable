# Changelog

All notable changes to this project will be documented in this file.

## [0.2.0]

### Added
- **Add is member valid functionality** ([#23](https://github.com/paritytech/verifiable/pull/23))

### Fixed
- **Fix panic on invalid keys and invalid signatures** ([#21](https://github.com/paritytech/verifiable/pull/21))
  - Fixed panic that occurred when processing invalid keys and invalid signatures in VRF implementation
  - Removed unused `InternalMember`, `external_member`, and `internal_member` components from the trait `GenerateVerifiable`