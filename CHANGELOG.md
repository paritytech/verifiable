# Changelog

All notable changes to this project will be documented in this file.

## [0.3.0]

### Breaking Changes
- **Rename `GenerateVerifiable` trait to `Verifiable`** ([#40](https://github.com/paritytech/verifiable/pull/40))
- **Generic ring VRF implementation** ([#27](https://github.com/paritytech/verifiable/pull/27))
  - `RingVrfVerifiable` is now generic over `RingSuiteExt` instead of being Bandersnatch-specific
  - Introduced `RingSuiteExt`, `RingCurveParams`, `RingSize`, `FixedBytes` traits
  - Ring capacity is now configurable via `RingDomainSize` ([#30](https://github.com/paritytech/verifiable/pull/30))
  - Added `prover` feature gate for proof generation code
  - `Capacity` trait replaces fixed ring size
- **Simplify trait API** ([#40](https://github.com/paritytech/verifiable/pull/40))
  - `create` and `validate` are now provided methods delegating to their multi-context counterparts
  - Plain signatures use IETF VRF proof directly (no VRF output), reducing signature size from 96 to 48 bytes
  - Removed `schnorrkel` and `bounded-collections` dependencies
  - Removed demo module (`Simple` and `Trivial` implementations)
- **Use uncompressed-unchecked codec for trusted domain types** ([#34](https://github.com/paritytech/verifiable/pull/34))

### Added
- **Multi-context proof creation and validation** ([#37](https://github.com/paritytech/verifiable/pull/37), [#40](https://github.com/paritytech/verifiable/pull/40))
  - Added `create_multi_context`, `validate_multi_context`, `is_valid_multi_context` methods
- **Batch proof validation** ([#26](https://github.com/paritytech/verifiable/pull/26))
  - Added `batch_validate` method and `BatchProofItem` type

### Changed
- **Bump `ark-vrf` to 0.3** ([#39](https://github.com/paritytech/verifiable/pull/39))

## [0.2.0]

### Added
- **Add is member valid functionality** ([#23](https://github.com/paritytech/verifiable/pull/23))

### Fixed
- **Fix panic on invalid keys and invalid signatures** ([#21](https://github.com/paritytech/verifiable/pull/21))
  - Fixed panic that occurred when processing invalid keys and invalid signatures in VRF implementation
  - Removed unused `InternalMember`, `external_member`, and `internal_member` components from the trait `Verifiable`
