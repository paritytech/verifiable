# Changelog

All notable changes to this project will be documented in this file.

## [0.5.0]

All changes are relative to 0.2.0, the last published version.

### Breaking Changes

- **Generic ring VRF implementation** ([#27](https://github.com/paritytech/verifiable/pull/27))
  - `RingVrfVerifiable` is now generic over `RingSuiteExt` instead of being Bandersnatch-specific
  - Introduced `RingSuiteExt`, `RingCurveParams`, `FixedBytes` traits
  - Ring capacity is selected via the `Config` associated type, which for the ring
    implementation is `RingDomainSize` ([#30](https://github.com/paritytech/verifiable/pull/30),
    [#51](https://github.com/paritytech/verifiable/pull/51), [#52](https://github.com/paritytech/verifiable/pull/52))
  - Proof generation code gated behind the `prover` feature
- **Simplify trait API** ([#40](https://github.com/paritytech/verifiable/pull/40))
  - `create` and `validate` are now provided methods delegating to their multi-context counterparts
  - Removed `schnorrkel` dependency
  - Replaced `Simple` (schnorrkel) and `Trivial` mock implementations with a new dependency-free
    `Mock` impl in the `mock` module, gated behind the `mock` feature
- **Plain signatures are Thin VRF proofs** ([#40](https://github.com/paritytech/verifiable/pull/40),
    [#43](https://github.com/paritytech/verifiable/pull/43))
  - No VRF output is bundled with the proof, reducing signature size from 96 to 64 bytes
- **Bounded proof type** ([#41](https://github.com/paritytech/verifiable/pull/41))
  - `Proof` is now `BoundedVec<u8, MaxRingVrfSignatureLen<S>>` instead of `Vec<u8>`
  - Added `ring_signature_size` const fn and `RING_PROOF_SIZE`, `VRF_OUTPUT_SIZE`,
    `MAX_VRF_CONTEXTS` constants to `RingSuiteExt`
  - Single-context proofs keep the VRF output inline, avoiding a heap allocation
- **Structured `Error` enum** ([#54](https://github.com/paritytech/verifiable/pull/54))
  - Fallible trait methods return `Error` instead of `()`
- **Use uncompressed-unchecked codec for trusted domain types** ([#34](https://github.com/paritytech/verifiable/pull/34))

### Added
- **Multi-context proof creation and validation** ([#37](https://github.com/paritytech/verifiable/pull/37),
   [#40](https://github.com/paritytech/verifiable/pull/40))
  - Added `create_multi_context`, `validate_multi_context`, `is_valid_multi_context` methods
  - `AliasVec`/`ContextVec` are SmallVec-backed ([#53](https://github.com/paritytech/verifiable/pull/53))
- **Batch proof validation** ([#26](https://github.com/paritytech/verifiable/pull/26))
  - Added `batch_validate` method and `BatchProofItem` type
- **Multi-ring batch validation**
  - Added `batch_validate_multi_ring` method and `MultiRingBatchProofItem` type, verifying
    proofs from *different* rings in a single batched check. Builds one ring verifier per
    distinct ring (each pinned to the shared canonical KZG verifier key) and aggregates all
    proofs into one pairing check; rings may use different `Config` (domain) sizes.
    `batch_validate` is now a thin single-ring wrapper over it.
- **Pluggable verifier/prover caches.** `RingSuiteExt` carries `VerifierCache` and
  `ProverCache` associated types (with a `NullCache` no-op impl). The Bandersnatch suite
  ships static caches so verification does not recompute `PiopParams` on every call
  ([#44](https://github.com/paritytech/verifiable/pull/44)) and the empty-ring members
  set is computed once per domain.
- **`DecodeUnchecked` trait for trusted-source SCALE decoding** ([#56](https://github.com/paritytech/verifiable/pull/56)).
  Exposes a `decode_unchecked` entry point on the ring types (`MembersSet`,
  `MembersCommitment`, `StaticChunk`, `ProverState`) that reads the same wire format as
  the default SCALE `Decode` impl but skips the arkworks curve-point validation. Includes
  a reusable `MockMembers` newtype in the `mock` module.
- **`secret-split` feature**: side-channel resistant secret scalar multiplication,
  bundled into `std` (the only place a production prover runs).
- **`insecure-deterministic-prover` feature**: deterministic, non-zero-knowledge prover
  for `no_std` test environments. Enabling `prover` on `no_std` without it is now a
  compile-time error, since the ring prover has no system RNG there and would panic.

### Fixed
- **Validate curve points on decode to prevent panics** ([#44](https://github.com/paritytech/verifiable/pull/44))
  - ark-serialize validation is enabled when decoding types that may come from untrusted sources
- **Reject trailing bytes when deserializing signatures and proofs** ([#48](https://github.com/paritytech/verifiable/pull/48))
  - Enforces a canonical encoding, preventing malleability via appended bytes
- **Reject the identity point in member validation and construction** ([#57](https://github.com/paritytech/verifiable/pull/57))
  - The neutral element passed `is_member_valid` but made `push_members` panic inside the
    ring backend; both paths now reject it with `Error::InvalidMember`
  - `push_members` also surfaces `Error::LookupFailed` instead of panicking when the
    `lookup` callback returns the wrong number of chunks

## [0.2.0]

### Added
- **Add is member valid functionality** ([#23](https://github.com/paritytech/verifiable/pull/23))

### Fixed
- **Fix panic on invalid keys and invalid signatures** ([#21](https://github.com/paritytech/verifiable/pull/21))
  - Fixed panic that occurred when processing invalid keys and invalid signatures in VRF implementation
  - Removed unused `InternalMember`, `external_member`, and `internal_member` components from the trait `Verifiable`
