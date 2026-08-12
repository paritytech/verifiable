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
- **`MembersCommitment` holds only the ring commitment** ([#62](https://github.com/paritytech/verifiable/pull/62))
  - Wraps `ark_vrf::ring::RingCommitment` instead of `RingVerifierKey`, dropping the
    embedded KZG verifier key; `MEMBERS_COMMITMENT_SIZE` shrinks from 768 to 288 bytes
  - Verification rebuilds the verifier key from the commitment and the suite's canonical
    KZG key via `ark_vrf::ring::verifier_key_from_commitment`, so the trusted setup can no
    longer be influenced by a decoded member set (the runtime verifier-key pinning check is
    removed; a commitment built under a foreign SRS now simply fails the pairing check)

### Added
- **Multi-context proof creation and validation** ([#37](https://github.com/paritytech/verifiable/pull/37),
   [#40](https://github.com/paritytech/verifiable/pull/40))
  - Added `create_multi_context`, `validate_multi_context`, `is_valid_multi_context` methods
  - `AliasVec`/`ContextVec` are SmallVec-backed ([#53](https://github.com/paritytech/verifiable/pull/53))
- **Batch proof validation** ([#26](https://github.com/paritytech/verifiable/pull/26),
  [#61](https://github.com/paritytech/verifiable/pull/61))
  - Added `batch_validate` method and `BatchProofItem` type
  - Added `batch_validate_per_item`, returning one outcome per item for callers batching
    proofs from untrusted submitters; the ring implementation keeps the single combined
    check as the fast path and bisects only on failure to attribute it to the offending
    items (#TODO)
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
- **`insecure-deterministic-no-std-prover` feature**: deterministic, non-zero-knowledge prover
  for `no_std` test environments. Enabling `prover` on `no_std` without it is now a
  compile-time error, since the ring prover has no system RNG there and would panic.

### Security
- **Feature unification can no longer disable the ring proof's zero-knowledge blinding**
  (SRLabs audit finding; [ring-proof#93](https://github.com/paritytech/ring-proof/pull/93),
  [ark-vrf#97](https://github.com/davxy/ark-vrf/pull/97))
  - `insecure-deterministic-no-std-prover` no longer enables `ark-vrf/test-vectors` (removed
    upstream): the deterministic prover is selected by building this crate's prover
    ring context via the new runtime `RingContext::new_without_blinding`, so other
    `ark-vrf` users in the same build are unaffected
  - Combining `insecure-deterministic-no-std-prover` with `std` (the production proving
    configuration) is now a compile-time error, mirroring the existing no_std guard
  - CI builds and tests both supported prover configurations explicitly instead of
    `--all-features`; a regression test pins blinding on (production) and off
    (deterministic prover)

### Changed
- **arkworks dependencies bumped to 0.6** (required by the upstream changes above).
  Note: since arkworks 0.6 the identity is represented as `(0, 0)` for short
  Weierstrass curves, so all-zero uncompressed G1 encodings (e.g. in
  `MembersCommitment`) decode as valid identity points instead of being rejected;
  such commitments still fail proof verification cleanly

### Fixed
- **Validate curve points on decode to prevent panics** ([#44](https://github.com/paritytech/verifiable/pull/44))
  - ark-serialize validation is enabled when decoding types that may come from untrusted sources
- **Reject trailing bytes when deserializing signatures and proofs** ([#48](https://github.com/paritytech/verifiable/pull/48))
  - Enforces a canonical encoding, preventing malleability via appended bytes
- **Remove bogus `MaxEncodedLen`/`ArkScaleMaxEncodedLen`/`TypeInfo` impls from `ProverState`**
  - The impls reported a zero maximum encoded length while real encodings are hundreds of
    kilobytes; there is no meaningful type-level bound since the size depends on the domain
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
