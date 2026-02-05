use alloc::vec;
use core::{marker::PhantomData, ops::Range};

pub use ark_vrf;

use ark_scale::ArkScale;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_vrf::{
	ring::{RingSuite, Verifier},
	suites::bandersnatch,
};
use parity_scale_codec::{Decode, Encode};
use scale_info::TypeInfo;

use super::*;

/// The max ring that can be handled for both sign/verify for the given PCS domain size.
const fn max_ring_size_from_pcs_domain_size<S: RingSuite>(pcs_domain_size: usize) -> usize {
	ark_vrf::ring::max_ring_size_from_pcs_domain_size::<S>(pcs_domain_size)
}

/// Domain sizes for the PCS (Polynomial Commitment Scheme).
///
/// This determines the maximum ring size that can be supported for a ring suite.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Encode, Decode, TypeInfo, DecodeWithMemTracking)]
pub enum RingDomainSize {
	/// Domain size 2^11
	Domain11,
	/// Domain size 2^12
	Domain12,
	/// Domain size 2^16
	Domain16,
}

impl RingDomainSize {
	/// Returns the domain size as a power of 2.
	pub const fn as_power(self) -> u32 {
		match self {
			RingDomainSize::Domain11 => 11,
			RingDomainSize::Domain12 => 12,
			RingDomainSize::Domain16 => 16,
		}
	}

	/// Returns the actual PCS domain size (2^power).
	pub const fn pcs_domain_size(self) -> usize {
		1 << self.as_power()
	}
}

/// Ring size configuration for a specific suite.
///
/// Wraps a [`RingDomainSize`] and computes the maximum ring capacity based on the
/// suite's curve parameters. Different suites may yield different max ring sizes
/// for the same domain size.
///
/// Example. For the Bandersnatch suite (`BandersnatchSha512Ell2`):
/// - `Domain11`: max 255 members
/// - `Domain12`: max 767 members
/// - `Domain16`: max 16127 members
#[derive(Clone, Copy, Encode, Decode, TypeInfo, DecodeWithMemTracking)]
pub struct RingSize<S: RingSuite> {
	dom_size: RingDomainSize,
	_phantom: PhantomData<S>,
}

impl<S: RingSuite> From<RingDomainSize> for RingSize<S> {
	fn from(dom_size: RingDomainSize) -> Self {
		Self {
			dom_size,
			_phantom: PhantomData,
		}
	}
}

impl<S: RingSuite> Capacity for RingSize<S> {
	fn size(&self) -> usize {
		max_ring_size_from_pcs_domain_size::<S>(self.dom_size.pcs_domain_size())
	}
}

// ---------------------------------------------------------------------------
// Traits for generic ring VRF support
// ---------------------------------------------------------------------------

/// Trait for providing pairing-curve-specific ring data.
///
/// All RingSuites that use the same pairing curve can share the same data provider.
/// For example, all suites using BLS12-381 (like Bandersnatch) use `Bls12_381RingData`.
pub trait RingCurveData {
	/// Raw SRS data (powers of tau).
	#[cfg(any(feature = "std", feature = "no-std-prover"))]
	fn srs_raw() -> &'static [u8];

	/// Ring builder params for a given domain size.
	#[cfg(any(feature = "std", feature = "builder-params"))]
	fn ring_builder_params(domain: RingDomainSize) -> &'static [u8];

	/// Empty ring commitment data for a given domain size.
	fn empty_ring_commitment(domain: RingDomainSize) -> &'static [u8];
}

/// Ring data for suites using BLS12-381 pairing (e.g., Bandersnatch curves).
pub struct Bls12_381RingData;

#[cfg(feature = "std")]
fn ring_prover_params(domain_size: RingDomainSize) -> &'static bandersnatch::RingProofParams {
	use std::sync::OnceLock;
	static CELL_11: OnceLock<bandersnatch::RingProofParams> = OnceLock::new();
	static CELL_12: OnceLock<bandersnatch::RingProofParams> = OnceLock::new();
	static CELL_16: OnceLock<bandersnatch::RingProofParams> = OnceLock::new();

	let cell = match domain_size {
		RingDomainSize::Domain11 => &CELL_11,
		RingDomainSize::Domain12 => &CELL_12,
		RingDomainSize::Domain16 => &CELL_16,
	};
	cell.get_or_init(|| ring_prover_params2(domain_size))
}

#[cfg(all(not(feature = "std"), feature = "no-std-prover"))]
fn ring_prover_params(domain_size: RingDomainSize) -> &'static bandersnatch::RingProofParams {
	use spin::Once;
	static CELL_11: Once<bandersnatch::RingProofParams> = Once::new();
	static CELL_12: Once<bandersnatch::RingProofParams> = Once::new();
	static CELL_16: Once<bandersnatch::RingProofParams> = Once::new();

	let cell = match domain_size {
		RingDomainSize::Domain11 => &CELL_11,
		RingDomainSize::Domain12 => &CELL_12,
		RingDomainSize::Domain16 => &CELL_16,
	};
	cell.call_once(|| ring_prover_params2(domain_size))
}

#[cfg(any(feature = "std", feature = "no-std-prover"))]
pub fn ring_prover_params2<S: RingSuiteTypes>(
	domain_size: RingDomainSize,
) -> ark_vrf::ring::RingProofParams<S> {
	let data = S::CurveData::srs_raw();
	let pcs_params =
		ark_vrf::ring::PcsParams::<S>::deserialize_uncompressed_unchecked(data).unwrap();
	let ring_size = max_ring_size_from_pcs_domain_size::<S>(domain_size.pcs_domain_size());
	ark_vrf::ring::RingProofParams::<S>::from_pcs_params(ring_size, pcs_params).unwrap()
}

/// Get ring builder params for the given domain size.
/// Only available with the `builder-params` or `std` features.
#[cfg(any(feature = "std", feature = "builder-params"))]
pub fn ring_verifier_builder_params<S: RingSuiteTypes>(
	domain_size: RingDomainSize,
) -> ark_vrf::ring::RingBuilderPcsParams<S> {
	let data = S::CurveData::ring_builder_params(domain_size);
	ark_vrf::ring::RingBuilderPcsParams::<S>::deserialize_uncompressed_unchecked(data).unwrap()
}

impl RingCurveData for Bls12_381RingData {
	#[cfg(any(feature = "std", feature = "no-std-prover"))]
	fn srs_raw() -> &'static [u8] {
		include_bytes!("ring-data/srs-uncompressed.bin")
	}

	#[cfg(any(feature = "std", feature = "builder-params"))]
	fn ring_builder_params(domain: RingDomainSize) -> &'static [u8] {
		match domain {
			RingDomainSize::Domain11 => {
				include_bytes!("ring-data/ring-builder-params-domain11.bin")
			}
			RingDomainSize::Domain12 => {
				include_bytes!("ring-data/ring-builder-params-domain12.bin")
			}
			RingDomainSize::Domain16 => {
				include_bytes!("ring-data/ring-builder-params-domain16.bin")
			}
		}
	}

	fn empty_ring_commitment(domain: RingDomainSize) -> &'static [u8] {
		match domain {
			RingDomainSize::Domain11 => include_bytes!("ring-data/ring-builder-domain11.bin"),
			RingDomainSize::Domain12 => include_bytes!("ring-data/ring-builder-domain12.bin"),
			RingDomainSize::Domain16 => include_bytes!("ring-data/ring-builder-domain16.bin"),
		}
	}
}

/// Trait providing suite-specific byte array types for ring VRF operations.
///
/// This trait defines the concrete array types used for serialized forms of
/// public keys, proofs, and signatures. Each suite specifies its own sizes.
pub trait RingSuiteTypes: RingSuite + 'static {
	/// Byte array type for encoded public keys.
	type EncodedPublicKey: Clone
		+ Eq
		+ PartialEq
		+ Encode
		+ Decode
		+ scale::EncodeLike
		+ core::fmt::Debug
		+ TypeInfo
		+ MaxEncodedLen
		+ AsRef<[u8]>
		+ AsMut<[u8]>
		+ Default
		+ DecodeWithMemTracking;

	/// Byte array type for ring VRF proofs.
	type RingProofBytes: Clone
		+ Eq
		+ PartialEq
		+ Encode
		+ Decode
		+ scale::EncodeLike
		+ core::fmt::Debug
		+ TypeInfo
		+ AsRef<[u8]>
		+ AsMut<[u8]>;

	/// Byte array type for plain VRF signatures.
	type SignatureBytes: Clone
		+ Eq
		+ PartialEq
		+ Encode
		+ Decode
		+ scale::EncodeLike
		+ core::fmt::Debug
		+ TypeInfo
		+ AsRef<[u8]>
		+ AsMut<[u8]>;

	/// Encoded size of a public key.
	const PUBLIC_KEY_SIZE: usize;
	/// Encoded size of MembersSet (Intermediate).
	const MEMBERS_SET_SIZE: usize;
	/// Encoded size of MembersCommitment (Members).
	const MEMBERS_COMMITMENT_SIZE: usize;
	/// Encoded size of StaticChunk (G1 point).
	const STATIC_CHUNK_SIZE: usize;

	/// The curve static data provider for this suite.
	type CurveData: RingCurveData;

	/// Get cached ring proof params for this suite.
	#[cfg(any(feature = "std", feature = "no-std-prover"))]
	fn ring_proof_params(
		domain_size: RingDomainSize,
	) -> &'static ark_vrf::ring::RingProofParams<Self>;

	/// Create a zero-initialized ring proof buffer.
	fn zero_proof() -> Self::RingProofBytes;

	/// Create a zero-initialized signature buffer.
	fn zero_signature() -> Self::SignatureBytes;
}

impl RingSuiteTypes for bandersnatch::BandersnatchSha512Ell2 {
	type EncodedPublicKey = [u8; 32];
	type RingProofBytes = [u8; 788];
	type SignatureBytes = [u8; 96];

	const PUBLIC_KEY_SIZE: usize = 32;
	const MEMBERS_SET_SIZE: usize = 432;
	const MEMBERS_COMMITMENT_SIZE: usize = 384;
	const STATIC_CHUNK_SIZE: usize = 48;

	type CurveData = Bls12_381RingData;

	#[cfg(any(feature = "std", feature = "no-std-prover"))]
	fn ring_proof_params(
		domain_size: RingDomainSize,
	) -> &'static ark_vrf::ring::RingProofParams<Self> {
		ring_prover_params(domain_size)
	}

	fn zero_proof() -> Self::RingProofBytes {
		[0u8; 788]
	}

	fn zero_signature() -> Self::SignatureBytes {
		[0u8; 96]
	}
}

// ---------------------------------------------------------------------------

const VRF_INPUT_DOMAIN: &[u8] = b"VerifiableVrfInput";

// /// A sequence of static chunks.
// /// Only available with the `builder-params` feature.
// #[cfg(any(feature = "std", feature = "builder-params"))]
// pub type RingBuilderParams = ark_vrf::ring::RingBuilderPcsParams<BandersnatchSha512Ell2>;

macro_rules! impl_common_traits {
	// Generic type version - size comes from RingSuiteTypes trait
	($type_name:ident<S: $bound:path>, $size_expr:expr) => {
		impl<S: $bound> Decode for $type_name<S> {
			ark_scale::impl_decode_via_ark!();
		}

		impl<S: $bound> Encode for $type_name<S> {
			ark_scale::impl_encode_via_ark!();
		}

		impl<S: $bound> scale::EncodeLike for $type_name<S> {}

		impl<S: $bound> scale::MaxEncodedLen for $type_name<S> {
			fn max_encoded_len() -> usize {
				$size_expr
			}
		}

		impl<S: $bound + 'static> scale_info::TypeInfo for $type_name<S> {
			type Identity = Self;
			fn type_info() -> scale_info::Type {
				scale_info::Type::builder()
					.path(scale_info::Path::new(
						stringify!($type_name),
						module_path!(),
					))
					.composite(scale_info::build::Fields::unnamed().field(|f| {
						f.ty::<alloc::vec::Vec<u8>>()
							.type_name(stringify!($type_name))
					}))
			}
		}

		impl<S: $bound> core::cmp::PartialEq for $type_name<S> {
			fn eq(&self, other: &Self) -> bool {
				self.encode() == other.encode()
			}
		}

		impl<S: $bound> core::cmp::Eq for $type_name<S> {}

		impl<S: $bound> DecodeWithMemTracking for $type_name<S> {}
	};
}

#[derive(CanonicalDeserialize, CanonicalSerialize)]
#[derive_where::derive_where(Clone)]
pub struct MembersSet<S: RingSuite>(pub(crate) ark_vrf::ring::RingVerifierKeyBuilder<S>);

impl_common_traits!(MembersSet<S: RingSuiteTypes>, S::MEMBERS_SET_SIZE);

impl<S: RingSuite> core::fmt::Debug for MembersSet<S> {
	fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
		write!(f, "MembersSet")
	}
}

#[derive(CanonicalDeserialize, CanonicalSerialize)]
#[derive_where::derive_where(Clone)]
pub struct MembersCommitment<S: RingSuite>(pub(crate) ark_vrf::ring::RingVerifierKey<S>);

impl_common_traits!(MembersCommitment<S: RingSuiteTypes>, S::MEMBERS_COMMITMENT_SIZE);

impl<S: RingSuite> core::fmt::Debug for MembersCommitment<S> {
	fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
		write!(f, "MembersCommitment")
	}
}

#[derive(CanonicalSerialize, CanonicalDeserialize)]
#[derive_where::derive_where(Clone, Debug)]
pub struct PublicKey<S: RingSuite>(pub(crate) ark_vrf::AffinePoint<S>);

impl_common_traits!(PublicKey<S: RingSuiteTypes>, S::PUBLIC_KEY_SIZE);

#[derive(CanonicalSerialize, CanonicalDeserialize)]
#[derive_where::derive_where(Clone, Debug)]
pub struct StaticChunk<S: RingSuite>(pub ark_vrf::ring::G1Affine<S>);

impl_common_traits!(StaticChunk<S: RingSuiteTypes>, S::STATIC_CHUNK_SIZE);

#[derive(CanonicalSerialize, CanonicalDeserialize)]
struct IetfVrfSignature<S: RingSuite> {
	output: ark_vrf::Output<S>,
	proof: ark_vrf::ietf::Proof<S>,
}

#[derive(CanonicalSerialize, CanonicalDeserialize)]
struct RingVrfSignature<S: RingSuite> {
	output: ark_vrf::Output<S>,
	proof: ark_vrf::ring::Proof<S>,
}

#[inline(always)]
fn make_alias<S: RingSuite>(output: &ark_vrf::Output<S>) -> Alias {
	Alias::try_from(&output.hash()[..32]).expect("Suite hash should be at least 32 bytes")
}

/// Generic ring VRF implementation parameterized over the ring suite.
///
/// The curve data provider is obtained from `S::CurveData`.
pub struct RingVrfVerifiable<S: RingSuiteTypes>(PhantomData<S>);

impl<S: RingSuiteTypes> RingVrfVerifiable<S> {
	fn to_public_key(value: &S::EncodedPublicKey) -> Result<PublicKey<S>, ()> {
		let pt =
			ark_vrf::AffinePoint::<S>::deserialize_compressed(value.as_ref()).map_err(|_| ())?;
		Ok(PublicKey(pt))
	}

	fn to_encoded_public_key(value: &PublicKey<S>) -> S::EncodedPublicKey {
		let mut bytes = S::EncodedPublicKey::default();
		value.using_encoded(|encoded| {
			bytes.as_mut().copy_from_slice(encoded);
		});
		bytes
	}
}

impl<S: RingSuiteTypes> GenerateVerifiable for RingVrfVerifiable<S> {
	type Members = MembersCommitment<S>;
	type Intermediate = MembersSet<S>;
	type Member = S::EncodedPublicKey;
	type Secret = ark_vrf::Secret<S>;
	type Commitment = (
		Self::Capacity,
		u32,
		ArkScale<ark_vrf::ring::RingProverKey<S>>,
	);
	type Proof = S::RingProofBytes;
	type Signature = S::SignatureBytes;
	type StaticChunk = StaticChunk<S>;
	type Capacity = RingSize<S>;

	fn start_members(capacity: Self::Capacity) -> Self::Intermediate {
		// TODO: Optimize by caching the deserialized value; must be compatible with the WASM runtime environment.
		let data = S::CurveData::empty_ring_commitment(capacity.dom_size);
		MembersSet::deserialize_uncompressed_unchecked(data).unwrap()
	}

	fn push_members(
		intermediate: &mut Self::Intermediate,
		members: impl Iterator<Item = Self::Member>,
		lookup: impl Fn(Range<usize>) -> Result<Vec<Self::StaticChunk>, ()>,
	) -> Result<(), ()> {
		let mut keys = vec![];
		for member in members {
			keys.push(Self::to_public_key(&member)?.0);
		}
		let loader = |range: Range<usize>| {
			let items = lookup(range)
				.ok()?
				.into_iter()
				.map(|c| c.0)
				.collect::<Vec<_>>();
			Some(items)
		};
		intermediate.0.append(&keys[..], loader).map_err(|_| ())
	}

	fn finish_members(intermediate: Self::Intermediate) -> Self::Members {
		let verifier_key = intermediate.0.finalize();
		MembersCommitment(verifier_key)
	}

	fn new_secret(entropy: Entropy) -> Self::Secret {
		Self::Secret::from_seed(&entropy)
	}

	fn member_from_secret(secret: &Self::Secret) -> Self::Member {
		Self::to_encoded_public_key(&PublicKey(secret.public().0))
	}

	fn validate(
		capacity: Self::Capacity,
		proof: &Self::Proof,
		members: &Self::Members,
		context: &[u8],
		message: &[u8],
	) -> Result<Alias, ()> {
		// This doesn't require the whole kzg. Thus is more appropriate if used on-chain
		// Is a bit slower as it requires to recompute piop_params, but still in the order of ms
		let ring_verifier = ark_vrf::ring::RingProofParams::<S>::verifier_no_context(
			members.0.clone(),
			capacity.size(),
		);

		let input_msg = [VRF_INPUT_DOMAIN, context].concat();
		let input = ark_vrf::Input::<S>::new(&input_msg[..]).expect("H2C can't fail here");

		let signature =
			RingVrfSignature::<S>::deserialize_compressed(proof.as_ref()).map_err(|_| ())?;

		ark_vrf::Public::<S>::verify(
			input,
			signature.output,
			message,
			&signature.proof,
			&ring_verifier,
		)
		.map_err(|_| ())?;

		Ok(make_alias(&signature.output))
	}

	fn sign(secret: &Self::Secret, message: &[u8]) -> Result<Self::Signature, ()> {
		use ark_vrf::ietf::Prover;
		let input_msg = [VRF_INPUT_DOMAIN, message].concat();
		let input = ark_vrf::Input::<S>::new(&input_msg[..]).expect("H2C can't fail here");
		let output = secret.output(input);

		let proof = secret.prove(input, output, b"");
		let signature = IetfVrfSignature::<S> { output, proof };

		let mut raw = S::zero_signature();
		signature
			.serialize_compressed(raw.as_mut())
			.map_err(|_| ())?;
		Ok(raw)
	}

	fn verify_signature(
		signature: &Self::Signature,
		message: &[u8],
		member: &Self::Member,
	) -> bool {
		use ark_vrf::ietf::Verifier;
		let Ok(signature) = IetfVrfSignature::<S>::deserialize_compressed(signature.as_ref())
		else {
			return false;
		};
		let input_msg = [VRF_INPUT_DOMAIN, message].concat();
		let input = ark_vrf::Input::<S>::new(&input_msg[..]).expect("H2C can't fail here");
		let Ok(member) = Self::to_public_key(member) else {
			return false;
		};
		let public = ark_vrf::Public::<S>::from(member.0);
		public
			.verify(input, signature.output, b"", &signature.proof)
			.is_ok()
	}

	#[cfg(any(feature = "std", feature = "no-std-prover"))]
	fn open(
		capacity: Self::Capacity,
		member: &Self::Member,
		members: impl Iterator<Item = Self::Member>,
	) -> Result<Self::Commitment, ()> {
		let pks = members
			.map(|m| Self::to_public_key(&m).map(|pk| pk.0))
			.collect::<Result<Vec<_>, _>>()?;
		let member = Self::to_public_key(member)?;
		let member_idx = pks.iter().position(|&m| m == member.0).ok_or(())?;
		let member_idx = member_idx as u32;
		let prover_key = S::ring_proof_params(capacity.dom_size).prover_key(&pks[..]);
		Ok((capacity, member_idx, prover_key.into()))
	}

	#[cfg(any(feature = "std", feature = "no-std-prover"))]
	fn create(
		commitment: Self::Commitment,
		secret: &Self::Secret,
		context: &[u8],
		message: &[u8],
	) -> Result<(Self::Proof, Alias), ()> {
		use ark_vrf::ring::Prover;
		let (capacity, prover_idx, prover_key) = commitment;
		let params = S::ring_proof_params(capacity.dom_size);
		if prover_idx >= params.max_ring_size() as u32 {
			return Err(());
		}

		let ring_prover = params.prover(prover_key.0, prover_idx as usize);

		let input_msg = [VRF_INPUT_DOMAIN, context].concat();
		let input = ark_vrf::Input::<S>::new(&input_msg[..]).expect("H2C can't fail here");
		let preout = secret.output(input);
		let alias = make_alias(&preout);

		let proof = secret.prove(input, preout, message, &ring_prover);

		let signature = RingVrfSignature::<S> {
			output: preout,
			proof,
		};

		let mut buf = S::zero_proof();
		signature
			.serialize_compressed(buf.as_mut())
			.map_err(|_| ())?;

		Ok((buf, alias))
	}

	fn alias_in_context(secret: &Self::Secret, context: &[u8]) -> Result<Alias, ()> {
		let input_msg = [VRF_INPUT_DOMAIN, context].concat();
		let input = ark_vrf::Input::<S>::new(&input_msg[..]).expect("H2C can't fail here");
		let output = secret.output(input);
		let alias = make_alias(&output);
		Ok(alias)
	}

	fn is_member_valid(member: &Self::Member) -> bool {
		Self::to_public_key(member).is_ok()
	}
}

/// Bandersnatch ring VRF Verifiable (BandersnatchSha512Ell2 suite).
pub type BandersnatchVrfVerifiable = RingVrfVerifiable<bandersnatch::BandersnatchSha512Ell2>;

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_plain_signature() {
		let msg = b"asd";
		let secret = BandersnatchVrfVerifiable::new_secret([0; 32]);
		let public = BandersnatchVrfVerifiable::member_from_secret(&secret);
		let signature = BandersnatchVrfVerifiable::sign(&secret, msg).unwrap();
		let res = BandersnatchVrfVerifiable::verify_signature(&signature, msg, &public);
		assert!(res);
	}

	#[test]
	fn test_is_member_valid_invalid() {
		let invalid_member = [0u8; 32];
		assert!(!BandersnatchVrfVerifiable::is_member_valid(&invalid_member));
	}

	#[test]
	fn test_is_member_valid_valid() {
		let secret = BandersnatchVrfVerifiable::new_secret([42u8; 32]);
		let valid_member = BandersnatchVrfVerifiable::member_from_secret(&secret);
		assert!(BandersnatchVrfVerifiable::is_member_valid(&valid_member));
	}
}

/// Tests that require the `builder-params` feature.
#[cfg(all(test, feature = "builder-params"))]
mod builder_tests {
	use super::*;
	use ark_vrf::{ring::SrsLookup, suites::bandersnatch::BandersnatchSha512Ell2};

	// Type aliases for Bandersnatch-specific generic types
	type MembersSet = super::MembersSet<BandersnatchSha512Ell2>;
	type MembersCommitment = super::MembersCommitment<BandersnatchSha512Ell2>;
	type PublicKey = super::PublicKey<BandersnatchSha512Ell2>;
	type RingSize = super::RingSize<BandersnatchSha512Ell2>;
	type RingBuilderPcsParams = ark_vrf::ring::RingBuilderPcsParams<BandersnatchSha512Ell2>;

	/// Macro to generate test functions for all implemented domain sizes.
	///
	/// Usage:
	/// ```ignore
	/// test_for_all_domains!(test_name, |domain_size| {
	///     // test body using domain_size
	/// });
	/// ```
	macro_rules! test_for_all_domains {
		($test_name:ident, |$domain_size:ident| $body:block) => {
			paste::paste! {
				#[test]
				fn [<$test_name _domain11>]() {
					let $domain_size = RingDomainSize::Domain11;
					$body
				}

				#[test]
				fn [<$test_name _domain12>]() {
					let $domain_size = RingDomainSize::Domain12;
					$body
				}

				#[test]
				fn [<$test_name _domain16>]() {
					let $domain_size = RingDomainSize::Domain16;
					$body
				}
			}
		};
	}

	fn start_members_from_params(
		domain_size: RingDomainSize,
	) -> (MembersSet, RingBuilderPcsParams) {
		let (builder, builder_pcs_params) = ring_prover_params(domain_size).verifier_key_builder();
		(MembersSet(builder), builder_pcs_params)
	}

	#[test]
	#[ignore = "srs generator"]
	fn generate_srs_from_full_zcash_srs() {
		use std::fs::File;
		use std::io::{Read, Write};

		const FULL_ZCASH_SRS_FILE: &str = concat!(
			env!("CARGO_MANIFEST_DIR"),
			"/src/ring-data/zcash-srs-2-16-uncompressed.bin"
		);
		const SRS_COMPRESSED_FILE: &str = concat!(
			env!("CARGO_MANIFEST_DIR"),
			"/src/ring-data/srs-compressed.bin"
		);
		const SRS_UNCOMPRESSED_FILE: &str = concat!(
			env!("CARGO_MANIFEST_DIR"),
			"/src/ring-data/srs-uncompressed.bin"
		);

		let mut buf = vec![];
		let mut file = File::open(FULL_ZCASH_SRS_FILE).unwrap();
		file.read_to_end(&mut buf).unwrap();
		println!("Full size: {}", buf.len());

		// Use Domain16 for SRS generation (largest domain)
		let full_params = ring_prover_params(RingDomainSize::Domain16);

		let mut buf = vec![];
		full_params.serialize_compressed(&mut buf).unwrap();
		println!("Reduced size (compressed): {}", buf.len());
		let mut file = File::create(SRS_COMPRESSED_FILE).unwrap();
		file.write_all(&buf).unwrap();

		let mut buf = vec![];
		full_params.serialize_uncompressed(&mut buf).unwrap();
		println!("Reduced size (uncompressed): {}", buf.len());
		let mut file = File::create(SRS_UNCOMPRESSED_FILE).unwrap();
		file.write_all(&buf).unwrap();
	}

	// Run only if there are some breaking changes in the backend crypto and binaries
	// need to be re-generated.
	#[test]
	#[ignore = "ring builder generator - generates ring data for all domain sizes"]
	fn generate_empty_ring_builders() {
		use std::io::Write;

		/// All available domain sizes.
		const ALL: [RingDomainSize; 3] = [
			RingDomainSize::Domain11,
			RingDomainSize::Domain12,
			RingDomainSize::Domain16,
		];

		for domain_size in ALL {
			let (builder, builder_params) = start_members_from_params(domain_size);

			let builder_file = format!(
				"{}/src/ring-data/ring-builder-domain{}.bin",
				env!("CARGO_MANIFEST_DIR"),
				domain_size.as_power()
			);
			let params_file = format!(
				"{}/src/ring-data/ring-builder-params-domain{}.bin",
				env!("CARGO_MANIFEST_DIR"),
				domain_size.as_power()
			);

			let mut buf = Vec::with_capacity(builder.uncompressed_size());
			builder.serialize_uncompressed(&mut buf).unwrap();
			println!("Writing empty ring builder to: {}", builder_file);
			let mut file = std::fs::File::create(&builder_file).unwrap();
			file.write_all(&buf).unwrap();

			let mut buf = Vec::with_capacity(builder_params.0.uncompressed_size());
			builder_params.0.serialize_uncompressed(&mut buf).unwrap();
			println!("G1 len: {}", builder_params.0.len());
			println!("Writing ring builder params to: {}", params_file);
			let mut file = std::fs::File::create(&params_file).unwrap();
			file.write_all(&buf).unwrap();
		}
	}

	test_for_all_domains!(check_pre_constructed_ring_builder, |domain_size| {
		let ring_size = domain_size.into();
		let builder = BandersnatchVrfVerifiable::start_members(ring_size);
		let builder_params = ring_verifier_builder_params::<BandersnatchSha512Ell2>(domain_size);
		let (builder2, builder_params2) = start_members_from_params(domain_size);

		let mut buf1 = vec![];
		builder_params.0.serialize_uncompressed(&mut buf1).unwrap();
		let mut buf2 = vec![];
		builder_params2.0.serialize_uncompressed(&mut buf2).unwrap();
		assert_eq!(buf1, buf2);

		let mut buf1 = vec![];
		builder.serialize_uncompressed(&mut buf1).unwrap();
		let mut buf2 = vec![];
		builder2.serialize_uncompressed(&mut buf2).unwrap();
		assert_eq!(buf1, buf2);
	});

	test_for_all_domains!(check_precomputed_size, |domain_size| {
		let ring_size = domain_size.into();
		let secret = BandersnatchVrfVerifiable::new_secret([0u8; 32]);
		let public = BandersnatchVrfVerifiable::member_from_secret(&secret);
		let internal = BandersnatchVrfVerifiable::to_public_key(&public).unwrap();
		assert_eq!(internal.compressed_size(), PublicKey::max_encoded_len());

		let members = BandersnatchVrfVerifiable::start_members(ring_size);
		assert_eq!(members.compressed_size(), MembersSet::max_encoded_len());

		let commitment = BandersnatchVrfVerifiable::finish_members(members);
		assert_eq!(
			commitment.compressed_size(),
			MembersCommitment::max_encoded_len()
		);
	});

	test_for_all_domains!(start_push_finish, |domain_size| {
		let capacity: RingSize = domain_size.into();
		let alice_sec = BandersnatchVrfVerifiable::new_secret([0u8; 32]);
		let bob_sec = BandersnatchVrfVerifiable::new_secret([1u8; 32]);
		let charlie_sec = BandersnatchVrfVerifiable::new_secret([2u8; 32]);

		let alice = BandersnatchVrfVerifiable::member_from_secret(&alice_sec);
		let bob = BandersnatchVrfVerifiable::member_from_secret(&bob_sec);
		let charlie = BandersnatchVrfVerifiable::member_from_secret(&charlie_sec);

		let mut inter1 = BandersnatchVrfVerifiable::start_members(capacity);
		let mut inter2 = inter1.clone();
		let builder_params = ring_verifier_builder_params::<BandersnatchSha512Ell2>(domain_size);

		let get_many = |range| {
			(&builder_params)
				.lookup(range)
				.map(|v| v.into_iter().map(|i| StaticChunk(i)).collect::<Vec<_>>())
				.ok_or(())
		};

		BandersnatchVrfVerifiable::push_members(
			&mut inter1,
			[alice.clone(), bob.clone(), charlie.clone()].into_iter(),
			get_many,
		)
		.unwrap();
		BandersnatchVrfVerifiable::push_members(&mut inter2, [alice.clone()].into_iter(), get_many)
			.unwrap();
		BandersnatchVrfVerifiable::push_members(&mut inter2, [bob.clone()].into_iter(), get_many)
			.unwrap();
		BandersnatchVrfVerifiable::push_members(
			&mut inter2,
			[charlie.clone()].into_iter(),
			get_many,
		)
		.unwrap();
		assert_eq!(inter1, inter2);

		let members1 = BandersnatchVrfVerifiable::finish_members(inter1);
		let members2 = BandersnatchVrfVerifiable::finish_members(inter2);
		assert_eq!(members1, members2);
	});

	test_for_all_domains!(start_push_finish_multiple_members, |domain_size| {
		let capacity: RingSize = domain_size.into();
		let alice_sec = BandersnatchVrfVerifiable::new_secret([0u8; 32]);
		let bob_sec = BandersnatchVrfVerifiable::new_secret([1u8; 32]);
		let charlie_sec = BandersnatchVrfVerifiable::new_secret([2u8; 32]);

		let alice = BandersnatchVrfVerifiable::member_from_secret(&alice_sec);
		let bob = BandersnatchVrfVerifiable::member_from_secret(&bob_sec);
		let charlie = BandersnatchVrfVerifiable::member_from_secret(&charlie_sec);

		// First set is everyone all at once with the regular starting root.
		let mut inter1 = BandersnatchVrfVerifiable::start_members(capacity);
		// Second set is everyone all at once but with a starting root constructed from params.
		let (mut inter2, builder_params) = start_members_from_params(domain_size);

		let get_many = |range| {
			(&builder_params)
				.lookup(range)
				.map(|v| v.into_iter().map(|i| StaticChunk(i)).collect::<Vec<_>>())
				.ok_or(())
		};

		// Third set is everyone added one by one.
		let mut inter3 = BandersnatchVrfVerifiable::start_members(capacity);
		// Fourth set is a single addition followed by a group addition.
		let mut inter4 = BandersnatchVrfVerifiable::start_members(capacity);

		// Construct the first set with all members added simultaneously.
		BandersnatchVrfVerifiable::push_members(
			&mut inter1,
			[alice.clone(), bob.clone(), charlie.clone()].into_iter(),
			get_many,
		)
		.unwrap();

		// Construct the second set with all members added simultaneously.
		BandersnatchVrfVerifiable::push_members(
			&mut inter2,
			[alice.clone(), bob.clone(), charlie.clone()].into_iter(),
			get_many,
		)
		.unwrap();

		// Construct the third set with all members added sequentially.
		BandersnatchVrfVerifiable::push_members(&mut inter3, [alice.clone()].into_iter(), get_many)
			.unwrap();
		BandersnatchVrfVerifiable::push_members(&mut inter3, [bob.clone()].into_iter(), get_many)
			.unwrap();
		BandersnatchVrfVerifiable::push_members(
			&mut inter3,
			[charlie.clone()].into_iter(),
			get_many,
		)
		.unwrap();

		// Construct the fourth set with the first member joining alone, followed by the other members joining together.
		BandersnatchVrfVerifiable::push_members(&mut inter4, [alice.clone()].into_iter(), get_many)
			.unwrap();
		BandersnatchVrfVerifiable::push_members(
			&mut inter4,
			[bob.clone(), charlie.clone()].into_iter(),
			get_many,
		)
		.unwrap();

		assert_eq!(inter1, inter2);
		assert_eq!(inter2, inter3);
		assert_eq!(inter3, inter4);

		let members1 = BandersnatchVrfVerifiable::finish_members(inter1);
		let members2 = BandersnatchVrfVerifiable::finish_members(inter2);
		let members3 = BandersnatchVrfVerifiable::finish_members(inter3);
		let members4 = BandersnatchVrfVerifiable::finish_members(inter4);
		assert_eq!(members1, members2);
		assert_eq!(members2, members3);
		assert_eq!(members3, members4);
	});

	test_for_all_domains!(open_validate_works, |domain_size| {
		use std::time::Instant;

		let capacity: RingSize = domain_size.into();
		let context = b"Context";
		let message = b"FooBar";

		let start = Instant::now();
		let _ = ring_prover_params(domain_size);
		println!(
			"* PCS params decode: {} ms",
			(Instant::now() - start).as_millis()
		);

		let members: Vec<_> = (0..10)
			.map(|i| {
				let secret = BandersnatchVrfVerifiable::new_secret([i as u8; 32]);
				BandersnatchVrfVerifiable::member_from_secret(&secret)
			})
			.collect();
		let member = members[3].clone();

		let start = Instant::now();
		let commitment =
			BandersnatchVrfVerifiable::open(capacity, &member, members.clone().into_iter())
				.unwrap();
		println!("* Open: {} ms", (Instant::now() - start).as_millis());
		println!("  Commitment size: {} bytes", commitment.encode().len());

		let secret = BandersnatchVrfVerifiable::new_secret([commitment.1 as u8; 32]);
		let start = Instant::now();
		let (proof, alias) =
			BandersnatchVrfVerifiable::create(commitment, &secret, context, message).unwrap();
		println!("* Create: {} ms", (Instant::now() - start).as_millis());
		println!("  Proof size: {} bytes", proof.encode().len());

		// `builder_params` can be serialized/deserialized to be loaded when required
		let (_, builder_params) = start_members_from_params(domain_size);

		let get_many = |range| {
			(&builder_params)
				.lookup(range)
				.map(|v| v.into_iter().map(|i| StaticChunk(i)).collect::<Vec<_>>())
				.ok_or(())
		};

		let start = Instant::now();
		let mut inter = BandersnatchVrfVerifiable::start_members(capacity);
		println!(
			"* Start members: {} ms",
			(Instant::now() - start).as_millis()
		);

		let start = Instant::now();
		members.iter().for_each(|member| {
			BandersnatchVrfVerifiable::push_members(
				&mut inter,
				[member.clone()].into_iter(),
				get_many,
			)
			.unwrap();
		});

		println!(
			"* Push {} members: {} ms",
			members.len(),
			(Instant::now() - start).as_millis()
		);

		let start = Instant::now();
		let members = BandersnatchVrfVerifiable::finish_members(inter);
		println!(
			"* Finish members: {} ms",
			(Instant::now() - start).as_millis()
		);

		let start = Instant::now();
		let alias2 =
			BandersnatchVrfVerifiable::validate(capacity, &proof, &members, context, message)
				.unwrap();
		println!("* Validate {} ms", (Instant::now() - start).as_millis());
		assert_eq!(alias, alias2);

		let start = Instant::now();
		let alias3 = BandersnatchVrfVerifiable::alias_in_context(&secret, context).unwrap();
		println!("* Alias: {} ms", (Instant::now() - start).as_millis());
		assert_eq!(alias, alias3);
	});

	test_for_all_domains!(open_validate_single_vs_multiple_keys, |domain_size| {
		use std::time::Instant;

		let capacity: RingSize = domain_size.into();
		let start = Instant::now();
		let _ = ring_prover_params(domain_size);
		println!("* KZG decode: {} ms", (Instant::now() - start).as_millis());

		// Use the domain's max ring size to test at capacity
		let max_members = capacity.size();
		println!(
			"* Testing with {} members (max for {:?})",
			max_members, domain_size
		);

		let members: Vec<_> = (0..max_members)
			.map(|i| {
				// Use a hash of the index to generate unique secrets for large rings
				let mut seed = [0u8; 32];
				seed[..8].copy_from_slice(&(i as u64).to_le_bytes());
				let secret = BandersnatchVrfVerifiable::new_secret(seed);
				BandersnatchVrfVerifiable::member_from_secret(&secret)
			})
			.collect();

		// `builder_params` can be serialized/deserialized to be loaded when required
		let (_, builder_params) = start_members_from_params(domain_size);

		let get_many = |range| {
			(&builder_params)
				.lookup(range)
				.map(|v| v.into_iter().map(|i| StaticChunk(i)).collect::<Vec<_>>())
				.ok_or(())
		};

		let mut inter1 = BandersnatchVrfVerifiable::start_members(capacity);
		let start = Instant::now();
		members.iter().for_each(|member| {
			BandersnatchVrfVerifiable::push_members(
				&mut inter1,
				[member.clone()].into_iter(),
				get_many,
			)
			.unwrap();
		});
		println!(
			"* Push {} members one at a time: {} ms",
			members.len(),
			(Instant::now() - start).as_millis()
		);

		let mut inter2 = BandersnatchVrfVerifiable::start_members(capacity);
		let start = Instant::now();

		BandersnatchVrfVerifiable::push_members(&mut inter2, members.iter().cloned(), get_many)
			.unwrap();
		println!(
			"* Push {} members simultaneously: {} ms",
			members.len(),
			(Instant::now() - start).as_millis()
		);

		assert_eq!(inter1, inter2);
	});
}
