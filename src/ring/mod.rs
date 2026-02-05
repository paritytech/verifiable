use alloc::vec;
use core::{marker::PhantomData, ops::Deref, ops::Range};

pub use ark_vrf;

use ark_scale::ArkScale;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_vrf::ring::{RingSuite, Verifier};
use parity_scale_codec::{Decode, Encode};
use scale_info::TypeInfo;

use super::*;

pub mod bandersnatch;

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
pub struct RingSize<S: RingSuiteExt> {
	dom_size: RingDomainSize,
	_phantom: PhantomData<S>,
}

impl<S: RingSuiteExt> From<RingDomainSize> for RingSize<S> {
	fn from(dom_size: RingDomainSize) -> Self {
		Self {
			dom_size,
			_phantom: PhantomData,
		}
	}
}

impl<S: RingSuiteExt> Capacity for RingSize<S> {
	fn size(&self) -> usize {
		max_ring_size_from_pcs_domain_size::<S>(self.dom_size.pcs_domain_size())
	}
}

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

impl RingCurveData for Bls12_381RingData {
	#[cfg(any(feature = "std", feature = "no-std-prover"))]
	fn srs_raw() -> &'static [u8] {
		include_bytes!("data/bls12-381/srs-uncompressed.bin")
	}

	#[cfg(any(feature = "std", feature = "builder-params"))]
	fn ring_builder_params(domain: RingDomainSize) -> &'static [u8] {
		match domain {
			RingDomainSize::Domain11 => {
				include_bytes!("data/bls12-381/ring-builder-params-domain11.bin")
			}
			RingDomainSize::Domain12 => {
				include_bytes!("data/bls12-381/ring-builder-params-domain12.bin")
			}
			RingDomainSize::Domain16 => {
				include_bytes!("data/bls12-381/ring-builder-params-domain16.bin")
			}
		}
	}

	fn empty_ring_commitment(domain: RingDomainSize) -> &'static [u8] {
		match domain {
			RingDomainSize::Domain11 => include_bytes!("data/bls12-381/ring-builder-domain11.bin"),
			RingDomainSize::Domain12 => include_bytes!("data/bls12-381/ring-builder-domain12.bin"),
			RingDomainSize::Domain16 => include_bytes!("data/bls12-381/ring-builder-domain16.bin"),
		}
	}
}

/// The max ring that can be handled for both sign/verify for the given PCS domain size.
const fn max_ring_size_from_pcs_domain_size<S: RingSuiteExt>(pcs_domain_size: usize) -> usize {
	ark_vrf::ring::max_ring_size_from_pcs_domain_size::<S>(pcs_domain_size)
}

/// Construct ring prover params from the suite's SRS data.
#[cfg(any(feature = "std", feature = "no-std-prover"))]
pub fn make_ring_prover_params<S: RingSuiteExt>(
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
pub fn ring_verifier_builder_params<S: RingSuiteExt>(
	domain_size: RingDomainSize,
) -> ark_vrf::ring::RingBuilderPcsParams<S> {
	let data = S::CurveData::ring_builder_params(domain_size);
	ark_vrf::ring::RingBuilderPcsParams::<S>::deserialize_uncompressed_unchecked(data).unwrap()
}

/// Trait for caching ring proof params.
///
/// The `Handle` associated type allows different caching strategies.
#[cfg(any(feature = "std", feature = "no-std-prover"))]
pub trait RingProofParamsCache<S: RingSuiteExt> {
	/// Handle type returned by the cache. Must deref to `RingProofParams<S>`.
	type Handle: Deref<Target = ark_vrf::ring::RingProofParams<S>>;

	/// Get or construct ring proof params for the given domain size.
	fn get(domain_size: RingDomainSize) -> Self::Handle;
}

/// No-caching implementation: always constructs new params.
#[cfg(any(feature = "std", feature = "no-std-prover"))]
impl<S: RingSuiteExt> RingProofParamsCache<S> for () {
	type Handle = alloc::boxed::Box<ark_vrf::ring::RingProofParams<S>>;

	fn get(domain_size: RingDomainSize) -> Self::Handle {
		alloc::boxed::Box::new(make_ring_prover_params::<S>(domain_size))
	}
}

pub trait EncodedTypesBounds:
	Clone + Eq + FullCodec + core::fmt::Debug + TypeInfo + MaxEncodedLen + AsRef<[u8]> + AsMut<[u8]>
{
	const ZERO: Self;
}
impl<const N: usize> EncodedTypesBounds for [u8; N] {
	const ZERO: Self = [0; N];
}

/// Trait providing suite-specific byte array types for ring VRF operations.
///
/// This trait defines the concrete array types used for serialized forms of
/// public keys, proofs, and signatures. Each suite specifies its own sizes.
pub trait RingSuiteExt: RingSuite + 'static {
	/// Encoded size of a public key.
	const PUBLIC_KEY_SIZE: usize;
	/// Encoded size of MembersSet (Intermediate).
	const MEMBERS_SET_SIZE: usize;
	/// Encoded size of MembersCommitment (Members).
	const MEMBERS_COMMITMENT_SIZE: usize;
	/// Encoded size of StaticChunk (G1 point).
	const STATIC_CHUNK_SIZE: usize;
	/// Encoded size of RingVrfSignature
	const RING_PROOF_SIZE: usize;
	/// Encoded size of IetfVrfSignature
	const SIGNATURE_SIZE: usize;

	/// Byte array type for encoded public keys.
	type PublicKeyBytes: EncodedTypesBounds;
	/// Byte array type for ring VRF proofs.
	type RingProofBytes: EncodedTypesBounds;
	/// Byte array type for plain VRF signatures.
	type SignatureBytes: EncodedTypesBounds;

	/// The curve static data provider for this suite.
	type CurveData: RingCurveData;

	/// Cache strategy for ring proof params.
	///
	/// Use `()` for no caching (always construct), or a type generated by
	/// [`impl_ring_params_cache!`] for static caching.
	#[cfg(any(feature = "std", feature = "no-std-prover"))]
	type ParamsCache: RingProofParamsCache<Self>;
}

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
pub struct MembersSet<S: RingSuiteExt>(pub(crate) ark_vrf::ring::RingVerifierKeyBuilder<S>);

impl_common_traits!(MembersSet<S: RingSuiteExt>, S::MEMBERS_SET_SIZE);

impl<S: RingSuiteExt> core::fmt::Debug for MembersSet<S> {
	fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
		write!(f, "MembersSet")
	}
}

#[derive(CanonicalDeserialize, CanonicalSerialize)]
#[derive_where::derive_where(Clone)]
pub struct MembersCommitment<S: RingSuiteExt>(pub(crate) ark_vrf::ring::RingVerifierKey<S>);

impl_common_traits!(MembersCommitment<S: RingSuiteExt>, S::MEMBERS_COMMITMENT_SIZE);

impl<S: RingSuiteExt> core::fmt::Debug for MembersCommitment<S> {
	fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
		write!(f, "MembersCommitment")
	}
}

#[derive(CanonicalSerialize, CanonicalDeserialize)]
#[derive_where::derive_where(Clone, Debug)]
pub struct PublicKey<S: RingSuiteExt>(pub(crate) ark_vrf::AffinePoint<S>);

impl_common_traits!(PublicKey<S: RingSuiteExt>, S::PUBLIC_KEY_SIZE);

#[derive(CanonicalSerialize, CanonicalDeserialize)]
#[derive_where::derive_where(Clone, Debug)]
pub struct StaticChunk<S: RingSuiteExt>(pub ark_vrf::ring::G1Affine<S>);

impl_common_traits!(StaticChunk<S: RingSuiteExt>, S::STATIC_CHUNK_SIZE);

#[derive(CanonicalSerialize, CanonicalDeserialize)]
struct IetfVrfSignature<S: RingSuiteExt> {
	output: ark_vrf::Output<S>,
	proof: ark_vrf::ietf::Proof<S>,
}

#[derive(CanonicalSerialize, CanonicalDeserialize)]
struct RingVrfSignature<S: RingSuiteExt> {
	output: ark_vrf::Output<S>,
	proof: ark_vrf::ring::Proof<S>,
}

#[inline(always)]
fn make_alias<S: RingSuiteExt>(output: &ark_vrf::Output<S>) -> Alias {
	Alias::try_from(&output.hash()[..32]).expect("Suite hash should be at least 32 bytes")
}

/// Generic ring VRF implementation parameterized over the ring suite.
///
/// The curve data provider is obtained from `S::CurveData`.
pub struct RingVrfVerifiable<S: RingSuiteExt>(PhantomData<S>);

const VRF_INPUT_DOMAIN: &[u8] = b"VerifiableVrfInput";

impl<S: RingSuiteExt> RingVrfVerifiable<S> {
	fn to_public_key(value: &S::PublicKeyBytes) -> Result<PublicKey<S>, ()> {
		let pt =
			ark_vrf::AffinePoint::<S>::deserialize_compressed(value.as_ref()).map_err(|_| ())?;
		Ok(PublicKey(pt))
	}

	fn to_encoded_public_key(value: &PublicKey<S>) -> S::PublicKeyBytes {
		let mut bytes = S::PublicKeyBytes::ZERO;
		value.using_encoded(|encoded| {
			bytes.as_mut().copy_from_slice(encoded);
		});
		bytes
	}
}

impl<S: RingSuiteExt> GenerateVerifiable for RingVrfVerifiable<S> {
	type Members = MembersCommitment<S>;
	type Intermediate = MembersSet<S>;
	type Member = S::PublicKeyBytes;
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

		let signature = RingVrfSignature::<S>::deserialize_compressed_unchecked(proof.as_ref())
			.map_err(|_| ())?;

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

		let mut raw = S::SignatureBytes::ZERO;
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
		let Ok(signature) =
			IetfVrfSignature::<S>::deserialize_compressed_unchecked(signature.as_ref())
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
		let prover_key = S::ParamsCache::get(capacity.dom_size).prover_key(&pks[..]);
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
		let params = S::ParamsCache::get(capacity.dom_size);
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

		let mut buf = S::RingProofBytes::ZERO;
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
