use alloc::vec;
use core::{marker::PhantomData, ops::Deref, ops::Range};

pub use ark_vrf;

use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_vrf::ring::{RingSuite, Verifier};
use parity_scale_codec::{Decode, Encode};
use scale_info::TypeInfo;

use super::*;

pub mod bandersnatch;

/// Encoding mode for types that are constructed internally from trusted sources
/// (e.g. on-chain state, locally built commitments) and do not need compression
/// or validation during SCALE codec round-trips.
///
/// Equivalent to `ark_scale::HOST_CALL`: `(Compress::No, Validate::No)`.
const TRUSTED_SOURCE: ark_scale::Usage =
	ark_scale::make_usage(ark_serialize::Compress::No, ark_serialize::Validate::No);

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

impl TryFrom<u32> for RingDomainSize {
	type Error = ();
	fn try_from(value: u32) -> Result<Self, Self::Error> {
		const ALL: [RingDomainSize; 3] = [
			RingDomainSize::Domain11,
			RingDomainSize::Domain12,
			RingDomainSize::Domain16,
		];
		ALL.iter().copied().find(|d| d.value() == value).ok_or(())
	}
}

impl From<RingDomainSize> for u32 {
	fn from(value: RingDomainSize) -> Self {
		value.value()
	}
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
	pub const fn value(self) -> u32 {
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
		max_ring_size_from_pcs_domain_size::<S>(self.dom_size.value())
	}
}

/// Trait for providing pairing-curve-specific ring data.
///
/// All RingSuites that use the same pairing curve can share the same data provider.
/// For example, all suites using BLS12-381 (like Bandersnatch) use `Bls12_381Params`.
pub trait RingCurveParams {
	/// Raw SRS data (powers of tau).
	#[cfg(feature = "prover")]
	fn srs_raw() -> &'static [u8];

	/// Ring builder params for a given domain size.
	#[cfg(any(feature = "std", feature = "builder-params"))]
	fn ring_builder_params(domain: RingDomainSize) -> &'static [u8];

	/// Empty ring commitment data for a given domain size.
	fn empty_ring_commitment(domain: RingDomainSize) -> &'static [u8];
}

/// Ring data for suites using BLS12-381 pairing (e.g., Bandersnatch curves).
pub struct Bls12_381Params;

impl RingCurveParams for Bls12_381Params {
	#[cfg(feature = "prover")]
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
const fn max_ring_size_from_pcs_domain_size<S: RingSuiteExt>(pcs_domain_size: u32) -> usize {
	ark_vrf::ring::max_ring_size_from_pcs_domain_size::<S>(pcs_domain_size as usize)
}

/// Construct ring prover params from the suite's SRS data.
#[cfg(feature = "prover")]
pub fn make_ring_prover_params<S: RingSuiteExt>(
	domain_size: RingDomainSize,
) -> ark_vrf::ring::RingProofParams<S> {
	let data = S::CurveParams::srs_raw();
	let pcs_params =
		ark_vrf::ring::PcsParams::<S>::deserialize_uncompressed_unchecked(data).unwrap();
	let ring_size = max_ring_size_from_pcs_domain_size::<S>(domain_size.value());
	ark_vrf::ring::RingProofParams::<S>::from_pcs_params(ring_size, pcs_params).unwrap()
}

/// Get ring builder params for the given domain size.
/// Only available with the `builder-params` or `std` features.
#[cfg(any(feature = "std", feature = "builder-params"))]
pub fn ring_verifier_builder_params<S: RingSuiteExt>(
	domain_size: RingDomainSize,
) -> ark_vrf::ring::RingBuilderPcsParams<S> {
	let data = S::CurveParams::ring_builder_params(domain_size);
	ark_vrf::ring::RingBuilderPcsParams::<S>::deserialize_uncompressed_unchecked(data).unwrap()
}

/// Trait for caching ring proof params.
///
/// The `Handle` associated type allows different caching strategies.
#[cfg(feature = "prover")]
pub trait RingProofParamsCache<S: RingSuiteExt> {
	/// Handle type returned by the cache. Must deref to `RingProofParams<S>`.
	type Handle: Deref<Target = ark_vrf::ring::RingProofParams<S>>;

	/// Get or construct ring proof params for the given domain size.
	fn get(domain_size: RingDomainSize) -> Self::Handle;
}

/// Null cache: always constructs new params without caching.
#[cfg(feature = "prover")]
pub type NullCache = ();

#[cfg(feature = "prover")]
impl<S: RingSuiteExt> RingProofParamsCache<S> for NullCache {
	type Handle = alloc::boxed::Box<ark_vrf::ring::RingProofParams<S>>;

	fn get(domain_size: RingDomainSize) -> Self::Handle {
		alloc::boxed::Box::new(make_ring_prover_params::<S>(domain_size))
	}
}

/// Fixed-size byte array used to represent a serialized cryptographic object
/// (public key, proof, or signature).
pub trait FixedBytes:
	Clone
	+ Eq
	+ FullCodec
	+ DecodeWithMemTracking
	+ core::fmt::Debug
	+ TypeInfo
	+ MaxEncodedLen
	+ AsRef<[u8]>
	+ AsMut<[u8]>
{
	/// The zero (all-bytes-zero) value, used as an initial buffer for serialization.
	const ZERO: Self;
}
impl<const N: usize> FixedBytes for [u8; N] {
	const ZERO: Self = [0; N];
}

/// Trait providing suite-specific byte array types for ring VRF operations.
///
/// This trait defines the concrete array types used for serialized forms of
/// public keys, proofs, and signatures. Each suite specifies its own sizes.
pub trait RingSuiteExt: RingSuite + Debug + 'static {
	/// VRF input domain separator.
	///
	/// Used to construct the VRF input from context/message data.
	/// Each suite should use a unique domain separator to avoid cross-suite collisions.
	const VRF_INPUT_DOMAIN: &[u8];

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
	type PublicKeyBytes: FixedBytes;
	/// Byte array type for ring VRF proofs.
	type RingProofBytes: FixedBytes;
	/// Byte array type for plain VRF signatures.
	type SignatureBytes: FixedBytes;

	/// The curve static data provider for this suite.
	type CurveParams: RingCurveParams;

	/// Cache strategy for ring proof params.
	#[cfg(feature = "prover")]
	type ParamsCache: RingProofParamsCache<Self>;
}

macro_rules! impl_common_traits {
	($type_name:ident<S: $bound:path>, $size_expr:expr) => {
		impl<S: $bound> Decode for $type_name<S> {
			fn decode<I: ark_scale::scale::Input>(
				input: &mut I,
			) -> Result<Self, ark_scale::scale::Error> {
				let a: ark_scale::ArkScale<Self, { TRUSTED_SOURCE }> =
					<ark_scale::ArkScale<Self, { TRUSTED_SOURCE }> as ark_scale::scale::Decode>::decode(
						input,
					)?;
				Ok(a.0)
			}

			fn skip<I: ark_scale::scale::Input>(
				input: &mut I,
			) -> Result<(), ark_scale::scale::Error> {
				<ark_scale::ArkScale<Self, { TRUSTED_SOURCE }> as ark_scale::scale::Decode>::skip(input)
			}

			fn encoded_fixed_size() -> Option<usize> {
				<ark_scale::ArkScale<Self, { TRUSTED_SOURCE }> as ark_scale::scale::Decode>::encoded_fixed_size()
			}
		}

		impl<S: $bound> Encode for $type_name<S> {
			fn size_hint(&self) -> usize {
				let a: ark_scale::ArkScaleRef<Self, { TRUSTED_SOURCE }> = ark_scale::ArkScaleRef(self);
				a.size_hint()
			}

			fn encode_to<O: ark_scale::scale::Output + ?Sized>(&self, dest: &mut O) {
				let a: ark_scale::ArkScaleRef<Self, { TRUSTED_SOURCE }> = ark_scale::ArkScaleRef(self);
				a.encode_to(dest)
			}

			fn encode(&self) -> alloc::vec::Vec<u8> {
				let a: ark_scale::ArkScaleRef<Self, { TRUSTED_SOURCE }> = ark_scale::ArkScaleRef(self);
				a.encode()
			}

			fn using_encoded<R, F: FnOnce(&[u8]) -> R>(&self, f: F) -> R {
				let a: ark_scale::ArkScaleRef<Self, { TRUSTED_SOURCE }> = ark_scale::ArkScaleRef(self);
				a.using_encoded(f)
			}

			fn encoded_size(&self) -> usize {
				let a: ark_scale::ArkScaleRef<Self, { TRUSTED_SOURCE }> = ark_scale::ArkScaleRef(self);
				a.encoded_size()
			}
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

/// Intermediate state while building a ring member set.
///
/// Wraps a [`ark_vrf::ring::VerifierKeyBuilder`] and accumulates members via
/// [`GenerateVerifiable::push_members`]. Finalized into a [`MembersCommitment`]
/// via [`GenerateVerifiable::finish_members`].
#[derive(CanonicalDeserialize, CanonicalSerialize, Clone)]
pub struct MembersSet<S: RingSuiteExt>(pub(crate) ark_vrf::ring::VerifierKeyBuilder<S>);

impl_common_traits!(MembersSet<S: RingSuiteExt>, S::MEMBERS_SET_SIZE);

impl<S: RingSuiteExt> core::fmt::Debug for MembersSet<S> {
	fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
		write!(f, "MembersSet")
	}
}

/// Finalized commitment to a set of ring members.
///
/// This is the compact representation used for proof verification. Produced by
/// [`GenerateVerifiable::finish_members`] from a [`MembersSet`].
#[derive(CanonicalDeserialize, CanonicalSerialize, Clone)]
pub struct MembersCommitment<S: RingSuiteExt>(pub(crate) ark_vrf::ring::RingVerifierKey<S>);

impl_common_traits!(MembersCommitment<S: RingSuiteExt>, S::MEMBERS_COMMITMENT_SIZE);

impl<S: RingSuiteExt> core::fmt::Debug for MembersCommitment<S> {
	fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
		write!(f, "MembersCommitment")
	}
}

pub(crate) type PublicKey<S> = ark_vrf::Public<S>;

/// A chunk of the ring builder's static data (a G1 affine point).
///
/// Used by the `lookup` function in [`GenerateVerifiable::push_members`] to supply
/// precomputed SRS points needed to update the ring commitment.
#[derive(CanonicalSerialize, CanonicalDeserialize, Clone, Debug)]
pub struct StaticChunk<S: RingSuiteExt>(pub ark_vrf::ring::G1Affine<S>);

impl_common_traits!(StaticChunk<S: RingSuiteExt>, S::STATIC_CHUNK_SIZE);

/// State produced by [`GenerateVerifiable::open`] and consumed by [`GenerateVerifiable::create`].
///
/// Contains the prover's position in the ring and the keying material needed to
/// generate a ring VRF proof. This is serializable so it can be transferred to
/// an offline/air-gapped signing device.
#[derive(CanonicalSerialize, CanonicalDeserialize, Clone)]
pub struct ProverState<S: RingSuiteExt> {
	pub(crate) domain_size: u32,
	pub(crate) prover_idx: u32,
	pub(crate) prover_key: ark_vrf::ring::RingProverKey<S>,
}

impl_common_traits!(ProverState<S: RingSuiteExt>, 0);

impl<S: RingSuiteExt> core::fmt::Debug for ProverState<S> {
	fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
		write!(f, "ProverState")
	}
}

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
	output
		.hash()
		.get(..32)
		.and_then(|raw| raw.try_into().ok())
		.expect("Suite hash should be at least 32 bytes")
}

/// Generic ring VRF implementation parameterized over the ring suite.
///
/// The curve params provider is obtained from `S::CurveParams`.
pub struct RingVrfVerifiable<S: RingSuiteExt>(PhantomData<S>);

impl<S: RingSuiteExt> GenerateVerifiable for RingVrfVerifiable<S> {
	type Secret = ark_vrf::Secret<S>;
	type Commitment = ProverState<S>;
	type Members = MembersCommitment<S>;
	type Intermediate = MembersSet<S>;
	type Member = S::PublicKeyBytes;
	type Proof = S::RingProofBytes;
	type Signature = S::SignatureBytes;
	type StaticChunk = StaticChunk<S>;
	type Capacity = RingSize<S>;

	fn start_members(capacity: Self::Capacity) -> Self::Intermediate {
		// TODO: Optimize by caching the deserialized value; must be compatible with the WASM runtime environment.
		let data = S::CurveParams::empty_ring_commitment(capacity.dom_size);
		MembersSet::deserialize_uncompressed_unchecked(data).unwrap()
	}

	fn push_members(
		intermediate: &mut Self::Intermediate,
		members: impl Iterator<Item = Self::Member>,
		lookup: impl Fn(Range<usize>) -> Result<Vec<Self::StaticChunk>, ()>,
	) -> Result<(), ()> {
		let mut keys = vec![];
		for member in members {
			let pk = PublicKey::<S>::deserialize_compressed(member.as_ref()).map_err(|_| ())?;
			keys.push(pk.0);
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
		let mut bytes = S::PublicKeyBytes::ZERO;
		secret
			.public()
			.serialize_compressed(bytes.as_mut())
			.expect("fixed-size buffer is large enough");
		bytes
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

		let input_msg = [S::VRF_INPUT_DOMAIN, context].concat();
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

	fn batch_validate(
		capacity: Self::Capacity,
		members: &Self::Members,
		proofs: &[BatchProofItem<Self::Proof>],
	) -> Result<Vec<Alias>, ()> {
		let verifier = ark_vrf::ring::RingProofParams::<S>::verifier_no_context(
			members.0.clone(),
			capacity.size(),
		);

		let mut aliases = Vec::with_capacity(proofs.len());
		let mut batch_verifier = ark_vrf::ring::BatchVerifier::<S>::new(verifier);
		for BatchProofItem { proof, context, message } in proofs {
			let input_msg = [S::VRF_INPUT_DOMAIN, context.as_slice()].concat();
			let input = ark_vrf::Input::<S>::new(&input_msg[..]).expect("H2C can't fail here");
			let signature = RingVrfSignature::<S>::deserialize_compressed_unchecked(proof.as_ref())
				.map_err(|_| ())?;
			aliases.push(make_alias(&signature.output));
			batch_verifier.push(input, signature.output, message, &signature.proof);
		}
		if batch_verifier.verify().is_ok() {
			return Ok(aliases);
		}
		Err(())
	}

	fn sign(secret: &Self::Secret, message: &[u8]) -> Result<Self::Signature, ()> {
		use ark_vrf::ietf::Prover;
		let input_msg = [S::VRF_INPUT_DOMAIN, message].concat();
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
		let Ok(signature) = IetfVrfSignature::<S>::deserialize_compressed(signature.as_ref())
		else {
			return false;
		};
		let input_msg = [S::VRF_INPUT_DOMAIN, message].concat();
		let input = ark_vrf::Input::<S>::new(&input_msg[..]).expect("H2C can't fail here");
		let Ok(public) = PublicKey::<S>::deserialize_compressed(member.as_ref()) else {
			return false;
		};
		public
			.verify(input, signature.output, b"", &signature.proof)
			.is_ok()
	}

	#[cfg(feature = "prover")]
	fn open(
		capacity: Self::Capacity,
		member: &Self::Member,
		members: impl Iterator<Item = Self::Member>,
	) -> Result<Self::Commitment, ()> {
		let pks = members
			.map(|m| {
				PublicKey::<S>::deserialize_compressed(m.as_ref())
					.map(|pk| pk.0)
					.map_err(|_| ())
			})
			.collect::<Result<Vec<_>, _>>()?;
		let member = PublicKey::<S>::deserialize_compressed(member.as_ref()).map_err(|_| ())?;
		let prover_idx = pks.iter().position(|&m| m == member.0).ok_or(())? as u32;
		let prover_key = S::ParamsCache::get(capacity.dom_size).prover_key(&pks[..]);
		Ok(ProverState {
			domain_size: capacity.dom_size.value(),
			prover_idx,
			prover_key,
		})
	}

	#[cfg(feature = "prover")]
	fn create(
		commitment: Self::Commitment,
		secret: &Self::Secret,
		context: &[u8],
		message: &[u8],
	) -> Result<(Self::Proof, Alias), ()> {
		use ark_vrf::ring::Prover;
		let domain_size = RingDomainSize::try_from(commitment.domain_size).map_err(|_| ())?;
		let params = S::ParamsCache::get(domain_size);
		if commitment.prover_idx >= params.max_ring_size() as u32 {
			return Err(());
		}

		let ring_prover = params.prover(commitment.prover_key, commitment.prover_idx as usize);

		let input_msg = [S::VRF_INPUT_DOMAIN, context].concat();
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
		let input_msg = [S::VRF_INPUT_DOMAIN, context].concat();
		let input = ark_vrf::Input::<S>::new(&input_msg[..]).expect("H2C can't fail here");
		let output = secret.output(input);
		let alias = make_alias(&output);
		Ok(alias)
	}

	fn is_member_valid(member: &Self::Member) -> bool {
		PublicKey::<S>::deserialize_compressed(member.as_ref()).is_ok()
	}
}
