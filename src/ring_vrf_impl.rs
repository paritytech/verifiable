use alloc::vec;
use core::ops::Range;

pub use ark_vrf;

use ark_scale::ArkScale;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
#[cfg(any(feature = "std", feature = "builder-params"))]
use ark_vrf::suites::bandersnatch::BandersnatchSha512Ell2;
use ark_vrf::{ring::Verifier, suites::bandersnatch};
use parity_scale_codec::{Decode, Encode};
use scale_info::TypeInfo;

use super::*;

#[cfg(any(feature = "std", feature = "no-std-prover"))]
pub(crate) const VERIFIABLE_SRS_RAW: &[u8] = include_bytes!("ring-data/srs-uncompressed.bin");

/// The max ring that can be handled for both sign/verify for the given PCS domain size.
const fn max_ring_size_from_pcs_domain_size(pcs_domain_size: usize) -> usize {
	ark_vrf::ring::max_ring_size_from_pcs_domain_size::<bandersnatch::BandersnatchSha512Ell2>(
		pcs_domain_size,
	)
}

/// Concrete domain sizes for the PCS (Polynomial Commitment Scheme).
///
/// This determines the maximum ring size that can be supported:
/// - `Domain11`: 2^11 = 2048 domain size, supports up to 255 members
/// - `Domain12`: 2^12 = 4096 domain size, supports up to 767 members
/// - `Domain16`: 2^16 = 65536 domain size, supports up to 16127 members
#[derive(
	Clone, Copy, Debug, PartialEq, Eq, Hash, Encode, Decode, TypeInfo, DecodeWithMemTracking,
)]
pub enum RingDomainSize {
	/// Domain size 2^11, max ring size 255
	Domain11,
	/// Domain size 2^12, max ring size 767
	Domain12,
	/// Domain size 2^16, max ring size 16127
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

	/// All available domain sizes.
	pub const ALL: [RingDomainSize; 3] = [
		RingDomainSize::Domain11,
		RingDomainSize::Domain12,
		RingDomainSize::Domain16,
	];
}

impl Capacity for RingDomainSize {
	fn size(&self) -> usize {
		max_ring_size_from_pcs_domain_size(self.pcs_domain_size())
	}
}

/// Ring builder params binary data.
/// Only available with the `builder-params` feature.
#[cfg(any(feature = "std", feature = "builder-params"))]
mod ring_params {
	pub const DOMAIN_11_RING_BUILDER_PARAMS: &[u8] =
		include_bytes!("ring-data/ring-builder-params-domain11.bin");
	pub const DOMAIN_12_RING_BUILDER_PARAMS: &[u8] =
		include_bytes!("ring-data/ring-builder-params-domain12.bin");
	pub const DOMAIN_16_RING_BUILDER_PARAMS: &[u8] =
		include_bytes!("ring-data/ring-builder-params-domain16.bin");
}
#[cfg(any(feature = "std", feature = "builder-params"))]
use ring_params::*;

/// Ring commitment serialized binary data.
mod ring_commitment_data {
	pub const DOMAIN_11_EMPTY_RING_COMMITMENT_DATA: &[u8] =
		include_bytes!("ring-data/ring-builder-domain11.bin");
	pub const DOMAIN_12_EMPTY_RING_COMMITMENT_DATA: &[u8] =
		include_bytes!("ring-data/ring-builder-domain12.bin");
	pub const DOMAIN_16_EMPTY_RING_COMMITMENT_DATA: &[u8] =
		include_bytes!("ring-data/ring-builder-domain16.bin");
}
use ring_commitment_data::*;

const VRF_INPUT_DOMAIN: &[u8] = b"VerifiableBandersnatchVrfInput";

/// A sequence of static chunks.
/// Only available with the `builder-params` feature.
#[cfg(any(feature = "std", feature = "builder-params"))]
pub type RingBuilderParams = ark_vrf::ring::RingBuilderPcsParams<BandersnatchSha512Ell2>;

macro_rules! impl_scale {
	($type_name:ident, $encoded_size:expr) => {
		ark_scale::impl_scale_via_ark!($type_name);

		impl scale::MaxEncodedLen for $type_name {
			fn max_encoded_len() -> usize {
				$encoded_size
			}
		}

		impl scale_info::TypeInfo for $type_name {
			type Identity = [u8; $encoded_size];
			fn type_info() -> scale_info::Type {
				Self::Identity::type_info()
			}
		}
	};
}

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

	cell.get_or_init(|| {
		let pcs_params =
			bandersnatch::PcsParams::deserialize_uncompressed_unchecked(VERIFIABLE_SRS_RAW)
				.unwrap();
		bandersnatch::RingProofParams::from_pcs_params(domain_size.size(), pcs_params).unwrap()
	})
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

	cell.call_once(|| {
		let pcs_params =
			bandersnatch::PcsParams::deserialize_uncompressed_unchecked(VERIFIABLE_SRS_RAW)
				.unwrap();
		bandersnatch::RingProofParams::from_pcs_params(domain_size.size(), pcs_params).unwrap()
	})
}

/// Get ring builder params for the given domain size.
/// Only available with the `builder-params` or `std` features.
#[cfg(any(feature = "std", feature = "builder-params"))]
pub fn ring_verifier_builder_params(domain_size: RingDomainSize) -> RingBuilderParams {
	use ark_vrf::ring::G1Affine;
	let data = match domain_size {
		RingDomainSize::Domain11 => DOMAIN_11_RING_BUILDER_PARAMS,
		RingDomainSize::Domain12 => DOMAIN_12_RING_BUILDER_PARAMS,
		RingDomainSize::Domain16 => DOMAIN_16_RING_BUILDER_PARAMS,
	};
	let inner =
		<Vec<G1Affine<BandersnatchSha512Ell2>>>::deserialize_uncompressed_unchecked(data).unwrap();
	ark_vrf::ring::RingBuilderPcsParams::<BandersnatchSha512Ell2>(inner)
}

#[derive(Clone, CanonicalDeserialize, CanonicalSerialize)]
pub struct MembersSet(bandersnatch::RingVerifierKeyBuilder);

impl_scale!(MembersSet, 432);

impl core::fmt::Debug for MembersSet {
	fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
		write!(f, "MembersSet")
	}
}

impl core::cmp::PartialEq for MembersSet {
	fn eq(&self, other: &Self) -> bool {
		self.encode() == other.encode()
	}
}

impl core::cmp::Eq for MembersSet {}

#[derive(Clone, CanonicalDeserialize, CanonicalSerialize)]
pub struct MembersCommitment(bandersnatch::RingVerifierKey);

impl_scale!(MembersCommitment, 384);

impl core::fmt::Debug for MembersCommitment {
	fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
		write!(f, "MemberCommitment")
	}
}

impl core::cmp::PartialEq for MembersCommitment {
	fn eq(&self, other: &Self) -> bool {
		self.encode() == other.encode()
	}
}
impl core::cmp::Eq for MembersCommitment {}

const PUBLIC_KEY_SIZE: usize = 32;

#[derive(
	Clone, Eq, PartialEq, Debug, Encode, Decode, TypeInfo, MaxEncodedLen, DecodeWithMemTracking,
)]
pub struct EncodedPublicKey(pub [u8; PUBLIC_KEY_SIZE]);

#[derive(Clone, Eq, PartialEq, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct PublicKey(bandersnatch::AffinePoint);
impl_scale!(PublicKey, PUBLIC_KEY_SIZE);

#[derive(Clone, Eq, PartialEq, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct StaticChunk(pub ark_vrf::ring::G1Affine<bandersnatch::BandersnatchSha512Ell2>);
impl_scale!(StaticChunk, 48);

impl DecodeWithMemTracking for StaticChunk {}

#[derive(CanonicalSerialize, CanonicalDeserialize)]
struct IetfVrfSignature {
	output: bandersnatch::Output,
	proof: bandersnatch::IetfProof,
}
const PLAIN_VRF_SIGNATURE_SIZE: usize = 96;

#[derive(CanonicalSerialize, CanonicalDeserialize)]
struct RingVrfSignature {
	output: bandersnatch::Output,
	proof: bandersnatch::RingProof,
}
const RING_VRF_SIGNATURE_SIZE: usize = 788;

#[inline(always)]
fn make_alias(output: &bandersnatch::Output) -> Alias {
	Alias::try_from(&output.hash()[..32]).expect("Bandersnatch suite hash is 64 bytes")
}

pub struct BandersnatchVrfVerifiable;

impl BandersnatchVrfVerifiable {
	fn to_public_key(value: &EncodedPublicKey) -> Result<PublicKey, ()> {
		let pt = bandersnatch::AffinePoint::deserialize_compressed(&value.0[..]).map_err(|_| ())?;
		Ok(PublicKey(pt.into()))
	}

	fn to_encoded_public_key(value: &PublicKey) -> EncodedPublicKey {
		let mut bytes = [0u8; PUBLIC_KEY_SIZE];
		value.using_encoded(|encoded| {
			bytes.copy_from_slice(encoded);
		});
		EncodedPublicKey(bytes)
	}
}

impl GenerateVerifiable for BandersnatchVrfVerifiable {
	type Members = MembersCommitment;
	type Intermediate = MembersSet;
	type Member = EncodedPublicKey;
	type Secret = bandersnatch::Secret;
	type Commitment = (RingDomainSize, u32, ArkScale<bandersnatch::RingProverKey>);
	type Proof = [u8; RING_VRF_SIGNATURE_SIZE];
	type Signature = [u8; PLAIN_VRF_SIGNATURE_SIZE];
	type StaticChunk = StaticChunk;
	type Capacity = RingDomainSize;

	fn start_members(capacity: RingDomainSize) -> Self::Intermediate {
		// TODO: Optimize by caching the deserialized value; must be compatible with the WASM runtime environment.
		let data = match capacity {
			RingDomainSize::Domain11 => DOMAIN_11_EMPTY_RING_COMMITMENT_DATA,
			RingDomainSize::Domain12 => DOMAIN_12_EMPTY_RING_COMMITMENT_DATA,
			RingDomainSize::Domain16 => DOMAIN_16_EMPTY_RING_COMMITMENT_DATA,
		};
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
		capacity: RingDomainSize,
		proof: &Self::Proof,
		members: &Self::Members,
		context: &[u8],
		message: &[u8],
	) -> Result<Alias, ()> {
		// This doesn't require the whole kzg. Thus is more appropriate if used on-chain
		// Is a bit slower as it requires to recompute piop_params, but still in the order of ms
		let ring_verifier =
			bandersnatch::RingProofParams::verifier_no_context(members.0.clone(), capacity.size());

		let input_msg = [VRF_INPUT_DOMAIN, context].concat();
		let input = bandersnatch::Input::new(&input_msg[..]).expect("H2C can't fail here");

		let signature =
			RingVrfSignature::deserialize_compressed(proof.as_slice()).map_err(|_| ())?;

		bandersnatch::Public::verify(
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
		let input = bandersnatch::Input::new(&input_msg[..]).expect("H2C can't fail here");
		let output = secret.output(input);

		let proof = secret.prove(input, output, b"");
		let signature = IetfVrfSignature { output, proof };

		let mut raw = [0u8; PLAIN_VRF_SIGNATURE_SIZE];
		signature
			.serialize_compressed(raw.as_mut_slice())
			.map_err(|_| ())?;
		Ok(raw)
	}

	fn verify_signature(
		signature: &Self::Signature,
		message: &[u8],
		member: &Self::Member,
	) -> bool {
		use ark_vrf::ietf::Verifier;
		let Ok(signature) = IetfVrfSignature::deserialize_compressed(signature.as_slice()) else {
			return false;
		};
		let input_msg = [VRF_INPUT_DOMAIN, message].concat();
		let input = bandersnatch::Input::new(&input_msg[..]).expect("H2C can't fail here");
		let Ok(member) = Self::to_public_key(member) else {
			return false;
		};
		let public = bandersnatch::Public::from(member.0);
		public
			.verify(input, signature.output, b"", &signature.proof)
			.is_ok()
	}

	#[cfg(any(feature = "std", feature = "no-std-prover"))]
	fn open(
		capacity: RingDomainSize,
		member: &Self::Member,
		members: impl Iterator<Item = Self::Member>,
	) -> Result<Self::Commitment, ()> {
		let pks = members
			.map(|m| Self::to_public_key(&m).map(|pk| pk.0))
			.collect::<Result<Vec<_>, _>>()?;
		let member = Self::to_public_key(member)?;
		let member_idx = pks.iter().position(|&m| m == member.0).ok_or(())?;
		let member_idx = member_idx as u32;
		let prover_key = ring_prover_params(capacity).prover_key(&pks[..]);
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
		let (domain_size, prover_idx, prover_key) = commitment;
		let params = ring_prover_params(domain_size);
		if prover_idx >= params.max_ring_size() as u32 {
			return Err(());
		}

		let ring_prover = params.prover(prover_key.0, prover_idx as usize);

		let input_msg = [VRF_INPUT_DOMAIN, context].concat();
		let input = bandersnatch::Input::new(&input_msg[..]).expect("H2C can't fail here");
		let preout = secret.output(input);
		let alias = make_alias(&preout);

		let proof = secret.prove(input, preout, message, &ring_prover);

		let signature = RingVrfSignature {
			output: preout,
			proof,
		};

		let mut buf = [0u8; RING_VRF_SIGNATURE_SIZE];
		signature
			.serialize_compressed(buf.as_mut_slice())
			.map_err(|_| ())?;

		Ok((buf, alias))
	}

	fn alias_in_context(secret: &Self::Secret, context: &[u8]) -> Result<Alias, ()> {
		let input_msg = [VRF_INPUT_DOMAIN, context].concat();
		let input = bandersnatch::Input::new(&input_msg[..]).expect("H2C can't fail here");
		let output = secret.output(input);
		let alias = make_alias(&output);
		Ok(alias)
	}

	fn is_member_valid(member: &Self::Member) -> bool {
		Self::to_public_key(member).is_ok()
	}
}

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
		let invalid_member = EncodedPublicKey([0; 32]);
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

		for domain_size in RingDomainSize::ALL {
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
		let builder = BandersnatchVrfVerifiable::start_members(domain_size);
		let builder_params = ring_verifier_builder_params(domain_size);
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
		let secret = BandersnatchVrfVerifiable::new_secret([0u8; 32]);
		let public = BandersnatchVrfVerifiable::member_from_secret(&secret);
		let internal = BandersnatchVrfVerifiable::to_public_key(&public).unwrap();
		assert_eq!(internal.compressed_size(), PublicKey::max_encoded_len());

		let members = BandersnatchVrfVerifiable::start_members(domain_size);
		assert_eq!(members.compressed_size(), MembersSet::max_encoded_len());

		let commitment = BandersnatchVrfVerifiable::finish_members(members);
		assert_eq!(
			commitment.compressed_size(),
			MembersCommitment::max_encoded_len()
		);
	});

	test_for_all_domains!(start_push_finish, |domain_size| {
		let alice_sec = BandersnatchVrfVerifiable::new_secret([0u8; 32]);
		let bob_sec = BandersnatchVrfVerifiable::new_secret([1u8; 32]);
		let charlie_sec = BandersnatchVrfVerifiable::new_secret([2u8; 32]);

		let alice = BandersnatchVrfVerifiable::member_from_secret(&alice_sec);
		let bob = BandersnatchVrfVerifiable::member_from_secret(&bob_sec);
		let charlie = BandersnatchVrfVerifiable::member_from_secret(&charlie_sec);

		let mut inter1 = BandersnatchVrfVerifiable::start_members(domain_size);
		let mut inter2 = inter1.clone();
		let builder_params = ring_verifier_builder_params(domain_size);

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
		let alice_sec = BandersnatchVrfVerifiable::new_secret([0u8; 32]);
		let bob_sec = BandersnatchVrfVerifiable::new_secret([1u8; 32]);
		let charlie_sec = BandersnatchVrfVerifiable::new_secret([2u8; 32]);

		let alice = BandersnatchVrfVerifiable::member_from_secret(&alice_sec);
		let bob = BandersnatchVrfVerifiable::member_from_secret(&bob_sec);
		let charlie = BandersnatchVrfVerifiable::member_from_secret(&charlie_sec);

		// First set is everyone all at once with the regular starting root.
		let mut inter1 = BandersnatchVrfVerifiable::start_members(domain_size);
		// Second set is everyone all at once but with a starting root constructed from params.
		let (mut inter2, builder_params) = start_members_from_params(domain_size);

		let get_many = |range| {
			(&builder_params)
				.lookup(range)
				.map(|v| v.into_iter().map(|i| StaticChunk(i)).collect::<Vec<_>>())
				.ok_or(())
		};

		// Third set is everyone added one by one.
		let mut inter3 = BandersnatchVrfVerifiable::start_members(domain_size);
		// Fourth set is a single addition followed by a group addition.
		let mut inter4 = BandersnatchVrfVerifiable::start_members(domain_size);

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
			BandersnatchVrfVerifiable::open(domain_size, &member, members.clone().into_iter())
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
		let mut inter = BandersnatchVrfVerifiable::start_members(domain_size);
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
			BandersnatchVrfVerifiable::validate(domain_size, &proof, &members, context, message)
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

		let start = Instant::now();
		let _ = ring_prover_params(domain_size);
		println!("* KZG decode: {} ms", (Instant::now() - start).as_millis());

		// Use the domain's max ring size to test at capacity
		let max_members = domain_size.size();
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

		let mut inter1 = BandersnatchVrfVerifiable::start_members(domain_size);
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

		let mut inter2 = BandersnatchVrfVerifiable::start_members(domain_size);
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
