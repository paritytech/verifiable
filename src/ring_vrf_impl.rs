use alloc::vec;
use core::ops::Range;

pub use ark_vrf;

use ark_scale::ArkScale;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_vrf::{
	ring::Verifier,
	suites::bandersnatch::{self, BandersnatchSha512Ell2},
};
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

pub trait RingParams {
	const MAX_RING_SIZE: usize;
	const RING_BUILDER_PARAMS: &[u8];
	const EMPTY_RING_COMMITMENT_DATA: &[u8];
	
	fn ring_prover_params() -> &'static bandersnatch::RingProofParams;

	fn decode_psc_params() -> bandersnatch::RingProofParams {
		let pcs_params =
				bandersnatch::PcsParams::deserialize_uncompressed_unchecked(VERIFIABLE_SRS_RAW)
					.unwrap();
			bandersnatch::RingProofParams::from_pcs_params(Self::MAX_RING_SIZE, pcs_params).unwrap()
	}

	fn ring_verifier_builder_params() -> RingBuilderParams {
		use ark_vrf::ring::G1Affine;
		let inner = <Vec<G1Affine<BandersnatchSha512Ell2>>>::deserialize_uncompressed_unchecked(
			Self::RING_BUILDER_PARAMS,
		)
		.unwrap();
		ark_vrf::ring::RingBuilderPcsParams::<BandersnatchSha512Ell2>(inner)
	}
}

pub struct SmallRingParams;
impl RingParams for SmallRingParams {
	const MAX_RING_SIZE: usize = max_ring_size_from_pcs_domain_size(1 << 11);
	const RING_BUILDER_PARAMS: &[u8] = include_bytes!("ring-data/ring-builder-params-small.bin");
	const EMPTY_RING_COMMITMENT_DATA: &[u8] = include_bytes!("ring-data/ring-builder-small.bin");

	fn ring_prover_params() -> &'static bandersnatch::RingProofParams {
		use spin::Once;
		static CELL: Once<bandersnatch::RingProofParams> = Once::new();
		CELL.call_once(Self::decode_psc_params)
	}
}

pub struct FullRingParams;
impl RingParams for FullRingParams {
	const MAX_RING_SIZE: usize = max_ring_size_from_pcs_domain_size(1 << 16);
	const RING_BUILDER_PARAMS: &[u8] = include_bytes!("ring-data/ring-builder-params-full.bin");
	const EMPTY_RING_COMMITMENT_DATA: &[u8] = include_bytes!("ring-data/ring-builder-full.bin");

	fn ring_prover_params() -> &'static bandersnatch::RingProofParams {
		use spin::Once;
		static CELL: Once<bandersnatch::RingProofParams> = Once::new();
		CELL.call_once(Self::decode_psc_params)
	}
}

const VRF_INPUT_DOMAIN: &[u8] = b"VerifiableBandersnatchVrfInput";

/// A sequence of static chunks.
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

pub struct BandersnatchVrfVerifiable<R>(pub ::core::marker::PhantomData<R>);

impl<R: RingParams> BandersnatchVrfVerifiable<R> {
	fn to_public_key(
		value: &EncodedPublicKey,
	) -> Result<PublicKey, ()> {
		let pt =
			bandersnatch::AffinePoint::deserialize_compressed(&value.0[..]).map_err(|_| ())?;
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

impl<R: RingParams> GenerateVerifiable for BandersnatchVrfVerifiable<R> {
	type Members = MembersCommitment;
	type Intermediate = MembersSet;
	type Member = EncodedPublicKey;
	type Secret = bandersnatch::Secret;
	type Commitment = (u32, ArkScale<bandersnatch::RingProverKey>);
	type Proof = [u8; RING_VRF_SIGNATURE_SIZE];
	type Signature = [u8; PLAIN_VRF_SIGNATURE_SIZE];
	type StaticChunk = StaticChunk;

	fn start_members() -> Self::Intermediate {
		MembersSet::deserialize_uncompressed_unchecked(R::EMPTY_RING_COMMITMENT_DATA).unwrap()
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
		proof: &Self::Proof,
		members: &Self::Members,
		context: &[u8],
		message: &[u8],
	) -> Result<Alias, ()> {
		// This doesn't require the whole kzg. Thus is more appropriate if used on-chain
		// Is a bit slower as it requires to recompute piop_params, but still in the order of ms
		let ring_verifier =
			bandersnatch::RingProofParams::verifier_no_context(members.0.clone(), R::MAX_RING_SIZE);

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
		member: &Self::Member,
		members: impl Iterator<Item = Self::Member>,
	) -> Result<Self::Commitment, ()> {
		let pks = members
			.map(|m| Self::to_public_key(&m).map(|pk| pk.0))
			.collect::<Result<Vec<_>, _>>()?;
		let member = Self::to_public_key(member)?;
		let member_idx = pks.iter().position(|&m| m == member.0).ok_or(())?;
		let member_idx = member_idx as u32;
		let prover_key = R::ring_prover_params().prover_key(&pks[..]);
		Ok((member_idx, prover_key.into()))
	}

	#[cfg(not(any(feature = "std", feature = "no-std-prover")))]
	fn open(
		_member: &Self::Member,
		_members: impl Iterator<Item = Self::Member>,
	) -> Result<Self::Commitment, ()> {
		panic!("not implemented: requires `std` or `no-std-prover`")
	}

	#[cfg(any(feature = "std", feature = "no-std-prover"))]
	fn create(
		commitment: Self::Commitment,
		secret: &Self::Secret,
		context: &[u8],
		message: &[u8],
	) -> Result<(Self::Proof, Alias), ()> {
		use ark_vrf::ring::Prover;
		let (prover_idx, prover_key) = commitment;
		let params = R::ring_prover_params();
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

	#[cfg(not(any(feature = "std", feature = "no-std-prover")))]
	fn create(
		_commitment: Self::Commitment,
		_secret: &Self::Secret,
		_context: &[u8],
		_message: &[u8],
	) -> Result<(Self::Proof, Alias), ()> {
		panic!("not implemented: requires `std` or `no-std-prover`")
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
	use ark_vrf::{ring::SrsLookup, suites::bandersnatch::BandersnatchSha512Ell2};

	type RingBuilderPcsParams = ark_vrf::ring::RingBuilderPcsParams<BandersnatchSha512Ell2>;

	fn start_members_from_params<R: RingParams>() -> (MembersSet, RingBuilderPcsParams) {
		let (builder, builder_pcs_params) = R::ring_prover_params().verifier_key_builder();
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

		let full_params = SmallRingParams::ring_prover_params();

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

	// This is used to generate parameters.
	// Run only if there are some breaking changes in the backend crypto and binaries
	// need to be re-generated.
	#[test]
	#[ignore = "ring builder generator"]
	fn generate_empty_ring_builder() {
		use std::io::Write;
		#[cfg(feature = "small-ring")]
		const RING_BUILDER_FILE: &str = concat!(
			env!("CARGO_MANIFEST_DIR"),
			"/src/ring-data/ring-builder-small.bin"
		);
		#[cfg(not(feature = "small-ring"))]
		const RING_BUILDER_FILE: &str = concat!(
			env!("CARGO_MANIFEST_DIR"),
			"/src/ring-data/ring-builder-full.bin"
		);

		#[cfg(feature = "small-ring")]
		const RING_BUILDER_PARAMS_FILE: &str = concat!(
			env!("CARGO_MANIFEST_DIR"),
			"/src/ring-data/ring-builder-params-small.bin"
		);
		#[cfg(not(feature = "small-ring"))]
		const RING_BUILDER_PARAMS_FILE: &str = concat!(
			env!("CARGO_MANIFEST_DIR"),
			"/src/ring-data/ring-builder-params-full.bin"
		);

		let (builder, builder_params) = start_members_from_params::<SmallRingParams>();

		let mut buf = Vec::with_capacity(builder.uncompressed_size());
		builder.serialize_uncompressed(&mut buf).unwrap();
		println!("Writing empty ring builder to: {}", RING_BUILDER_FILE);
		let mut file = std::fs::File::create(RING_BUILDER_FILE).unwrap(); // Create or truncate the file
		file.write_all(&buf).unwrap();

		let mut buf = Vec::with_capacity(builder_params.0.uncompressed_size());
		builder_params.0.serialize_uncompressed(&mut buf).unwrap();
		println!("G1 len: {}", builder_params.0.len());
		println!(
			"Writing ring builder params to: {}",
			RING_BUILDER_PARAMS_FILE
		);
		let mut file = std::fs::File::create(RING_BUILDER_PARAMS_FILE).unwrap(); // Create or truncate the file
		file.write_all(&buf).unwrap();
	}

	#[test]
	fn check_pre_constructed_ring_builder_small() {
		check_pre_constructed_ring_builder::<SmallRingParams>();
	}

	#[test]
	fn check_pre_constructed_ring_builder_full() {
		check_pre_constructed_ring_builder::<FullRingParams>();
	}

	fn check_pre_constructed_ring_builder<R: RingParams>() {
		let builder = BandersnatchVrfVerifiable::<R>::start_members();
		let builder_params = R::ring_verifier_builder_params();
		let (builder2, builder_params2) = start_members_from_params::<R>();

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
	}

	#[test]
	fn check_precomputed_size_small() {
		check_precomputed_size::<SmallRingParams>();
	}

	#[test]
	fn check_precomputed_size_full() {
		check_precomputed_size::<FullRingParams>();
	}
	fn check_precomputed_size<R: RingParams>() {
		let secret = BandersnatchVrfVerifiable::<R>::new_secret([0u8; 32]);
		let public = BandersnatchVrfVerifiable::<R>::member_from_secret(&secret);
		let internal = BandersnatchVrfVerifiable::<R>::to_public_key(&public).unwrap();
		assert_eq!(internal.compressed_size(), PublicKey::max_encoded_len());

		let members = BandersnatchVrfVerifiable::<R>::start_members();
		assert_eq!(members.compressed_size(), MembersSet::max_encoded_len());

		let commitment = BandersnatchVrfVerifiable::<R>::finish_members(members);
		assert_eq!(
			commitment.compressed_size(),
			MembersCommitment::max_encoded_len()
		);
	}

	#[test]
	fn start_push_finish_small() {
		start_push_finish::<SmallRingParams>();
	}

	#[test]
	fn start_push_finish_full() {
		start_push_finish::<FullRingParams>();
	}
	fn start_push_finish<R: RingParams>() {
		let alice_sec = BandersnatchVrfVerifiable::<R>::new_secret([0u8; 32]);
		let bob_sec = BandersnatchVrfVerifiable::<R>::new_secret([1u8; 32]);
		let charlie_sec = BandersnatchVrfVerifiable::<R>::new_secret([2u8; 32]);

		let alice = BandersnatchVrfVerifiable::<R>::member_from_secret(&alice_sec);
		let bob = BandersnatchVrfVerifiable::<R>::member_from_secret(&bob_sec);
		let charlie = BandersnatchVrfVerifiable::<R>::member_from_secret(&charlie_sec);

		let mut inter1 = BandersnatchVrfVerifiable::<R>::start_members();
		let mut inter2 = inter1.clone();
		let builder_params = R::ring_verifier_builder_params();

		let get_many = |range| {
			(&builder_params)
				.lookup(range)
				.map(|v| v.into_iter().map(|i| StaticChunk(i)).collect::<Vec<_>>())
				.ok_or(())
		};

		BandersnatchVrfVerifiable::<R>::push_members(
			&mut inter1,
			[alice.clone(), bob.clone(), charlie.clone()].into_iter(),
			get_many,
		)
		.unwrap();
		BandersnatchVrfVerifiable::<R>::push_members(&mut inter2, [alice.clone()].into_iter(), get_many)
			.unwrap();
		BandersnatchVrfVerifiable::<R>::push_members(&mut inter2, [bob.clone()].into_iter(), get_many)
			.unwrap();
		BandersnatchVrfVerifiable::<R>::push_members(
			&mut inter2,
			[charlie.clone()].into_iter(),
			get_many,
		)
		.unwrap();
		assert_eq!(inter1, inter2);

		let members1 = BandersnatchVrfVerifiable::<R>::finish_members(inter1);
		let members2 = BandersnatchVrfVerifiable::<R>::finish_members(inter2);
		assert_eq!(members1, members2);
	}

	#[test]
	fn start_push_finish_multiple_members_small() {
		start_push_finish_multiple_members::<SmallRingParams>();
	}

	#[test]
	fn start_push_finish_multiple_members_full() {
		start_push_finish_multiple_members::<FullRingParams>();
	}
	fn start_push_finish_multiple_members<R: RingParams>() {
		let alice_sec = BandersnatchVrfVerifiable::<R>::new_secret([0u8; 32]);
		let bob_sec = BandersnatchVrfVerifiable::<R>::new_secret([1u8; 32]);
		let charlie_sec = BandersnatchVrfVerifiable::<R>::new_secret([2u8; 32]);

		let alice = BandersnatchVrfVerifiable::<R>::member_from_secret(&alice_sec);
		let bob = BandersnatchVrfVerifiable::<R>::member_from_secret(&bob_sec);
		let charlie = BandersnatchVrfVerifiable::<R>::member_from_secret(&charlie_sec);

		// First set is everyone all at once with the regular starting root.
		let mut inter1 = BandersnatchVrfVerifiable::<R>::start_members();
		// Second set is everyone all at once but with a starting root constructed from params.
		let (mut inter2, builder_params) = start_members_from_params::<R>();

		let get_many = |range| {
			(&builder_params)
				.lookup(range)
				.map(|v| v.into_iter().map(|i| StaticChunk(i)).collect::<Vec<_>>())
				.ok_or(())
		};

		// Third set is everyone added one by one.
		let mut inter3 = BandersnatchVrfVerifiable::<R>::start_members();
		// Fourth set is a single addition followed by a group addition.
		let mut inter4 = BandersnatchVrfVerifiable::<R>::start_members();

		// Construct the first set with all members added simultaneously.
		BandersnatchVrfVerifiable::<R>::push_members(
			&mut inter1,
			[alice.clone(), bob.clone(), charlie.clone()].into_iter(),
			get_many,
		)
		.unwrap();

		// Construct the second set with all members added simultaneously.
		BandersnatchVrfVerifiable::<R>::push_members(
			&mut inter2,
			[alice.clone(), bob.clone(), charlie.clone()].into_iter(),
			get_many,
		)
		.unwrap();

		// Construct the third set with all members added sequentially.
		BandersnatchVrfVerifiable::<R>::push_members(&mut inter3, [alice.clone()].into_iter(), get_many)
			.unwrap();
		BandersnatchVrfVerifiable::<R>::push_members(&mut inter3, [bob.clone()].into_iter(), get_many)
			.unwrap();
		BandersnatchVrfVerifiable::<R>::push_members(
			&mut inter3,
			[charlie.clone()].into_iter(),
			get_many,
		)
		.unwrap();

		// Construct the fourth set with the first member joining alone, followed by the other members joining together.
		BandersnatchVrfVerifiable::<R>::push_members(&mut inter4, [alice.clone()].into_iter(), get_many)
			.unwrap();
		BandersnatchVrfVerifiable::<R>::push_members(
			&mut inter4,
			[bob.clone(), charlie.clone()].into_iter(),
			get_many,
		)
		.unwrap();

		assert_eq!(inter1, inter2);
		assert_eq!(inter2, inter3);
		assert_eq!(inter3, inter4);

		let members1 = BandersnatchVrfVerifiable::<R>::finish_members(inter1);
		let members2 = BandersnatchVrfVerifiable::<R>::finish_members(inter2);
		let members3 = BandersnatchVrfVerifiable::<R>::finish_members(inter3);
		let members4 = BandersnatchVrfVerifiable::<R>::finish_members(inter4);
		assert_eq!(members1, members2);
		assert_eq!(members2, members3);
		assert_eq!(members3, members4);
	}

	#[test]
	fn test_plain_signature_small() {
		test_plain_signature::<SmallRingParams>();
	}

	#[test]
	fn test_plain_signature_full() {
		test_plain_signature::<FullRingParams>();
	}

	fn test_plain_signature<R: RingParams>() {
		let msg = b"asd";
		let secret = BandersnatchVrfVerifiable::<R>::new_secret([0; 32]);
		let public = BandersnatchVrfVerifiable::<R>::member_from_secret(&secret);
		let signature = BandersnatchVrfVerifiable::<R>::sign(&secret, msg).unwrap();
		let res = BandersnatchVrfVerifiable::<R>::verify_signature(&signature, msg, &public);
		assert!(res);
	}

	#[test]
	fn open_validate_works_small() {
		open_validate_works::<SmallRingParams>();
	}

	#[test]
	fn open_validate_works_full() {
		open_validate_works::<FullRingParams>();
	}

	fn open_validate_works<R: RingParams>() {
		use std::time::Instant;

		let context = b"Context";
		let message = b"FooBar";

		timed("PCS params decode", 1000, || {
			R::decode_psc_params()
		});
		R::ring_prover_params();  // init once cell

		let members: Vec<_> = (0..10)
			.map(|i| {
				let secret = BandersnatchVrfVerifiable::<R>::new_secret([i as u8; 32]);
				BandersnatchVrfVerifiable::<R>::member_from_secret(&secret)
			})
			.collect();
		let member = members[3].clone();

		let commitment = timed("Open", 10, || {
			BandersnatchVrfVerifiable::<R>::open(&member, members.clone().into_iter()).unwrap()
		});
		println!("  Commitment size: {} bytes", commitment.encoded_size());

		let encoded_commitment = timed("Commitment encode", 100, || {
			commitment.encode()
		});

		timed("Commitment decode", 5, || {
			<BandersnatchVrfVerifiable::<R> as GenerateVerifiable>::Commitment::decode(&mut &encoded_commitment.clone()[..]).unwrap()
		});

		let secret = BandersnatchVrfVerifiable::<R>::new_secret([commitment.0 as u8; 32]);
		let start = Instant::now();

		let (proof, alias) = BandersnatchVrfVerifiable::<R>::create(commitment, &secret, context, message).unwrap();
		println!("* Create: {} ms", (Instant::now() - start).as_millis());
		println!("  Proof size: {} bytes", proof.encode().len()); // 788 bytes

		// `builder_params` can be serialized/deserialized to be loaded when required
		let (_, builder_params) = start_members_from_params::<R>();

		let get_many = |range| {
			(&builder_params)
				.lookup(range)
				.map(|v| v.into_iter().map(|i| StaticChunk(i)).collect::<Vec<_>>())
				.ok_or(())
		};

		let inter = timed("Start members", 1000, || {
			BandersnatchVrfVerifiable::<R>::start_members()
		});

		let inter = timed("Push members", 1000, || {
			let mut inter = inter.clone();

			members.iter().for_each(|member| {
				BandersnatchVrfVerifiable::<R>::push_members(
					&mut inter,
					[member.clone()].into_iter(),
					get_many,
				)
				.unwrap();
			});
			
			inter
		});

		let members = timed("Finish members", 100, || {
			BandersnatchVrfVerifiable::<R>::finish_members(inter.clone())
		});

		timed("Validate", 100, || {
			let alias2 =
				BandersnatchVrfVerifiable::<R>::validate(&proof, &members, context, message).unwrap();
			assert_eq!(alias, alias2);
		});
		
		timed("Alias", 1000, || {
			let alias3 = BandersnatchVrfVerifiable::<R>::alias_in_context(&secret, context).unwrap();
			assert_eq!(alias, alias3);
		});
	}

	fn timed<T>(name: &str, n: u32, mut f: impl FnMut() -> T) -> T {
		let start = std::time::Instant::now();
		for _ in 0..(n - 1) {
			f();
		}
		let last = f();
		let elapsed = start.elapsed() / n;
		println!("* {} ({} reps): {} ms", name, n, elapsed.as_millis());

		last
	}

	#[test]
	fn open_validate_single_vs_multiple_keys_small() {
		open_validate_single_vs_multiple_keys::<SmallRingParams>();
	}

	#[test]
	fn open_validate_single_vs_multiple_keys_full() {
		open_validate_single_vs_multiple_keys::<FullRingParams>();
	}

	fn open_validate_single_vs_multiple_keys<R: RingParams>() {
		use std::time::Instant;
		let _ = R::ring_prover_params(); // init once cell

		let members: Vec<_> = (0..255)
			.map(|i| {
				let secret = BandersnatchVrfVerifiable::<R>::new_secret([i as u8; 32]);
				BandersnatchVrfVerifiable::<R>::member_from_secret(&secret)
			})
			.collect();

		// `builder_params` can be serialized/deserialized to be loaded when required
		let (_, builder_params) = start_members_from_params::<R>();

		let get_many = |range| {
			(&builder_params)
				.lookup(range)
				.map(|v| v.into_iter().map(|i| StaticChunk(i)).collect::<Vec<_>>())
				.ok_or(())
		};

		let mut inter1 = BandersnatchVrfVerifiable::<R>::start_members();
		let start = Instant::now();
		members.iter().for_each(|member| {
			BandersnatchVrfVerifiable::<R>::push_members(
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

		let mut inter2 = BandersnatchVrfVerifiable::<R>::start_members();
		let start = Instant::now();

		BandersnatchVrfVerifiable::<R>::push_members(&mut inter2, members.iter().cloned(), get_many)
			.unwrap();
		println!(
			"* Push {} members simultaneously: {} ms",
			members.len(),
			(Instant::now() - start).as_millis()
		);

		assert_eq!(inter1, inter2);
	}

	#[test]
	fn test_is_member_valid_invalid() {
		let invalid_member = EncodedPublicKey([0; 32]);

		assert!(!BandersnatchVrfVerifiable::<SmallRingParams>::is_member_valid(&invalid_member));
		assert!(!BandersnatchVrfVerifiable::<FullRingParams>::is_member_valid(&invalid_member));
	}

	#[test]
	fn test_is_member_valid_valid_small() {
		test_is_member_valid_valid::<SmallRingParams>();
	}

	#[test]
	fn test_is_member_valid_valid_full() {
		test_is_member_valid_valid::<FullRingParams>();
	}

	fn test_is_member_valid_valid<R: RingParams>() {
		let secret = BandersnatchVrfVerifiable::<R>::new_secret([42u8; 32]);
		let valid_member = BandersnatchVrfVerifiable::<R>::member_from_secret(&secret);
		assert!(BandersnatchVrfVerifiable::<R>::is_member_valid(&valid_member));
	}
}


/*

* PCS params decode: 27 ms
* Open: 71 ms
  Commitment size: 12322611 bytes
* Create: 242 ms
  Proof size: 788 bytes
* Start members: 0 ms
* Push 10 members: 5 ms
* Finish members: 0 ms
* Validate: 11 ms
* Alias: 0 ms


*/
