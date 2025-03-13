#![allow(unused)]

use alloc::vec;
use core::ops::Range;

use ark_ec_vrfs::{ring::Verifier, suites::bandersnatch};
use ark_scale::{impl_scale_via_ark, ArkScale, ArkScaleMaxEncodedLen};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

use super::*;

#[cfg(feature = "small-ring")]
mod domain_params {
	use super::*;
	pub const DOMAIN_SIZE: usize = 1 << 9;
	pub const RING_SIZE: usize = 255; // TODO
	#[cfg(feature = "std")]
	pub(crate) const OFFCHAIN_PK: &[u8] = include_bytes!("ring-data/zcash-9.pk");
}

#[cfg(not(feature = "small-ring"))]
mod domain_params {
	use super::*;
	pub const DOMAIN_SIZE: usize = 1 << 16;
	pub const RING_SIZE: usize = 255; // TODO
	#[cfg(feature = "std")]
	pub(crate) const OFFCHAIN_PK: &[u8] = include_bytes!("ring-data/zcash-16.pk");
}

pub use domain_params::*;

const VRF_INPUT_DOMAIN: &[u8] = b"VerifiableBandersnatchInput";
const THIN_SIGNATURE_CONTEXT: &[u8] = b"VerifiableBandersnatchThinSignature";

#[cfg(feature = "std")]
fn ring_context() -> &'static bandersnatch::RingContext {
	use ark_ec_vrfs::ring::PcsParams;
	use std::sync::OnceLock;
	static CELL: OnceLock<bandersnatch::RingContext> = OnceLock::new();
	CELL.get_or_init(|| {
		let pcs_params =
			bandersnatch::PcsParams::deserialize_uncompressed_unchecked(OFFCHAIN_PK).unwrap();
		bandersnatch::RingContext::from_srs(RING_SIZE, pcs_params).unwrap()
	})
}

#[derive(Clone, CanonicalDeserialize, CanonicalSerialize)]
pub struct MembersSet {
	inner: bandersnatch::RingVerifierKeyBuilder,
}

ark_scale::impl_scale_via_ark!(MembersSet);

// TODO: check
const MEMBERS_SET_SIZE: usize = 4 * 48 + 2 * 96 + 32 + 2 * 4; // 4 bls G1 + 2 bls G2 + jubjub + 2 usize

impl scale_info::TypeInfo for MembersSet {
	type Identity = [u8; MEMBERS_SET_SIZE];

	fn type_info() -> Type {
		Self::Identity::type_info()
	}
}

impl MaxEncodedLen for MembersSet {
	fn max_encoded_len() -> usize {
		MEMBERS_SET_SIZE
	}
}

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

ark_scale::impl_scale_via_ark!(MembersCommitment);

// TODO: check
const MEMBERS_COMMITMENT_SIZE: usize = 4 * 48 + 2 * 96; // 4 bls G1 + 2 bls G2

impl scale_info::TypeInfo for MembersCommitment {
	type Identity = [u8; MEMBERS_COMMITMENT_SIZE];

	fn type_info() -> Type {
		Self::Identity::type_info()
	}
}

impl MaxEncodedLen for MembersCommitment {
	fn max_encoded_len() -> usize {
		MEMBERS_COMMITMENT_SIZE
	}
}

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

pub struct BandersnatchVrfVerifiable;

// impl BandersnatchVrfVerifiable {
// 	pub fn start_members_from_params(
// 		vk: KzgVk,
// 		srs: impl Fn(Range<usize>) -> Result<Vec<bls12_381::G1Affine>, ()>,
// 	) -> MembersSet {
// 		let piop_params = bandersnatch_vrfs::ring::make_piop_params(DOMAIN_SIZE);
// 		let ring = RingCommitment::empty(&piop_params, srs, vk.g1.into());
// 		MembersSet {
// 			ring,
// 			kzg_raw_vk: vk,
// 		}
// 	}
// }

const PUBLIC_KEY_LENGTH: usize = 32;

#[derive(
	Clone, Eq, PartialEq, Debug, Encode, Decode, TypeInfo, MaxEncodedLen, DecodeWithMemTracking,
)]
pub struct EncodedPublicKey(pub [u8; PUBLIC_KEY_LENGTH]);

#[derive(Clone, Eq, PartialEq, Debug, Encode, Decode)]
pub struct InternalPublicKey(ArkScale<bandersnatch::AffinePoint>);

impl MaxEncodedLen for InternalPublicKey {
	fn max_encoded_len() -> usize {
		PUBLIC_KEY_LENGTH
	}
}

#[derive(Clone, Eq, PartialEq, Debug, Encode, Decode)]
pub struct StaticChunkImpl(
	ArkScale<ark_ec_vrfs::ring::G1Affine<bandersnatch::BandersnatchSha512Ell2>>,
);

const G1_POINT_LENGTH: usize = 48;

impl MaxEncodedLen for StaticChunkImpl {
	fn max_encoded_len() -> usize {
		G1_POINT_LENGTH
	}
}

impl scale_info::TypeInfo for StaticChunkImpl {
	type Identity = [u8; G1_POINT_LENGTH];

	fn type_info() -> Type {
		Self::Identity::type_info()
	}
}

const IETF_SIGNATURE_SIZE: usize = 96;

#[derive(CanonicalSerialize, CanonicalDeserialize)]
struct IetfVrfSignature {
	output: bandersnatch::Output,
	proof: bandersnatch::IetfProof,
}

const RING_SIGNATURE_SIZE: usize = 788;

#[derive(CanonicalSerialize, CanonicalDeserialize)]
struct RingVrfSignature {
	output: bandersnatch::Output,
	proof: bandersnatch::RingProof,
}

fn make_alias(output: &bandersnatch::Output) -> Alias {
	Alias::try_from(&output.hash()[..32]).expect("Bandersnatch suite hash is 64 bytes")
}

impl GenerateVerifiable for BandersnatchVrfVerifiable {
	type Members = MembersCommitment;
	type Intermediate = MembersSet;
	type Member = EncodedPublicKey;
	type InternalMember = InternalPublicKey;
	type Secret = bandersnatch::Secret;
	type Commitment = (u32, ArkScale<bandersnatch::RingProverKey>);
	type Proof = [u8; RING_SIGNATURE_SIZE];
	type Signature = [u8; IETF_SIGNATURE_SIZE];
	type StaticChunk = StaticChunkImpl;

	fn start_members() -> Self::Intermediate {
		// TODO: load a pre-constructed empty ring key builder.
		// Get it by serializing inner.
		let ctx = ring_context();
		let (inner, _loader) = ctx.verifier_key_builder();
		MembersSet { inner }
	}

	fn push_member(
		intermediate: &mut Self::Intermediate,
		who: Self::Member,
		lookup: impl Fn(usize) -> Result<Self::StaticChunk, ()>,
	) -> Result<(), ()> {
		let who: Self::InternalMember = Self::internal_member(&who);
		let loader = |range: Range<usize>| {
			let item = lookup(range.start).ok()?.0 .0;
			Some(vec![item])
		};
		intermediate.inner.append(&[who.0 .0], loader);
		Ok(())
	}

	fn finish_members(intermediate: Self::Intermediate) -> Self::Members {
		let verifier_key = intermediate.inner.finalize();
		MembersCommitment(verifier_key)
	}

	fn new_secret(entropy: Entropy) -> Self::Secret {
		Self::Secret::from_seed(&entropy)
	}

	fn member_from_secret(secret: &Self::Secret) -> Self::Member {
		Self::external_member(&InternalPublicKey(ArkScale(secret.public().0)))
	}

	fn validate(
		proof: &Self::Proof,
		members: &Self::Members,
		context: &[u8],
		message: &[u8],
	) -> Result<Alias, ()> {
		use ark_ec_vrfs::ring::Prover;
		// This doesn't require the whole kzg. Thus is more appropriate if used on-chain
		// Is a bit slower as it requires to recompute piop_params, but still in the order of ms
		let ring_verifier =
			bandersnatch::RingContext::verifier_no_context(members.0.clone(), DOMAIN_SIZE);

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

		let alias = make_alias(&signature.output);
		Ok(alias)
	}

	// TODO: implement a plain Schnorr signature for Bandersnatch
	fn sign(secret: &Self::Secret, message: &[u8]) -> Result<Self::Signature, ()> {
		use ark_ec_vrfs::ietf::Prover;
		// let mut transcript = Transcript::new_labeled(THIN_SIGNATURE_CONTEXT);
		// transcript.append_slice(message);
		let input_msg = [THIN_SIGNATURE_CONTEXT, message].concat();
		let input = bandersnatch::Input::new(&input_msg[..]).expect("H2C can't fail here");
		let output = secret.output(input);

		let proof = secret.prove(input, output, b"");

		let signature = IetfVrfSignature { output, proof };

		let mut raw = [0u8; IETF_SIGNATURE_SIZE];
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
		use ark_ec_vrfs::ietf::Verifier;
		let signature = IetfVrfSignature::deserialize_compressed(signature.as_slice()).unwrap();
		let input_msg = [THIN_SIGNATURE_CONTEXT, message].concat();
		let input = bandersnatch::Input::new(&input_msg[..]).expect("H2C can't fail here");
		let member = Self::internal_member(member);
		let public = bandersnatch::Public::from(member.0 .0);
		public
			.verify(input, signature.output, b"", &signature.proof)
			.is_ok()
	}

	#[cfg(feature = "std")]
	fn open(
		member: &Self::Member,
		members: impl Iterator<Item = Self::Member>,
	) -> Result<Self::Commitment, ()> {
		let pks = members
			.map(|m| Self::internal_member(&m).0 .0)
			.collect::<Vec<_>>();
		let member: Self::InternalMember = Self::internal_member(member);
		let member_idx = pks.iter().position(|&m| m == member.0 .0).ok_or(())?;
		let member_idx = member_idx as u32;
		let prover_key = ring_context().prover_key(&pks[..]);
		Ok((member_idx, prover_key.into()))
	}

	#[cfg(not(feature = "std"))]
	fn open(
		_member: &Self::Member,
		_members: impl Iterator<Item = Self::Member>,
	) -> Result<Self::Commitment, ()> {
		panic!("Not implemented")
	}

	#[cfg(feature = "std")]
	fn create(
		commitment: Self::Commitment,
		secret: &Self::Secret,
		context: &[u8],
		message: &[u8],
	) -> Result<(Self::Proof, Alias), ()> {
		use ark_ec_vrfs::ring::Prover;
		let (prover_idx, prover_key) = commitment;
		let ctx = ring_context();
		if prover_idx >= ctx.max_ring_size() as u32 {
			return Err(());
		}

		let ring_prover = ctx.prover(prover_key.0, prover_idx as usize);

		let input_msg = [VRF_INPUT_DOMAIN, context].concat();
		let input = bandersnatch::Input::new(&input_msg[..]).expect("H2C can't fail here");
		let preout = secret.output(input);
		let alias = make_alias(&preout);

		let proof = secret.prove(input, preout, message, &ring_prover);

		let signature = RingVrfSignature {
			output: preout,
			proof,
		};

		let mut buf = [0u8; RING_SIGNATURE_SIZE];
		signature
			.serialize_compressed(buf.as_mut_slice())
			.map_err(|_| ())?;

		Ok((buf, alias))
	}

	#[cfg(not(feature = "std"))]
	fn create(
		_commitment: Self::Commitment,
		_secret: &Self::Secret,
		_context: &[u8],
		_message: &[u8],
	) -> Result<(Self::Proof, Alias), ()> {
		panic!("Not implemented")
	}

	fn alias_in_context(secret: &Self::Secret, context: &[u8]) -> Result<Alias, ()> {
		let input_msg = [VRF_INPUT_DOMAIN, context].concat();
		let input = bandersnatch::Input::new(&input_msg[..]).expect("H2C can't fail here");
		let output = secret.output(input);
		let alias = make_alias(&output);
		Ok(alias)
	}

	fn external_member(value: &Self::InternalMember) -> Self::Member {
		let mut bytes = [0u8; PUBLIC_KEY_LENGTH];
		value.using_encoded(|encoded| {
			bytes.copy_from_slice(encoded);
		});
		EncodedPublicKey(bytes)
	}

	fn internal_member(value: &Self::Member) -> Self::InternalMember {
		let pt =
			bandersnatch::AffinePoint::deserialize_compressed(&value.0[..]).expect("must be valid");
		InternalPublicKey(pt.into())
	}
}

#[cfg(test)]
mod tests {
	// use bandersnatch_vrfs::ring::StaticVerifierKey;

	use super::*;

	#[cfg(feature = "small-ring")]
	const ONCHAIN_VK: &[u8] = include_bytes!("ring-data/zcash-9.vk");
	#[cfg(not(feature = "small-ring"))]
	const ONCHAIN_VK: &[u8] = include_bytes!("ring-data/zcash-16.vk");

	#[test]
	fn start_push_finish() {
		let alice_sec = BandersnatchVrfVerifiable::new_secret([0u8; 32]);
		let bob_sec = BandersnatchVrfVerifiable::new_secret([1u8; 32]);
		let charlie_sec = BandersnatchVrfVerifiable::new_secret([2u8; 32]);

		let alice = BandersnatchVrfVerifiable::member_from_secret(&alice_sec);
		let bob = BandersnatchVrfVerifiable::member_from_secret(&bob_sec);
		let charlie = BandersnatchVrfVerifiable::member_from_secret(&charlie_sec);

		// 		let vk = StaticVerifierKey::deserialize_uncompressed_unchecked(ONCHAIN_VK).unwrap();
		// 		let get_one = |i| Ok(ArkScale(vk.lag_g1[i]));
		// 		let get_many = |range: Range<usize>| Ok(vk.lag_g1[range].to_vec());

		// 		let mut inter1 = BandersnatchVrfVerifiable::start_members();
		// 		let mut inter2 = BandersnatchVrfVerifiable::start_members_from_params(vk.kzg_vk, get_many);
		// 		assert_eq!(inter1, inter2);

		// 		BandersnatchVrfVerifiable::push_member(&mut inter1, alice.clone(), get_one).unwrap();
		// 		BandersnatchVrfVerifiable::push_member(&mut inter2, alice.clone(), get_one).unwrap();
		// 		BandersnatchVrfVerifiable::push_member(&mut inter1, bob.clone(), get_one).unwrap();
		// 		BandersnatchVrfVerifiable::push_member(&mut inter2, bob.clone(), get_one).unwrap();
		// 		BandersnatchVrfVerifiable::push_member(&mut inter1, charlie.clone(), get_one).unwrap();
		// 		BandersnatchVrfVerifiable::push_member(&mut inter2, charlie.clone(), get_one).unwrap();
		// 		assert_eq!(inter1, inter2);

		// 		let members1 = BandersnatchVrfVerifiable::finish_members(inter1);
		// 		let members2 = BandersnatchVrfVerifiable::finish_members(inter2);
		// 		assert_eq!(members1, members2);
	}

	// 	#[test]
	// 	fn test_plain_signature() {
	// 		let msg = b"asd";
	// 		let secret = BandersnatchVrfVerifiable::new_secret([0; 32]);
	// 		let public = BandersnatchVrfVerifiable::member_from_secret(&secret);
	// 		let signature = BandersnatchVrfVerifiable::sign(&secret, msg).unwrap();
	// 		let res = BandersnatchVrfVerifiable::verify_signature(&signature, msg, &public);
	// 		assert!(res);
	// 	}

	// 	#[test]
	// 	fn open_validate_works() {
	// 		use std::time::Instant;

	// 		let context = b"Context";
	// 		let message = b"FooBar";

	// 		let start = Instant::now();
	// 		let _ = kzg();
	// 		println!("* KZG decode: {} ms", (Instant::now() - start).as_millis());

	// 		let members: Vec<_> = (0..10)
	// 			.map(|i| {
	// 				let secret = BandersnatchVrfVerifiable::new_secret([i as u8; 32]);
	// 				BandersnatchVrfVerifiable::member_from_secret(&secret)
	// 			})
	// 			.collect();
	// 		let member = members[3].clone();

	// 		let start = Instant::now();
	// 		let commitment =
	// 			BandersnatchVrfVerifiable::open(&member, members.clone().into_iter()).unwrap();
	// 		println!("* Open: {} ms", (Instant::now() - start).as_millis());
	// 		println!("  Commitment size: {} bytes", commitment.encode().len()); // ~49 MB

	// 		let secret = BandersnatchVrfVerifiable::new_secret([commitment.0 as u8; 32]);
	// 		let start = Instant::now();
	// 		let (proof, alias) =
	// 			BandersnatchVrfVerifiable::create(commitment, &secret, context, message).unwrap();
	// 		println!("* Create: {} ms", (Instant::now() - start).as_millis());
	// 		println!("  Proof size: {} bytes", proof.encode().len()); // 788 bytes

	// 		let vk = StaticVerifierKey::deserialize_uncompressed_unchecked(ONCHAIN_VK).unwrap();
	// 		let get_one = |i| Ok(ArkScale(vk.lag_g1[i]));

	// 		let start = Instant::now();
	// 		let mut inter = BandersnatchVrfVerifiable::start_members();
	// 		println!(
	// 			"* Start members: {} ms",
	// 			(Instant::now() - start).as_millis()
	// 		);

	// 		let start = Instant::now();
	// 		members.iter().for_each(|member| {
	// 			BandersnatchVrfVerifiable::push_member(&mut inter, member.clone(), get_one).unwrap();
	// 		});
	// 		println!(
	// 			"* Push {} members: {} ms",
	// 			members.len(),
	// 			(Instant::now() - start).as_millis()
	// 		);

	// 		let start = Instant::now();
	// 		let members = BandersnatchVrfVerifiable::finish_members(inter);
	// 		println!(
	// 			"* Finish members: {} ms",
	// 			(Instant::now() - start).as_millis()
	// 		);

	// 		let start = Instant::now();
	// 		let alias2 =
	// 			BandersnatchVrfVerifiable::validate(&proof, &members, context, message).unwrap();
	// 		println!("* Validate {} ms", (Instant::now() - start).as_millis());
	// 		assert_eq!(alias, alias2);

	// 		let start = Instant::now();
	// 		let alias3 = BandersnatchVrfVerifiable::alias_in_context(&secret, context).unwrap();
	// 		println!("* Alias: {} ms", (Instant::now() - start).as_millis());
	// 		assert_eq!(alias, alias3);
	// 	}
}
