use alloc::vec;
use core::ops::Range;

use ark_scale::ArkScale;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use bandersnatch_vrfs::ring::{KzgVk, RingCommitment, VerifierKey};
use bandersnatch_vrfs::{bls12_381, deserialize_publickey, PUBLIC_KEY_LENGTH};
use bandersnatch_vrfs::{
	ring::ProverKey, zcash_consts, IntoVrfInput, Message, PublicKey as PublicKeyInternal,
	RingVerifier, SecretKey, Transcript, VrfInput,
};
#[cfg(feature = "std")]
use bandersnatch_vrfs::{ring::StaticProverKey, ring::KZG, RingProver};

use super::*;

pub use bandersnatch_vrfs;

type ThinVrfSignature = bandersnatch_vrfs::ThinVrfSignature<0>;
type RingVrfSignature = bandersnatch_vrfs::RingVrfSignature<1>;

#[cfg(feature = "small-ring")]
mod domain_params {
	use super::*;
	pub const DOMAIN_SIZE: usize = 1 << 9;
	pub(crate) const EMPTY_RING: RingCommitment = zcash_consts::EMPTY_RING_ZCASH_9;
	#[cfg(feature = "std")]
	pub(crate) const OFFCHAIN_PK: &[u8] = include_bytes!("ring-data/zcash-9.pk");
}

#[cfg(not(feature = "small-ring"))]
mod domain_params {
	use super::*;
	pub const DOMAIN_SIZE: usize = 1 << 16;
	pub(crate) const EMPTY_RING: RingCommitment = zcash_consts::EMPTY_RING_ZCASH_16;
	#[cfg(feature = "std")]
	pub(crate) const OFFCHAIN_PK: &[u8] = include_bytes!("ring-data/zcash-16.pk");
}

pub use domain_params::*;

const THIN_SIGNATURE_CONTEXT: &[u8] = b"VerifiableBandersnatchThinSignature";

const VRF_INPUT_DOMAIN: &[u8] = b"VerifiableBandersnatchInput";
const VRF_OUTPUT_DOMAIN: &[u8] = b"VerifiableBandersnatchInput";

const THIN_SIGNATURE_SIZE: usize = 65;
const RING_SIGNATURE_SIZE: usize = 788;

#[cfg(feature = "std")]
fn kzg() -> &'static KZG {
	use std::sync::OnceLock;
	static CELL: OnceLock<KZG> = OnceLock::new();
	CELL.get_or_init(|| {
		let pk = StaticProverKey::deserialize_uncompressed_unchecked(OFFCHAIN_PK).unwrap();
		KZG::kzg_setup(DOMAIN_SIZE, pk)
	})
}

#[derive(Debug, Clone, Eq, PartialEq, CanonicalDeserialize, CanonicalSerialize)]
pub struct MembersSet {
	pub ring: RingCommitment,
	pub kzg_raw_vk: KzgVk,
}

ark_scale::impl_scale_via_ark!(MembersSet);

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

#[derive(Clone, CanonicalDeserialize, CanonicalSerialize)]
pub struct MembersCommitment(VerifierKey);

ark_scale::impl_scale_via_ark!(MembersCommitment);

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

impl BandersnatchVrfVerifiable {
	pub fn start_members_from_params(
		vk: KzgVk,
		srs: impl Fn(Range<usize>) -> Result<Vec<bls12_381::G1Affine>, ()>,
	) -> MembersSet {
		let piop_params = bandersnatch_vrfs::ring::make_piop_params(DOMAIN_SIZE);
		let ring = RingCommitment::empty(&piop_params, srs, vk.g1.into());
		MembersSet {
			ring,
			kzg_raw_vk: vk,
		}
	}
}

#[derive(
	Clone, Eq, PartialEq, Debug, Encode, Decode, TypeInfo, MaxEncodedLen, DecodeWithMemTracking,
)]
pub struct EncodedPublicKey(pub [u8; PUBLIC_KEY_LENGTH]);

impl GenerateVerifiable for BandersnatchVrfVerifiable {
	type Members = MembersCommitment;
	type Intermediate = MembersSet;
	type Member = EncodedPublicKey;
	type InternalMember = PublicKeyInternal;
	type Secret = SecretKey;
	type Commitment = (u32, ArkScale<ProverKey>);
	type Proof = [u8; RING_SIGNATURE_SIZE];
	type Signature = [u8; THIN_SIGNATURE_SIZE];
	type StaticChunk = ArkScale<bls12_381::G1Affine>;

	fn start_members() -> Self::Intermediate {
		MembersSet {
			ring: EMPTY_RING,
			kzg_raw_vk: bandersnatch_vrfs::zcash_consts::ZCASH_KZG_VK,
		}
	}

	fn push_members(
		intermediate: &mut Self::Intermediate,
		members: impl Iterator<Item = Self::Member>,
		lookup: impl Fn(Range<usize>) -> Result<Vec<Self::StaticChunk>, ()>,
	) -> Result<(), ()> {
		let mut keys = vec![];
		for member in members {
			keys.push(Self::internal_member(&member).0);
		}
		intermediate.ring.append(&keys[..], |range| {
			Ok(lookup(range)?.into_iter().map(|c| c.0).collect::<Vec<_>>())
		});
		Ok(())
	}

	fn finish_members(inter: Self::Intermediate) -> Self::Members {
		let verifier_key = VerifierKey::from_ring_and_kzg_vk(&inter.ring, inter.kzg_raw_vk);
		MembersCommitment(verifier_key)
	}

	fn new_secret(entropy: Entropy) -> Self::Secret {
		SecretKey::from_seed(&entropy)
	}

	fn member_from_secret(secret: &Self::Secret) -> Self::Member {
		Self::external_member(&secret.to_public())
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
			bandersnatch_vrfs::ring::make_ring_verifier(members.0.clone(), DOMAIN_SIZE);

		let vrf_input = Message {
			domain: VRF_INPUT_DOMAIN,
			message: context,
		}
		.into_vrf_input();

		let ring_signature =
			RingVrfSignature::deserialize_compressed(proof.as_slice()).map_err(|_| ())?;

		let ios = RingVerifier(&ring_verifier)
			.verify_ring_vrf(message, core::iter::once(vrf_input), &ring_signature)
			.map_err(|_| ())?;

		let alias: Alias = ios[0].vrf_output_bytes(VRF_OUTPUT_DOMAIN);
		Ok(alias)
	}

	fn sign(secret: &Self::Secret, message: &[u8]) -> Result<Self::Signature, ()> {
		let mut transcript = Transcript::new_labeled(THIN_SIGNATURE_CONTEXT);
		transcript.append_slice(message);
		let signature = secret.sign_thin_vrf(transcript, &[]);
		let mut raw = [0u8; THIN_SIGNATURE_SIZE];
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
		let signature: ThinVrfSignature =
			ThinVrfSignature::deserialize_compressed(signature.as_slice()).unwrap();
		let mut transcript = Transcript::new_labeled(THIN_SIGNATURE_CONTEXT);
		transcript.append_slice(message);
		let member: Self::InternalMember = Self::internal_member(member);
		member
			.verify_thin_vrf(transcript, core::iter::empty::<VrfInput>(), &signature)
			.is_ok()
	}

	#[cfg(feature = "std")]
	fn open(
		member: &Self::Member,
		members: impl Iterator<Item = Self::Member>,
	) -> Result<Self::Commitment, ()> {
		let pks: Vec<_> = members.map(|m| Self::internal_member(&m).0).collect();
		let member: Self::InternalMember = Self::internal_member(member);
		let member_idx = pks.iter().position(|&m| m == member.0).ok_or(())?;
		let member_idx = member_idx as u32;
		let prover_key = kzg().prover_key(pks);
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
		let (prover_idx, prover_key) = commitment;
		if prover_idx >= kzg().max_keyset_size() as u32 {
			return Err(());
		}

		let ring_prover = kzg().init_ring_prover(prover_key.0, prover_idx as usize);

		let vrf_input = Message {
			domain: VRF_INPUT_DOMAIN,
			message: context,
		}
		.into_vrf_input();

		let ios = [secret.vrf_inout(vrf_input)];

		let signature: RingVrfSignature = RingProver {
			ring_prover: &ring_prover,
			secret,
		}
		.sign_ring_vrf(message, &ios);

		let mut buf = [0u8; RING_SIGNATURE_SIZE];
		signature
			.serialize_compressed(buf.as_mut_slice())
			.map_err(|_| ())?;

		let alias: Alias = ios[0].vrf_output_bytes(VRF_OUTPUT_DOMAIN);

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
		let vrf_input = Message {
			domain: VRF_INPUT_DOMAIN,
			message: context,
		}
		.into_vrf_input();

		let ios = [secret.vrf_inout(vrf_input)];

		let alias: Alias = ios[0].vrf_output_bytes(VRF_OUTPUT_DOMAIN);
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
		deserialize_publickey(&value.0[..]).expect("must be valid")
	}
}

#[cfg(test)]
mod tests {
	use bandersnatch_vrfs::ring::StaticVerifierKey;

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

		let vk = StaticVerifierKey::deserialize_uncompressed_unchecked(ONCHAIN_VK).unwrap();
		let get_many = |range: Range<usize>| Ok(vk.lag_g1[range].to_vec());
		let get_many_arkscale = |range: Range<usize>| {
			Ok(vk.lag_g1[range]
				.iter()
				.cloned()
				.map(|a| ArkScale(a))
				.collect())
		};

		let mut inter1 = BandersnatchVrfVerifiable::start_members();
		let mut inter2 = BandersnatchVrfVerifiable::start_members_from_params(vk.kzg_vk, get_many);
		assert_eq!(inter1, inter2);

		BandersnatchVrfVerifiable::push_members(
			&mut inter1,
			[alice.clone(), bob.clone(), charlie.clone()].into_iter(),
			get_many_arkscale,
		)
		.unwrap();
		BandersnatchVrfVerifiable::push_members(
			&mut inter2,
			[alice.clone()].into_iter(),
			get_many_arkscale,
		)
		.unwrap();
		BandersnatchVrfVerifiable::push_members(
			&mut inter2,
			[bob.clone()].into_iter(),
			get_many_arkscale,
		)
		.unwrap();
		BandersnatchVrfVerifiable::push_members(
			&mut inter2,
			[charlie.clone()].into_iter(),
			get_many_arkscale,
		)
		.unwrap();
		assert_eq!(inter1, inter2);

		let members1 = BandersnatchVrfVerifiable::finish_members(inter1);
		let members2 = BandersnatchVrfVerifiable::finish_members(inter2);
		assert_eq!(members1, members2);
	}

	#[test]
	fn start_push_finish_multiple_members() {
		let alice_sec = BandersnatchVrfVerifiable::new_secret([0u8; 32]);
		let bob_sec = BandersnatchVrfVerifiable::new_secret([1u8; 32]);
		let charlie_sec = BandersnatchVrfVerifiable::new_secret([2u8; 32]);

		let alice = BandersnatchVrfVerifiable::member_from_secret(&alice_sec);
		let bob = BandersnatchVrfVerifiable::member_from_secret(&bob_sec);
		let charlie = BandersnatchVrfVerifiable::member_from_secret(&charlie_sec);

		let vk = StaticVerifierKey::deserialize_uncompressed_unchecked(ONCHAIN_VK).unwrap();
		let chunks: Vec<_> = vk.lag_g1.iter().cloned().map(|a| ArkScale(a)).collect();
		let get_many = |range: Range<usize>| Ok(chunks[range].to_vec());

		// First set is everyone all at once with the regular starting root.
		let mut inter1 = BandersnatchVrfVerifiable::start_members();
		// Second set is everyone all at once but with a starting root constructed from params.
		let mut inter2 = BandersnatchVrfVerifiable::start_members_from_params(vk.kzg_vk, |range| {
			Ok(vk.lag_g1[range].to_vec())
		});
		// Third set is everyone added one by one.
		let mut inter3 = BandersnatchVrfVerifiable::start_members();
		// Fourth set is a single addition followed by a group addition.
		let mut inter4 = BandersnatchVrfVerifiable::start_members();

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
	}

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
	fn open_validate_works() {
		use std::time::Instant;

		let context = b"Context";
		let message = b"FooBar";

		let start = Instant::now();
		let _ = kzg();
		println!("* KZG decode: {} ms", (Instant::now() - start).as_millis());

		let members: Vec<_> = (0..10)
			.map(|i| {
				let secret = BandersnatchVrfVerifiable::new_secret([i as u8; 32]);
				BandersnatchVrfVerifiable::member_from_secret(&secret)
			})
			.collect();
		let member = members[3].clone();

		let start = Instant::now();
		let commitment =
			BandersnatchVrfVerifiable::open(&member, members.clone().into_iter()).unwrap();
		println!("* Open: {} ms", (Instant::now() - start).as_millis());
		println!("  Commitment size: {} bytes", commitment.encode().len()); // ~49 MB

		let secret = BandersnatchVrfVerifiable::new_secret([commitment.0 as u8; 32]);
		let start = Instant::now();
		let (proof, alias) =
			BandersnatchVrfVerifiable::create(commitment, &secret, context, message).unwrap();
		println!("* Create: {} ms", (Instant::now() - start).as_millis());
		println!("  Proof size: {} bytes", proof.encode().len()); // 788 bytes

		let vk = StaticVerifierKey::deserialize_uncompressed_unchecked(ONCHAIN_VK).unwrap();
		let get_many = |range: Range<usize>| {
			Ok(vk.lag_g1[range]
				.to_vec()
				.into_iter()
				.map(|a| ArkScale(a))
				.collect())
		};

		let start = Instant::now();
		let mut inter = BandersnatchVrfVerifiable::start_members();
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
			BandersnatchVrfVerifiable::validate(&proof, &members, context, message).unwrap();
		println!("* Validate {} ms", (Instant::now() - start).as_millis());
		assert_eq!(alias, alias2);

		let start = Instant::now();
		let alias3 = BandersnatchVrfVerifiable::alias_in_context(&secret, context).unwrap();
		println!("* Alias: {} ms", (Instant::now() - start).as_millis());
		assert_eq!(alias, alias3);
	}

	#[test]
	fn open_validate_single_vs_multiple_keys() {
		use std::time::Instant;

		let start = Instant::now();
		let _ = kzg();
		println!("* KZG decode: {} ms", (Instant::now() - start).as_millis());

		let members: Vec<_> = (0..255)
			.map(|i| {
				let secret = BandersnatchVrfVerifiable::new_secret([i as u8; 32]);
				BandersnatchVrfVerifiable::member_from_secret(&secret)
			})
			.collect();

		let vk = StaticVerifierKey::deserialize_uncompressed_unchecked(ONCHAIN_VK).unwrap();
		let chunks: Vec<_> = vk.lag_g1.iter().cloned().map(|a| ArkScale(a)).collect();

		let get_many = |range: Range<usize>| Ok(chunks[range].to_vec());

		let mut inter1 = BandersnatchVrfVerifiable::start_members();
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

		let mut inter2 = BandersnatchVrfVerifiable::start_members();
		let start = Instant::now();

		BandersnatchVrfVerifiable::push_members(&mut inter2, members.iter().cloned(), get_many)
			.unwrap();
		println!(
			"* Push {} members simultaneously: {} ms",
			members.len(),
			(Instant::now() - start).as_millis()
		);

		assert_eq!(inter1, inter2);
	}
}
