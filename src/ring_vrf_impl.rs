use ark_scale::ArkScale;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use bandersnatch_vrfs::bandersnatch::BandersnatchConfig;
use bandersnatch_vrfs::bls12_381;
use bandersnatch_vrfs::bls12_381::Bls12_381;
use bandersnatch_vrfs::ring::VerifierKey;
use bandersnatch_vrfs::{
	ring::ProverKey, IntoVrfInput, Message, PublicKey, RingVerifier, SecretKey, Transcript,
	VrfInput,
};
#[cfg(feature = "std")]
use bandersnatch_vrfs::{ring::KZG, RingProver};
use fflonk::pcs::kzg::params::RawKzgVerifierKey;
use ring::ring::{Ring, SrsSegment};

use super::*;

type ThinVrfSignature = bandersnatch_vrfs::ThinVrfSignature<0>;
type RingVrfSignature = bandersnatch_vrfs::RingVrfSignature<1>;

const DOMAIN_SIZE: usize = 1 << 9;

const THIN_SIGNATURE_CONTEXT: &[u8] = b"VerifiableBandersnatchThinSignature";

const VRF_INPUT_DOMAIN: &[u8] = b"VerifiableBandersnatchInput";
const VRF_OUTPUT_DOMAIN: &[u8] = b"VerifiableBandersnatchInput";

const THIN_SIGNATURE_SIZE: usize = 65;
const RING_SIGNATURE_SIZE: usize = 788;

#[cfg(feature = "std")]
static KZG_BYTES: &[u8] = include_bytes!("test2e9.kzg");

// Some naive benchmarking for deserialization of KZG with domain size 2^16
// - compressed + checked = ~16 s
// - uncompressed + checked = ~12 s
// - compressed + unchecked = ~5 s
// - uncompressed + unchecked = 211 ms  <<<<<<<<<<<<<<<<<<<
#[cfg(feature = "std")]
fn kzg() -> &'static KZG {
	use std::sync::OnceLock;
	static CELL: OnceLock<KZG> = OnceLock::new();
	CELL.get_or_init(|| {
		<KZG as CanonicalDeserialize>::deserialize_compressed_unchecked(KZG_BYTES).unwrap()
	})
}

#[derive(Debug, Clone, Eq, PartialEq, CanonicalDeserialize, CanonicalSerialize)]
pub struct MembersSet {
	ring: Ring<bandersnatch_vrfs::bls12_381::Fr, Bls12_381, BandersnatchConfig>,
	kzg_raw_vk: RawKzgVerifierKey<Bls12_381>,
}

ark_scale::impl_scale_via_ark!(MembersSet);

const MEMBERS_SET_MAX_SIZE: usize = 48 * 1024; //TODO

impl scale_info::TypeInfo for MembersSet {
	type Identity = [u8; MEMBERS_SET_MAX_SIZE];

	fn type_info() -> Type {
		Self::Identity::type_info()
	}
}

impl MaxEncodedLen for MembersSet {
	fn max_encoded_len() -> usize {
		<[u8; MEMBERS_SET_MAX_SIZE]>::max_encoded_len()
	}
}

#[derive(Clone, CanonicalDeserialize, CanonicalSerialize)]
pub struct MembersCommitment(VerifierKey);

ark_scale::impl_scale_via_ark!(MembersCommitment);

const MEMBERS_COMMITMENT_MAX_SIZE: usize = 512;

impl scale_info::TypeInfo for MembersCommitment {
	type Identity = [u8; MEMBERS_COMMITMENT_MAX_SIZE];

	fn type_info() -> Type {
		Self::Identity::type_info()
	}
}

impl MaxEncodedLen for MembersCommitment {
	fn max_encoded_len() -> usize {
		MEMBERS_COMMITMENT_MAX_SIZE
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

impl GenerateVerifiable for BandersnatchVrfVerifiable {
	type MembersSetupKey = RawKzgVerifierKey<Bls12_381>;
	type Members = MembersCommitment;
	type Intermediate = MembersSet;
	type Member = ArkScale<PublicKey>;
	type Secret = SecretKey;
	type Commitment = (u32, ArkScale<ProverKey>);
	type Proof = [u8; RING_SIGNATURE_SIZE];
	type Signature = [u8; THIN_SIGNATURE_SIZE];
	type StaticChunk = ArkScale<bls12_381::G1Affine>;

	fn start_members(
		vk: Self::MembersSetupKey,
		lookup: impl Fn(usize, usize) -> Result<Vec<Self::StaticChunk>, ()>,
	) -> MembersSet {
		let piop_params = bandersnatch_vrfs::ring::make_piop_params(DOMAIN_SIZE);
		let offset = piop_params.keyset_part_size;
		let len = DOMAIN_SIZE - offset;
		let srs_segment = lookup(offset, len).unwrap();
		let srs_segment: Vec<bls12_381::G1Affine> = srs_segment.iter().map(|p| p.0).collect();
		let srs_segment = SrsSegment::<Bls12_381>::shift(&srs_segment, offset);
		let ring = Ring::<bls12_381::Fr, Bls12_381, BandersnatchConfig>::empty(
			&piop_params,
			&srs_segment,
			vk.g1.into(),
		);
		MembersSet {
			ring,
			kzg_raw_vk: vk,
		}
	}

	fn push_member(
		intermediate: &mut Self::Intermediate,
		who: Self::Member,
		lookup: impl Fn(usize) -> Result<Self::StaticChunk, ()>,
	) -> Result<(), ()> {
		let curr_size = intermediate.ring.curr_keys;
		let srs_point = lookup(curr_size)?;
		let srs_point = [srs_point.0];
		let srs_segment = SrsSegment::<Bls12_381>::shift(&srs_point, curr_size);
		intermediate.ring.append(&[who.0 .0], &srs_segment);
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
		secret.to_public().into()
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
		// let ring_verifier = kzg().init_ring_verifier(members.0.clone());

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
		member
			.0
			.verify_thin_vrf(transcript, core::iter::empty::<VrfInput>(), &signature)
			.is_ok()
	}

	#[cfg(feature = "std")]
	fn open(
		member: &Self::Member,
		members: impl Iterator<Item = Self::Member>,
	) -> Result<Self::Commitment, ()> {
		let max_len: u32 = kzg()
			.max_keyset_size()
			.try_into()
			.expect("Impossibly large a KZG, qed");
		let mut prover_idx = u32::MAX;
		let mut pks = Vec::with_capacity(members.size_hint().0);
		for (idx, m) in members.enumerate() {
			if idx as u32 >= max_len {
				return Err(());
			}
			if &m == member {
				prover_idx = idx as u32
			}
			pks.push(m.0 .0);
		}
		let prover_key = kzg().prover_key(pks);

		Ok((prover_idx, prover_key.into()))
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
}

#[cfg(test)]
mod tests {
	use super::*;
	use fflonk::pcs::PcsParams;
	use ring::ring::RingBuilderKey;

	#[test]
	#[ignore = "Build a test KZG"]
	fn build_static_kzg() {
		println!("Building testing KZG");

		let path = std::path::Path::new("src/test2e9.kzg");
		use std::fs::OpenOptions;
		let mut oo = OpenOptions::new();
		oo.read(true).write(true).create(true).truncate(true);
		if let Ok(mut file) = oo.open(path) {
			let kzg = KZG::insecure_kzg_setup(DOMAIN_SIZE as u32, &mut rand_core::OsRng);

			kzg.serialize_compressed(&mut file).unwrap_or_else(|why| {
				panic!("couldn't write {}: {}", path.display(), why);
			});
		}
	}

	#[test]
	fn start_push_finish() {
		let alice_sec = BandersnatchVrfVerifiable::new_secret([0u8; 32]);
		let bob_sec = BandersnatchVrfVerifiable::new_secret([1u8; 32]);
		let chalie_sec = BandersnatchVrfVerifiable::new_secret([2u8; 32]);

		let alice = BandersnatchVrfVerifiable::member_from_secret(&alice_sec);
		let bob = BandersnatchVrfVerifiable::member_from_secret(&bob_sec);
		let charlie = BandersnatchVrfVerifiable::member_from_secret(&chalie_sec);

		let kzg = kzg();
		let ring_builder_key = RingBuilderKey::from_srs(&kzg.pcs_params, kzg.domain_size as usize);
		let lis = ring_builder_key.lis_in_g1;
		let get_one = |i: usize| Ok(ArkScale(lis[i]));
		let get_many = |start: usize, len: usize| {
			let res = lis[start..start + len]
				.iter()
				.map(|p| ArkScale(*p))
				.collect();
			Ok(res)
		};
		let mut inter = BandersnatchVrfVerifiable::start_members(kzg.pcs_params.raw_vk(), get_many);
		BandersnatchVrfVerifiable::push_member(&mut inter, alice.clone(), get_one).unwrap();
		BandersnatchVrfVerifiable::push_member(&mut inter, bob.clone(), get_one).unwrap();
		BandersnatchVrfVerifiable::push_member(&mut inter, charlie.clone(), get_one).unwrap();
		let _members = BandersnatchVrfVerifiable::finish_members(inter);
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

		let kzg = kzg();
		let ring_builder_key = RingBuilderKey::from_srs(&kzg.pcs_params, kzg.domain_size as usize);
		let lis = ring_builder_key.lis_in_g1;
		let get_one = |i: usize| Ok(ArkScale(lis[i]));
		let get_many = |start: usize, len: usize| {
			let res = lis[start..start + len]
				.iter()
				.map(|p| ArkScale(*p))
				.collect();
			Ok(res)
		};

		let mut inter = BandersnatchVrfVerifiable::start_members(kzg.pcs_params.raw_vk(), get_many);
		members.iter().for_each(|member| {
			BandersnatchVrfVerifiable::push_member(&mut inter, member.clone(), get_one).unwrap();
		});

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
	}
}
