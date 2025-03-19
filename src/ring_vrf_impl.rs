#![allow(unused)]

use alloc::vec;
use core::ops::Range;

use ark_ec_vrfs::{ring::Verifier, suites::bandersnatch};
use ark_scale::{impl_scale_via_ark, ArkScale, ArkScaleMaxEncodedLen};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use scale_info::TypeInfo;

use super::*;

#[cfg(feature = "std")]
pub(crate) const PCS_PARAMS_ZCASH: &[u8] =
	include_bytes!("ring-data/zcash-srs-2-16-uncompressed.bin");

#[cfg(feature = "small-ring")]
pub const RING_SIZE: usize = 255; // TODO

#[cfg(not(feature = "small-ring"))]
pub const RING_SIZE: usize = 255; // TODO

const VRF_INPUT_DOMAIN: &[u8] = b"VerifiableBandersnatchInput";
const THIN_SIGNATURE_CONTEXT: &[u8] = b"VerifiableBandersnatchThinSignature";

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
fn ring_context() -> &'static bandersnatch::RingContext {
	use ark_ec_vrfs::ring::PcsParams;
	use std::sync::OnceLock;
	static CELL: OnceLock<bandersnatch::RingContext> = OnceLock::new();
	CELL.get_or_init(|| {
		let pcs_params =
			bandersnatch::PcsParams::deserialize_uncompressed_unchecked(PCS_PARAMS_ZCASH).unwrap();
		bandersnatch::RingContext::from_srs(RING_SIZE, pcs_params).unwrap()
	})
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
pub struct StaticChunk(ark_ec_vrfs::ring::G1Affine<bandersnatch::BandersnatchSha512Ell2>);
impl_scale!(StaticChunk, 48);

#[derive(CanonicalSerialize, CanonicalDeserialize)]
struct IetfVrfSignature {
	output: bandersnatch::Output,
	proof: bandersnatch::IetfProof,
}
const IETF_SIGNATURE_SIZE: usize = 96;

#[derive(CanonicalSerialize, CanonicalDeserialize)]
struct RingVrfSignature {
	output: bandersnatch::Output,
	proof: bandersnatch::RingProof,
}
const RING_SIGNATURE_SIZE: usize = 788;

#[inline(always)]
fn make_alias(output: &bandersnatch::Output) -> Alias {
	Alias::try_from(&output.hash()[..32]).expect("Bandersnatch suite hash is 64 bytes")
}

pub struct BandersnatchVrfVerifiable;

impl GenerateVerifiable for BandersnatchVrfVerifiable {
	type Members = MembersCommitment;
	type Intermediate = MembersSet;
	type Member = EncodedPublicKey;
	type InternalMember = PublicKey;
	type Secret = bandersnatch::Secret;
	type Commitment = (u32, ArkScale<bandersnatch::RingProverKey>);
	type Proof = [u8; RING_SIGNATURE_SIZE];
	type Signature = [u8; IETF_SIGNATURE_SIZE];
	type StaticChunk = StaticChunk;

	fn start_members() -> Self::Intermediate {
		const EMPTY_RING_COMMITMENT_DATA: &[u8] = include_bytes!("ring-data/ring-builder.bin");
		MembersSet::deserialize_uncompressed_unchecked(EMPTY_RING_COMMITMENT_DATA).unwrap()
	}

	fn push_member(
		intermediate: &mut Self::Intermediate,
		who: Self::Member,
		lookup: impl Fn(usize) -> Result<Self::StaticChunk, ()>,
	) -> Result<(), ()> {
		let who: Self::InternalMember = Self::internal_member(&who);
		let loader = |range: Range<usize>| {
			let item = lookup(range.start).ok()?.0;
			Some(vec![item])
		};
		intermediate.0.append(&[who.0], loader);
		Ok(())
	}

	fn finish_members(intermediate: Self::Intermediate) -> Self::Members {
		let verifier_key = intermediate.0.finalize();
		MembersCommitment(verifier_key)
	}

	fn new_secret(entropy: Entropy) -> Self::Secret {
		Self::Secret::from_seed(&entropy)
	}

	fn member_from_secret(secret: &Self::Secret) -> Self::Member {
		Self::external_member(&PublicKey(secret.public().0))
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
			bandersnatch::RingContext::verifier_no_context(members.0.clone(), RING_SIZE);

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
		let public = bandersnatch::Public::from(member.0);
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
			.map(|m| Self::internal_member(&m).0)
			.collect::<Vec<_>>();
		let member: Self::InternalMember = Self::internal_member(member);
		let member_idx = pks.iter().position(|&m| m == member.0).ok_or(())?;
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
		let mut bytes = [0u8; PUBLIC_KEY_SIZE];
		value.using_encoded(|encoded| {
			bytes.copy_from_slice(encoded);
		});
		EncodedPublicKey(bytes)
	}

	fn internal_member(value: &Self::Member) -> Self::InternalMember {
		let pt =
			bandersnatch::AffinePoint::deserialize_compressed(&value.0[..]).expect("must be valid");
		PublicKey(pt.into())
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use ark_ec_vrfs::{ring::SrsLookup, suites::bandersnatch::BandersnatchSha512Ell2};

	type RingBuilderPcsParams = ark_ec_vrfs::ring::RingBuilderPcsParams<BandersnatchSha512Ell2>;

	impl BandersnatchVrfVerifiable {
		fn start_members_from_params() -> (MembersSet, RingBuilderPcsParams) {
			let (builder, builder_pcs_params) = ring_context().verifier_key_builder();
			(MembersSet(builder), builder_pcs_params)
		}
	}

	#[test]
	#[ignore = "empty ring builder"]
	fn generate_empty_ring_builder() {
		use std::io::Write;
		const EMPTY_RING_COMMITMENT_FILE: &str = concat!(
			env!("CARGO_MANIFEST_DIR"),
			"/src/ring-data/ring-builder.bin"
		);
		let (builder, builder_pcs_params) = BandersnatchVrfVerifiable::start_members_from_params();
		let mut buf = Vec::with_capacity(builder.uncompressed_size());
		builder.serialize_uncompressed(&mut buf).unwrap();
		println!("Writing empty ring to: {}", EMPTY_RING_COMMITMENT_FILE);
		let mut file = std::fs::File::create(EMPTY_RING_COMMITMENT_FILE).unwrap(); // Create or truncate the file
		file.write_all(&buf).unwrap();
	}

	#[test]
	fn check_precomputed_size() {
		let secret = BandersnatchVrfVerifiable::new_secret([0u8; 32]);
		let public = BandersnatchVrfVerifiable::member_from_secret(&secret);
		let internal = BandersnatchVrfVerifiable::internal_member(&public);
		assert_eq!(internal.compressed_size(), PublicKey::max_encoded_len());

		let members = BandersnatchVrfVerifiable::start_members();
		assert_eq!(members.compressed_size(), MembersSet::max_encoded_len());

		let commitment = BandersnatchVrfVerifiable::finish_members(members);
		assert_eq!(
			commitment.compressed_size(),
			MembersCommitment::max_encoded_len()
		);
	}

	#[test]
	fn start_push_finish() {
		let alice_sec = BandersnatchVrfVerifiable::new_secret([0u8; 32]);
		let bob_sec = BandersnatchVrfVerifiable::new_secret([1u8; 32]);
		let charlie_sec = BandersnatchVrfVerifiable::new_secret([2u8; 32]);

		let alice = BandersnatchVrfVerifiable::member_from_secret(&alice_sec);
		let bob = BandersnatchVrfVerifiable::member_from_secret(&bob_sec);
		let charlie = BandersnatchVrfVerifiable::member_from_secret(&charlie_sec);

		let mut inter1 = BandersnatchVrfVerifiable::start_members();
		let (mut inter2, builder_params) = BandersnatchVrfVerifiable::start_members_from_params();
		assert_eq!(inter1, inter2);

		let get_one = |i| {
			(&builder_params)
				.lookup(i..i + 1)
				.map(|v| StaticChunk(v[0]))
				.ok_or(())
		};

		BandersnatchVrfVerifiable::push_member(&mut inter1, alice.clone(), get_one).unwrap();
		BandersnatchVrfVerifiable::push_member(&mut inter2, alice.clone(), get_one).unwrap();
		BandersnatchVrfVerifiable::push_member(&mut inter1, bob.clone(), get_one).unwrap();
		BandersnatchVrfVerifiable::push_member(&mut inter2, bob.clone(), get_one).unwrap();
		BandersnatchVrfVerifiable::push_member(&mut inter1, charlie.clone(), get_one).unwrap();
		BandersnatchVrfVerifiable::push_member(&mut inter2, charlie.clone(), get_one).unwrap();
		assert_eq!(inter1, inter2);

		let members1 = BandersnatchVrfVerifiable::finish_members(inter1);
		let members2 = BandersnatchVrfVerifiable::finish_members(inter2);
		assert_eq!(members1, members2);
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
		let _ = ring_context();
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
			BandersnatchVrfVerifiable::open(&member, members.clone().into_iter()).unwrap();
		println!("* Open: {} ms", (Instant::now() - start).as_millis());
		println!("  Commitment size: {} bytes", commitment.encode().len()); // ~49 MB

		let secret = BandersnatchVrfVerifiable::new_secret([commitment.0 as u8; 32]);
		let start = Instant::now();
		let (proof, alias) =
			BandersnatchVrfVerifiable::create(commitment, &secret, context, message).unwrap();
		println!("* Create: {} ms", (Instant::now() - start).as_millis());
		println!("  Proof size: {} bytes", proof.encode().len()); // 788 bytes

		let (mut builder, builder_params) = BandersnatchVrfVerifiable::start_members_from_params();

		let get_one = |i| {
			(&builder_params)
				.lookup(i..i + 1)
				.map(|v| StaticChunk(v[0]))
				.ok_or(())
		};

		let start = Instant::now();
		let mut inter = BandersnatchVrfVerifiable::start_members();
		println!(
			"* Start members: {} ms",
			(Instant::now() - start).as_millis()
		);

		let start = Instant::now();
		members.iter().for_each(|member| {
			BandersnatchVrfVerifiable::push_member(&mut inter, member.clone(), get_one).unwrap();
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
}
