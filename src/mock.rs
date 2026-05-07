//! Mock implementation of [`GenerateVerifiable`] for tests.
//!
//! This is a non-cryptographic implementation: there is no anonymity (the proof
//! reveals which member produced it), and "signatures" are trivially forgeable
//! because the public key (`Member`) is also the private key (`Secret`). It is,
//! however, a faithful exerciser of the trait contract -- every output is bound
//! to all of its inputs via SHA-256 with domain-separated tags, so any test
//! that swaps a context, message, member set, or alias produces a different
//! result and fails verification. Use it to exercise code that consumes the
//! trait; do not use it in production.
//!
//! Differences from a real ring-VRF impl:
//! - `Member == Secret`, so anyone observing a `Member` can forge.
//! - Aliases are deterministic per `(member, context)` and the proof carries
//!   the `member` in the clear, so observers can link aliases back to members.
//! - Set membership is checked by linear scan, not zero-knowledge.

use super::*;
use bounded_collections::{BoundedVec, ConstU32};
use sha2::{Digest, Sha256};

pub const MAX_MEMBERS: u32 = 1024;
pub const MAX_CONTEXTS: u32 = 3;

const TAG_ALIAS: &[u8] = b"verifiable-mock:v1:alias";
const TAG_SIG: &[u8] = b"verifiable-mock:v1:sig";
const TAG_PROOF: &[u8] = b"verifiable-mock:v1:proof";

/// SHA-256 with length-prefixed inputs for unambiguous concatenation.
fn h(domain: &[u8], parts: &[&[u8]]) -> [u8; 32] {
	let mut hasher = Sha256::new();
	hasher.update((domain.len() as u32).to_le_bytes());
	hasher.update(domain);
	hasher.update((parts.len() as u32).to_le_bytes());
	for p in parts {
		hasher.update((p.len() as u32).to_le_bytes());
		hasher.update(p);
	}
	hasher.finalize().into()
}

fn make_alias(member: &[u8; 32], context: &[u8]) -> Alias {
	h(TAG_ALIAS, &[member, context])
}

fn make_signature(member: &[u8; 32], message: &[u8]) -> [u8; 32] {
	h(TAG_SIG, &[member, message])
}

fn make_proof_tag(
	member: &[u8; 32],
	contexts: &[&[u8]],
	aliases: &[Alias],
	message: &[u8],
) -> [u8; 32] {
	let n = (contexts.len() as u32).to_le_bytes();
	let mut parts: Vec<&[u8]> = Vec::with_capacity(3 + contexts.len() + aliases.len());
	parts.push(member);
	parts.push(&n);
	parts.extend(contexts.iter().copied());
	parts.extend(aliases.iter().map(|a| a.as_slice()));
	parts.push(message);
	h(TAG_PROOF, &parts)
}

/// Proof for [`Mock`]. The `tag` is a hash that binds the member, contexts,
/// aliases, and message together; the verifier recomputes it and compares.
#[derive(Default, Clone, Eq, PartialEq, Encode, Decode, DecodeWithMemTracking, Debug, TypeInfo)]
pub struct MockProof {
	pub tag: [u8; 32],
	pub member: [u8; 32],
	pub aliases: BoundedVec<Alias, ConstU32<MAX_CONTEXTS>>,
}

/// Mock [`GenerateVerifiable`] implementation.
#[derive(Debug)]
pub struct Mock;

impl GenerateVerifiable for Mock {
	type Members = BoundedVec<Self::Member, ConstU32<MAX_MEMBERS>>;
	type Intermediate = BoundedVec<Self::Member, ConstU32<MAX_MEMBERS>>;
	type Member = [u8; 32];
	type Secret = [u8; 32];
	type Commitment = (Self::Member, Vec<Self::Member>);
	type Proof = MockProof;
	type Signature = [u8; 32];
	type StaticChunk = ();
	type Capacity = ();

	fn start_members(_capacity: Self::Capacity) -> Self::Intermediate {
		BoundedVec::new()
	}

	fn push_members(
		inter: &mut Self::Intermediate,
		members: impl Iterator<Item = Self::Member>,
		_lookup: impl Fn(Range<usize>) -> Result<Vec<Self::StaticChunk>, ()>,
	) -> Result<(), ()> {
		for member in members {
			if inter.contains(&member) {
				return Err(());
			}
			inter.try_push(member).map_err(|_| ())?;
		}
		Ok(())
	}

	fn finish_members(inter: Self::Intermediate) -> Self::Members {
		inter
	}

	fn new_secret(entropy: Entropy) -> Self::Secret {
		entropy
	}

	fn member_from_secret(secret: &Self::Secret) -> Self::Member {
		*secret
	}

	#[cfg(feature = "prover")]
	fn open(
		_capacity: Self::Capacity,
		member: &Self::Member,
		members: impl Iterator<Item = Self::Member>,
	) -> Result<Self::Commitment, ()> {
		let set = members.collect::<Vec<_>>();
		if !set.contains(member) {
			return Err(());
		}
		Ok((*member, set))
	}

	#[cfg(feature = "prover")]
	fn create_multi_context(
		(member, _): Self::Commitment,
		secret: &Self::Secret,
		contexts: &[&[u8]],
		message: &[u8],
	) -> Result<(Self::Proof, Vec<Alias>), ()> {
		if &member != secret {
			return Err(());
		}
		if contexts.len() > MAX_CONTEXTS as usize {
			return Err(());
		}
		let aliases: Vec<Alias> = contexts.iter().map(|ctx| make_alias(secret, ctx)).collect();
		let bounded = BoundedVec::try_from(aliases.clone()).map_err(|_| ())?;
		let tag = make_proof_tag(secret, contexts, &aliases, message);
		let proof = MockProof {
			tag,
			member,
			aliases: bounded,
		};
		Ok((proof, aliases))
	}

	fn validate_multi_context(
		_capacity: Self::Capacity,
		proof: &Self::Proof,
		members: &Self::Members,
		contexts: &[&[u8]],
		message: &[u8],
	) -> Result<Vec<Alias>, ()> {
		let MockProof {
			tag,
			member,
			aliases,
		} = proof;
		if !members.contains(member) {
			return Err(());
		}
		if aliases.len() != contexts.len() {
			return Err(());
		}
		for (alias, ctx) in aliases.iter().zip(contexts.iter()) {
			if alias != &make_alias(member, ctx) {
				return Err(());
			}
		}
		let expected_tag = make_proof_tag(member, contexts, aliases, message);
		if tag != &expected_tag {
			return Err(());
		}
		Ok(aliases.to_vec())
	}

	fn alias_in_context(secret: &Self::Secret, context: &[u8]) -> Result<Alias, ()> {
		Ok(make_alias(secret, context))
	}

	fn is_member_valid(_member: &Self::Member) -> bool {
		true
	}

	fn sign(secret: &Self::Secret, message: &[u8]) -> Result<Self::Signature, ()> {
		Ok(make_signature(secret, message))
	}

	fn verify_signature(
		signature: &Self::Signature,
		message: &[u8],
		member: &Self::Member,
	) -> bool {
		// Toy: `Member == Secret`, so the verifier recomputes the MAC. This is
		// trivially forgeable -- the point is that it binds to the message.
		signature == &make_signature(member, message)
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	fn make_members(secrets: &[[u8; 32]]) -> <Mock as GenerateVerifiable>::Members {
		let mut inter = Mock::start_members(());
		let members = secrets.iter().map(Mock::member_from_secret);
		Mock::push_members(&mut inter, members, |_| Ok(vec![()])).unwrap();
		Mock::finish_members(inter)
	}

	#[cfg(feature = "prover")]
	#[test]
	fn create_and_verify() {
		let alice_sec = Mock::new_secret([0u8; 32]);
		let bob_sec = Mock::new_secret([1u8; 32]);
		let charlie_sec = Mock::new_secret([2u8; 32]);
		let members = make_members(&[alice_sec, bob_sec]);

		let context = b"ctx";
		let message = b"hello";

		type MockReceipt = Receipt<Mock>;
		let receipt = MockReceipt::create(
			(),
			&alice_sec,
			members.iter().cloned(),
			context,
			message.to_vec(),
		)
		.unwrap();
		let (alias, msg) = receipt.verify((), &members, context).unwrap();
		assert_eq!(&msg, message);
		assert_eq!(alias, make_alias(&alice_sec, context));

		// Charlie (not a member) cannot create a proof.
		assert!(MockReceipt::create(
			(),
			&charlie_sec,
			members.iter().cloned(),
			context,
			message.to_vec(),
		)
		.is_err());
	}

	#[cfg(feature = "prover")]
	#[test]
	fn proof_binds_to_message() {
		let secret = Mock::new_secret([7u8; 32]);
		let member = Mock::member_from_secret(&secret);
		let members = make_members(&[secret]);

		let commitment = Mock::open((), &member, members.iter().cloned()).unwrap();
		let (proof, _) =
			Mock::create_multi_context(commitment, &secret, &[b"ctx"], b"msg").unwrap();

		assert!(Mock::validate((), &proof, &members, b"ctx", b"msg").is_ok());
		// Different message must fail.
		assert!(Mock::validate((), &proof, &members, b"ctx", b"other").is_err());
	}

	#[cfg(feature = "prover")]
	#[test]
	fn proof_binds_to_context() {
		let secret = Mock::new_secret([7u8; 32]);
		let member = Mock::member_from_secret(&secret);
		let members = make_members(&[secret]);

		let commitment = Mock::open((), &member, members.iter().cloned()).unwrap();
		let (proof, _) = Mock::create_multi_context(commitment, &secret, &[b"a"], b"msg").unwrap();

		assert!(Mock::validate((), &proof, &members, b"a", b"msg").is_ok());
		// Wrong context must fail (alias mismatch).
		assert!(Mock::validate((), &proof, &members, b"b", b"msg").is_err());
	}

	#[cfg(feature = "prover")]
	#[test]
	fn proof_rejected_for_non_member() {
		let prover_sec = Mock::new_secret([7u8; 32]);
		let prover = Mock::member_from_secret(&prover_sec);
		let prover_members = make_members(&[prover_sec]);

		let commitment = Mock::open((), &prover, prover_members.iter().cloned()).unwrap();
		let (proof, _) =
			Mock::create_multi_context(commitment, &prover_sec, &[b"ctx"], b"msg").unwrap();

		// Different member set that does not contain the prover.
		let other = make_members(&[Mock::new_secret([8u8; 32])]);
		assert!(Mock::validate((), &proof, &other, b"ctx", b"msg").is_err());
	}

	#[cfg(feature = "prover")]
	#[test]
	fn multi_context() {
		let secret = Mock::new_secret([0u8; 32]);
		let member = Mock::member_from_secret(&secret);
		let members = make_members(&[secret]);

		let contexts: Vec<&[u8]> = vec![b"ctx1", b"ctx2"];
		let commitment = Mock::open((), &member, members.iter().cloned()).unwrap();
		let (proof, aliases) =
			Mock::create_multi_context(commitment, &secret, &contexts, b"msg").unwrap();

		assert_eq!(aliases.len(), 2);
		assert_ne!(aliases[0], aliases[1]);
		assert!(Mock::is_valid_multi_context(
			(),
			&proof,
			&members,
			&contexts,
			&aliases,
			b"msg"
		));
		// Swapped aliases must fail.
		let swapped = vec![aliases[1], aliases[0]];
		assert!(!Mock::is_valid_multi_context(
			(),
			&proof,
			&members,
			&contexts,
			&swapped,
			b"msg"
		));
	}

	#[test]
	fn signature_binds_to_message() {
		let secret = Mock::new_secret([42u8; 32]);
		let member = Mock::member_from_secret(&secret);
		let sig = Mock::sign(&secret, b"msg").unwrap();
		assert!(Mock::verify_signature(&sig, b"msg", &member));
		// Different message must fail.
		assert!(!Mock::verify_signature(&sig, b"other", &member));
		// Different member must fail.
		let other = Mock::member_from_secret(&Mock::new_secret([43u8; 32]));
		assert!(!Mock::verify_signature(&sig, b"msg", &other));
	}

	#[test]
	fn alias_is_collision_resistant_per_context() {
		let secret = Mock::new_secret([1u8; 32]);
		let a1 = Mock::alias_in_context(&secret, b"ctx1").unwrap();
		let a2 = Mock::alias_in_context(&secret, b"ctx2").unwrap();
		assert_ne!(a1, a2);
		// Trailing-zero distinguishability (broken in the old XOR-fold hash).
		let a3 = Mock::alias_in_context(&secret, b"ctx1\x00").unwrap();
		assert_ne!(a1, a3);
	}

	#[test]
	fn duplicate_member_rejected() {
		let secret = Mock::new_secret([0u8; 32]);
		let member = Mock::member_from_secret(&secret);
		let mut inter = Mock::start_members(());
		assert!(Mock::push_members(&mut inter, [member].into_iter(), |_| Ok(vec![()])).is_ok());
		assert!(Mock::push_members(&mut inter, [member].into_iter(), |_| Ok(vec![()])).is_err());
	}
}
