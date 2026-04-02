//! Simple (insecure) implementation of [`Verifiable`] for illustration and testing.
//!
//! This module provides a toy implementation that demonstrates how to implement
//! the trait. It has no real cryptographic properties -- the "alias" is just
//! a hash of (secret, context) and the "proof" bundles those aliases with the
//! member identity. Do not use in production.

use super::*;
use bounded_collections::{BoundedVec, ConstU32};

const MAX_MEMBERS: u32 = 1024;
const MAX_CONTEXTS: u32 = 16;

/// [`Capacity`] impl for the simple demo (no ring VRF).
impl Capacity for () {
	fn size(&self) -> usize {
		MAX_MEMBERS as usize
	}
}

fn simple_hash(data: &[&[u8]]) -> [u8; 32] {
	// Poor man's hash: XOR-fold all input bytes into a 32-byte block.
	// Not collision-resistant -- just enough for a demo.
	let mut out = [0u8; 32];
	let mut pos = 0usize;
	for chunk in data {
		for &byte in *chunk {
			out[pos % 32] ^= byte;
			pos += 1;
		}
	}
	out
}

fn simple_alias(secret: &[u8; 32], context: &[u8]) -> Alias {
	simple_hash(&[secret, context])
}

/// Proof for [`Simple`]: a tuple of (member, aliases) where aliases are one per context.
pub type SimpleProof = ([u8; 32], BoundedVec<Alias, ConstU32<MAX_CONTEXTS>>);

/// Toy [`Verifiable`] implementation.
///
/// - Secret and Member are both `[u8; 32]` (member = secret, i.e. no real key derivation).
/// - Alias is `hash(secret, context)`.
/// - Proof is `(member, aliases)` -- verification just checks the member is in the set
///   and the aliases match.
/// - Signature is the secret itself (anyone who knows the secret can forge it).
#[derive(Debug)]
pub struct Simple;

impl Verifiable for Simple {
	type Members = BoundedVec<Self::Member, ConstU32<MAX_MEMBERS>>;
	type Intermediate = BoundedVec<Self::Member, ConstU32<MAX_MEMBERS>>;
	type Member = [u8; 32];
	type Secret = [u8; 32];
	type Commitment = (Self::Member, Vec<Self::Member>);
	type Proof = SimpleProof;
	type Signature = [u8; 32];
	type StaticChunk = ();
	type Capacity = ();

	fn start_members(_capacity: ()) -> Self::Intermediate {
		BoundedVec::new()
	}

	fn push_members(
		inter: &mut Self::Intermediate,
		members: impl Iterator<Item = Self::Member>,
		_lookup: impl Fn(Range<usize>) -> Result<Vec<Self::StaticChunk>, ()>,
	) -> Result<(), ()> {
		for member in members {
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
		_capacity: (),
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
		_message: &[u8],
	) -> Result<(Self::Proof, Vec<Alias>), ()> {
		if &member != secret {
			return Err(());
		}
		let aliases: Vec<Alias> = contexts
			.iter()
			.map(|ctx| simple_alias(secret, ctx))
			.collect();
		let bounded_aliases = BoundedVec::try_from(aliases.clone()).map_err(|_| ())?;
		Ok(((member, bounded_aliases), aliases))
	}

	fn validate_multi_context(
		_capacity: Self::Capacity,
		proof: &Self::Proof,
		members: &Self::Members,
		contexts: &[&[u8]],
		_message: &[u8],
	) -> Result<Vec<Alias>, ()> {
		let (member, aliases) = proof;
		if !members.contains(member) {
			return Err(());
		}
		if aliases.len() != contexts.len() {
			return Err(());
		}
		Ok(aliases.to_vec())
	}

	fn alias_in_context(secret: &Self::Secret, context: &[u8]) -> Result<Alias, ()> {
		Ok(simple_alias(secret, context))
	}

	fn is_member_valid(_member: &Self::Member) -> bool {
		true
	}

	fn sign(secret: &Self::Secret, _message: &[u8]) -> Result<Self::Signature, ()> {
		Ok(*secret)
	}

	fn verify_signature(
		signature: &Self::Signature,
		_message: &[u8],
		member: &Self::Member,
	) -> bool {
		signature == member
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[cfg(feature = "prover")]
	#[test]
	fn simple_create_and_verify() {
		let alice_sec = Simple::new_secret([0u8; 32]);
		let bob_sec = Simple::new_secret([1u8; 32]);
		let charlie_sec = Simple::new_secret([2u8; 32]);
		let alice = Simple::member_from_secret(&alice_sec);
		let bob = Simple::member_from_secret(&bob_sec);

		let mut inter = Simple::start_members(());
		Simple::push_members(&mut inter, [alice, bob].into_iter(), |_| Ok(vec![()])).unwrap();
		let members = Simple::finish_members(inter);

		let context = b"ctx";
		let message = b"hello";

		// Alice can create and verify a proof.
		type SimpleReceipt = Receipt<Simple>;
		let receipt = SimpleReceipt::create(
			(),
			&alice_sec,
			members.iter().cloned(),
			context,
			message.to_vec(),
		)
		.unwrap();
		let (alias, msg) = receipt.verify((), &members, context).unwrap();
		assert_eq!(&msg, message);
		assert_eq!(alias, simple_alias(&alice_sec, context));

		// Charlie (not a member) cannot create a proof.
		assert!(SimpleReceipt::create(
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
	fn simple_multi_context() {
		let secret = Simple::new_secret([0u8; 32]);
		let member = Simple::member_from_secret(&secret);

		let mut inter = Simple::start_members(());
		Simple::push_members(&mut inter, [member].into_iter(), |_| Ok(vec![()])).unwrap();
		let members = Simple::finish_members(inter);

		let contexts: Vec<&[u8]> = vec![b"ctx1", b"ctx2"];
		let commitment = Simple::open((), &member, members.iter().cloned()).unwrap();
		let (proof, aliases) =
			Simple::create_multi_context(commitment, &secret, &contexts, b"msg").unwrap();

		assert_eq!(aliases.len(), 2);
		assert!(Simple::is_valid_multi_context(
			(),
			&proof,
			&members,
			&contexts,
			&aliases,
			b"msg"
		));
	}

	#[test]
	fn simple_signature() {
		let secret = Simple::new_secret([42u8; 32]);
		let member = Simple::member_from_secret(&secret);
		let sig = Simple::sign(&secret, b"msg").unwrap();
		assert!(Simple::verify_signature(&sig, b"msg", &member));
	}
}
