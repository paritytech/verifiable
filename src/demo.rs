use super::*;
use bounded_collections::{BoundedVec, ConstU32};

/// [`Capacity`] impl for demo implementations that don't use ring VRF.
/// Always returns a fixed size of 1024.
impl Capacity for () {
	fn size(&self) -> usize {
		1024
	}
}

// Example impls:

/// Totally insecure Anonymizer: Member and Secret are both the same `[u8; 32]` and the proof is
/// just the identity. The `alias` is always the identity and the root is just a `Vec<Self::Member>`.
/// Verification just checks that the proof and the alias are the same and that the alias exists
/// in the "root" (just a Vec).
pub struct Trivial;
impl GenerateVerifiable for Trivial {
	type Members = BoundedVec<Self::Member, ConstU32<1024>>;
	type Intermediate = BoundedVec<Self::Member, ConstU32<1024>>;
	type Member = [u8; 32];
	type Secret = [u8; 32];
	type Commitment = (Self::Member, Vec<Self::Member>);
	type Proof = Vec<[u8; 32]>;
	type Signature = [u8; 32];
	type StaticChunk = ();
	type Capacity = ();

	fn is_member_valid(_member: &Self::Member) -> bool {
		true
	}

	fn start_members(_capacity: ()) -> Self::Intermediate {
		BoundedVec::new()
	}

	fn push_members(
		inter: &mut Self::Intermediate,
		members: impl Iterator<Item = Self::Member>,
		_lookup: impl Fn(Range<usize>) -> Result<Vec<Self::StaticChunk>, ()>,
	) -> Result<(), ()> {
		for member in members {
			inter.try_push(member).map_err(|_| ())?
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
	fn create(
		commitment: Self::Commitment,
		secret: &Self::Secret,
		context: &[u8],
		message: &[u8],
	) -> Result<(Self::Proof, Alias), ()> {
		let (proof, aliases) =
			Self::create_multi_context(commitment, secret, &[context], message)?;
		Ok((proof, aliases[0]))
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
		let aliases = contexts.iter().map(|_| *secret).collect();
		Ok((vec![*secret; contexts.len()], aliases))
	}

	fn validate(
		capacity: Self::Capacity,
		proof: &Self::Proof,
		members: &Self::Members,
		context: &[u8],
		message: &[u8],
	) -> Result<Alias, ()> {
		let result = Self::validate_multi_context(capacity, proof, members, &[context], message)?;
		Ok(result[0])
	}

	fn validate_multi_context(
		_capacity: Self::Capacity,
		proof: &Self::Proof,
		members: &Self::Members,
		_contexts: &[&[u8]],
		_message: &[u8],
	) -> Result<Vec<Alias>, ()> {
		proof
			.iter()
			.map(|p| {
				if members.contains(p) {
					Ok(*p)
				} else {
					Err(())
				}
			})
			.collect()
	}

	fn alias_in_context(secret: &Self::Secret, _context: &[u8]) -> Result<Alias, ()> {
		Ok(*secret)
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

	#[test]
	fn trivial_signature_works() {
		let secret = [0; 32];
		let member = <Trivial as GenerateVerifiable>::member_from_secret(&secret);
		let signature = <Trivial as GenerateVerifiable>::sign(&secret, b"Hello world").unwrap();
		assert!(<Trivial as GenerateVerifiable>::verify_signature(
			&signature,
			b"Hello world",
			&member
		));
	}
}
