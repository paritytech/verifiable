use super::*;
use bounded_collections::{BoundedVec, ConstU32};
use schnorrkel::{signing_context, ExpansionMode, MiniSecretKey, PublicKey};

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
	type Proof = [u8; 32];
	type Signature = [u8; 32];
	type AccStep = ();
	type StaticChunk = ();

	fn is_member_valid(_member: &Self::Member) -> bool {
		true
	}

	fn start_members() -> Self::Intermediate {
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
		secret.clone()
	}

	fn batch_step(
		_proof: &Self::Proof,
		_members: &Self::Members,
		_context: &[u8],
		_message: &[u8],
	) -> Self::AccStep {
		()
	}

	fn open(
		member: &Self::Member,
		members: impl Iterator<Item = Self::Member>,
	) -> Result<Self::Commitment, ()> {
		let set = members.collect::<Vec<_>>();
		if !set.contains(member) {
			return Err(());
		}
		Ok((member.clone(), set))
	}

	fn create(
		(member, _): Self::Commitment,
		secret: &Self::Secret,
		_context: &[u8],
		_message: &[u8],
	) -> Result<(Self::Proof, Alias), ()> {
		if &member != secret {
			return Err(());
		}
		Ok(((secret.clone()), secret.clone()))
	}

	fn validate(
		proof: &Self::Proof,
		members: &Self::Members,
		_context: &[u8],
		_message: &[u8],
	) -> Result<Alias, ()> {
		if members.contains(&proof) {
			Ok(proof.clone())
		} else {
			Err(())
		}
	}

	fn alias_in_context(secret: &Self::Secret, _context: &[u8]) -> Result<Alias, ()> {
		Ok(secret.clone())
	}

	fn sign(secret: &Self::Secret, _message: &[u8]) -> Result<Self::Signature, ()> {
		Ok(secret.clone())
	}

	fn verify_signature(
		signature: &Self::Signature,
		_message: &[u8],
		member: &Self::Member,
	) -> bool {
		signature == member
	}
}

const SIG_CON: &[u8] = b"verifiable";

/// Example impl of `Verifiable` which uses Schnorrkel. This doesn't anonymise anything.
#[derive(
	Clone, Eq, PartialEq, Encode, Decode, Debug, TypeInfo, MaxEncodedLen, DecodeWithMemTracking,
)]
pub struct Simple;
impl GenerateVerifiable for Simple {
	type Members = BoundedVec<Self::Member, ConstU32<1024>>;
	type Intermediate = BoundedVec<Self::Member, ConstU32<1024>>;
	type Member = [u8; 32];
	type Secret = [u8; 32];
	type Commitment = (Self::Member, Vec<Self::Member>);
	type Proof = ([u8; 64], Alias);
	type Signature = [u8; 64];
	type AccStep = ();
	type StaticChunk = ();

	fn is_member_valid(_member: &Self::Member) -> bool {
		true
	}

	fn start_members() -> Self::Intermediate {
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
		let secret = MiniSecretKey::from_bytes(&secret[..]).unwrap();
		let pair = secret.expand_to_keypair(ExpansionMode::Ed25519);
		pair.public.to_bytes()
	}

	fn batch_step(
		_proof: &Self::Proof,
		_members: &Self::Members,
		_context: &[u8],
		_message: &[u8],
	) -> Self::AccStep {
		()
	}

	fn open(
		member: &Self::Member,
		members: impl Iterator<Item = Self::Member>,
	) -> Result<Self::Commitment, ()> {
		let set = members.collect::<Vec<_>>();
		if !set.contains(member) {
			return Err(());
		}
		Ok((member.clone(), set))
	}

	fn create(
		(member, _): Self::Commitment,
		secret: &Self::Secret,
		context: &[u8],
		message: &[u8],
	) -> Result<(Self::Proof, Alias), ()> {
		let public = Self::member_from_secret(&secret);
		if member != public {
			return Err(());
		}

		let secret = MiniSecretKey::from_bytes(&secret[..]).unwrap();
		let pair = secret.expand_to_keypair(ExpansionMode::Ed25519);

		let sig = (context, message)
			.using_encoded(|b| pair.sign(signing_context(SIG_CON).bytes(b)).to_bytes());
		Ok(((sig, public.clone()), public))
	}

	fn validate(
		proof: &Self::Proof,
		members: &Self::Members,
		context: &[u8],
		message: &[u8],
	) -> Result<Alias, ()> {
		if !members.contains(&proof.1) {
			return Err(());
		}
		let s = schnorrkel::Signature::from_bytes(&proof.0).unwrap();
		let p = PublicKey::from_bytes(&proof.1).unwrap();
		(context, message).using_encoded(|b| {
			p.verify_simple(SIG_CON, b, &s)
				.map(|_| proof.1.clone())
				.map_err(|_| ())
		})
	}

	fn alias_in_context(secret: &Self::Secret, _context: &[u8]) -> Result<Alias, ()> {
		Ok(Self::member_from_secret(&secret))
	}

	fn sign(secret: &Self::Secret, message: &[u8]) -> Result<Self::Signature, ()> {
		let secret = MiniSecretKey::from_bytes(&secret[..]).unwrap();
		let pair = secret.expand_to_keypair(ExpansionMode::Ed25519);

		let sig = ("no-ctxt", message)
			.using_encoded(|b| pair.sign(signing_context(SIG_CON).bytes(b)).to_bytes());

		Ok(sig)
	}
	fn verify_signature(
		signature: &Self::Signature,
		message: &[u8],
		member: &Self::Member,
	) -> bool {
		let p = PublicKey::from_bytes(&member[..]).unwrap();
		let s = schnorrkel::Signature::from_bytes(&signature[..]).unwrap();
		("no-ctxt", message).using_encoded(|b| p.verify_simple(SIG_CON, b, &s).is_ok())
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn simple_works() {
		let alice_sec = <Simple as GenerateVerifiable>::new_secret([0u8; 32]);
		let bob_sec = <Simple as GenerateVerifiable>::new_secret([1u8; 32]);
		let charlie_sec = <Simple as GenerateVerifiable>::new_secret([2u8; 32]);
		let alice = <Simple as GenerateVerifiable>::member_from_secret(&alice_sec);
		let bob = <Simple as GenerateVerifiable>::member_from_secret(&bob_sec);

		let mut inter = <Simple as GenerateVerifiable>::start_members();
		<Simple as GenerateVerifiable>::push_members(
			&mut inter,
			[alice.clone()].into_iter(),
			|_| Ok(vec![()]),
		)
		.unwrap();
		<Simple as GenerateVerifiable>::push_members(&mut inter, [bob.clone()].into_iter(), |_| {
			Ok(vec![()])
		})
		.unwrap();
		let members = <Simple as GenerateVerifiable>::finish_members(inter);

		type SimpleReceipt = Receipt<Simple>;
		let context = &b"My context"[..];
		let message = b"Hello world";

		let r = SimpleReceipt::create(
			&alice_sec,
			members.iter().cloned(),
			context,
			message.to_vec(),
		)
		.unwrap();
		let (alias, msg) = r.verify(&members, &context).unwrap();
		assert_eq!(&message[..], &msg[..]);
		assert_eq!(alias, alice);

		let r = SimpleReceipt::create(&bob_sec, members.iter().cloned(), context, message.to_vec())
			.unwrap();
		let (alias, msg) = r.verify(&members, &context).unwrap();
		assert_eq!(&message[..], &msg[..]);
		assert_eq!(alias, bob);

		assert!(SimpleReceipt::create(
			&charlie_sec,
			members.iter().cloned(),
			context,
			message.to_vec()
		)
		.is_err());
	}

	const SIG_CON: &[u8] = b"test";

	#[test]
	fn simple_crypto() {
		let secret = [0; 32];
		let keypair = MiniSecretKey::from_bytes(&secret[..])
			.unwrap()
			.expand_to_keypair(ExpansionMode::Ed25519);
		let public: [u8; 32] = keypair.public.to_bytes();
		let message = b"Hello world!";
		let sig = keypair
			.sign(signing_context(SIG_CON).bytes(&message[..]))
			.to_bytes();

		let ok = {
			let s = schnorrkel::Signature::from_bytes(&sig).unwrap();
			let p = PublicKey::from_bytes(&public).unwrap();
			p.verify_simple(SIG_CON, &message[..], &s).is_ok()
		};
		assert!(ok);

		let mut sig = sig;
		sig[0] = 0;

		let ok = {
			let s = schnorrkel::Signature::from_bytes(&sig).unwrap();
			let p = PublicKey::from_bytes(&public).unwrap();
			p.verify_simple(SIG_CON, &message[..], &s).is_ok()
		};
		assert!(!ok);
	}

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

	#[test]
	fn simple_signature_works() {
		let secret = [0; 32];
		let member = <Simple as GenerateVerifiable>::member_from_secret(&secret);
		let signature = <Simple as GenerateVerifiable>::sign(&secret, b"Hello world").unwrap();

		let another_secrect = [1; 32];
		let another_member = <Simple as GenerateVerifiable>::member_from_secret(&another_secrect);
		let another_signature =
			<Simple as GenerateVerifiable>::sign(&another_secrect, b"Hello world").unwrap();

		assert!(<Simple as GenerateVerifiable>::verify_signature(
			&signature,
			b"Hello world",
			&member
		));
		assert!(!<Simple as GenerateVerifiable>::verify_signature(
			&signature,
			b"Hello world",
			&another_member
		));
		assert!(!<Simple as GenerateVerifiable>::verify_signature(
			&signature,
			b"No hello",
			&member
		));
		assert!(!<Simple as GenerateVerifiable>::verify_signature(
			&another_signature,
			b"Hello world",
			&member
		));
	}
}
