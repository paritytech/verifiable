use super::*;

// Example impls:

/// Totally insecure Anonymizer: Member and Secret are both the same `[u8; 32]` and the proof is
/// just the identity. The `alias` is always the identity and the root is just a `Vec<Self::Member>`.
/// Verification just checks that the proof and the alias are the same and that the alias exists
/// in the "root" (just a Vec).
#[derive(Clone, Eq, PartialEq, Encode, Decode, Debug, TypeInfo, MaxEncodedLen)]
pub struct Trivial([u8; 32]);
impl Verifiable for Trivial {
	type Members = Vec<Self::Member>;
	type Intermediate = Vec<Self::Member>;
	type Member = [u8; 32];
	type Secret = [u8; 32];
	type Commitment = (Self::Member, Self::Members);

	fn start_members() -> Self::Intermediate {
		Vec::new()
	}
	fn push_member(inter: &mut Self::Intermediate, who: Self::Member) -> Result<(), ()> {
		inter.push(who);
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

	fn open<'a>(
		member: &Self::Member,
		members: impl Iterator<Item = &'a Self::Member>,
	) -> Result<Self::Commitment, ()>
	where
		Self::Member: 'a,
	{
		let set = members.cloned().collect::<Vec<_>>();
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
	) -> Result<(Self, Alias), ()> {
		if &member != secret {
			return Err(())
		}
		Ok((Self(secret.clone()), secret.clone()))
	}

	fn validate(
		&self,
		members: &Self::Members,
		_context: &[u8],
		_message: &[u8],
	) -> Result<Alias, ()> {
		if members.contains(&self.0) {
			Ok(self.0.clone())
		} else {
			Err(())
		}
	}
}

const SIG_CON: &[u8] = b"verifiable";

/// Example impl of `Verifiable` which uses Schnorrkel. This doesn't anonymise anything.
#[derive(Clone, Eq, PartialEq, Encode, Decode, Debug, TypeInfo, MaxEncodedLen)]
pub struct Simple([u8; 64], Alias);
impl Verifiable for Simple {
	type Members = Vec<Self::Member>;
	type Intermediate = Vec<Self::Member>;
	type Member = [u8; 32];
	type Secret = [u8; 32];
	type Commitment = (Self::Member, Self::Members);

	fn start_members() -> Self::Intermediate {
		Vec::new()
	}
	fn push_member(inter: &mut Self::Intermediate, who: Self::Member) -> Result<(), ()> {
		inter.push(who);
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

	fn open<'a>(
		member: &Self::Member,
		members: impl Iterator<Item = &'a Self::Member>,
	) -> Result<Self::Commitment, ()>
	where
		Self::Member: 'a,
	{
		let set = members.cloned().collect::<Vec<_>>();
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
	) -> Result<(Self, Alias), ()> {
		let public = Self::member_from_secret(&secret);
		if member != public {
			return Err(());
		}

		let secret = MiniSecretKey::from_bytes(&secret[..]).unwrap();
		let pair = secret.expand_to_keypair(ExpansionMode::Ed25519);

		let sig = (context, message)
			.using_encoded(|b| pair.sign(signing_context(SIG_CON).bytes(b)).to_bytes());
		Ok((Self(sig, public.clone()), public))
	}

	fn validate(
		&self,
		members: &Self::Members,
		context: &[u8],
		message: &[u8],
	) -> Result<Alias, ()> {
		if !members.contains(&self.1) {
			return Err(());
		}
		let s = schnorrkel::Signature::from_bytes(&self.0).unwrap();
		let p = PublicKey::from_bytes(&self.1).unwrap();
		(context, message).using_encoded(|b| p.verify_simple(SIG_CON, b, &s).map(|_| self.1.clone()).map_err(|_| ()))
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn simple_works() {
		let alice_sec = <Simple as Verifiable>::new_secret([0u8; 32]);
		let bob_sec = <Simple as Verifiable>::new_secret([1u8; 32]);
		let charlie_sec = <Simple as Verifiable>::new_secret([2u8; 32]);
		let alice = <Simple as Verifiable>::member_from_secret(&alice_sec);
		let bob = <Simple as Verifiable>::member_from_secret(&bob_sec);

		let mut inter = <Simple as Verifiable>::start_members();
		<Simple as Verifiable>::push_member(&mut inter, alice.clone());
		<Simple as Verifiable>::push_member(&mut inter, bob.clone());
		let members = <Simple as Verifiable>::finish_members(inter);

		type SimpleReceipt = Receipt<Simple>;
		let context = &b"My context"[..];
		let message = b"Hello world";

		let r = SimpleReceipt::create(
			&alice_sec,
			members.iter(),
			context,
			message.to_vec(),
		)
		.unwrap();
		let (alias, msg) = r.verify(&members, &context).unwrap();
		assert_eq!(&message[..], &msg[..]);
		assert_eq!(alias, alice);

		let r = SimpleReceipt::create(
			&bob_sec,
			members.iter(),
			context,
			message.to_vec(),
		)
		.unwrap();
		let (alias, msg) = r.verify(&members, &context).unwrap();
		assert_eq!(&message[..], &msg[..]);
		assert_eq!(alias, bob);

		assert!(SimpleReceipt::create(
			&charlie_sec,
			members.iter(),
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
}
