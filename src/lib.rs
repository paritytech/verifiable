use core::fmt::Debug;
use parity_scale_codec::{Decode, Encode, FullCodec, MaxEncodedLen};
use scale_info::*;
use schnorrkel::{signing_context, ExpansionMode, MiniSecretKey, PublicKey};
use std::vec::Vec;

// Fixed types:

/// Identifier for an member verifiable by a proof. A member's alias is fixed for any given context.
pub type Alias = [u8; 32];
/// Entropy supplied for the creation of a secret key.
pub type Entropy = [u8; 32];

// The trait. This (alone) must be implemented in its entirely by the Ring-VRF.

/// Trait allowing cryptographic proof of membership of a set with known members under multiple
/// contexts without exposing the underlying member who is proving it and giving an unlinkable
/// deterministic pseudonymic "alias" under each context.
///
/// A value of this type represents a proof. It can be created using the `Self::create` function
/// from the `Self::Secret` value associated with a `Self::Member` value who exists within a set of
/// members identified with a `Self::Members` value. It can later be validated with the
/// `Self::is_valid` function using `self` together with the same information used to crate it
/// (except the secret, of course!).
///
/// A convenience `Receipt` type is provided for typical use cases which bundles the proof along
/// with needed witness information describing the message and alias.
pub trait Verifiable:
	Clone + Eq + PartialEq + FullCodec + Debug + TypeInfo + MaxEncodedLen
{
	/// Consolidated value identifying a particular set of members. Corresponds to the Ring Root.
	type Members: Clone + PartialEq + FullCodec;
	/// Intermediate value while building a `Self::Members` value. Probably just an unfinished Ring
	/// Root(?)
	type Intermediate: Clone + PartialEq + FullCodec;
	/// Value identifying a single member. Corresponds to the Public Key.
	type Member: Clone + PartialEq + FullCodec;
	/// Value with which a member can create a proof of membership. Corresponds to the Secret Key.
	type Secret: Clone + PartialEq + FullCodec;
	/// A partially-created proof. This is created by the `open` function and utilized by the
	/// `create` function.
	type Commitment: Clone + PartialEq + FullCodec;

	/// Begin building a `Members` value.
	fn start_members() -> Self::Intermediate;
	/// Introduce a new `Member` into the intermediate value used to build a new `Members` value.
	fn push_member(intermediate: &mut Self::Intermediate, who: Self::Member);
	/// Consume the `intermediate` value to create a new `Members` value.
	fn finish_members(inter: Self::Intermediate) -> Self::Members;

	/// Create a new secret from some particular `entropy`.
	fn new_secret(entropy: Entropy) -> Self::Secret;

	/// Determine the `Member` value corresponding to a given `Secret`. Basically just the
	/// secret-to-public-key function of the crypto.
	fn member_from_secret(secret: &Self::Secret) -> Self::Member;

	/// First step in creating a proof that `member` exists in a group `members`. The result of this
	/// must be passed into `create` in order to actually create the proof.
	///
	/// This operation uses the potentially large set `members` and as such is expected to be
	/// executed on a device with access to the chain state and is presumably online. The
	/// counterpart operation `create` does not utilize this data. It does require knowledge of the
	/// `Secret` for `member` and as such is practical to conduct on an offline/air-gapped device.
	///
	/// NOTE: We never expect to use this code on-chain; it should be used only in the wallet.
	fn open<'a>(
		member: &Self::Member,
		members_iter: impl Iterator<Item = &'a Self::Member>,
	) -> Result<Self::Commitment, ()> where Self::Member: 'a;

	/// Create a proof of membership with the `commitment` using the given `secret` of the member
	/// of the `commitment`.
	///
	/// The proof will be specific to a given `context` (which determines the resultant `Alias` of
	/// the member in a way unlinkable to the member's original identifiaction and aliases in any
	/// other contexts) together with a provided `message` which entirely at the choice of the
	/// individual.
	///
	/// - `context`: The context under which membership is proven. Proofs over different `[u8]`s
	/// are unlinkable.
	///
	/// NOTE: We never expect to use this code on-chain; it should be used only in the wallet.
	fn create(
		commitment: Self::Commitment,
		secret: &Self::Secret,
		context: &[u8],
		message: &[u8],
	) -> Result<(Self, Alias), ()>;

	/// Check whether `self` is a valid proof of membership in `members` in the given `context`;
	/// if so, ensure that the member is necessarily associated with `alias` in this `context` and
	/// that they elected to opine `message`.
	fn is_valid(
		&self,
		members: &Self::Members,
		context: &[u8],
		alias: &Alias,
		message: &[u8],
	) -> bool;
}

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
	fn push_member(inter: &mut Self::Intermediate, who: Self::Member) {
		inter.push(who);
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

	fn is_valid(
		&self,
		members: &Self::Members,
		_context: &[u8],
		alias: &Alias,
		_message: &[u8],
	) -> bool {
		&self.0 == alias && members.contains(alias)
	}
}

const SIG_CON: &[u8] = b"verifiable";

/// Example impl of `Verifiable` which uses Schnorrkel. This doesn't anonymise anything.
#[derive(Clone, Eq, PartialEq, Encode, Decode, Debug, TypeInfo, MaxEncodedLen)]
pub struct Simple([u8; 64]);
impl Verifiable for Simple {
	type Members = Vec<Self::Member>;
	type Intermediate = Vec<Self::Member>;
	type Member = [u8; 32];
	type Secret = [u8; 32];
	type Commitment = (Self::Member, Self::Members);

	fn start_members() -> Self::Intermediate {
		Vec::new()
	}
	fn push_member(inter: &mut Self::Intermediate, who: Self::Member) {
		inter.push(who);
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
		Ok((Self(sig), public))
	}

	fn is_valid(
		&self,
		members: &Self::Members,
		context: &[u8],
		alias: &Alias,
		message: &[u8],
	) -> bool {
		if !members.contains(alias) {
			return false;
		}
		let s = schnorrkel::Signature::from_bytes(&self.0).unwrap();
		let p = PublicKey::from_bytes(alias).unwrap();
		(context, message).using_encoded(|b| p.verify_simple(SIG_CON, b, &s).is_ok())
	}
}

// This is just a convenience struct to help manage some of the witness data. No need to look at it.
#[derive(Clone, Eq, PartialEq, Encode, Decode, Debug, TypeInfo)]
pub struct Receipt<Proof> {
	proof: Proof,
	alias: Alias,
	message: Vec<u8>,
}

impl<Proof: Verifiable> Receipt<Proof> {
	pub fn create<'a>(
		secret: &Proof::Secret,
		members: impl Iterator<Item = &'a Proof::Member>,
		context: &[u8],
		message: Vec<u8>,
	) -> Result<Self, ()>
	where
		Proof::Member: 'a,
	{
		let commitment = Proof::open(&Proof::member_from_secret(secret), members)?;
		let (proof, alias) = Proof::create(commitment, secret, context, &message)?;
		Ok(Self { proof, alias, message })
	}
	pub fn alias(&self) -> &Alias {
		&self.alias
	}
	pub fn message(&self) -> &[u8] {
		&self.message
	}
	pub fn into_parts(self) -> (Alias, Vec<u8>) {
		(self.alias, self.message)
	}
	pub fn verify(
		self,
		members: &Proof::Members,
		context: &[u8],
	) -> Result<(Alias, Vec<u8>), Self> {
		if self.is_valid(members, context) {
			Ok(self.into_parts())
		} else {
			Err(self)
		}
	}
	pub fn is_valid(&self, members: &Proof::Members, context: &[u8]) -> bool {
		self.proof
			.is_valid(members, context, &self.alias, &self.message)
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
