use parity_scale_codec::{Encode, Decode, FullCodec, MaxEncodedLen};
use scale_info::*;
use core::fmt::Debug;
use std::vec::Vec;
use schnorrkel::{
	signing_context, ExpansionMode, MiniSecretKey, PublicKey,
};

/// The context under which membership is proven. Proofs over different `Context`s are
/// unlinkable.
pub type Context = [u8; 32];
/// Identifier for an member verifiable by a proof. A member's alias is fixed for any given context.
pub type Alias = [u8; 32];
/// Entropy supplied for the creation of a secret key.
pub type Entropy = [u8; 32];

pub trait Build<Member> {
	type Intermediate: Clone + PartialEq + FullCodec;
	fn start() -> Self::Intermediate;
	fn push(inter: &mut Self::Intermediate, who: Member);
	fn finish(inter: Self::Intermediate) -> Self;
}

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
pub trait Verifiable: Clone + Eq + PartialEq + FullCodec + Debug + TypeInfo + MaxEncodedLen {
	/// Consolidated value identifying a particular set of members. Corresponds to the Ring Root.
	type Members: Clone + PartialEq + FullCodec + Build<Self::Member>;
	/// Value identifying a single member. Corresponds to the Public Key.
	type Member: Clone + PartialEq + FullCodec + From<Self::Secret>;
	/// Value with which a member can create a proof of membership. Corresponds to the Secret Key.
	type Secret: Clone + PartialEq + FullCodec + From<Entropy>;

	/// Create a proof of membership in `members` using the given `secret` of a member. Witness
	/// information of an iterator through the set idenfified by `members` must be provided with
	/// `members_iter`.
	///
	/// The proof will be specific to a given `context` (which determines the resultant `Alias` of
	/// the member in a way unlinkable to the member's original identifiaction and aliases in any
	/// other contexts) together with a provided `message` which entirely at the choice of the
	/// individual.
	fn create<'a>(
		secret: &Self::Secret,
		members: &Self::Members,
		members_iter: impl Iterator<Item = &'a Self::Member>,
		context: &Context,
		message: &[u8],
	) -> Result<(Self, Alias), ()> where Self::Member: 'a;

	/// Check whether `self` is a valid proof of membership in `members` in the given `context`;
	/// if so, ensure that the member is necessarily associated with `alias` in this `context` and
	/// that they elected to opine `message`.
	fn is_valid(
		&self,
		members: &Self::Members,
		context: &Context,
		alias: &Alias,
		message: &[u8],
	) -> bool;
}

#[derive(Clone, Eq, PartialEq, Encode, Decode, Debug, TypeInfo)]
pub struct Receipt<Proof> {
	proof: Proof,
	alias: Alias,
	message: Vec<u8>,
}

impl<Proof: Verifiable> Receipt<Proof> {
	pub fn create<'a>(
		secret: &Proof::Secret,
		members: &Proof::Members,
		members_iter: impl Iterator<Item = &'a Proof::Member>,
		context: Context,
		message: Vec<u8>,
	) -> Result<Self, ()> where Proof::Member: 'a {
		let (proof, alias) = Proof::create(secret, members, members_iter, &context, &message)?;
		Ok(Self { proof, alias, message })
	}
	pub fn alias(&self) -> &Alias { &self.alias }
	pub fn message(&self) -> &[u8] { &self.message }
	pub fn into_parts(self) -> (Alias, Vec<u8>) {
		(self.alias, self.message)
	}
	pub fn verify(self, members: &Proof::Members, context: &Context) -> Result<(Alias, Vec<u8>), Self> {
		if self.is_valid(members, context) {
			Ok(self.into_parts())
		} else {
			Err(self)
		}
	}
	pub fn is_valid(&self, members: &Proof::Members, context: &Context) -> bool {
		self.proof.is_valid(members, context, &self.alias, &self.message)
	}
}

#[derive(Clone, Eq, PartialEq, Encode, Decode, Debug, TypeInfo)]
pub struct VecMembers<Member>(Vec<Member>);
impl<Member: Clone + PartialEq + FullCodec> Build<Member> for VecMembers<Member> {
	type Intermediate = Vec<Member>;
	fn start() -> Self::Intermediate {
		Vec::new()
	}
	fn push(inter: &mut Self::Intermediate, who: Member) {
		inter.push(who);
	}
	fn finish(inter: Self::Intermediate) -> Self {
		Self(inter)
	}
}

// Totally insecure Anonymizer: Member and Secret are both the same `[u8; 32]` and the proof is
// just the identity. The `alias` is always the identity and the root is just a `Vec<Self::Member>`.
// Verification just checks that the proof and the alias are the same and that the alias exists
// in the "root" (just a Vec).
#[derive(Clone, Eq, PartialEq, Encode, Decode, Debug, TypeInfo, MaxEncodedLen)]
pub struct Trivial([u8; 32]);
impl Verifiable for Trivial {
	type Members = VecMembers<Self::Member>;
	type Member = [u8; 32];
	type Secret = [u8; 32];

	fn create<'a>(
		secret: &Self::Secret,
		members: &Self::Members,
		_members_iter: impl Iterator<Item = &'a Self::Member>,
		_context: &Context,
		_message: &[u8],
	) -> Result<(Self, Alias), ()> where Self::Member: 'a {
		if !members.0.contains(&secret) { return Err(()) }
		Ok((Self(secret.clone()), secret.clone()))
	}

	fn is_valid(
		&self,
		members: &Self::Members,
		_context: &Context,
		alias: &Alias,
		_message: &[u8],
	) -> bool {
		&self.0 == alias && members.0.contains(alias)
	}
}

#[derive(Clone, Eq, PartialEq, Encode, Decode, Debug, TypeInfo, MaxEncodedLen)]
pub struct SchnorrkelPublic([u8; 32]);
impl From<SchnorrkelSecret> for SchnorrkelPublic {
	fn from(secret: SchnorrkelSecret) -> Self {
		let secret = MiniSecretKey::from_bytes(&secret.0[..]).unwrap();
		let pair = secret.expand_to_keypair(ExpansionMode::Ed25519);
		Self(pair.public.to_bytes())
	}
}


#[derive(Clone, Eq, PartialEq, Encode, Decode, Debug, TypeInfo, MaxEncodedLen)]
pub struct SchnorrkelSecret([u8; 32]);
impl From<Entropy> for SchnorrkelSecret {
	fn from(entropy: [u8; 32]) -> Self {
		Self(entropy)
	}
}

const SIG_CON: &[u8] = b"verifiable";

#[derive(Clone, Eq, PartialEq, Encode, Decode, Debug, TypeInfo, MaxEncodedLen)]
pub struct Simple([u8; 64]);
impl Verifiable for Simple {
	type Members = VecMembers<Self::Member>;
	type Member = SchnorrkelPublic;
	type Secret = SchnorrkelSecret;

	fn create<'a>(
		secret: &Self::Secret,
		members: &Self::Members,
		_members_iter: impl Iterator<Item = &'a Self::Member>,
		context: &Context,
		message: &[u8],
	) -> Result<(Self, Alias), ()> where Self::Member: 'a {
		let public: SchnorrkelPublic = secret.clone().into();
		if !members.0.contains(&public) {
			return Err(())
		}

		let secret = MiniSecretKey::from_bytes(&secret.0[..]).unwrap();
		let pair = secret.expand_to_keypair(ExpansionMode::Ed25519);

		let sig = (context, message).using_encoded(|b|
			pair.sign(signing_context(SIG_CON).bytes(b)).to_bytes()
		);
		Ok((Self(sig), public.0))
	}

	fn is_valid(
		&self,
		members: &Self::Members,
		context: &Context,
		alias: &Alias,
		message: &[u8],
	) -> bool {
		if !members.0.contains(&SchnorrkelPublic(alias.clone())) {
			return false
		}
		let s = schnorrkel::Signature::from_bytes(&self.0).unwrap();
		let p = PublicKey::from_bytes(alias).unwrap();
		(context, message).using_encoded(|b|
			p.verify_simple(SIG_CON, b, &s).is_ok()
		)
	}
}


#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn simple_works() {
		let alice_sec: SchnorrkelSecret = [0u8; 32].into();
		let bob_sec: SchnorrkelSecret = [1u8; 32].into();
		let charlie_sec: SchnorrkelSecret = [2u8; 32].into();
		let alice: SchnorrkelPublic = alice_sec.clone().into();
		let bob: SchnorrkelPublic = bob_sec.clone().into();
		let mut build_members = <Simple as Verifiable>::Members::start();
		<Simple as Verifiable>::Members::push(&mut build_members, alice.clone());
		<Simple as Verifiable>::Members::push(&mut build_members, bob.clone());
		let members = <Simple as Verifiable>::Members::finish(build_members);

		type SimpleReceipt = Receipt<Simple>;
		let context = [69u8; 32];
		let message = b"Hello world";

		let r = SimpleReceipt::create(&alice_sec, &members, members.0.iter(), context, message.to_vec()).unwrap();
		let (alias, msg) = r.verify(&members, &context).unwrap();
		assert_eq!(&message[..], &msg[..]);
		assert_eq!(alias, alice.0);

		let r = SimpleReceipt::create(&bob_sec, &members, members.0.iter(), context, message.to_vec()).unwrap();
		let (alias, msg) = r.verify(&members, &context).unwrap();
		assert_eq!(&message[..], &msg[..]);
		assert_eq!(alias, bob.0);

		assert!(SimpleReceipt::create(&charlie_sec, &members, members.0.iter(), context, message.to_vec()).is_err());
	}

	const SIG_CON: &[u8] = b"test";

	#[test]
	fn simple_crypto() {
		let secret = [0; 32];
		let keypair = MiniSecretKey::from_bytes(&secret[..]).unwrap().expand_to_keypair(ExpansionMode::Ed25519);
		let public: [u8; 32] = keypair.public.to_bytes();
		let message = b"Hello world!";
		let sig = keypair.sign(signing_context(SIG_CON).bytes(&message[..])).to_bytes();

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
