#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;
extern crate core;

use alloc::vec::Vec;

use core::fmt::Debug;
use parity_scale_codec::{Decode, Encode, FullCodec, MaxEncodedLen};
use scale_info::*;

pub mod demo_impls;
pub mod ring_vrf_impl;

// Fixed types:

/// Cryptographic identifier for a person within a specific application which deals with people.
/// The underlying crypto should guarantee that all `Alias` values used by a person to represent
/// themself for each `Context` are unlinkable from both their underlying `PersonalId` as well as
/// all other `Alias` values of theirs.
///
/// NOTE: This MUST remain equivalent to the type `Alias` in the crate `verifiable`.
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
pub trait GenerateVerifiable {
	/// Setup data which may be required by the implementation.
	type MembersSetupKey;

	/// Consolidated value identifying a particular set of members. Corresponds to the Ring Root.
	///
	/// This is envisioned to be stored on-chain and passed between chains.
	type Members: Clone + Eq + PartialEq + FullCodec + Debug + TypeInfo + MaxEncodedLen;
	/// Intermediate value while building a `Self::Members` value. Probably just an unfinished Ring
	/// Root(?).
	///
	/// This is envisioned to be stored on-chain.
	type Intermediate: Clone + Eq + PartialEq + FullCodec + Debug + TypeInfo + MaxEncodedLen;
	/// Value identifying a single member. Corresponds to the Public Key.
	///
	/// This is stored on-chain and also expected to be passed on-chain as a parameter.
	type Member: Clone + Eq + PartialEq + FullCodec + Debug + TypeInfo + MaxEncodedLen;
	/// Value with which a member can create a proof of membership. Corresponds to the Secret Key.
	///
	/// This is not envisioned to be used on-chain.
	type Secret: Clone;
	/// A partially-created proof. This is created by the `open` function and utilized by the
	/// `create` function.
	///
	/// This is not envisioned to be used on-chain.
	type Commitment: FullCodec;
	/// A proof which can be verified.
	///
	/// This is expected to be passed on-chain as a parameter, but never stored.
	type Proof: Clone + Eq + PartialEq + FullCodec + Debug + TypeInfo;
	/// A signature, creatable from a `Secret` for a message and which can be verified as valid
	/// with respect to the corresponding `Member`.
	type Signature: Clone + Eq + PartialEq + FullCodec + Debug + TypeInfo;

	type StaticChunk: Clone + Eq + PartialEq + FullCodec + Debug + TypeInfo;

	/// Begin building a `Members` value.
	fn start_members(
		vk: Self::MembersSetupKey,
		lookup: impl Fn(usize, usize) -> Result<Vec<Self::StaticChunk>, ()>,
	) -> Self::Intermediate;

	/// Introduce a new `Member` into the intermediate value used to build a new `Members` value.
	fn push_member(
		intermediate: &mut Self::Intermediate,
		who: Self::Member,
		lookup: impl Fn(usize) -> Result<Self::StaticChunk, ()>,
	) -> Result<(), ()>;
	// push_members
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
	fn open(
		member: &Self::Member,
		members_iter: impl Iterator<Item = Self::Member>,
	) -> Result<Self::Commitment, ()>;

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
	) -> Result<(Self::Proof, Alias), ()>;

	/// Make a non-anonymous signature of `message` using `secret`.
	fn sign(_secret: &Self::Secret, _message: &[u8]) -> Result<Self::Signature, ()> {
		Err(())
	}

	/// Check whether `self` is a valid proof of membership in `members` in the given `context`;
	/// if so, ensure that the member is necessarily associated with `alias` in this `context` and
	/// that they elected to opine `message`.
	fn is_valid(
		proof: &Self::Proof,
		members: &Self::Members,
		context: &[u8],
		alias: &Alias,
		message: &[u8],
	) -> bool {
		match Self::validate(proof, members, context, message) {
			Ok(a) => &a == alias,
			Err(()) => false,
		}
	}

	/// Like `is_valid`, but `alias` is returned, not provided.
	fn validate(
		_proof: &Self::Proof,
		_members: &Self::Members,
		_context: &[u8],
		_message: &[u8],
	) -> Result<Alias, ()> {
		Err(())
	}

	fn verify_signature(
		_signature: &Self::Signature,
		_message: &[u8],
		_member: &Self::Member,
	) -> bool {
		false
	}
}

// This is just a convenience struct to help manage some of the witness data. No need to look at it.
#[derive(Clone, Eq, PartialEq, Encode, Decode, Debug, TypeInfo)]
pub struct Receipt<Gen: GenerateVerifiable> {
	proof: Gen::Proof,
	alias: Alias,
	message: Vec<u8>,
}

impl<Gen: GenerateVerifiable> Receipt<Gen> {
	pub fn create<'a>(
		secret: &Gen::Secret,
		members: impl Iterator<Item = Gen::Member>,
		context: &[u8],
		message: Vec<u8>,
	) -> Result<Self, ()>
	where
		Gen::Member: 'a,
	{
		let commitment = Gen::open(&Gen::member_from_secret(secret), members)?;
		let (proof, alias) = Gen::create(commitment, secret, context, &message)?;
		Ok(Self {
			proof,
			alias,
			message,
		})
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
	pub fn verify(self, members: &Gen::Members, context: &[u8]) -> Result<(Alias, Vec<u8>), Self> {
		match Gen::validate(&self.proof, members, context, &self.message) {
			Ok(alias) => Ok((alias, self.message)),
			Err(()) => {
				if self.is_valid(members, context) {
					Ok(self.into_parts())
				} else {
					Err(self)
				}
			}
		}
	}
	pub fn is_valid(&self, members: &Gen::Members, context: &[u8]) -> bool {
		Gen::is_valid(&self.proof, members, context, &self.alias, &self.message)
	}
}
