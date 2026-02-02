#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;
extern crate core;

use alloc::vec::Vec;

use core::{fmt::Debug, ops::Range};
use parity_scale_codec::{Decode, DecodeWithMemTracking, Encode, FullCodec, MaxEncodedLen};
use scale_info::*;

pub mod demo_impls;
pub mod ring_vrf_impl;

/// Trait for capacity types used in ring operations.
///
/// The capacity determines the maximum ring size that can be supported.
pub trait Capacity: Clone + Copy {
	/// Returns the maximum ring size for this capacity.
	fn size(&self) -> usize;
}

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
	/// Consolidated value identifying a particular set of members. Corresponds to the Ring Root.
	///
	/// This is envisioned to be stored on-chain and passed between chains.
	type Members: Clone + Eq + PartialEq + FullCodec + Debug + TypeInfo + MaxEncodedLen;
	/// Intermediate value while building a `Self::Members` value. Probably just an unfinished Ring
	/// Root(?).
	///
	/// This is envisioned to be stored on-chain.
	type Intermediate: Clone + Eq + PartialEq + FullCodec + Debug + TypeInfo + MaxEncodedLen;
	/// Encoded value identifying a single member. Corresponds to the user representation of a Public Key.
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

	type StaticChunk: Clone + Eq + PartialEq + FullCodec + Debug + TypeInfo + MaxEncodedLen;

	/// The capacity type used to parametrize ring operations.
	/// Must implement the `Capacity` trait which provides `size()`.
	type Capacity: Clone + Copy + Capacity;

	/// Begin building a `Members` value.
	fn start_members(capacity: Self::Capacity) -> Self::Intermediate;

	/// Introduce a set of new `Member`s into the intermediate value used to build a new `Members`
	/// value.
	///
	/// An error is returned if at least one member failed to be pushed. This happens in those
	/// situations:
	/// * the maximum capacity has already been reached
	/// * the member is already part of the set
	/// * the member is invalid (can be checked with `is_member_valid`)
	/// * the lookup function is invalid
	fn push_members(
		intermediate: &mut Self::Intermediate,
		members: impl Iterator<Item = Self::Member>,
		lookup: impl Fn(Range<usize>) -> Result<Vec<Self::StaticChunk>, ()>,
	) -> Result<(), ()>;

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
	///
	/// **WARNING**: This function may panic if called from on-chain or an environment not
	/// implementing the functionality.
	#[cfg(any(feature = "std", feature = "no-std-prover"))]
	fn open(
		capacity: Self::Capacity,
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
	///
	/// **WARNING**: This function may panic if called from on-chain or an environment not
	/// implementing the functionality.
	#[cfg(any(feature = "std", feature = "no-std-prover"))]
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
		capacity: Self::Capacity,
		proof: &Self::Proof,
		members: &Self::Members,
		context: &[u8],
		alias: &Alias,
		message: &[u8],
	) -> bool {
		match Self::validate(capacity, proof, members, context, message) {
			Ok(a) => &a == alias,
			Err(()) => false,
		}
	}

	/// Generate the alias a `secret` would have in a given `context`.
	fn alias_in_context(secret: &Self::Secret, context: &[u8]) -> Result<Alias, ()>;

	/// Like `is_valid`, but `alias` is returned, not provided.
	fn validate(
		_capacity: Self::Capacity,
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

	fn is_member_valid(_member: &Self::Member) -> bool;
}

// This is just a convenience struct to help manage some of the witness data. No need to look at it.
#[derive(Clone, Eq, PartialEq, Encode, Decode, Debug, TypeInfo, DecodeWithMemTracking)]
pub struct Receipt<Gen: GenerateVerifiable> {
	proof: Gen::Proof,
	alias: Alias,
	message: Vec<u8>,
}

impl<Gen: GenerateVerifiable> Receipt<Gen> {
	#[cfg(any(feature = "std", feature = "no-std-prover"))]
	pub fn create<'a>(
		capacity: Gen::Capacity,
		secret: &Gen::Secret,
		members: impl Iterator<Item = Gen::Member>,
		context: &[u8],
		message: Vec<u8>,
	) -> Result<Self, ()>
	where
		Gen::Member: 'a,
	{
		let commitment = Gen::open(capacity, &Gen::member_from_secret(secret), members)?;
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
	pub fn verify(
		self,
		capacity: Gen::Capacity,
		members: &Gen::Members,
		context: &[u8],
	) -> Result<(Alias, Vec<u8>), Self> {
		match Gen::validate(capacity, &self.proof, members, context, &self.message) {
			Ok(alias) => Ok((alias, self.message)),
			Err(()) => {
				if self.is_valid(capacity, members, context) {
					Ok(self.into_parts())
				} else {
					Err(self)
				}
			}
		}
	}
	pub fn is_valid(
		&self,
		capacity: Gen::Capacity,
		members: &Gen::Members,
		context: &[u8],
	) -> bool {
		Gen::is_valid(
			capacity,
			&self.proof,
			members,
			context,
			&self.alias,
			&self.message,
		)
	}
}
