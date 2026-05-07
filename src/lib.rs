#![cfg_attr(not(feature = "std"), no_std)]
#![allow(clippy::result_unit_err)]

extern crate alloc;
extern crate core;

use alloc::vec::Vec;

use core::{fmt::Debug, ops::Range};
use parity_scale_codec::{Decode, DecodeWithMemTracking, Encode, FullCodec, MaxEncodedLen};
use scale_info::*;

#[cfg(feature = "mock")]
pub mod mock;
pub mod ring;

// Fixed types:

/// Cryptographic identifier for a person within a specific application which deals with people.
/// The underlying crypto should guarantee that all `Alias` values used by a person to represent
/// themself for each `Context` are unlinkable from both their underlying `PersonalId` as well as
/// all other `Alias` values of theirs.
pub type Alias = [u8; 32];

/// Entropy supplied for the creation of a secret key.
pub type Entropy = [u8; 32];

/// A single item in a batch proof validation request.
///
/// Groups together a proof with the context and message it was created for,
/// so that multiple proofs can be validated in a single batch operation via
/// [`GenerateVerifiable::batch_validate`].
#[derive(Clone)]
pub struct BatchProofItem<Proof> {
	/// The ring VRF proof to validate.
	pub proof: Proof,
	/// The context under which the proof was created.
	pub context: Vec<u8>,
	/// The message that was signed.
	pub message: Vec<u8>,
}

// The trait. This (alone) must be implemented in its entirely by the Ring-VRF.

/// Trait allowing cryptographic proof of membership of a set with known members under multiple
/// contexts without exposing the underlying member who is proving it and giving an unlinkable
/// deterministic pseudonymic "alias" under each context.
///
/// A value of this type represents a proof. It can be created using the `Self::create` function
/// from the `Self::Secret` value associated with a `Self::Member` value who exists within a set of
/// members identified with a `Self::Members` value. It can later be validated with the
/// `Self::is_valid` function using `self` together with the same information used to create it
/// (except the secret, of course!).
///
/// A convenience [`Receipt`] type is provided for typical use cases which bundles the proof along
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

	/// A proof of membership in a group, verifiable against `Members`.
	///
	/// Created via the two-step `open`/`create` flow. The verifier learns only the
	/// context-specific `Alias` and the message, not which `Member` produced it.
	///
	/// This is expected to be passed on-chain as a parameter, but never stored.
	type Proof: Clone + Eq + PartialEq + FullCodec + Debug + TypeInfo;

	/// A chunk of precomputed static data used by the `lookup` function when pushing members.
	///
	/// For ring VRF implementations, this is typically a G1 affine point from the SRS.
	type StaticChunk: Clone + Eq + PartialEq + FullCodec + Debug + TypeInfo + MaxEncodedLen;

	/// The capacity type used to parametrize ring operations.
	type Capacity: Clone + Copy;

	/// A signature attributable to a specific `Member`, verifiable against that member's
	/// public key.
	///
	/// Created via `sign`, verified via `verify_signature`.
	type Signature: Clone + Eq + PartialEq + FullCodec + Debug + TypeInfo;

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
	#[cfg(feature = "prover")]
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
	///   are unlinkable.
	///
	/// NOTE: We never expect to use this code on-chain; it should be used only in the wallet.
	///
	/// **WARNING**: This function may panic if called from on-chain or an environment not
	/// implementing the functionality.
	#[cfg(feature = "prover")]
	fn create(
		commitment: Self::Commitment,
		secret: &Self::Secret,
		context: &[u8],
		message: &[u8],
	) -> Result<(Self::Proof, Alias), ()> {
		let (proof, aliases) = Self::create_multi_context(commitment, secret, &[context], message)?;
		Ok((proof, aliases[0]))
	}

	/// Works like [`Self::create`] but takes multiple contexts as an input and returns aliases
	/// corresponding to these contexts.
	///
	/// Calling it will have the same effect as running [`Self::create`] multiple times on each
	/// `context` from the `contexts` but additionally the proof will guarantee that all these
	/// aliases are derived from the correponding contexts using the same `secret`.
	#[cfg(feature = "prover")]
	fn create_multi_context(
		commitment: Self::Commitment,
		secret: &Self::Secret,
		contexts: &[&[u8]],
		message: &[u8],
	) -> Result<(Self::Proof, Vec<Alias>), ()>;

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

	/// Check whether `proof` is a valid proof of membership in `members` in every `context` from the given `contexts`;
	/// if so, ensure that the member is necessarily associated with corresponding `alias` from the given `aliases` in this `context` and
	/// that they elected to opine `message`.
	fn is_valid_multi_context(
		capacity: Self::Capacity,
		proof: &Self::Proof,
		members: &Self::Members,
		contexts: &[&[u8]],
		aliases: &[Alias],
		message: &[u8],
	) -> bool {
		match Self::validate_multi_context(capacity, proof, members, contexts, message) {
			Ok(a) => a == aliases,
			Err(()) => false,
		}
	}

	/// Generate the alias a `secret` would have in a given `context`.
	fn alias_in_context(secret: &Self::Secret, context: &[u8]) -> Result<Alias, ()>;

	/// Like `is_valid`, but `alias` is returned, not provided.
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

	/// Like `is_valid_multi_context`, but aliases are returned, not provided.
	fn validate_multi_context(
		capacity: Self::Capacity,
		proof: &Self::Proof,
		members: &Self::Members,
		contexts: &[&[u8]],
		message: &[u8],
	) -> Result<Vec<Alias>, ()>;

	/// Check whether all of the proofs in this batch are valid, returning the `Alias` for each one,
	/// in order of input.
	///
	/// Currently only supports single-context proofs. Multi-context proofs should be
	/// validated individually via [`Self::validate_multi_context`].
	fn batch_validate(
		capacity: Self::Capacity,
		members: &Self::Members,
		proofs: &[BatchProofItem<Self::Proof>],
	) -> Result<Vec<Alias>, ()> {
		proofs
			.iter()
			.map(|item| {
				Self::validate(capacity, &item.proof, members, &item.context, &item.message)
			})
			.collect()
	}

	/// Check whether `member` is a valid encoded public key for this scheme.
	fn is_member_valid(member: &Self::Member) -> bool;

	/// Make a non-anonymous signature of `message` using `secret`.
	fn sign(secret: &Self::Secret, message: &[u8]) -> Result<Self::Signature, ()>;

	/// Verify a non-anonymous signature of `message` against the given `member`'s public key.
	fn verify_signature(signature: &Self::Signature, message: &[u8], member: &Self::Member)
	-> bool;
}

/// Convenience wrapper bundling a proof with its associated alias and message.
///
/// Provides a simpler API for the common create-then-verify workflow via
/// [`Receipt::create`] and [`Receipt::verify`].
#[derive(Clone, Eq, PartialEq, Encode, Decode, Debug, TypeInfo, DecodeWithMemTracking)]
pub struct Receipt<Gen: GenerateVerifiable> {
	proof: Gen::Proof,
	alias: Alias,
	message: Vec<u8>,
}

impl<Gen: GenerateVerifiable> Receipt<Gen> {
	/// Create a receipt by opening a commitment and producing a proof in one step.
	///
	/// Combines [`GenerateVerifiable::open`] and [`GenerateVerifiable::create`].
	#[cfg(feature = "prover")]
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
	/// Returns the alias associated with this receipt.
	pub fn alias(&self) -> &Alias {
		&self.alias
	}
	/// Returns the message associated with this receipt.
	pub fn message(&self) -> &[u8] {
		&self.message
	}
	/// Consume the receipt and return the alias and message.
	pub fn into_parts(self) -> (Alias, Vec<u8>) {
		(self.alias, self.message)
	}
	/// Verify the receipt against the given `members` set and `context`.
	///
	/// On success, returns the validated alias and message. On failure, returns
	/// the receipt back so it can be inspected or retried.
	pub fn verify(
		self,
		capacity: Gen::Capacity,
		members: &Gen::Members,
		context: &[u8],
	) -> Result<(Alias, Vec<u8>), Self> {
		match Gen::validate(capacity, &self.proof, members, context, &self.message) {
			Ok(alias) => Ok((alias, self.message)),
			Err(()) => Err(self),
		}
	}
	/// Check whether this receipt contains a valid proof for the given `members` and `context`.
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
