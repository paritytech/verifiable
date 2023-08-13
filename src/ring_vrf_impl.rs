use super::*;
use core::{
	fmt::Debug,
	marker::PhantomData,
};
use parity_scale_codec::{Decode, Encode, FullCodec, MaxEncodedLen};
use scale_info::*;
use ark_scale::ArkScale;
use bandersnatch_vrfs::{
	SecretKey, PublicKey, RingVrfSignature, ring,
	CanonicalSerialize,CanonicalDeserialize,SerializationError, // ark_serialize::
};
use alloc::vec::Vec;
use core::fmt;
use derive_where::derive_where;

// A hack that moves the .
pub trait Web3SumKZG: 'static {
	fn kzg_bytes() -> &'static [u8];
	fn kzg() -> &'static ring::KZG {
		// TODO: Find a no_std analog.  Check it supports multiple setups.
		use std::sync::OnceLock;
		static CELL: OnceLock<ring::KZG> = OnceLock::new();
		CELL.get_or_init(|| {
			<ring::KZG as CanonicalDeserialize>::deserialize_compressed(Self::kzg_bytes()).unwrap()
		})
	}
}

pub struct Test2e10;

impl Web3SumKZG for Test2e10 {
	fn kzg_bytes() -> &'static [u8] {
        &b"Hello"[..]
//		include_bytes!("testing.kzg")
	}
}

#[derive(Encode, Decode, TypeInfo, MaxEncodedLen)]
#[derive_where(Clone, Eq, PartialEq, Debug)]
#[scale_info(skip_type_params(KZG))]
pub struct BandersnatchRingVRF<KZG: 'static>(
	ArkScale<RingVrfSignature<1>>,
	PhantomData<fn() -> &'static KZG>
);

/*impl<KZG> fmt::Debug for BandersnatchRingVRF<KZG> {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		write!(f, "BandersnatchRingVRF({:?})", self.0)
	}
}*/

fn do_input(context: &[u8]) -> bandersnatch_vrfs::VrfInput {
	use bandersnatch_vrfs::IntoVrfInput;
    bandersnatch_vrfs::Message {
		domain: b"Polkadot Fellowship Alias : Input",
		message: context
	}.into_vrf_input()
}

fn do_output(out: [bandersnatch_vrfs::VrfInOut; 1]) -> Alias {
	out[0].vrf_output_bytes(b"Polkadot Fellowship Alias : Output")
} 

impl<KZG: Web3SumKZG> Verifiable for BandersnatchRingVRF<KZG> {

//	fn unverified_alias(&self, context: &[u8]) -> Alias {
//		self.0.preoutputs[0]
//	}

	type Secret = SecretKey;
	type Member = [u8; 33];

	fn new_secret(entropy: Entropy) -> Self::Secret {
		SecretKey::from_seed(&entropy)
	}
	fn member_from_secret(secret: &Self::Secret) -> Self::Member {
		secret.to_public().serialize()
	}

	/// TODO: Interface #2 would make this sane.
	type Intermediate = ArkScale<Vec<bandersnatch_vrfs::bandersnatch::SWAffine>>;

	type Members = ArkScale<bandersnatch_vrfs::ring::VerifierKey>;

	fn start_members() -> Self::Intermediate {
		ArkScale(Vec::with_capacity( KZG::kzg().max_keyset_size() ))
	}
	fn push_member(inter: &mut Self::Intermediate, who: Self::Member) -> Result<(),()> {
        if inter.0.len() == KZG::kzg().max_keyset_size() { return Err(()); }
		let pk = PublicKey::deserialize(&who[..]).map_err(|_| ()) ?;
		inter.0.push(pk.0.0);
		Ok(())
	}
	fn finish_members(inter: Self::Intermediate) -> Self::Members {
		//if inter.0.len() > KZG::kzg().max_keyset_size() { return Err(()); }
        // This is guaranteed in `push_member`.
        // In theory, our ring-prover should pad the KZG but sergey has blatantly
		// insecure padding right now:
		// https://github.com/w3f/ring-proof/blob/master/ring/src/piop/params.rs#L56
        ArkScale(KZG::kzg().verifier_key(inter.0))
	}

	fn validate(
		&self,
		members: &Self::Members,
		context: &[u8],
		message: &[u8],
	) -> Result<Alias, ()> {
        let ring_verifier = KZG::kzg().init_ring_verifier(members.0.clone());
 		self.0.0.verify_ring_vrf(message, core::iter::once(do_input(context)), &ring_verifier)
		.map(do_output).map_err(|x| { let r: Result<Alias, _> = Err(x); r.unwrap(); () })
	}

    ///
	type Commitment = (u32, ArkScale<bandersnatch_vrfs::ring::ProverKey>);

	fn open<'a>(
		myself: &Self::Member,
		members: impl Iterator<Item = &'a Self::Member>,
	) -> Result<Self::Commitment, ()>
	where
		Self::Member: 'a,
	{
		let max_len: u32 = KZG::kzg().max_keyset_size().try_into().expect("Impossibly large a KZG, qed");
		let mut i = 0u32;
		let mut me = u32::MAX;
		// #![feature(iterator_try_collect)]
		let mut pks = Vec::with_capacity(members.size_hint().0);
		for member in members {
            if i >= max_len { return Err(()); }
			if myself == member { me = i }
			pks.push(PublicKey::deserialize(&member[..]).map_err(|_| ())?.0.0);
			i += 1;
		}
		if me == u32::MAX { return Err(()); }
		Ok(( me, ArkScale(KZG::kzg().prover_key(pks)) ))
	}

	fn create(
		// Sergey TODO: This should be a borrow but ring-prover still consumes it.
		(me, members): Self::Commitment,
		secret: &Self::Secret,
		context: &[u8],
		message: &[u8],
	) -> Result<(Self, Alias), ()> {
		assert!((me as usize) < KZG::kzg().max_keyset_size());
		let io: [_; 1] = [secret.0.vrf_inout(do_input(context))];
        let ring_prover = KZG::kzg().init_ring_prover(members.0, me as usize);
        let signature: RingVrfSignature<1> = secret.sign_ring_vrf(message, &io, &ring_prover);
        Ok(( BandersnatchRingVRF(ArkScale(signature),PhantomData), do_output(io) ))
	}
}
