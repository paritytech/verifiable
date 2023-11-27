use super::*;
use alloc::vec::Vec;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use bandersnatch_vrfs::{
    ring,
    scale::{ArkScale, EncodeLike},
    PublicKey, RingProver, RingVerifier, RingVrfSignature, SecretKey,
};
use core::marker::PhantomData;
use derive_where::derive_where;
use parity_scale_codec::{Decode, Encode, MaxEncodedLen};

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
        include_bytes!("test2e10.kzg")
    }
}

#[derive(Encode, Decode, TypeInfo, MaxEncodedLen)]
#[derive_where(Clone, Eq, PartialEq, Debug)]
#[scale_info(skip_type_params(KZG))]
pub struct BandersnatchRingVRF<KZG: 'static>(PhantomData<fn() -> &'static KZG>);

/*impl<KZG> fmt::Debug for BandersnatchRingVRF<KZG> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "BandersnatchRingVRF({:?})", self.0)
    }
}*/

fn do_input(context: &[u8]) -> bandersnatch_vrfs::VrfInput {
    use bandersnatch_vrfs::IntoVrfInput;
    bandersnatch_vrfs::Message {
        domain: b"Polkadot Fellowship Alias : Input",
        message: context,
    }
    .into_vrf_input()
}

fn do_output(out: [bandersnatch_vrfs::VrfInOut; 1]) -> Alias {
    out[0].vrf_output_bytes(b"Polkadot Fellowship Alias : Output")
}

#[derive(Debug, Clone, Eq, PartialEq, CanonicalDeserialize, CanonicalSerialize)]
pub struct MembersSet(pub Vec<bandersnatch_vrfs::bandersnatch::SWAffine>);

ark_scale::impl_scale_via_ark!(MembersSet);

impl MaxEncodedLen for MembersSet {
    fn max_encoded_len() -> usize {
        // TODO: Sergey please fix this
        32 * 1024 // Based upon maximum set size of 2^10
    }
}

// TODO: Sergey, Ain't clear if ring::VerifierKey was properly
// designed for serialization.
//
// TODO: Sergey, Add Debug + Eq + PartialEq if they make sense
#[derive(Clone, CanonicalDeserialize, CanonicalSerialize)]
pub struct MemberCommitment(bandersnatch_vrfs::ring::VerifierKey);

use core::fmt;
impl fmt::Debug for MemberCommitment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "MemberCommitment")
    }
}

ark_scale::impl_scale_via_ark!(MemberCommitment);

impl MaxEncodedLen for MemberCommitment {
    fn max_encoded_len() -> usize {
        // TODO: Sergey please fix this
        4096
    }
}

impl<KZG: Web3SumKZG> GenerateVerifiable for BandersnatchRingVRF<KZG> {
    //	fn unverified_alias(&self, context: &[u8]) -> Alias {
    //		self.0.preoutputs[0]
    //	}

    // TODO davxy: why not BoundedVec<Member, N>;
    type Members = MemberCommitment;
    type Intermediate = MembersSet;
    type Member = [u8; 33];
    type Secret = SecretKey;
    type Commitment = (u32, bandersnatch_vrfs::ring::ProverKey);
    type Proof = RingVrfSignature<1>;

    fn new_secret(entropy: Entropy) -> Self::Secret {
        SecretKey::from_seed(&entropy)
    }

    fn member_from_secret(secret: &Self::Secret) -> Self::Member {
        bandersnatch_vrfs::serialize_publickey(&secret.to_public())
    }

    fn start_members() -> Self::Intermediate {
        MembersSet(Vec::with_capacity(KZG::kzg().max_keyset_size()))
    }

    fn push_member(inter: &mut Self::Intermediate, who: Self::Member) -> Result<(), ()> {
        if inter.0.len() == KZG::kzg().max_keyset_size() {
            return Err(());
        }
        let pk = PublicKey::deserialize(&who[..]).map_err(|_| ())?;
        inter.0.push(pk.0);
        Ok(())
    }

    fn finish_members(inter: Self::Intermediate) -> Self::Members {
        //if inter.0.len() > KZG::kzg().max_keyset_size() { return Err(()); }
        // This is guaranteed in `push_member`.
        // In theory, our ring-prover should pad the KZG but sergey has blatantly
        // insecure padding right now:
        // https://github.com/w3f/ring-proof/blob/master/ring/src/piop/params.rs#L56
        MemberCommitment(KZG::kzg().verifier_key(inter.0))
    }

    fn validate(
        proof: &Self::Proof,
        members: &Self::Members,
        context: &[u8],
        message: &[u8],
    ) -> Result<Alias, ()> {
        let ring_verifier = KZG::kzg().init_ring_verifier(members.0.clone());
        RingVerifier(&ring_verifier)
            .verify_ring_vrf(message, core::iter::once(do_input(context)), &proof)
            .map(do_output)
            .map_err(|x| {
                let r: Result<Alias, _> = Err(x);
                r.unwrap();
                ()
            })
    }

    fn open<'a>(
        myself: &Self::Member,
        members: impl Iterator<Item = &'a Self::Member>,
    ) -> Result<Self::Commitment, ()>
    where
        Self::Member: 'a,
    {
        let max_len: u32 = KZG::kzg()
            .max_keyset_size()
            .try_into()
            .expect("Impossibly large a KZG, qed");
        let mut i = 0u32;
        let mut me = u32::MAX;
        // #![feature(iterator_try_collect)]
        let mut pks = Vec::with_capacity(members.size_hint().0);
        for member in members {
            if i >= max_len {
                return Err(());
            }
            if myself == member {
                me = i
            }
            pks.push(PublicKey::deserialize(&member[..]).map_err(|_| ())?.0);
            i += 1;
        }
        if me == u32::MAX {
            return Err(());
        }
        Ok((me, KZG::kzg().prover_key(pks)))
    }

    fn create(
        // Sergey TODO: This should be a borrow but ring-prover still consumes it.
        (me, members): Self::Commitment,
        secret: &Self::Secret,
        context: &[u8],
        message: &[u8],
    ) -> Result<(Self::Proof, Alias), ()> {
        assert!((me as usize) < KZG::kzg().max_keyset_size());
        let io: [_; 1] = [secret.vrf_inout(do_input(context))];
        let ring_prover = KZG::kzg().init_ring_prover(members, me as usize);
        let signature: RingVrfSignature<1> = RingProver {
            ring_prover: &ring_prover,
            secret,
        }
        .sign_ring_vrf(message, &io);
        Ok((signature, do_output(io)))
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use core::iter;
    use rand_core::{OsRng, RngCore};

    fn random_bytes<const N: usize>() -> [u8; N] {
        let mut entropy = [0u8; N];
        OsRng.fill_bytes(&mut entropy);
        entropy
    }

    type BRVRF = BandersnatchRingVRF<Test2e10>;
    type Member = [u8; 33];

    fn random_keypair() -> (Member, SecretKey) {
        let secret = BRVRF::new_secret(random_bytes());
        (BRVRF::member_from_secret(&secret), secret)
    }

    fn random_ring() -> Vec<Member> {
        let len = Test2e10::kzg().max_keyset_size();
        let len = usize::from_le_bytes(random_bytes()) % len;
        let mut v = Vec::with_capacity(len);
        for _ in 0..len {
            v.push(random_keypair().0);
        }
        v
    }

    #[test]
    fn send_n_recieve() {
        let (me, secret) = random_keypair();

        // Random ring including me.
        let mut ring = random_ring();
        let idx = ring.len() / 2;
        ring[idx] = me;

        let context = random_bytes::<32>();
        let message = random_bytes::<1024>();

        // Sign
        let opening = BRVRF::open(&me, ring.iter()).unwrap();
        let (signature, alias1) = BRVRF::create(opening, &secret, &context, &message).unwrap();

        // Serialize+Deserialize
        let signature = signature.encode();
        let signature =
            <BRVRF as GenerateVerifiable>::Proof::decode(&mut signature.as_slice()).unwrap();

        // Verify
        let mut inter = BRVRF::start_members();
        for m in &ring {
            BRVRF::push_member(&mut inter, m.clone()).unwrap();
        }
        let members = BRVRF::finish_members(inter);
        let alias2 = BRVRF::validate(&signature, &members, &context, &message).unwrap();
        assert_eq!(alias1, alias2);
    }
}
