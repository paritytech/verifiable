use crate::ring::{Bls12_381RingData, RingSuiteExt, RingVrfVerifiable};
use ark_vrf::suites::bandersnatch::{BandersnatchSha512Ell2, RingProofParams};

#[cfg(any(feature = "std", feature = "no-std-prover"))]
use crate::ring::{make_ring_prover_params, RingDomainSize, RingProofParamsCache};

/// Bandersnatch ring VRF Verifiable (BandersnatchSha512Ell2 suite).
pub type BandersnatchVrfVerifiable = RingVrfVerifiable<BandersnatchSha512Ell2>;

#[cfg(any(feature = "std", feature = "no-std-prover"))]
pub struct BandersnatchParamsCache;

#[cfg(any(feature = "std", feature = "no-std-prover"))]
impl RingProofParamsCache<BandersnatchSha512Ell2> for BandersnatchParamsCache {
	type Handle = &'static ark_vrf::ring::RingProofParams<BandersnatchSha512Ell2>;

	fn get(domain_size: RingDomainSize) -> Self::Handle {
		use spin::Once;
		static D11: Once<RingProofParams> = Once::new();
		static D12: Once<RingProofParams> = Once::new();
		static D16: Once<RingProofParams> = Once::new();
		match domain_size {
			RingDomainSize::Domain11 => D11.call_once(|| make_ring_prover_params(domain_size)),
			RingDomainSize::Domain12 => D12.call_once(|| make_ring_prover_params(domain_size)),
			RingDomainSize::Domain16 => D16.call_once(|| make_ring_prover_params(domain_size)),
		}
	}
}

impl RingSuiteExt for ark_vrf::suites::bandersnatch::BandersnatchSha512Ell2 {
	const PUBLIC_KEY_SIZE: usize = 32;
	const MEMBERS_SET_SIZE: usize = 432;
	const MEMBERS_COMMITMENT_SIZE: usize = 384;
	const STATIC_CHUNK_SIZE: usize = 48;
	const RING_PROOF_SIZE: usize = 788;
	const SIGNATURE_SIZE: usize = 96;

	type CurveData = Bls12_381RingData;

	type PublicKeyBytes = [u8; Self::PUBLIC_KEY_SIZE];
	type RingProofBytes = [u8; Self::RING_PROOF_SIZE];
	type SignatureBytes = [u8; Self::SIGNATURE_SIZE];

	#[cfg(any(feature = "std", feature = "no-std-prover"))]
	type ParamsCache = BandersnatchParamsCache;
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::GenerateVerifiable;

	#[test]
	fn test_plain_signature() {
		let msg = b"asd";
		let secret = BandersnatchVrfVerifiable::new_secret([0; 32]);
		let public = BandersnatchVrfVerifiable::member_from_secret(&secret);
		let signature = BandersnatchVrfVerifiable::sign(&secret, msg).unwrap();
		let res = BandersnatchVrfVerifiable::verify_signature(&signature, msg, &public);
		assert!(res);
	}

	#[test]
	fn test_is_member_valid_invalid() {
		let invalid_member = [0u8; 32];
		assert!(!BandersnatchVrfVerifiable::is_member_valid(&invalid_member));
	}

	#[test]
	fn test_is_member_valid_valid() {
		let secret = BandersnatchVrfVerifiable::new_secret([42u8; 32]);
		let valid_member = BandersnatchVrfVerifiable::member_from_secret(&secret);
		assert!(BandersnatchVrfVerifiable::is_member_valid(&valid_member));
	}
}
