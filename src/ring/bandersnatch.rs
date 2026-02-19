use crate::ring::{Bls12_381Params, RingSuiteExt, RingVrfVerifiable};
use ark_vrf::suites::bandersnatch::{BandersnatchSha512Ell2, RingProofParams};

#[cfg(feature = "prover")]
use crate::ring::{make_ring_prover_params, RingDomainSize, RingProofParamsCache};

/// Bandersnatch ring VRF Verifiable (BandersnatchSha512Ell2 suite).
pub type BandersnatchVrfVerifiable = RingVrfVerifiable<BandersnatchSha512Ell2>;

#[cfg(feature = "prover")]
pub struct BandersnatchParamsCache;

#[cfg(feature = "prover")]
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
	const VRF_INPUT_DOMAIN: &[u8] = b"VerifiableBandersnatchVrfInput";

	const PUBLIC_KEY_SIZE: usize = 32;
	const MEMBERS_SET_SIZE: usize = 432;
	const MEMBERS_COMMITMENT_SIZE: usize = 384;
	const STATIC_CHUNK_SIZE: usize = 48;
	const RING_PROOF_SIZE: usize = 788;
	const SIGNATURE_SIZE: usize = 96;

	type CurveParams = Bls12_381Params;

	type PublicKeyBytes = [u8; Self::PUBLIC_KEY_SIZE];
	type RingProofBytes = [u8; Self::RING_PROOF_SIZE];
	type SignatureBytes = [u8; Self::SIGNATURE_SIZE];

	#[cfg(feature = "prover")]
	type ParamsCache = BandersnatchParamsCache;
}

#[cfg(test)]
mod tests {
	use ark_scale::MaxEncodedLen;
	use ark_serialize::CanonicalSerialize;
	use ark_vrf::ring::SrsLookup;

	use super::*;
	use crate::{ring::RingSize, Capacity, GenerateVerifiable};

	// Type aliases for Bandersnatch-specific generic types
	pub type MembersSet = crate::ring::MembersSet<BandersnatchSha512Ell2>;
	pub type MembersCommitment = crate::ring::MembersCommitment<BandersnatchSha512Ell2>;
	pub type PublicKey = crate::ring::PublicKey<BandersnatchSha512Ell2>;
	pub type StaticChunk = crate::ring::StaticChunk<BandersnatchSha512Ell2>;

	type RingBuilderPcsParams = ark_vrf::ring::RingBuilderPcsParams<BandersnatchSha512Ell2>;

	pub fn bandersnatch_ring_prover_params(
		domain_size: RingDomainSize,
	) -> &'static ark_vrf::suites::bandersnatch::RingProofParams {
		<BandersnatchSha512Ell2 as RingSuiteExt>::ParamsCache::get(domain_size)
	}

	pub fn start_members_from_params(
		domain_size: RingDomainSize,
	) -> (MembersSet, RingBuilderPcsParams) {
		let (builder, builder_pcs_params) =
			bandersnatch_ring_prover_params(domain_size).verifier_key_builder();
		(crate::ring::MembersSet(builder), builder_pcs_params)
	}

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

	#[test]
	fn ring_size_check() {
		const DOM_TO_RING_SIZE_MAP: [(RingDomainSize, usize); 3] = [
			(RingDomainSize::Domain11, 255),
			(RingDomainSize::Domain12, 767),
			(RingDomainSize::Domain16, 16127),
		];
		for (dom_size, exp_ring_size) in DOM_TO_RING_SIZE_MAP {
			let ring_size = RingSize::<BandersnatchSha512Ell2>::from(dom_size);
			assert_eq!(ring_size.size(), exp_ring_size);
		}
	}

	/// Verify that the size constants in `RingSuiteExt` match actual serialized sizes.
	#[test]
	fn codec_assumptions_check() {
		use ark_vrf::suites::bandersnatch::BandersnatchSha512Ell2 as S;

		// PUBLIC_KEY_SIZE
		let secret = BandersnatchVrfVerifiable::new_secret([0u8; 32]);
		let public = BandersnatchVrfVerifiable::member_from_secret(&secret);
		let internal = BandersnatchVrfVerifiable::to_public_key(&public).unwrap();
		assert_eq!(internal.compressed_size(), S::PUBLIC_KEY_SIZE);
		assert_eq!(PublicKey::max_encoded_len(), S::PUBLIC_KEY_SIZE);

		// MEMBERS_SET_SIZE
		let members_set = BandersnatchVrfVerifiable::start_members(RingDomainSize::Domain11.into());
		assert_eq!(members_set.compressed_size(), S::MEMBERS_SET_SIZE);
		assert_eq!(MembersSet::max_encoded_len(), S::MEMBERS_SET_SIZE);

		// MEMBERS_COMMITMENT_SIZE
		let commitment = BandersnatchVrfVerifiable::finish_members(members_set);
		assert_eq!(commitment.compressed_size(), S::MEMBERS_COMMITMENT_SIZE);
		assert_eq!(
			MembersCommitment::max_encoded_len(),
			S::MEMBERS_COMMITMENT_SIZE
		);

		// STATIC_CHUNK_SIZE
		let (_, builder_params) = start_members_from_params(RingDomainSize::Domain11);
		let chunks: Vec<_> = (&builder_params).lookup(0..1).unwrap();
		let chunk: StaticChunk = crate::ring::StaticChunk(chunks[0]);
		assert_eq!(chunk.compressed_size(), S::STATIC_CHUNK_SIZE);
		assert_eq!(StaticChunk::max_encoded_len(), S::STATIC_CHUNK_SIZE);

		// SIGNATURE_SIZE
		let signature = BandersnatchVrfVerifiable::sign(&secret, b"test").unwrap();
		assert_eq!(signature.len(), S::SIGNATURE_SIZE);

		// RING_PROOF_SIZE
		let members: Vec<_> = (0..3)
			.map(|i| {
				let s = BandersnatchVrfVerifiable::new_secret([i as u8; 32]);
				BandersnatchVrfVerifiable::member_from_secret(&s)
			})
			.collect();
		let member = members[0].clone();
		let commitment = BandersnatchVrfVerifiable::open(
			RingDomainSize::Domain11.into(),
			&member,
			members.into_iter(),
		)
		.unwrap();
		let prover_secret = BandersnatchVrfVerifiable::new_secret([0u8; 32]);
		let (proof, _) =
			BandersnatchVrfVerifiable::create(commitment, &prover_secret, b"ctx", b"msg").unwrap();
		assert_eq!(proof.len(), S::RING_PROOF_SIZE);
	}
}

/// Tests that require the `builder-params` feature.
#[cfg(all(test, feature = "builder-params"))]
mod builder_tests {
	use crate::{ring::ring_verifier_builder_params, Capacity, GenerateVerifiable};

	use super::*;
	use ark_scale::MaxEncodedLen;
	use ark_serialize::CanonicalSerialize;
	use ark_vrf::{ring::SrsLookup, suites::bandersnatch::BandersnatchSha512Ell2};
	use parity_scale_codec::Encode;

	use tests::{
		bandersnatch_ring_prover_params, start_members_from_params, MembersCommitment, MembersSet,
		PublicKey,
	};

	pub type RingSize = crate::ring::RingSize<BandersnatchSha512Ell2>;

	/// Macro to generate test functions for all implemented domain sizes.
	///
	/// Usage:
	/// ```ignore
	/// test_for_all_domains!(test_name, |domain_size| {
	///     // test body using domain_size
	/// });
	/// ```
	macro_rules! test_for_all_domains {
		($test_name:ident, |$domain_size:ident| $body:block) => {
			paste::paste! {
				#[test]
				fn [<$test_name _domain11>]() {
					let $domain_size = RingDomainSize::Domain11;
					$body
				}

				#[test]
				fn [<$test_name _domain12>]() {
					let $domain_size = RingDomainSize::Domain12;
					$body
				}

				#[test]
				fn [<$test_name _domain16>]() {
					let $domain_size = RingDomainSize::Domain16;
					$body
				}
			}
		};
	}

	#[test]
	#[ignore = "srs generator"]
	fn generate_srs_from_full_zcash_srs() {
		use std::fs::File;
		use std::io::{Read, Write};

		const FULL_ZCASH_SRS_FILE: &str = concat!(
			env!("CARGO_MANIFEST_DIR"),
			"/src/ring/data/bls12-381/zcash-srs-2-16-uncompressed.bin"
		);
		const SRS_COMPRESSED_FILE: &str = concat!(
			env!("CARGO_MANIFEST_DIR"),
			"/src/ring/data/bls12-381/srs-compressed.bin"
		);
		const SRS_UNCOMPRESSED_FILE: &str = concat!(
			env!("CARGO_MANIFEST_DIR"),
			"/src/ring/data/bls12-381/srs-uncompressed.bin"
		);

		let mut buf = vec![];
		let mut file = File::open(FULL_ZCASH_SRS_FILE).unwrap();
		file.read_to_end(&mut buf).unwrap();
		println!("Full size: {}", buf.len());

		// Use Domain16 for SRS generation (largest domain)
		let full_params = bandersnatch_ring_prover_params(RingDomainSize::Domain16);

		let mut buf = vec![];
		full_params.serialize_compressed(&mut buf).unwrap();
		println!("Reduced size (compressed): {}", buf.len());
		let mut file = File::create(SRS_COMPRESSED_FILE).unwrap();
		file.write_all(&buf).unwrap();

		let mut buf = vec![];
		full_params.serialize_uncompressed(&mut buf).unwrap();
		println!("Reduced size (uncompressed): {}", buf.len());
		let mut file = File::create(SRS_UNCOMPRESSED_FILE).unwrap();
		file.write_all(&buf).unwrap();
	}

	// Run only if there are some breaking changes in the backend crypto and binaries
	// need to be re-generated.
	#[test]
	#[ignore = "ring builder generator - generates ring data for all domain sizes"]
	fn generate_empty_ring_builders() {
		use std::io::Write;

		/// All available domain sizes.
		const ALL: [RingDomainSize; 3] = [
			RingDomainSize::Domain11,
			RingDomainSize::Domain12,
			RingDomainSize::Domain16,
		];

		for domain_size in ALL {
			let (builder, builder_params) = start_members_from_params(domain_size);

			let builder_file = format!(
				"{}/src/ring/data/bls12-381/ring-builder-domain{}.bin",
				env!("CARGO_MANIFEST_DIR"),
				domain_size.as_power()
			);
			let params_file = format!(
				"{}/src/ring/data/bls12-381/ring-builder-params-domain{}.bin",
				env!("CARGO_MANIFEST_DIR"),
				domain_size.as_power()
			);

			let mut buf = Vec::with_capacity(builder.uncompressed_size());
			builder.serialize_uncompressed(&mut buf).unwrap();
			println!("Writing empty ring builder to: {}", builder_file);
			let mut file = std::fs::File::create(&builder_file).unwrap();
			file.write_all(&buf).unwrap();

			let mut buf = Vec::with_capacity(builder_params.0.uncompressed_size());
			builder_params.0.serialize_uncompressed(&mut buf).unwrap();
			println!("G1 len: {}", builder_params.0.len());
			println!("Writing ring builder params to: {}", params_file);
			let mut file = std::fs::File::create(&params_file).unwrap();
			file.write_all(&buf).unwrap();
		}
	}

	test_for_all_domains!(check_pre_constructed_ring_builder, |domain_size| {
		let ring_size = domain_size.into();
		let builder = BandersnatchVrfVerifiable::start_members(ring_size);
		let builder_params = ring_verifier_builder_params::<BandersnatchSha512Ell2>(domain_size);
		let (builder2, builder_params2) = start_members_from_params(domain_size);

		let mut buf1 = vec![];
		builder_params.0.serialize_uncompressed(&mut buf1).unwrap();
		let mut buf2 = vec![];
		builder_params2.0.serialize_uncompressed(&mut buf2).unwrap();
		assert_eq!(buf1, buf2);

		let mut buf1 = vec![];
		builder.serialize_uncompressed(&mut buf1).unwrap();
		let mut buf2 = vec![];
		builder2.serialize_uncompressed(&mut buf2).unwrap();
		assert_eq!(buf1, buf2);
	});

	test_for_all_domains!(check_precomputed_size, |domain_size| {
		let ring_size = domain_size.into();
		let secret = BandersnatchVrfVerifiable::new_secret([0u8; 32]);
		let public = BandersnatchVrfVerifiable::member_from_secret(&secret);
		let internal = BandersnatchVrfVerifiable::to_public_key(&public).unwrap();
		assert_eq!(internal.compressed_size(), PublicKey::max_encoded_len());

		let members = BandersnatchVrfVerifiable::start_members(ring_size);
		assert_eq!(members.compressed_size(), MembersSet::max_encoded_len());

		let commitment = BandersnatchVrfVerifiable::finish_members(members);
		assert_eq!(
			commitment.compressed_size(),
			MembersCommitment::max_encoded_len()
		);
	});

	test_for_all_domains!(start_push_finish, |domain_size| {
		let capacity: RingSize = domain_size.into();
		let alice_sec = BandersnatchVrfVerifiable::new_secret([0u8; 32]);
		let bob_sec = BandersnatchVrfVerifiable::new_secret([1u8; 32]);
		let charlie_sec = BandersnatchVrfVerifiable::new_secret([2u8; 32]);

		let alice = BandersnatchVrfVerifiable::member_from_secret(&alice_sec);
		let bob = BandersnatchVrfVerifiable::member_from_secret(&bob_sec);
		let charlie = BandersnatchVrfVerifiable::member_from_secret(&charlie_sec);

		let mut inter1 = BandersnatchVrfVerifiable::start_members(capacity);
		let mut inter2 = inter1.clone();
		let builder_params = ring_verifier_builder_params::<BandersnatchSha512Ell2>(domain_size);

		let get_many = |range| {
			(&builder_params)
				.lookup(range)
				.map(|v| {
					v.into_iter()
						.map(|i| crate::ring::StaticChunk(i))
						.collect::<Vec<_>>()
				})
				.ok_or(())
		};

		BandersnatchVrfVerifiable::push_members(
			&mut inter1,
			[alice.clone(), bob.clone(), charlie.clone()].into_iter(),
			get_many,
		)
		.unwrap();
		BandersnatchVrfVerifiable::push_members(&mut inter2, [alice.clone()].into_iter(), get_many)
			.unwrap();
		BandersnatchVrfVerifiable::push_members(&mut inter2, [bob.clone()].into_iter(), get_many)
			.unwrap();
		BandersnatchVrfVerifiable::push_members(
			&mut inter2,
			[charlie.clone()].into_iter(),
			get_many,
		)
		.unwrap();
		assert_eq!(inter1, inter2);

		let members1 = BandersnatchVrfVerifiable::finish_members(inter1);
		let members2 = BandersnatchVrfVerifiable::finish_members(inter2);
		assert_eq!(members1, members2);
	});

	test_for_all_domains!(start_push_finish_multiple_members, |domain_size| {
		let capacity: RingSize = domain_size.into();
		let alice_sec = BandersnatchVrfVerifiable::new_secret([0u8; 32]);
		let bob_sec = BandersnatchVrfVerifiable::new_secret([1u8; 32]);
		let charlie_sec = BandersnatchVrfVerifiable::new_secret([2u8; 32]);

		let alice = BandersnatchVrfVerifiable::member_from_secret(&alice_sec);
		let bob = BandersnatchVrfVerifiable::member_from_secret(&bob_sec);
		let charlie = BandersnatchVrfVerifiable::member_from_secret(&charlie_sec);

		// First set is everyone all at once with the regular starting root.
		let mut inter1 = BandersnatchVrfVerifiable::start_members(capacity);
		// Second set is everyone all at once but with a starting root constructed from params.
		let (mut inter2, builder_params) = start_members_from_params(domain_size);

		let get_many = |range| {
			(&builder_params)
				.lookup(range)
				.map(|v| {
					v.into_iter()
						.map(|i| crate::ring::StaticChunk(i))
						.collect::<Vec<_>>()
				})
				.ok_or(())
		};

		// Third set is everyone added one by one.
		let mut inter3 = BandersnatchVrfVerifiable::start_members(capacity);
		// Fourth set is a single addition followed by a group addition.
		let mut inter4 = BandersnatchVrfVerifiable::start_members(capacity);

		// Construct the first set with all members added simultaneously.
		BandersnatchVrfVerifiable::push_members(
			&mut inter1,
			[alice.clone(), bob.clone(), charlie.clone()].into_iter(),
			get_many,
		)
		.unwrap();

		// Construct the second set with all members added simultaneously.
		BandersnatchVrfVerifiable::push_members(
			&mut inter2,
			[alice.clone(), bob.clone(), charlie.clone()].into_iter(),
			get_many,
		)
		.unwrap();

		// Construct the third set with all members added sequentially.
		BandersnatchVrfVerifiable::push_members(&mut inter3, [alice.clone()].into_iter(), get_many)
			.unwrap();
		BandersnatchVrfVerifiable::push_members(&mut inter3, [bob.clone()].into_iter(), get_many)
			.unwrap();
		BandersnatchVrfVerifiable::push_members(
			&mut inter3,
			[charlie.clone()].into_iter(),
			get_many,
		)
		.unwrap();

		// Construct the fourth set with the first member joining alone, followed by the other members joining together.
		BandersnatchVrfVerifiable::push_members(&mut inter4, [alice.clone()].into_iter(), get_many)
			.unwrap();
		BandersnatchVrfVerifiable::push_members(
			&mut inter4,
			[bob.clone(), charlie.clone()].into_iter(),
			get_many,
		)
		.unwrap();

		assert_eq!(inter1, inter2);
		assert_eq!(inter2, inter3);
		assert_eq!(inter3, inter4);

		let members1 = BandersnatchVrfVerifiable::finish_members(inter1);
		let members2 = BandersnatchVrfVerifiable::finish_members(inter2);
		let members3 = BandersnatchVrfVerifiable::finish_members(inter3);
		let members4 = BandersnatchVrfVerifiable::finish_members(inter4);
		assert_eq!(members1, members2);
		assert_eq!(members2, members3);
		assert_eq!(members3, members4);
	});

	test_for_all_domains!(open_validate_works, |domain_size| {
		use std::time::Instant;

		let capacity: RingSize = domain_size.into();
		let context = b"Context";
		let message = b"FooBar";

		let start = Instant::now();
		let _ = bandersnatch_ring_prover_params(domain_size);
		println!(
			"* PCS params decode: {} ms",
			(Instant::now() - start).as_millis()
		);

		let members: Vec<_> = (0..10)
			.map(|i| {
				let secret = BandersnatchVrfVerifiable::new_secret([i as u8; 32]);
				BandersnatchVrfVerifiable::member_from_secret(&secret)
			})
			.collect();
		let member = members[3].clone();

		let start = Instant::now();
		let commitment =
			BandersnatchVrfVerifiable::open(capacity, &member, members.clone().into_iter())
				.unwrap();
		println!("* Open: {} ms", (Instant::now() - start).as_millis());
		println!("  Commitment size: {} bytes", commitment.encode().len());

		let secret = BandersnatchVrfVerifiable::new_secret([commitment.1 as u8; 32]);
		let start = Instant::now();
		let (proof, alias) =
			BandersnatchVrfVerifiable::create(commitment, &secret, context, message).unwrap();
		println!("* Create: {} ms", (Instant::now() - start).as_millis());
		println!("  Proof size: {} bytes", proof.encode().len());

		// `builder_params` can be serialized/deserialized to be loaded when required
		let (_, builder_params) = start_members_from_params(domain_size);

		let get_many = |range| {
			(&builder_params)
				.lookup(range)
				.map(|v| {
					v.into_iter()
						.map(|i| crate::ring::StaticChunk(i))
						.collect::<Vec<_>>()
				})
				.ok_or(())
		};

		let start = Instant::now();
		let mut inter = BandersnatchVrfVerifiable::start_members(capacity);
		println!(
			"* Start members: {} ms",
			(Instant::now() - start).as_millis()
		);

		let start = Instant::now();
		members.iter().for_each(|member| {
			BandersnatchVrfVerifiable::push_members(
				&mut inter,
				[member.clone()].into_iter(),
				get_many,
			)
			.unwrap();
		});

		println!(
			"* Push {} members: {} ms",
			members.len(),
			(Instant::now() - start).as_millis()
		);

		let start = Instant::now();
		let members = BandersnatchVrfVerifiable::finish_members(inter);
		println!(
			"* Finish members: {} ms",
			(Instant::now() - start).as_millis()
		);

		let start = Instant::now();
		let alias2 =
			BandersnatchVrfVerifiable::validate(capacity, &proof, &members, context, message)
				.unwrap();
		println!("* Validate {} ms", (Instant::now() - start).as_millis());
		assert_eq!(alias, alias2);

		let start = Instant::now();
		let alias3 = BandersnatchVrfVerifiable::alias_in_context(&secret, context).unwrap();
		println!("* Alias: {} ms", (Instant::now() - start).as_millis());
		assert_eq!(alias, alias3);
	});

	test_for_all_domains!(open_validate_single_vs_multiple_keys, |domain_size| {
		use std::time::Instant;

		let capacity: RingSize = domain_size.into();
		let start = Instant::now();
		let _ = bandersnatch_ring_prover_params(domain_size);
		println!("* KZG decode: {} ms", (Instant::now() - start).as_millis());

		// Use the domain's max ring size to test at capacity
		let max_members = capacity.size();
		println!(
			"* Testing with {} members (max for {:?})",
			max_members, domain_size
		);

		let members: Vec<_> = (0..max_members)
			.map(|i| {
				// Use a hash of the index to generate unique secrets for large rings
				let mut seed = [0u8; 32];
				seed[..8].copy_from_slice(&(i as u64).to_le_bytes());
				let secret = BandersnatchVrfVerifiable::new_secret(seed);
				BandersnatchVrfVerifiable::member_from_secret(&secret)
			})
			.collect();

		// `builder_params` can be serialized/deserialized to be loaded when required
		let (_, builder_params) = start_members_from_params(domain_size);

		let get_many = |range| {
			(&builder_params)
				.lookup(range)
				.map(|v| {
					v.into_iter()
						.map(|i| crate::ring::StaticChunk(i))
						.collect::<Vec<_>>()
				})
				.ok_or(())
		};

		let mut inter1 = BandersnatchVrfVerifiable::start_members(capacity);
		let start = Instant::now();
		members.iter().for_each(|member| {
			BandersnatchVrfVerifiable::push_members(
				&mut inter1,
				[member.clone()].into_iter(),
				get_many,
			)
			.unwrap();
		});
		println!(
			"* Push {} members one at a time: {} ms",
			members.len(),
			(Instant::now() - start).as_millis()
		);

		let mut inter2 = BandersnatchVrfVerifiable::start_members(capacity);
		let start = Instant::now();

		BandersnatchVrfVerifiable::push_members(&mut inter2, members.iter().cloned(), get_many)
			.unwrap();
		println!(
			"* Push {} members simultaneously: {} ms",
			members.len(),
			(Instant::now() - start).as_millis()
		);

		assert_eq!(inter1, inter2);
	});
}
