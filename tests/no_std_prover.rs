//! Executes the ring prover in a genuine `no_std` environment.
//!
//! The std-linked test suite cannot catch a prover regression that only
//! surfaces without std (e.g. a new ambient-randomness call deep in the
//! proving stack): unit tests always link std and the wasm CI job only
//! compiles an rlib. This test closes that gap. It builds
//! `tests/fixtures/wasm-prover` (a `no_std` cdylib using `no-std-prover`
//! with a registered `getrandom` custom backend) for wasm32-unknown-unknown,
//! runs it under the `wasmi` interpreter and checks that:
//!
//! - the module links (a missing randomness source is a link error),
//! - proof creation completes in wasm (no trap, i.e. no runtime panic),
//! - two proofs over identical inputs differ (blinding is active in
//!   `no_std`, the SRLabs finding #710 property),
//! - both proofs validate on the host and bind to the expected alias.
//!
//! Runs in the no-std-prover test configuration (see `[[test]]` in
//! Cargo.toml) and needs the wasm32-unknown-unknown target installed.

use std::process::Command;

use verifiable::{
	GenerateVerifiable,
	ring::{
		RingDomainSize, StaticChunk,
		ark_vrf::{ring::SrsLookup, suites::bandersnatch::BandersnatchSha512Ell2},
		bandersnatch::BandersnatchVrfVerifiable,
		ring_verifier_builder_params,
	},
};

// Must match the fixture (`tests/fixtures/wasm-prover/src/lib.rs`).
const ENTROPY: [u8; 32] = [0u8; 32];
const CONTEXT: &[u8] = b"ctx";
const MESSAGE: &[u8] = b"msg";

const DOMAIN: RingDomainSize = RingDomainSize::Domain11;

fn build_fixture() -> Vec<u8> {
	let fixture_dir = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/wasm-prover");
	let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".into());
	let status = Command::new(cargo)
		.current_dir(fixture_dir)
		// Host flags and target dir must not leak into the nested wasm build.
		.env_remove("RUSTFLAGS")
		.env_remove("CARGO_ENCODED_RUSTFLAGS")
		.env_remove("CARGO_TARGET_DIR")
		.args(["build", "--release", "--target", "wasm32-unknown-unknown"])
		.status()
		.expect("failed to spawn cargo for the fixture build");
	assert!(
		status.success(),
		"fixture build failed; is the wasm32-unknown-unknown target installed?"
	);
	let wasm_path =
		format!("{fixture_dir}/target/wasm32-unknown-unknown/release/wasm_prover_fixture.wasm");
	std::fs::read(&wasm_path).unwrap_or_else(|e| panic!("cannot read {wasm_path}: {e}"))
}

fn run_wasm_prover(wasm: &[u8], calls: usize) -> Vec<Vec<u8>> {
	let engine = wasmi::Engine::default();
	let module = wasmi::Module::new(&engine, wasm).expect("fixture is valid wasm");
	let mut store = wasmi::Store::new(&engine, ());
	let linker = wasmi::Linker::<()>::new(&engine);
	let instance = linker
		.instantiate(&mut store, &module)
		.expect("fixture needs no imports")
		.start(&mut store)
		.expect("fixture start");
	let prove = instance
		.get_typed_func::<(), i32>(&store, "prove")
		.expect("`prove` export");
	let out_ptr = instance
		.get_typed_func::<(), i32>(&store, "out_ptr")
		.expect("`out_ptr` export");
	let memory = instance
		.get_memory(&store, "memory")
		.expect("`memory` export");

	(0..calls)
		.map(|_| {
			let len = prove.call(&mut store, ()).expect("prove trapped in wasm");
			assert!(len > 0, "prove failed in wasm with code {len}");
			let ptr = out_ptr
				.call(&mut store, ())
				.expect("out_ptr trapped in wasm") as usize;
			let mut proof = vec![0u8; len as usize];
			memory
				.read(&store, ptr, &mut proof)
				.expect("proof read from wasm memory");
			proof
		})
		.collect()
}

fn members_commitment_for(
	member: <BandersnatchVrfVerifiable as GenerateVerifiable>::Member,
) -> <BandersnatchVrfVerifiable as GenerateVerifiable>::Members {
	let params = ring_verifier_builder_params::<BandersnatchSha512Ell2>(DOMAIN);
	let mut inter = BandersnatchVrfVerifiable::start_members(DOMAIN);
	BandersnatchVrfVerifiable::push_members(&mut inter, [member].into_iter(), |range| {
		(&params)
			.lookup(range)
			.map(|points| points.into_iter().map(StaticChunk).collect())
			.ok_or(())
	})
	.expect("push member");
	BandersnatchVrfVerifiable::finish_members(inter)
}

#[test]
fn no_std_wasm_prover_creates_valid_blinded_proofs() {
	let wasm = build_fixture();
	let proofs = run_wasm_prover(&wasm, 2);

	// Identical inputs, different bytes: blinding is active in no_std.
	assert_ne!(proofs[0], proofs[1]);

	let secret = BandersnatchVrfVerifiable::new_secret(ENTROPY);
	let member = BandersnatchVrfVerifiable::member_from_secret(&secret);
	let expected_alias = BandersnatchVrfVerifiable::alias_in_context(&secret, CONTEXT).unwrap();
	let members = members_commitment_for(member);

	for proof_bytes in proofs {
		let proof: <BandersnatchVrfVerifiable as GenerateVerifiable>::Proof = proof_bytes
			.try_into()
			.expect("proof fits the bounded proof type");
		let alias = BandersnatchVrfVerifiable::validate(DOMAIN, &proof, &members, CONTEXT, MESSAGE)
			.expect("wasm-created proof validates on the host");
		assert_eq!(alias, expected_alias);
	}
}
