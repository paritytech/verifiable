//! Fixture for `tests/no_std_prover.rs`: a genuine `no_std` wasm module that
//! builds a single-member ring and creates a ring VRF proof inside wasm.
//! Blinding randomness comes from the registered `getrandom` custom backend
//! (a deterministic counter stream; each call still draws fresh values).
//!
//! The secret entropy, context and message must match the host-side test.
#![no_std]

extern crate alloc;

use core::sync::atomic::{AtomicU64, Ordering};

use verifiable::{
	ring::{bandersnatch::BandersnatchVrfVerifiable, RingDomainSize},
	GenerateVerifiable,
};

#[global_allocator]
static ALLOCATOR: dlmalloc::GlobalDlmalloc = dlmalloc::GlobalDlmalloc;

getrandom::register_custom_getrandom!(fill_from_counter);

fn fill_from_counter(dest: &mut [u8]) -> Result<(), getrandom::Error> {
	static COUNTER: AtomicU64 = AtomicU64::new(0);
	for chunk in dest.chunks_mut(8) {
		let word = split_mix_64(COUNTER.fetch_add(1, Ordering::Relaxed));
		chunk.copy_from_slice(&word.to_le_bytes()[..chunk.len()]);
	}
	Ok(())
}

fn split_mix_64(counter: u64) -> u64 {
	let mut word = counter.wrapping_add(1).wrapping_mul(0x9E3779B97F4A7C15);
	word = (word ^ (word >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
	word = (word ^ (word >> 27)).wrapping_mul(0x94D049BB133111EB);
	word ^ (word >> 31)
}

static mut OUT: [u8; 2048] = [0; 2048];

#[no_mangle]
pub extern "C" fn out_ptr() -> *const u8 {
	core::ptr::addr_of!(OUT).cast()
}

/// Create a ring proof and store it in `OUT`. Returns the proof length,
/// or a negative code on failure.
#[no_mangle]
pub extern "C" fn prove() -> i32 {
	let secret = BandersnatchVrfVerifiable::new_secret([0u8; 32]);
	let member = BandersnatchVrfVerifiable::member_from_secret(&secret);
	let commitment = match BandersnatchVrfVerifiable::open(
		RingDomainSize::Domain11,
		&member,
		[member].into_iter(),
	) {
		Ok(commitment) => commitment,
		Err(_) => return -1,
	};
	let (proof, _alias) = match BandersnatchVrfVerifiable::create(commitment, &secret, b"ctx", b"msg")
	{
		Ok(result) => result,
		Err(_) => return -2,
	};
	let out = unsafe { &mut *core::ptr::addr_of_mut!(OUT) };
	if proof.len() > out.len() {
		return -3;
	}
	out[..proof.len()].copy_from_slice(proof.as_slice());
	proof.len() as i32
}

#[panic_handler]
fn on_panic(_info: &core::panic::PanicInfo) -> ! {
	core::arch::wasm32::unreachable()
}
