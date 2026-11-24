//! The heap use of the batch validation methods must not depend on the order of
//! the items, and their peak heap must not depend on the rings the items name.
//!
//! The submitters of a batch control both. A ring verifier holds a copy of the
//! ring domain (megabytes for large rings). If a batch keeps one verifier per
//! ring change, an attacker who alternates two rings makes the memory grow with
//! the batch length. If it keeps one verifier per ring, an attacker who sends a
//! new ring with each item does the same. In a runtime with a fixed heap, the
//! allocation failure aborts the whole call and with it the honest proofs of
//! the batch.
//!
//! Each verifier build allocates a copy of the domain, so the allocated bytes
//! count the builds. If a batch builds a verifier on each ring change, an
//! attacker who alternates two rings forces one build per item, and one build
//! per ring is the minimum.
//!
//! The last item of each batch is invalid, so the attribution path runs too.
//!
//! This test is its own binary because the counters of the global allocator
//! are shared by all the threads of the process.

use std::{
	alloc::{GlobalAlloc, Layout, System},
	sync::atomic::{AtomicUsize, Ordering::Relaxed},
};
use verifiable::{
	Alias, BatchProofItem, BatchProofItemFor, Error, GenerateVerifiable,
	ring::{
		RingDomainSize, StaticChunk,
		bandersnatch::{BandersnatchSha512Ell2 as Suite, BandersnatchVrfVerifiable as Verifiable},
		ring_verifier_builder_params,
	},
};

struct CountingAllocator;

static LIVE_BYTES: AtomicUsize = AtomicUsize::new(0);
static PEAK_BYTES: AtomicUsize = AtomicUsize::new(0);
static ALLOCATED_BYTES: AtomicUsize = AtomicUsize::new(0);

unsafe impl GlobalAlloc for CountingAllocator {
	unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
		let ptr = unsafe { System.alloc(layout) };
		if !ptr.is_null() {
			let live = LIVE_BYTES.fetch_add(layout.size(), Relaxed) + layout.size();
			PEAK_BYTES.fetch_max(live, Relaxed);
			ALLOCATED_BYTES.fetch_add(layout.size(), Relaxed);
		}
		ptr
	}

	unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
		unsafe { System.dealloc(ptr, layout) };
		LIVE_BYTES.fetch_sub(layout.size(), Relaxed);
	}
}

#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator;

#[derive(Debug)]
struct HeapUse {
	peak_growth: usize,
	allocated: usize,
}

fn heap_use<T>(run: impl FnOnce() -> T) -> (T, HeapUse) {
	let live = LIVE_BYTES.load(Relaxed);
	PEAK_BYTES.store(live, Relaxed);
	let allocated = ALLOCATED_BYTES.load(Relaxed);
	let output = run();
	let heap_use = HeapUse {
		peak_growth: PEAK_BYTES.load(Relaxed) - live,
		allocated: ALLOCATED_BYTES.load(Relaxed) - allocated,
	};
	(output, heap_use)
}

const DOMAIN: RingDomainSize = RingDomainSize::Domain11;
const CONTEXT: &[u8] = b"context";
const BATCH_LEN: usize = 32;

type Case = (BatchProofItemFor<Verifiable>, Result<Alias, Error>);

/// A valid proof of the only member of a one-member ring, and its expected result.
fn one_member_ring_case(seed: u8) -> Case {
	let builder_params = ring_verifier_builder_params::<Suite>(DOMAIN);
	let lookup = |range: core::ops::Range<usize>| {
		let points = builder_params.0.get(range).ok_or(())?;
		Ok(points.iter().copied().map(StaticChunk).collect())
	};
	let secret = Verifiable::new_secret([seed; 32]);
	let member = Verifiable::member_from_secret(&secret);
	let mut intermediate = Verifiable::start_members(DOMAIN);
	Verifiable::push_members(&mut intermediate, [member].into_iter(), lookup).unwrap();
	let members = Verifiable::finish_members(intermediate);

	let commitment = Verifiable::open(DOMAIN, &member, [member].into_iter()).unwrap();
	let message = b"message".to_vec();
	let (proof, alias) = Verifiable::create(commitment, &secret, CONTEXT, &message).unwrap();
	let item = BatchProofItem {
		proof,
		config: DOMAIN,
		members,
		context: CONTEXT.to_vec(),
		message,
	};
	(item, Ok(alias))
}

fn with_last_item_invalid(
	mut cases: Vec<Case>,
) -> (
	Vec<BatchProofItemFor<Verifiable>>,
	Vec<Result<Alias, Error>>,
) {
	let (item, expected) = cases.last_mut().unwrap();
	item.message = b"tampered message".to_vec();
	*expected = Err(Error::VerificationFailed);
	cases.into_iter().unzip()
}

#[test]
fn heap_use_does_not_depend_on_item_order_or_rings() {
	let ring_a = one_member_ring_case(0);
	let ring_b = one_member_ring_case(1);
	let (grouped, grouped_expected) = with_last_item_invalid(
		[
			vec![ring_a.clone(); BATCH_LEN / 2],
			vec![ring_b.clone(); BATCH_LEN / 2],
		]
		.concat(),
	);
	let (alternating, alternating_expected) = with_last_item_invalid(
		(0..BATCH_LEN / 2)
			.flat_map(|_| [ring_a.clone(), ring_b.clone()])
			.collect(),
	);
	let (ring_per_item, ring_per_item_expected) =
		with_last_item_invalid((0..BATCH_LEN as u8).map(one_member_ring_case).collect());

	// Initializes the lazy statics (ring context, verifier params), so that
	// the measures below hold only the allocations of the batch.
	Verifiable::batch_validate_per_item(&grouped);

	let (results, grouped_use) = heap_use(|| Verifiable::batch_validate_per_item(&grouped));
	assert_eq!(results, grouped_expected);
	let (results, alternating_use) = heap_use(|| Verifiable::batch_validate_per_item(&alternating));
	assert_eq!(results, alternating_expected);
	let (results, ring_per_item_use) =
		heap_use(|| Verifiable::batch_validate_per_item(&ring_per_item));
	assert_eq!(results, ring_per_item_expected);

	// The parallel MSM threads move the peaks by up to 2 times; one verifier
	// per item at this length gives more than 5 times.
	assert!(
		alternating_use.peak_growth < 3 * grouped_use.peak_growth,
		"alternating {alternating_use:?}, grouped {grouped_use:?}"
	);
	assert!(
		ring_per_item_use.peak_growth < 3 * grouped_use.peak_growth,
		"ring per item {ring_per_item_use:?}, grouped {grouped_use:?}"
	);

	// The two methods share the accumulation. The allocations of the per-item
	// attribution checks hide the verifier builds, so the all-or-nothing method
	// counts them.
	let (_, grouped_use) = heap_use(|| Verifiable::batch_validate(&grouped));
	let (_, alternating_use) = heap_use(|| Verifiable::batch_validate(&alternating));
	assert!(
		alternating_use.allocated < 2 * grouped_use.allocated,
		"alternating {alternating_use:?}, grouped {grouped_use:?}"
	);
}
