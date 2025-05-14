use crate::ring_vrf_impl::{ring_verifier_builder_params, BandersnatchVrfVerifiable, StaticChunk};
use crate::{Entropy, GenerateVerifiable};
use ark_vrf::ring::SrsLookup;
use bounded_collections::{BoundedVec, ConstU32};
use js_sys::{Boolean, JsString, Object, Uint8Array};
use parity_scale_codec::{Decode, Encode};
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub fn one_shot(
	entropy: Uint8Array,
	members: Uint8Array,
	context: Uint8Array,
	message: Uint8Array,
) -> Result<Object, JsString> {
	// store entropy instead of key is fine
	let entropy_vec = entropy.to_vec();
	let entropy = Entropy::decode(&mut &entropy_vec[..])
		.map_err(|_| JsString::from("Entropy decoding failed"))?;

	// Secret
	let secret = BandersnatchVrfVerifiable::new_secret(entropy);

	// Member
	let member = BandersnatchVrfVerifiable::member_from_secret(&secret);
	let member_encoded = member.encode();

	// All Members
	let raw_members = members.to_vec();
	let members: BoundedVec<
		<BandersnatchVrfVerifiable as GenerateVerifiable>::Member,
		ConstU32<{ u32::MAX }>,
	> = Decode::decode(&mut &raw_members[..])
		.map_err(|_| JsString::from("Decoding Members failed"))?;

	let members_encoded = members.encode();

	// Open
	let commitment = BandersnatchVrfVerifiable::open(&member, members.into_iter())
		.map_err(|_| JsString::from("Verifiable::open failed"))?;

	// Create
	let context = &context.to_vec()[..];
	let message = &message.to_vec()[..];
	let (proof, alias) = BandersnatchVrfVerifiable::create(commitment, &secret, context, message)
		.map_err(|_| JsString::from("Verifiable::create failed"))?;

	// Return Results
	let obj = Object::new();
	js_sys::Reflect::set(
		&obj,
		&"member".into(),
		&Uint8Array::from(&member_encoded[..]),
	)
	.unwrap();
	js_sys::Reflect::set(
		&obj,
		&"members".into(),
		&Uint8Array::from(&members_encoded[..]),
	)
	.unwrap();
	js_sys::Reflect::set(&obj, &"proof".into(), &Uint8Array::from(&proof[..])).unwrap();
	js_sys::Reflect::set(&obj, &"alias".into(), &Uint8Array::from(&alias[..])).unwrap();
	js_sys::Reflect::set(&obj, &"message".into(), &Uint8Array::from(&message[..])).unwrap();
	js_sys::Reflect::set(&obj, &"context".into(), &Uint8Array::from(&context[..])).unwrap();
	Ok(obj)
}

#[wasm_bindgen]
pub fn validate(
	proof: Uint8Array,
	members: Uint8Array,
	context: Uint8Array,
	message: Uint8Array,
) -> Uint8Array {
	let proof = proof.to_vec();
	let proof: <BandersnatchVrfVerifiable as GenerateVerifiable>::Proof =
		Decode::decode(&mut &proof[..]).unwrap();

	let members = members.to_vec();
	let members: BoundedVec<
		<BandersnatchVrfVerifiable as GenerateVerifiable>::Member,
		ConstU32<{ u32::MAX }>,
	> = Decode::decode(&mut &members[..]).unwrap();

	// Get the builder params for verification
	let builder_params = ring_verifier_builder_params();
	let get_many = |range| {
		(&builder_params)
			.lookup(range)
			.map(|v| v.into_iter().map(|i| StaticChunk(i)).collect::<Vec<_>>())
			.ok_or(())
	};

	// Start with empty members set
	let mut inter = BandersnatchVrfVerifiable::start_members();

	// Add all members at once
	BandersnatchVrfVerifiable::push_members(&mut inter, members.into_iter(), get_many).unwrap();

	// Finish building the members commitment
	let members_commitment = BandersnatchVrfVerifiable::finish_members(inter);

	let context = &context.to_vec()[..];
	let message = &message.to_vec()[..];
	let alias = BandersnatchVrfVerifiable::validate(&proof, &members_commitment, context, message)
		.expect("Proof not able to be validated");

	Uint8Array::from(&Encode::encode(&alias)[..])
}

#[wasm_bindgen]
pub fn sign(entropy: Uint8Array, message: Uint8Array) -> Result<Uint8Array, JsString> {
	let entropy_vec = entropy.to_vec();
	let entropy = Entropy::decode(&mut &entropy_vec[..])
		.map_err(|_| JsString::from("Entropy decoding failed"))?;

	// Secret
	let secret = BandersnatchVrfVerifiable::new_secret(entropy);

	let message = &message.to_vec()[..];
	let signature = BandersnatchVrfVerifiable::sign(&secret, &message)
		.map_err(|_| JsString::from("Verifiable::sign failed"))?;

	Ok(Uint8Array::from(&Encode::encode(&signature)[..]))
}

#[wasm_bindgen]
pub fn verify_signature(signature: Uint8Array, message: Uint8Array, member: Uint8Array) -> Boolean {
	let signature = signature.to_vec();
	let signature: <BandersnatchVrfVerifiable as GenerateVerifiable>::Signature =
		Decode::decode(&mut &signature[..]).unwrap();

	let member = member.to_vec();
	let member: <BandersnatchVrfVerifiable as GenerateVerifiable>::Member =
		Decode::decode(&mut &member[..]).unwrap();

	let message = &message.to_vec()[..];

	BandersnatchVrfVerifiable::verify_signature(&signature, &message, &member).into()
}

#[wasm_bindgen]
pub fn member_from_entropy(entropy: Uint8Array) -> Uint8Array {
	let entropy_vec = entropy.to_vec();
	let entropy = Entropy::decode(&mut &entropy_vec[..]).unwrap();

	// Secret
	let secret = BandersnatchVrfVerifiable::new_secret(entropy);

	// Member
	let member = BandersnatchVrfVerifiable::member_from_secret(&secret);
	let member_encoded = member.encode();

	Uint8Array::from(&member_encoded[..])
}

#[cfg(test)]
mod tests {
	use super::*;
	use wasm_bindgen_test::*;

	#[wasm_bindgen_test]
	fn create_proof_validate_proof() {
		let entropy = [5u8; 32];
		let js_member = member_from_entropy(Uint8Array::from(entropy.as_slice()));

		let get_secret_and_member = |entropy: &[u8; 32]| {
			let secret = BandersnatchVrfVerifiable::new_secret(entropy.clone());
			let member = BandersnatchVrfVerifiable::member_from_secret(&secret);
			(secret, member)
		};

		let members: Vec<_> = (0..10)
			.map(|i| get_secret_and_member(&[i as u8; 32]))
			.map(|(_, m)| m)
			.collect();

		assert_eq!(
			js_member.to_vec(),
			members.get(5).unwrap().encode().to_vec()
		);

		let context = b"Context";
		let message = b"FooBar";

		let result = one_shot(
			Uint8Array::from(entropy.as_slice()),
			Uint8Array::from(members.encode().to_vec().as_slice()),
			Uint8Array::from(context.as_slice()),
			Uint8Array::from(message.as_slice()),
		)
		.expect("creating one_shot proof should work");

		let alias =
			js_sys::Reflect::get(&result, &JsValue::from_str("alias")).expect("alias should exist");
		let alias = Uint8Array::new(&alias);

		let proof =
			js_sys::Reflect::get(&result, &JsValue::from_str("proof")).expect("proof should exist");
		let proof = Uint8Array::new(&proof);

		let validated_alias = validate(
			proof,
			Uint8Array::from(&members.encode().to_vec()[..]),
			Uint8Array::from(context.as_slice()),
			Uint8Array::from(message.as_slice()),
		);

		assert_eq!(alias.to_vec(), validated_alias.to_vec());
	}

	#[wasm_bindgen_test]
	fn js_rust_equal_member() {
		let entropy = [0u8; 32];
		let alice_secret = BandersnatchVrfVerifiable::new_secret(entropy);
		let rust_member = BandersnatchVrfVerifiable::member_from_secret(&alice_secret);

		let js_member = member_from_entropy(Uint8Array::from(&entropy[..]));

		assert_eq!(rust_member.encode().len(), js_member.to_vec().len());
		assert_eq!(rust_member.encode().len(), 32);
		assert_eq!(js_member.to_vec().len(), 32);
		assert_eq!(rust_member.encode(), js_member.to_vec());
	}

	#[wasm_bindgen_test]
	fn js_rust_equal_members() {
		let get_secret_and_member = |entropy: &[u8; 32]| {
			let secret = BandersnatchVrfVerifiable::new_secret(entropy.clone());
			let member = BandersnatchVrfVerifiable::member_from_secret(&secret);
			(secret, member)
		};

		let rust_members: Vec<_> = (0..10)
			.map(|i| get_secret_and_member(&[i as u8; 32]))
			.map(|(_, m)| m)
			.collect();

		let js_members: Vec<Vec<u8>> = (0..10)
			.map(|i| member_from_entropy(Uint8Array::from([i as u8; 32].as_slice())))
			.map(|key| key.to_vec())
			.collect();

		assert_eq!(js_members.len(), rust_members.len());

		// let rust_members = rust_members.encode();
		// TODO this not equal, why? We need to encoded the keys individual for it to be the same.
		// assert_eq!(js_members.encode(), rust_members.encode());

		let rust_members_with_encoded_keys = rust_members
			.iter()
			.map(|key| key.encode())
			.collect::<Vec<Vec<u8>>>();

		let rust_members_with_encoded_keys = rust_members_with_encoded_keys.encode();
		let js_members = js_members.encode();

		assert_eq!(js_members, rust_members_with_encoded_keys);
	}

	#[wasm_bindgen_test]
	fn js_rust_equal_proofs() {
		let get_secret_and_member = |entropy: &[u8; 32]| {
			let secret = BandersnatchVrfVerifiable::new_secret(entropy.clone());
			let member = BandersnatchVrfVerifiable::member_from_secret(&secret);
			(secret, member)
		};

		let alice_entropy = [0u8; 32];

		let members: Vec<_> = (0..10)
			.map(|i| get_secret_and_member(&[i as u8; 32]))
			.map(|(_, m)| m)
			.collect();

		let alice_member = members.get(0).unwrap();

		// Create Rust Proof
		let context = b"Context";
		let message = b"FooBar";

		let commitment =
			BandersnatchVrfVerifiable::open(&alice_member, members.clone().into_iter()).unwrap();
		let secret = BandersnatchVrfVerifiable::new_secret([commitment.0 as u8; 32]);
		let (proof, alias) =
			BandersnatchVrfVerifiable::create(commitment, &secret, context, message).unwrap();

		// Create JS Proof
		let result = one_shot(
			Uint8Array::from(&alice_entropy[..]),
			Uint8Array::from(&members.encode().to_vec()[..]),
			Uint8Array::from(&context[..]),
			Uint8Array::from(&message[..]),
		)
		.expect("creating one_shot proof should work");

		// Compare js & rust values
		let get_u8a_value = |key: &str| {
			let value =
				js_sys::Reflect::get(&result, &JsValue::from_str(key)).expect("key should exist");
			let value = Uint8Array::new(&value);
			value
		};

		let js_alias = get_u8a_value("alias");
		assert_eq!(js_alias.to_vec(), alias.to_vec());

		let js_member = get_u8a_value("member");
		assert_eq!(js_member.to_vec(), alice_member.encode().to_vec());

		let js_members = get_u8a_value("members");
		assert_eq!(js_members.to_vec(), members.encode().to_vec());

		let js_context = get_u8a_value("context");
		assert_eq!(js_context.to_vec(), context.to_vec());

		let js_message = get_u8a_value("message");
		assert_eq!(js_message.to_vec(), message.to_vec());

		let js_proof = get_u8a_value("proof");
		assert_eq!(js_proof.to_vec().len(), proof.len());

		let js_proof_alias = validate(
			js_proof,
			Uint8Array::from(&members.encode().to_vec()[..]),
			Uint8Array::from(context.as_slice()),
			Uint8Array::from(message.as_slice()),
		);
		assert_eq!(js_proof_alias.to_vec(), alias.to_vec());

		let rs_proof_alias = validate(
			Uint8Array::from(&proof.encode().to_vec()[..]),
			Uint8Array::from(&members.encode().to_vec()[..]),
			Uint8Array::from(context.as_slice()),
			Uint8Array::from(message.as_slice()),
		);
		assert_eq!(rs_proof_alias.to_vec(), alias.to_vec());
	}

	#[wasm_bindgen_test]
	fn js_produces_valid_signatures() {
		let entropy = [23u8; 32];
		let message = b"FooBar";
		let secret = BandersnatchVrfVerifiable::new_secret(entropy);

		let member = BandersnatchVrfVerifiable::member_from_secret(&secret);

		// Create Rust signature
		let rs_signature = BandersnatchVrfVerifiable::sign(&secret, message).unwrap();
		assert!(BandersnatchVrfVerifiable::verify_signature(
			&rs_signature,
			message,
			&member
		));

		// // Create JS signature
		let js_signature = sign(
			Uint8Array::from(&entropy[..]),
			Uint8Array::from(&message[..]),
		)
		.expect("creating signature should work");

		let js_member = member_from_entropy(Uint8Array::from(&entropy[..]));

		assert!(verify_signature(
			js_signature.clone(),
			Uint8Array::from(&message[..]),
			js_member.clone()
		)
		.is_truthy());

		let other_message: &[u8; 6] = b"BarFoo";

		assert!(verify_signature(
			js_signature,
			Uint8Array::from(&other_message[..]),
			js_member
		)
		.is_falsy());
	}
}
