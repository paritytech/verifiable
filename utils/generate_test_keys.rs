use rand::RngCore;
use verifiable::ring::bandersnatch::BandersnatchVrfVerifiable;
use verifiable::GenerateVerifiable;

const PROOF_PREFIX: &[u8] = b"pop register using";
const VOUCHER_NAMES: [&str; 2] = ["TEST_VOUCHER_KEY_1", "TEST_VOUCHER_KEY_2"];

fn print_byte_array(name: &str, data: &[u8]) {
	println!("const {} = new Uint8Array([", name);
	for (i, &byte) in data.iter().enumerate() {
		if i % 16 == 0 && i > 0 {
			println!();
			print!("  ");
		}
		if i == 0 {
			print!("  ");
		}
		print!("{:#04x}", byte);
		if i < data.len() - 1 {
			print!(", ");
		}
	}
	println!();
	println!("]);");
	println!();
}

fn validate_keys(member: &[u8; 32], message: &[u8], signature: &[u8; 96]) {
	let is_valid = BandersnatchVrfVerifiable::verify_signature(signature, message, member);

	if is_valid {
		eprintln!("All generated keys are valid");
	} else {
		eprintln!("Key validation failed");
		std::process::exit(1);
	}
}

fn main() {
	let mut rng = rand::thread_rng();

	let mut entropy = [0u8; 32];
	let mut candidate_address = [0u8; 32];
	rng.fill_bytes(&mut entropy);
	rng.fill_bytes(&mut candidate_address);

	let secret = BandersnatchVrfVerifiable::new_secret(entropy);
	let member = BandersnatchVrfVerifiable::member_from_secret(&secret);

	let mut message = Vec::new();
	message.extend_from_slice(PROOF_PREFIX);
	message.extend_from_slice(&candidate_address);

	let signature = BandersnatchVrfVerifiable::sign(&secret, &message).unwrap();

	print_byte_array("TEST_PUBLIC_KEY", &member);
	print_byte_array("TEST_VRF_SIGNATURE", &signature);

	for i in 0..2 {
		let mut voucher_entropy = [0u8; 32];
		rng.fill_bytes(&mut voucher_entropy);
		let voucher_secret = BandersnatchVrfVerifiable::new_secret(voucher_entropy);
		let voucher_member = BandersnatchVrfVerifiable::member_from_secret(&voucher_secret);
		print_byte_array(VOUCHER_NAMES[i], &voucher_member);
	}

	validate_keys(&member, &message, &signature);
}
