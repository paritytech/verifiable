
use std::io::prelude::*;

use rand_core::{OsRng,RngCore};
use bandersnatch_vrfs::{ring,CanonicalSerialize};


fn main() {
    let domain_size = 2u32.pow(10);

    let path = std::path::Path::new("test2e10.kzg");
    // File::create_new(&path)
    use std::fs::{OpenOptions};
    let mut oo = OpenOptions::new();
    oo.read(true).write(true).create_new(true);
    if let Ok(mut file) = oo.open(path) {

        let rng = &mut OsRng;
        let mut seed = [0u8;32];
        rng.fill_bytes(&mut seed);

        let kzg = ring::KZG::insecure_kzg_setup(seed, domain_size, rng);

        kzg.serialize_compressed(&mut file).unwrap_or_else(|why| {
            panic!("couldn't write {}: {}", path.display(), why);
        });
    }
}

