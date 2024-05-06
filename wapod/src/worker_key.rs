use scale::{Decode, Encode};
use std::sync::OnceLock;
use wapod_signature::crypto::sr25519::Pair;

use crate::paths;

pub fn load_or_generate_key() -> &'static Pair {
    static KEY: OnceLock<Pair> = OnceLock::new();

    KEY.get_or_init(|| {
        let keyfile = paths::secret_data_path().join("worker.key");
        match std::fs::read(&keyfile) {
            Ok(secret) => Pair::decode(&mut &secret[..]).expect("Failed to load keypair"),
            Err(err) => {
                if err.kind() != std::io::ErrorKind::NotFound {
                    panic!("Failed to read keypair: {err}");
                }
                let pair = Pair::new();
                std::fs::write(&keyfile, pair.encode()).expect("Failed to write keypair");
                pair
            }
        }
    })
}
