use scale::{Decode, Encode};
use std::sync::OnceLock;
use wapod_crypto::sr25519::Pair;

use crate::paths;

pub fn worker_identity_key() -> &'static Pair {
    static KEY: OnceLock<Pair> = OnceLock::new();

    KEY.get_or_init(|| {
        let keyfile = paths::secret_data_path().join("worker.key");
        match std::fs::read(&keyfile) {
            Ok(secret) => Pair::decode(&mut &secret[..]).expect("failed to load keypair"),
            Err(err) => {
                if err.kind() != std::io::ErrorKind::NotFound {
                    panic!("Failed to read keypair: {err}");
                }
                let pair = Pair::new();
                std::fs::write(&keyfile, pair.encode()).expect("failed to write keypair");
                pair
            }
        }
    })
}
