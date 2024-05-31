use std::{path::PathBuf, sync::OnceLock};

use anyhow::{Context, Result};
use scale::{Decode as _, Encode};
use sp_core::blake2_256;
use wapod_crypto::sr25519::Pair;
use wapod_rpc::{prpc::Manifest, types::Address};

pub struct DefaultWorkerConfig;

pub trait AddressGenerator {
    fn generate_address(manifest: &Manifest) -> Address;
}

impl AddressGenerator for DefaultWorkerConfig {
    fn generate_address(manifest: &Manifest) -> Address {
        blake2_256(&manifest.encode())
    }
}

pub trait KeyProvider {
    type Paths: Paths;
    fn get_key() -> &'static Pair {
        static KEY: OnceLock<Pair> = OnceLock::new();

        KEY.get_or_init(|| {
            let keyfile = Self::Paths::secret_data_dir().join("worker.key");
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
}

impl KeyProvider for DefaultWorkerConfig {
    type Paths = Self;
}

pub trait Paths {
    fn data_dir() -> PathBuf;
    fn storage_dir() -> PathBuf {
        Self::data_dir().join("storage_files")
    }
    fn blobs_dir() -> PathBuf {
        Self::storage_dir().join("blobs")
    }
    fn secret_data_dir() -> PathBuf {
        Self::data_dir().join("protected_files")
    }
    fn create_dirs_if_needed() -> Result<()> {
        for dir in &[
            Self::secret_data_dir(),
            Self::storage_dir(),
            Self::blobs_dir(),
        ] {
            std::fs::create_dir_all(dir).context("failed to create data directory")?;
        }
        Ok(())
    }
}

impl Paths for DefaultWorkerConfig {
    fn data_dir() -> PathBuf {
        std::env::var("WAPOD_DATA_DIR")
            .unwrap_or_else(|_| "./data/".to_string())
            .into()
    }
}

pub trait WorkerConfig: 'static {
    type AddressGenerator: AddressGenerator;
    type KeyProvider: KeyProvider;
    type Paths: Paths;
}

impl WorkerConfig for DefaultWorkerConfig {
    type AddressGenerator = Self;
    type KeyProvider = Self;
    type Paths = Self;
}
