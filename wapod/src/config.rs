use std::{marker::PhantomData, path::PathBuf, sync::OnceLock};

use anyhow::{Context, Result};
use rocket::figment::{
    providers::{Format, Toml},
    Figment,
};
use scale::{Decode as _, Encode};
use sp_core::blake2_256;
use wapod_crypto::sr25519::Pair;
use wapod_rpc::{prpc::Manifest, types::Address};

pub const CONFIG_FILENAME: &str = "Wapod.toml";
pub const DEFAULT_CONFIG: &str = include_str!("../Wapod.toml");

pub fn load_config_file() -> Figment {
    Figment::from(Toml::string(DEFAULT_CONFIG).nested()).merge(Toml::file(CONFIG_FILENAME).nested())
}

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
    fn get_key() -> &'static Pair;
}

pub struct DefaultKerProvider<P>(PhantomData<P>);

impl<P: Paths> KeyProvider for DefaultKerProvider<P> {
    fn get_key() -> &'static Pair {
        static KEY: OnceLock<Pair> = OnceLock::new();

        KEY.get_or_init(|| {
            let keyfile = P::secret_data_dir().join("worker.key");
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
    type KeyProvider = DefaultKerProvider<Self>;
    type Paths = Self;
}
