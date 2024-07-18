pub use rpc_client::WorkerClient;

pub mod endpoints;
pub mod register;
mod rpc_client;

pub mod bridge;
pub mod chain_state;
pub mod deploy;
pub mod ipfs_downloader;

mod util {
    use anyhow::{Context, Result};
    use core::fmt::Debug;
    use std::path::Path;
    use tracing::error;

    pub fn read_file(path: impl AsRef<Path>) -> Result<Vec<u8>> {
        std::fs::read(path.as_ref())
            .with_context(|| format!("failed to read file: {}", path.as_ref().display()))
    }

    pub fn write_file(path: impl AsRef<Path>, data: &[u8]) -> Result<()> {
        std::fs::write(path.as_ref(), data)
            .with_context(|| format!("failed to write file: {}", path.as_ref().display()))
    }

    pub trait IgnoreError {
        type T;
        fn ignore_error(self, prefix: &str) -> Option<Self::T>;
    }

    impl<T, E: Debug> IgnoreError for Result<T, E> {
        type T = T;
        fn ignore_error(self, prefix: &str) -> Option<T> {
            match self {
                Ok(v) => Some(v),
                Err(err) => {
                    error!("{prefix}: {err:?}");
                    None
                }
            }
        }
    }
}
