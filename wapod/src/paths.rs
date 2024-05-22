use std::path::PathBuf;

use anyhow::{Context, Result};

fn data_dir() -> PathBuf {
    std::env::var("WAPOD_DATA_DIR")
        .unwrap_or_else(|_| "./data/".to_string())
        .into()
}

pub fn secret_data_dir() -> PathBuf {
    data_dir().join("protected_files")
}

pub fn storage_dir() -> PathBuf {
    data_dir().join("storage_files")
}

pub fn blobs_dir() -> PathBuf {
    storage_dir().join("blobs")
}

pub fn create_dirs_if_needed() -> Result<()> {
    for dir in &[secret_data_dir(), storage_dir()] {
        std::fs::create_dir_all(dir).context("failed to create data directory")?;
    }
    Ok(())
}
