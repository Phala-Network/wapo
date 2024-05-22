use std::path::PathBuf;

use anyhow::{Context, Result};

fn data_dir() -> PathBuf {
    let todo = "put WAPOD_DATA_DIR in gramine manifest";
    std::env::var("WAPOD_DATA_DIR")
        .unwrap_or_else(|_| "./data/".to_string())
        .into()
}

pub fn secret_data_dir() -> PathBuf {
    data_dir().join("protected_files")
}

pub fn blobs_dir() -> PathBuf {
    data_dir().join("blobs")
}

pub fn create_dirs_if_needed() -> Result<()> {
    for dir in &[secret_data_dir(), blobs_dir()] {
        std::fs::create_dir_all(dir).context("failed to create data directory")?;
    }
    Ok(())
}
