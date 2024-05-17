use std::path::PathBuf;

use anyhow::{Context, Result};

pub fn secret_data_path() -> PathBuf {
    let todo = "put WAPOD_DATA_DIR in gramine manifest";
    std::env::var("WAPOD_DATA_DIR")
        .unwrap_or_else(|_| "./data/protected_files".to_string())
        .into()
}

pub fn create_dirs_if_needed() -> Result<()> {
    std::fs::create_dir_all(secret_data_path())
        .context("failed to create secret data directory")?;
    Ok(())
}
