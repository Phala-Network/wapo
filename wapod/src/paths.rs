use std::path::PathBuf;

pub fn secret_data_path() -> PathBuf {
    let todo = "put WAPOD_DATA_DIR in gramine manifest";
    std::env::var("WAPOD_DATA_DIR")
        .unwrap_or_else(|_| "./data/sealed".to_string())
        .into()
}

pub fn create_dirs_if_needed() {
    std::fs::create_dir_all(secret_data_path()).expect("Failed to create secret data directory");
}
