use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result};
use hex_fmt::HexFmt;
use phaxt::{
    phala::runtime_types::{sp_core::sr25519::Public, wapod_types::ticket::Prices},
    RecodeTo,
};
use serde::Deserialize;
use tracing::info;
use wapod_rpc::prpc::SignWorkerDescriptionArgs;
use wapod_types::{ticket::AppManifest, Address};

use crate::{
    chain_state::ChainClient,
    util::{read_file, write_file},
};

#[derive(Deserialize, Debug, Clone)]
struct DeployConfig {
    output_dir: Option<String>,
    wasm_code: PathBuf,
    args: Vec<String>,
    env_vars: BTreeMap<String, String>,
    on_demand: bool,
    resizable: bool,
    max_query_size: u32,
    label: String,
    deps: Vec<String>,
}

fn sha256_hash(data: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(data);
    format!("sha256:{}", hex::encode(hasher.finalize()))
}

fn cid_of(data: &[u8]) -> Result<String> {
    let cid = ipfs_cid::generate_cid_v0(data)?;
    Ok(cid)
}

fn hash(data: &[u8], output_dir: impl AsRef<Path>) -> Result<(String, String)> {
    let hash = sha256_hash(data);
    let cid = cid_of(data)?;
    write_file(output_dir.as_ref().join(&cid), data)?;
    Ok((hash, cid))
}

pub fn build_manifest(config_file: impl AsRef<Path>) -> Result<(Address, String)> {
    let todo = "more config items";
    let config_file = std::fs::canonicalize(config_file.as_ref())?;
    let config: DeployConfig = serde_json::from_reader(std::fs::File::open(&config_file)?)
        .context("failed to parse config")?;

    let base_dir = config_file.parent().context("no parent")?;
    let output_dir = base_dir.join(config.output_dir.unwrap_or_else(|| "build".to_string()));
    let blobs_dir = output_dir.join("blobs");
    if output_dir.exists() {
        std::fs::remove_dir_all(&output_dir).context("failed to remove output_dir")?;
    }
    std::fs::create_dir_all(&blobs_dir).context("failed to create output_dir")?;

    let mut deps = BTreeMap::new();

    let wasm_code =
        read_file(base_dir.join(config.wasm_code)).context("failed to read wasm_code")?;
    let (code_hash, cid) = hash(&wasm_code, &blobs_dir)?;
    deps.insert(code_hash.clone(), cid);

    let mut args = vec![];

    for arg in config.args.into_iter() {
        let prefix = "sha256-of-file:";
        if arg.starts_with(prefix) {
            let file = arg.trim_start_matches(prefix);
            let data = read_file(base_dir.join(file)).context("failed to read file")?;
            let (hash, cid) = hash(&data, &blobs_dir)?;
            args.push(hash.clone());
            deps.insert(hash, cid);
        } else {
            args.push(arg);
        }
    }

    for dep in config.deps {
        let dep_code = read_file(base_dir.join(dep)).context("failed to read dep")?;
        let (dep_hash, dep_cid) = hash(&dep_code, &blobs_dir)?;
        if deps.contains_key(&dep_hash) {
            continue;
        }
        deps.insert(dep_hash, dep_cid);
    }

    let manifest = AppManifest {
        version: 1,
        code_hash,
        args,
        env_vars: config.env_vars.into_iter().collect(),
        on_demand: config.on_demand,
        resizable: config.resizable,
        max_query_size: config.max_query_size,
        label: config.label,
        required_blobs: deps.into_iter().collect(),
    };
    let address = manifest.address(sp_core::hashing::blake2_256);

    let manifest_json = serde_json::to_string_pretty(&manifest)?;
    let (_manifest_hash, manifest_cid) =
        hash(manifest_json.as_bytes(), &blobs_dir).context("failed to hash manifest file")?;
    write_file(output_dir.join("manifest.json"), manifest_json.as_bytes())
        .context("failed to write manifest")?;
    println!("manifest cid : {}", manifest_cid);
    println!("app address  : 0x{}", HexFmt(address));
    Ok((address, manifest_cid))
}

pub async fn deploy_manifest(
    config_file: impl AsRef<Path>,
    node_url: &str,
    signer: &str,
    deposit: u128,
    worker_list: u64,
) -> Result<()> {
    let (address, manifest_cid) = build_manifest(config_file)?;
    let tx = phaxt::phala::tx().phala_wapod_workers().ticket_create(
        deposit,
        address,
        manifest_cid,
        worker_list,
        Prices {
            general_fee_per_second: Some(1_000_000_000),
            ..Default::default()
        },
    );
    let chain_client = ChainClient::connect(node_url, signer).await?;
    chain_client
        .submit_tx("create ticket", tx, true, &mut Default::default())
        .await?;
    Ok(())
}

pub async fn create_worker_list(
    node_url: String,
    signer: String,
    worker_url: String,
    worker_token: String,
) -> Result<()> {
    let worker_client = crate::WorkerClient::new(worker_url, worker_token);
    let chain_client = ChainClient::connect(&node_url, &signer).await?;
    let info = worker_client.operation().info().await?;
    let pubkey = info.decode_pubkey()?;

    info!("worker pubkey: {:?}", HexFmt(pubkey));
    let signed = worker_client
        .operation()
        .sign_worker_description(SignWorkerDescriptionArgs::new(
            "test-worker".into(),
            Default::default(),
        ))
        .await?
        .decode_signed_description()?;
    info!("signed worker description");
    let tx = phaxt::phala::tx()
        .phala_wapod_workers()
        .worker_description_set(
            signed
                .recode_to()
                .context("failed to encode worker description")?,
        );
    info!("setting worker description...");
    chain_client
        .submit_tx("set worker description", tx, true, &mut Default::default())
        .await?;
    info!("worker description set");

    let tx = phaxt::phala::tx().phala_wapod_workers().worker_list_create(
        "pherry-created".into(),
        Prices {
            general_fee_per_second: Some(1_000_000_000),
            ..Default::default()
        },
        vec![Public(pubkey)],
    );
    info!("creating worker list...");
    chain_client
        .submit_tx("create worker list", tx, true, &mut Default::default())
        .await?;
    info!("worker list created");
    Ok(())
}
