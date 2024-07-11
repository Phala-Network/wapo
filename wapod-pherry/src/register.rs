use std::str::FromStr as _;
use std::time::Duration;

use anyhow::{Context, Result};
use phaxt::subxt::utils::AccountId32;
use scale::Encode;
use sgx_attestation::dcap::report::get_collateral;
use tracing::info;
use wapod_rpc::prpc::SignRegisterInfoArgs;
use wapod_rpc::types::AttestationReport;

use crate::chain_state::ChainClient;
use crate::WorkerClient;

pub struct RegisterArgs {
    pub worker_url: String,
    pub token: String,
    pub node_url: String,
    pub signer: String,
    pub operator: String,
    pub pccs_url: String,
}

pub async fn register(args: RegisterArgs) -> Result<()> {
    let RegisterArgs {
        worker_url,
        token,
        node_url,
        signer,
        operator,
        pccs_url,
    } = args;
    let worker_client = WorkerClient::new(worker_url, token);
    info!("connecting to the chain");
    let chain_client = ChainClient::connect(&node_url, &signer)
        .await
        .context("failed to connect to the chain")?;
    register_with_client(&chain_client, &worker_client, &operator, &pccs_url).await
}

pub async fn register_with_client(
    chain_client: &ChainClient,
    worker_client: &WorkerClient,
    operator: &str,
    pccs_url: &str,
) -> Result<()> {
    info!("getting paraid");
    let para_id = chain_client.get_paraid().await?;
    let genesis_block_hash = chain_client.genesis_hash();
    let operator = if operator.is_empty() {
        None
    } else {
        Some(
            AccountId32::from_str(&operator)
                .context("invalid operator")?
                .0,
        )
    };
    info!("requesting worker to sign register data");
    let register_info = SignRegisterInfoArgs::new(genesis_block_hash.into(), operator, para_id);
    let response = worker_client
        .operation()
        .sign_register_info(register_info)
        .await?;
    info!("got signed register data");
    let attestation = response.decode_report()?;
    let report = match attestation {
        Some(AttestationReport::SgxDcap {
            quote,
            collateral: _,
        }) => {
            #[derive(Encode)]
            pub enum Report<C> {
                _SgxIas,
                SgxDcap {
                    quote: Vec<u8>,
                    collateral: Option<Collateral<C>>,
                },
            }
            #[derive(Encode)]
            pub enum Collateral<T> {
                SgxV30(T),
            }

            let collateral = get_collateral(pccs_url, &quote, Duration::from_secs(10)).await?;
            Some(Report::SgxDcap {
                quote,
                collateral: Some(Collateral::SgxV30(collateral)),
            })
            .encode()
        }
        _ => attestation.encode(),
    };

    chain_client
        .register_worker(response.encoded_runtime_info, report)
        .await?;
    let info = worker_client.operation().info().await?;
    info!(
        "worker 0x{} registered successfully",
        hex::encode(info.pubkey)
    );
    Ok(())
}
