use std::str::FromStr as _;
use std::time::Duration;

use anyhow::{Context, Result};
use phaxt::signer::PairSigner;
use phaxt::subxt::utils::AccountId32;
use scale::Encode;
use sgx_attestation::dcap::report::get_collateral;
use sp_core::Pair;
use tracing::info;
use wapod_rpc::prpc::SignRegisterInfoArgs;
use wapod_rpc::types::AttestationReport;

use crate::WorkerClient;

pub struct RegisterArgs {
    pub worker_uri: String,
    pub token: String,
    pub chain_uri: String,
    pub signer: String,
    pub operator: String,
    pub pccs_url: String,
}

pub async fn register(args: RegisterArgs) -> Result<()> {
    let RegisterArgs {
        worker_uri,
        token,
        chain_uri,
        signer,
        operator,
        pccs_url,
    } = args;
    let worker_client = WorkerClient::new(worker_uri, token);
    let chain_client = phaxt::connect(&chain_uri)
        .await
        .context("failed to connect to the chain")?;
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
    let register_info = SignRegisterInfoArgs::new(genesis_block_hash.into(), operator, para_id);
    let response = worker_client
        .operation()
        .sign_register_info(register_info)
        .await?;
    info!("register_info response: {:?}", response);
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

            let collateral = get_collateral(&pccs_url, &quote, Duration::from_secs(10)).await?;
            Some(Report::SgxDcap {
                quote,
                collateral: Some(Collateral::SgxV30(collateral)),
            })
            .encode()
        }
        _ => attestation.encode(),
    };

    let alice = sp_core::sr25519::Pair::from_string(&signer, None)
        .expect("should create signer from mnemonic");
    let mut signer = PairSigner::new(alice);
    chain_client
        .register_worker(response.encoded_runtime_info, report, &mut signer)
        .await?;
    info!("register_worker tx finalized");
    Ok(())
}
