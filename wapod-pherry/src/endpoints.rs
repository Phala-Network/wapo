use anyhow::{Context, Result};
use phaxt::signer::PairSigner;
use sp_core::Pair;
use wapod_rpc::prpc::SignEndpointsArgs;

use crate::WorkerClient;

pub struct UpdateEndpointArgs {
    pub worker_url: String,
    pub token: String,
    pub node_url: String,
    pub endpoint: String,
    pub signer: String,
}

pub async fn update_endpoint(args: UpdateEndpointArgs) -> Result<()> {
    let UpdateEndpointArgs {
        worker_url,
        token,
        node_url,
        endpoint,
        signer: operator,
    } = args;
    let worker_client = WorkerClient::new(worker_url, token);
    let chain_client = phaxt::connect(&node_url)
        .await
        .context("failed to connect to the chain")?;
    let rpc_args = SignEndpointsArgs {
        endpoints: vec![endpoint],
    };
    let response = worker_client.operation().sign_endpoints(rpc_args).await?;
    let alice = sp_core::sr25519::Pair::from_string(&operator, None)
        .expect("should create signer from mnemonic");
    let mut signer = PairSigner::new(alice);
    chain_client
        .update_worker_endpoints(
            response.encoded_endpoint_payload,
            response.signature,
            &mut signer,
        )
        .await?;
    Ok(())
}
