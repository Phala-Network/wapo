use anyhow::{anyhow, Context, Result};
use jsonrpsee::{async_client::ClientBuilder, client_transport::ws::WsTransportClientBuilder};
use scale::{Decode, Encode};
use std::ops::Deref;
use subxt::ext::scale_value::At;
use subxt::{dynamic::Value, storage::StaticStorageKey};
use tracing::info;

use crate::signer::{PairSigner, ToMultiSignature};
use crate::ExtrinsicParamsBuilder;

use super::{OnlineClient, RpcClient};

#[derive(Clone)]
pub struct ChainApi {
    rpc_client: RpcClient,
    online_client: OnlineClient,
}

impl Deref for ChainApi {
    type Target = OnlineClient;

    fn deref(&self) -> &Self::Target {
        &self.online_client
    }
}

impl ChainApi {
    pub fn rpc(&self) -> &RpcClient {
        &self.rpc_client
    }

    pub fn client(&self) -> &OnlineClient {
        &self.online_client
    }

    pub fn storage_key(
        &self,
        pallet_name: &str,
        entry_name: &str,
        key: &impl Encode,
    ) -> Result<Vec<u8>> {
        let address = subxt::dynamic::storage(pallet_name, entry_name, StaticStorageKey::new(key));
        Ok(self.storage().address_bytes(&address)?)
    }

    pub fn paras_heads_key(&self, para_id: u32) -> Result<Vec<u8>> {
        let id = crate::ParaId(para_id);
        self.storage_key("Paras", "Heads", &id)
    }

    pub async fn get_paraid(&self) -> Result<u32> {
        let address = subxt::dynamic::storage("ParachainInfo", "ParachainId", ());
        let Some(id) = self
            .storage()
            .at_latest()
            .await?
            .fetch(&address)
            .await
            .context("Failed to get current set_id")?
        else {
            return Ok(0);
        };
        let id = id
            .to_value()?
            .at(0)
            .ok_or_else(|| anyhow!("Invalid paraid"))?
            .as_u128()
            .ok_or_else(|| anyhow!("Invalid paraid"))?;
        Ok(id as _)
    }

    pub async fn fetch<K: Encode, V: Decode>(
        &self,
        pallet: &str,
        name: &str,
        key: Option<K>,
    ) -> Result<Option<V>> {
        let mut args = vec![];
        if let Some(key) = key {
            let key = Value::from_bytes(key.encode());
            args.push(key);
        }
        let address = subxt::dynamic::storage(pallet, name, args);
        let Some(data) = self
            .storage()
            .at_latest()
            .await?
            .fetch(&address)
            .await
            .context("Failed to get worker endpoints")?
        else {
            return Ok(None);
        };
        Ok(Some(Decode::decode(&mut &data.encoded()[..])?))
    }

    pub async fn mk_params(&self, longevity: u64, tip: u128) -> Result<ExtrinsicParamsBuilder> {
        let params = if longevity > 0 {
            let block = self.blocks().at_latest().await?;
            info!("using tx longevity: {longevity}");
            ExtrinsicParamsBuilder::new()
                .tip(tip)
                .mortal(block.header(), longevity)
        } else {
            ExtrinsicParamsBuilder::new().tip(tip)
        };
        Ok(params)
    }

    pub async fn update_worker_endpoints<P>(
        &self,
        encoded_endpoints: Vec<u8>,
        signature: Vec<u8>,
        signer: &mut PairSigner<super::Config, P>,
    ) -> Result<()>
    where
        P: sp_core::Pair,
        P::Signature: ToMultiSignature,
    {
        let params = self.mk_params(8, 0).await?.build();
        let tx = crate::dynamic::tx::update_worker_endpoint(encoded_endpoints, signature);
        info!("seding update_worker_endpoints");
        let progress = self
            .tx()
            .create_signed(&tx, signer, params)
            .await
            .context("failed to sign the update_worker_endpoints tx")?
            .submit_and_watch()
            .await
            .context("failed to submit the update_worker_endpoints tx")?;
        info!("update_worker_endpoints tx submitted, waiting for finalization...");
        let block = progress
            .wait_for_finalized()
            .await
            .context("failed to finalize the update_worker_endpoints tx")?;
        info!(
            "update_worker_endpoints tx finalized at block {:?}",
            block.block_hash()
        );
        Ok(())
    }

    pub async fn register_worker<P>(
        &self,
        encoded_runtime_info: Vec<u8>,
        attestation: Vec<u8>,
        signer: &mut PairSigner<super::Config, P>,
    ) -> Result<()>
    where
        P: sp_core::Pair,
        P::Signature: ToMultiSignature,
    {
        let params = self.mk_params(8, 0).await?.build();
        let tx = crate::dynamic::tx::register_worker(encoded_runtime_info, attestation, true);
        info!("sending register_worker");
        let progress = self
            .tx()
            .create_signed(&tx, signer, params)
            .await
            .context("failed to sign the register_worker tx")?
            .submit_and_watch()
            .await
            .context("failed to submit the register_worker tx")?;
        info!("register_worker tx submitted, waiting for finalization...");
        let block = progress
            .wait_for_finalized()
            .await
            .context("failed to finalize the register_worker tx")?;
        info!(
            "register_worker tx finalized at block {:?}",
            block.block_hash()
        );
        Ok(())
    }

    pub async fn get_genesis_hash(&self) -> Result<[u8; 32]> {
        let hash = self.backend().genesis_hash().await?;
        Ok(hash.into())
    }
}

pub async fn connect(url: &str) -> Result<ChainApi> {
    let ws_client = ws_client(url).await?;
    let rpc_client = RpcClient::new(ws_client);
    let online_client = OnlineClient::from_rpc_client(rpc_client.clone())
        .await
        .context("Failed to connect to substrate")?;
    let update_client = online_client.updater();
    tokio::spawn(async move {
        let result = update_client.perform_runtime_updates().await;
        eprintln!("Runtime update failed with result={result:?}");
    });
    Ok(ChainApi {
        rpc_client,
        online_client,
    })
}

async fn ws_client(url: &str) -> Result<jsonrpsee::async_client::Client> {
    let url = url.parse().context("Invalid websocket url")?;
    let (sender, receiver) = WsTransportClientBuilder::default()
        .max_request_size(u32::MAX)
        .max_response_size(u32::MAX)
        .build(url)
        .await
        .context("Failed to build ws transport")?;
    Ok(ClientBuilder::default().build_with_tokio(sender, receiver))
}
