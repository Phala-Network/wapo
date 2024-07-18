use std::ops::Deref;

use anyhow::{Context, Result};
use phaxt::{
    phala::Event,
    signer::PhalaSigner,
    subxt::{
        config::{Header as _, RefineParams, RefineParamsData},
        dynamic::Value,
        metadata::DecodeWithMetadata,
        storage::{DefaultAddress, StorageKey},
        tx::{Payload, SubmittableExtrinsic},
        utils::Yes,
    },
    BuiltExtrinsicParams, ChainApi,
};
use sp_core::{sr25519, Pair};
use tokio::time::timeout;
use tracing::{debug, error, info};

use super::NET_TIMEOUT;

#[derive(Debug, Default)]
pub struct NonceJar {
    next_nonce: Option<u64>,
}

impl NonceJar {
    pub async fn next(&mut self, client: &ChainClient) -> Result<u64> {
        let nonce = match self.next_nonce {
            Some(nonce) => nonce,
            None => client.account_nonce(client.signer().account_id()).await?,
        };
        self.next_nonce = Some(nonce + 1);
        Ok(nonce)
    }
    pub fn reset(&mut self) {
        self.next_nonce = None;
    }
}

pub struct ChainClient {
    client: ChainApi,
    signer: PhalaSigner,
}

impl Deref for ChainClient {
    type Target = ChainApi;

    fn deref(&self) -> &Self::Target {
        &self.client
    }
}

impl ChainClient {
    pub fn new(client: ChainApi, signer: PhalaSigner) -> Self {
        Self { client, signer }
    }

    pub fn signer(&self) -> &PhalaSigner {
        &self.signer
    }

    pub async fn connect(url: &str, signer: &str) -> Result<Self> {
        let client = timeout(NET_TIMEOUT, phaxt::connect(url))
            .await
            .context("connect to chain timeout")?
            .context("connect to chain failed")?;
        let pair = sr25519::Pair::from_string(signer, None).context("invalid signer")?;
        let signer = PhalaSigner::new(pair);
        Ok(Self::new(client, signer))
    }

    pub async fn fetch<Keys, ReturnTy, Defaultable, Iterable>(
        &self,
        address: DefaultAddress<Keys, ReturnTy, Yes, Defaultable, Iterable>,
    ) -> Result<Option<ReturnTy>>
    where
        Keys: StorageKey,
        ReturnTy: DecodeWithMetadata,
    {
        self.storage()
            .at_latest()
            .await?
            .fetch(&address)
            .await
            .context("failed to get worker session")
    }

    pub async fn submit_tx<Call>(
        &self,
        label: &str,
        tx: Call,
        wait_finalized: bool,
        nonce_jar: &mut NonceJar,
    ) -> Result<()>
    where
        Call: Payload,
    {
        self.submit_tx_innner(tx, wait_finalized, label, nonce_jar)
            .await
            .with_context(|| format!("submit tx({label}) failed"))
    }

    async fn submit_tx_innner<Call>(
        &self,
        tx: Call,
        wait_finalized: bool,
        label: &str,
        nonce_jar: &mut NonceJar,
    ) -> Result<()>
    where
        Call: Payload,
    {
        let todo = "support tx lifetime and tip";
        let todo = "manage account nonce";
        let params = self
            .mk_params(8, 0)
            .await
            .context("mk params failed")?
            .build();
        let nonce = nonce_jar.next(self).await?;
        let signed_tx = self
            .create_signed(&tx, params, nonce)
            .await
            .context("sign tx failed")?;
        let progress = signed_tx
            .submit_and_watch()
            .await
            .context("submit tx failed")?;
        if wait_finalized {
            let events = progress
                .wait_for_finalized_success()
                .await
                .context("tx failed")?;
            info!("tx({label}) finalized");
            for (i, event) in events.all_events_in_block().iter().enumerate() {
                let Ok(event) = event else {
                    debug!("event {i}: decode failed");
                    continue;
                };
                let Ok(event) = event.as_root_event::<Event>() else {
                    debug!("event {i}: decode failed");
                    continue;
                };
                debug!("event {i}: {:?}", event);
            }
        } else {
            info!("tx({label}) submitted: {:?}", progress);
            let label = label.to_string();
            tokio::spawn(async move {
                match progress.wait_for_finalized_success().await {
                    Err(err) => error!("tx({label}) failed: {err}"),
                    Ok(_) => info!("tx({label}) finalized"),
                }
            });
        }
        Ok(())
    }

    pub async fn ticket_balance(&self, ticket_id: u64) -> Result<u128> {
        let runtime_api_call = phaxt::subxt::dynamic::runtime_api_call(
            "WapodWorkersApi",
            "balance_of_ticket",
            vec![Value::u128(ticket_id as _)],
        );

        let balance = self
            .client
            .runtime_api()
            .at_latest()
            .await?
            .call(runtime_api_call)
            .await?
            .to_value()?
            .as_u128()
            .context("invalid balance")?;
        Ok(balance)
    }

    pub async fn register_worker(
        &self,
        runtime_info: Vec<u8>,
        attestation: Vec<u8>,
        nonce_jar: &mut NonceJar,
    ) -> Result<()> {
        let tx = phaxt::dynamic::tx::register_worker(runtime_info, attestation, true);
        self.submit_tx("register worker", tx, true, nonce_jar).await
    }
}

impl ChainClient {
    async fn create_signed<Call>(
        &self,
        call: &Call,
        mut params: BuiltExtrinsicParams,
        account_nonce: u64,
    ) -> Result<SubmittableExtrinsic<phaxt::Config, phaxt::OnlineClient>>
    where
        Call: Payload,
    {
        let tx_client = self.client.tx();
        tx_client.validate(call)?;
        self.refine_params(account_nonce, &mut params).await?;
        let partial_signed = tx_client.create_partial_signed_offline(call, params.into())?;
        Ok(partial_signed.sign(self.signer()))
    }

    async fn refine_params(
        &self,
        account_nonce: u64,
        params: &mut BuiltExtrinsicParams,
    ) -> Result<()> {
        let block_ref = self.client.backend().latest_finalized_block_ref().await?;
        let block_header = self
            .client
            .backend()
            .block_header(block_ref.hash())
            .await?
            .context("block header not found")?;

        params.refine(&RefineParamsData::new(
            account_nonce,
            block_header.number.into(),
            block_header.hash(),
        ));
        Ok(())
    }
}
