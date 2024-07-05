use std::{
    collections::{BTreeMap, BTreeSet},
    rc::Rc,
};

use anyhow::{Context, Result};
use cid::Cid;
use hex_fmt::HexFmt as Hex;
use phaxt::phala::runtime_types::{
    phala_pallets::wapod_workers::pallet::TicketInfo,
    sp_core::sr25519::Public,
    wapod_types::{session::SessionUpdate, ticket::Prices},
};
use scale::Decode;
use tokio::sync::mpsc;
use tracing::{error, info};
use wapod_rpc::{
    prpc::{self as pb, AppListArgs, DeployArgs, InitArgs, Manifest, ResizeArgs},
    types::Address,
};
use wapod_types::ticket::TicketManifest;

use crate::{chain_state::ChainClient, ipfs_downloader::IpfsDownloader};
use crate::{chain_state::TicketId, rpc_client::WorkerClient};

pub enum Event {
    ManifestResolved {
        cid: String,
        result: Result<TicketManifest>,
    },
}

pub struct BridgeState {
    worker_client: WorkerClient,
    chain_client: ChainClient,
    tickets: BTreeMap<TicketId, TicketInfo>,
    ticket_contents: BTreeMap<Cid, Vec<BlobDep>>,
    all_apps: BTreeMap<Address, Rc<AppInfo>>,
    selected_apps: BTreeMap<Address, AppPlan>,
    bench_app_address: Option<Address>,
    downloader: IpfsDownloader,
}

pub struct AppInfo {
    manifest: Manifest,
    associated_tickets: BTreeSet<TicketId>,
}

pub struct AppPlan {
    info: Rc<AppInfo>,
    instances: u64,
}

#[derive(Clone)]
pub struct BlobDep {
    pub hash: String,
    pub cid: String,
}

impl BridgeState {
    pub fn new(
        worker_client: WorkerClient,
        chain_client: ChainClient,
        downloader: IpfsDownloader,
    ) -> Self {
        Self {
            worker_client,
            chain_client,
            all_apps: BTreeMap::new(),
            selected_apps: BTreeMap::new(),
            tickets: BTreeMap::new(),
            ticket_contents: BTreeMap::new(),
            bench_app_address: None,
            downloader,
        }
    }

    pub async fn init_worker(&self) -> Result<()> {
        let info = self.worker_client.operation().info().await?;
        let pubkey = Public(info.decode_pubkey()?);
        let worker_session_address = phaxt::phala::storage()
            .phala_wapod_workers()
            .worker_sessions(&pubkey);
        let session = self
            .chain_client
            .storage()
            .at_latest()
            .await?
            .fetch(&worker_session_address)
            .await
            .context("Failed to get worker session")?;
        // if there is a session recorded on-chain, use the last_nonce to initialize the worker
        // else initialize the worker with an empty nonce
        let nonce = match &session {
            Some(session) => &session.last_nonce[..],
            None => &[],
        };
        info!("initializing worker with nonce: 0x{}", Hex(nonce));
        let response = self
            .worker_client
            .operation()
            .worker_init(InitArgs {
                nonce: nonce.to_vec(),
            })
            .await?;
        let update = response.decode_session_update()?;
        info!(?update, "updating worker session");
        let tx = phaxt::phala::tx().phala_wapod_workers().update_session(
            pubkey.0,
            SessionUpdate {
                session: update.session,
                seed: update.seed,
            },
            response.signature,
        );
        self.chain_client
            .submit_tx(&tx, true)
            .await
            .context("failed to update session")?;
        Ok(())
    }

    pub async fn get_running_apps(&self) -> Result<BTreeMap<Address, u64>> {
        let apps = self
            .worker_client
            .operation()
            .app_list(AppListArgs {
                start: 0,
                count: u32::MAX,
            })
            .await?
            .apps;
        let apps = apps
            .into_iter()
            .map(|app| {
                let address =
                    Address::decode(&mut &app.address[..]).context("invalid app address")?;
                Ok((address, app.instances))
            })
            .collect::<Result<_>>()?;
        Ok(apps)
    }

    pub async fn update_plan(&mut self) -> Result<()> {
        let todo = "";
        Ok(())
    }

    pub async fn apply_plan(&self) -> Result<()> {
        let info = self.worker_client.operation().info().await?;

        if info.session.is_empty() {
            self.init_worker().await?;
        }

        let apps = self.get_running_apps().await?;
        let total_planned: u64 = self.selected_apps.values().map(|p| p.instances).sum();
        let total_running: u64 = apps.values().copied().sum();

        let mut to_deploy = vec![];
        let mut to_remove = vec![];
        let mut to_resize = vec![];

        for (address, plan) in self.selected_apps.iter() {
            let Some(running_instances) = apps.get(address).cloned() else {
                to_deploy.push((*address, plan));
                continue;
            };

            if total_running <= total_planned && running_instances < plan.instances as u64 {
                to_resize.push((*address, plan.instances));
            }
        }
        for (address, _running_instances) in apps.iter() {
            if !self.selected_apps.contains_key(address) {
                to_remove.push(*address);
            }
        }

        info!("applying plan, total planned: {total_planned}, total running: {total_running}");
        info!(
            "to_deploy: {}, to_remove: {}, to_resize: {}",
            to_deploy.len(),
            to_remove.len(),
            to_resize.len()
        );

        for (address, plan) in to_deploy {
            let result = self
                .worker_client
                .operation()
                .app_deploy(DeployArgs {
                    manifest: Some(plan.info.manifest.clone()),
                })
                .await;
            match result {
                Ok(response) => {
                    if response.address != address {
                        error!(
                            "deployed address mismatch: expected 0x{}, got 0x{}",
                            Hex(address),
                            Hex(response.address)
                        );
                    } else {
                        info!("deployed app 0x{}", Hex(address));
                    }
                }
                Err(e) => {
                    error!("failed to deploy app 0x{}: {:?}", Hex(address), e);
                }
            }
        }

        for address in to_remove {
            let result = self
                .worker_client
                .operation()
                .app_remove(pb::Address {
                    address: address.to_vec(),
                })
                .await;
            match result {
                Ok(_) => {
                    info!("removed app {}", Hex(address));
                }
                Err(e) => {
                    error!("failed to remove app {}: {:?}", Hex(address), e);
                }
            }
        }

        for (address, instances) in to_resize {
            let result = self
                .worker_client
                .operation()
                .app_resize(ResizeArgs {
                    address: address.to_vec(),
                    instances: instances as _,
                })
                .await;
            match result {
                Ok(_) => {
                    info!("resized app 0x{} to {}", Hex(address), instances);
                }
                Err(e) => {
                    error!("failed to resize app 0x{}: {:?}", Hex(address), e);
                }
            }
        }
        Ok(())
    }
}

async fn do_resolve_manifest(cid: String, downloader: IpfsDownloader) -> Result<TicketManifest> {
    let cid = Cid::try_from(cid.as_str()).context("invalid cid")?;
    let manifest_data = downloader.read_or_download(&cid).await?;
    let manifest: TicketManifest =
        serde_json::from_slice(&manifest_data).context("invalid manifest")?;
    Ok(manifest)
}

async fn resolve_manifest(cid: String, downloader: IpfsDownloader, event_tx: mpsc::Sender<Event>) {
    let result = do_resolve_manifest(cid.clone(), downloader).await;
    _ = event_tx.send(Event::ManifestResolved { cid, result }).await;
}

pub async fn run_bridge() -> Result<()> {
    // let state = BridgeState::new(
    //     WorkerClient::new(),
    //     ChainClient::new(),
    //     IpfsDownloader::new(),
    // );
    // sync chain state
    // hunt for new tickets
    // hunt for heartbeat
    // hunt for new bench apps
    // monitor worker state, schedule jobs
    // submit bench score
    Ok(())
}
