use std::{
    collections::{BTreeMap, BTreeSet},
    pin::pin,
    rc::Rc,
};

use anyhow::{bail, Context, Result};
use cid::Cid;
use hex_fmt::HexFmt as Hex;
use phaxt::phala::runtime_types::{
    phala_pallets::wapod_workers::pallet::{TicketInfo, WorkerSet},
    sp_core::sr25519::Public,
    wapod_types::{session::SessionUpdate, ticket::Prices},
};
use scale::Decode;
use sp_core::{sr25519, Pair};
use tokio::sync::mpsc;
use tracing::{debug, error, info};
use wapod_rpc::{
    prpc::{self as pb, AppListArgs, DeployArgs, InitArgs, ResizeArgs},
    types::Address,
};
use wapod_types::ticket::{AppManifest, TicketManifest};

use crate::{
    chain_state::{monitor_chain_state, ChainClient},
    ipfs_downloader::{self, IpfsDownloader},
};
use crate::{
    chain_state::{ChainState, TicketId},
    rpc_client::WorkerClient,
};

pub struct BridgeConfig {
    pub node_uri: String,
    pub tx_signer: String,
    pub worker_uri: String,
    pub worker_token: String,
    pub ipfs_base_uri: String,
    pub ipfs_data_dir: String,
    pub max_apps: usize,
}

pub enum Event {
    ManifestResolved {
        cid: String,
        result: Result<TicketManifest>,
    },
}

#[derive(Clone, Debug)]
struct Ticket {
    info: TicketInfo,
    manifest: TicketManifest,
    // prices: Prices,
}

pub struct BridgeState {
    worker_pubkey: Address,
    worker_client: WorkerClient,
    chain_client: ChainClient,
    ipfs_downloader: IpfsDownloader,
    planning_state: PlanningState,
    chain_state: ChainState,
    config: BridgeConfig,
}

#[derive(Default)]
struct PlanningState {
    tickets: BTreeMap<TicketId, Ticket>,
    ticket_balances: BTreeMap<TicketId, u128>,
    /// (address, instances) of the bench app
    bench_app: Option<(Address, u64)>,
    all_apps: BTreeMap<Address, Rc<AppInfo>>,
    selected_apps: BTreeMap<Address, Rc<AppInfo>>,
}

pub struct AppInfo {
    manifest: AppManifest,
    associated_tickets: BTreeSet<TicketId>,
    balance: u128,
}

#[derive(Clone)]
pub struct BlobDep {
    pub hash: String,
    pub cid: String,
}

impl BridgeState {
    pub async fn create(
        config: BridgeConfig,
        worker_client: WorkerClient,
        chain_client: ChainClient,
        downloader: IpfsDownloader,
    ) -> Result<Self> {
        let info = worker_client.operation().info().await?;
        Ok(Self {
            worker_pubkey: info.decode_pubkey().context("invalid pubkey from worker")?,
            worker_client,
            chain_client,
            ipfs_downloader: downloader,
            planning_state: Default::default(),
            chain_state: Default::default(),
            config,
        })
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

    fn set_chain_state(&mut self, chain_state: ChainState) {
        self.chain_state = chain_state;
        self.planning_state = Default::default();
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

    pub async fn apply_plan(&self) -> Result<()> {
        let info = self.worker_client.operation().info().await?;

        if info.session.is_empty() {
            self.init_worker().await?;
        }

        let apps = self.get_running_apps().await?;
        let total_running: u64 = apps.values().copied().sum();

        let mut to_deploy = vec![];
        let mut to_remove = vec![];

        for (address, plan) in self.planning_state.selected_apps.iter() {
            let Some(running_instances) = apps.get(address).cloned() else {
                to_deploy.push((*address, plan));
                continue;
            };
        }
        for (address, _running_instances) in apps.iter() {
            if !self.planning_state.selected_apps.contains_key(address) {
                to_remove.push(*address);
            }
        }

        info!(
            "to_deploy: {}, to_remove: {}",
            to_deploy.len(),
            to_remove.len(),
        );

        for (address, info) in to_deploy {
            let result = self
                .worker_client
                .operation()
                .app_deploy(DeployArgs {
                    manifest: Some(info.manifest.clone().into()),
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
        Ok(())
    }

    /// Try to resolve a ticket.
    ///
    /// Returns the resolved ticket if all required blobs are ready.
    /// Returns None if the manifest or any of the required blobs are not
    /// ready and ask the downloader to download them.
    async fn try_resolve(&self, ticket_info: &TicketInfo) -> Result<Option<Ticket>> {
        let cid = ticket_info
            .manifest_cid
            .parse()
            .context("invalid manifest cid")?;
        let Some(manifest_data) = self.ipfs_downloader.read(&cid).await? else {
            self.ipfs_downloader.download(&cid, false)?;
            return Ok(None);
        };
        let manifest: TicketManifest =
            serde_json::from_slice(&manifest_data).context("invalid manifest")?;
        for (_hash, cid_str) in manifest.required_blobs.iter() {
            let cid: Cid = cid_str.parse().context("invalid blob cid")?;
            let downloaded = self.ipfs_downloader.download(&cid, false)?;
            if !downloaded {
                return Ok(None);
            }
        }
        Ok(Some(Ticket {
            info: ticket_info.clone(),
            manifest,
        }))
    }

    fn is_ticket_for_worker(&self, info: &TicketInfo) -> bool {
        if Some(info.address) == self.chain_state.bench_app_address {
            return true;
        }
        let WorkerSet::WorkerList(list_id) = info.workers else {
            return false;
        };
        let Some(list) = self.chain_state.worker_list_workers.get(&list_id) else {
            return false;
        };
        list.contains(&self.worker_pubkey)
    }

    async fn try_resolve_deps(&mut self) -> Result<()> {
        let todo = "todo";
        for (id, info) in self.chain_state.tickets.iter() {
            if self.planning_state.tickets.contains_key(id) {
                continue;
            }
            if !self.is_ticket_for_worker(info) {
                continue;
            }
            debug!(id, "resolving ticket");
            let resolved = match self.try_resolve(info).await {
                Ok(r) => r,
                Err(err) => {
                    error!("failed to resolve ticket {}: {:?}", id, err);
                    continue;
                }
            };
            debug!(id, "resolved ticket: {resolved:?}");
            let Some(ticket) = resolved else {
                continue;
            };
            self.planning_state.tickets.insert(*id, ticket);
        }
        Ok(())
    }

    async fn update_plan(&mut self) -> Result<()> {
        let todo = "review codegen";
        self.try_resolve_deps().await?;
        let worker_info = self.worker_client.operation().info().await?;
        let mut all_apps = BTreeMap::new();
        for (id, ticket) in self.planning_state.tickets.iter() {
            let info = &ticket.info;
            let manifest = &ticket.manifest;
            let address = manifest.manifest.address(sp_core::hashing::blake2_256);
            if info.address != address {
                error!(
                    id,
                    "ticket address mismatch: expected 0x{}, got 0x{}",
                    Hex(info.address),
                    Hex(address)
                );
                continue;
            }
            let balance = match self.planning_state.ticket_balances.get(id) {
                Some(b) => *b,
                None => {
                    let balance = self
                        .chain_client
                        .ticket_balance(*id)
                        .await
                        .context("failed to get ticket balance")?;
                    self.planning_state.ticket_balances.insert(*id, balance);
                    balance
                }
            };
            let entry = all_apps.entry(address);
            let app_info = entry.or_insert(AppInfo {
                manifest: manifest.manifest.clone(),
                associated_tickets: BTreeSet::new(),
                balance: 0,
            });
            app_info.associated_tickets.insert(*id);
            app_info.balance += balance;
        }
        let all_apps: BTreeMap<_, _> = all_apps.into_iter().map(|(k, v)| (k, Rc::new(v))).collect();
        let mut sorted_apps: Vec<_> = all_apps
            .iter()
            .map(|(id, info)| (id.clone(), info.clone()))
            .collect();

        // Sort apps by balance in descending order.
        let todo = "Better strategy to select apps.";
        sorted_apps.sort_by(|a, b| b.1.balance.cmp(&a.1.balance));

        let selected_apps = sorted_apps
            .into_iter()
            .take(self.config.max_apps)
            .collect::<BTreeMap<_, _>>();
        self.planning_state.all_apps = all_apps;
        self.planning_state.selected_apps = selected_apps;
        self.planning_state.bench_app = self
            .chain_state
            .bench_app_address
            .map(|address| (address, worker_info.max_instances));
        Ok(())
    }

    async fn bridge(mut self) -> Result<()> {
        // things the bridge does:
        //  init worker if needed
        //  sync chain state
        //  hunt for new tickets
        //  hunt for heartbeat and response it
        //  hunt for new bench apps
        //  monitor worker state, schedule jobs
        //  submit bench score
        let node_uri = self.config.node_uri.clone();
        let (chain_state_tx, mut chain_state_rx) = mpsc::channel(1);
        let mut chain_state_monitor = pin!(monitor_chain_state(node_uri, chain_state_tx));
        let mut downloader_events = self.ipfs_downloader.subscribe_events();
        loop {
            tokio::select! {
                _ = &mut chain_state_monitor => {}
                state = chain_state_rx.recv() => {
                    self.set_chain_state(state.context("chain state monitor ended")?);
                }
                _ = downloader_events.recv() => {
                }
            }
            self.update_plan().await?;
        }
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

pub async fn run_bridge(config: BridgeConfig) -> Result<()> {
    let pair = sr25519::Pair::from_string(&config.tx_signer, None).context("invalid tx signer")?;
    let chain_api = phaxt::connect(&config.node_uri.clone())
        .await
        .context("connect to chain failed")?;
    let chain_client = ChainClient::new(chain_api, pair.into());
    let worker_client = WorkerClient::new(config.worker_uri.clone(), config.worker_token.clone());
    let ipfs_downloader =
        IpfsDownloader::new(config.ipfs_base_uri.clone(), config.ipfs_data_dir.clone());
    let state = BridgeState::create(config, worker_client, chain_client, ipfs_downloader)
        .await
        .context("failed to create bridge")?;
    state.bridge().await
}
