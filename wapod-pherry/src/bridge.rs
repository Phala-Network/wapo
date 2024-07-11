use std::{
    collections::{BTreeMap, BTreeSet},
    pin::pin,
    rc::Rc,
    time::{Duration, Instant},
};

use anyhow::{bail, Context, Result};
use cid::Cid;
use hex_fmt::HexFmt as Hex;
use phaxt::{
    phala::{
        phala_computation::events::HeartbeatChallenge,
        runtime_types::{
            phala_pallets::wapod_workers::pallet::{TicketInfo, WorkerSet},
            sp_core::sr25519::Public,
            wapod_types::session::SessionUpdate,
        },
    },
    subxt::storage::Address as _,
    RecodeTo,
};
use scale::Decode;
use sp_core::{sr25519, Pair};
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};
use wapod_rpc::{
    prpc::{self as pb, AppListArgs, Blob, DeployArgs, InitArgs, QueryArgs, SetBenchAppArgs},
    types::{Address, VersionedAppsMetrics},
};
use wapod_types::{
    metrics::{SignedAppsMetrics, MAX_CLAIM_TICKETS},
    primitives::BoundedVec,
    ticket::AppManifest,
};

use crate::{
    chain_state::{monitor_chain_state, ChainClient},
    ipfs_downloader::IpfsDownloader,
    register::register_with_client,
    util::IgnoreError,
};
use crate::{
    chain_state::{ChainState, TicketId},
    rpc_client::WorkerClient,
};

pub struct BridgeConfig {
    pub node_url: String,
    pub tx_signer: String,
    pub worker_url: String,
    pub worker_token: String,
    pub ipfs_base_url: String,
    pub ipfs_cache_dir: String,
    pub max_apps: usize,
    pub metrics_interval: Duration,
    pub reward_receiver: String,
    pub operator: String,
    pub pccs_url: String,
}

pub enum Event {
    ManifestResolved {
        cid: String,
        result: Result<AppManifest>,
    },
}

#[derive(Clone, Debug)]
struct Ticket {
    info: TicketInfo,
    manifest: AppManifest,
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
    last_metrics_report: Instant,
}

#[derive(Default)]
struct PlanningState {
    tickets: BTreeMap<TicketId, Ticket>,
    ticket_balances: BTreeMap<TicketId, u128>,
    /// (address, instances) of the bench app
    bench_app: Option<(Address, u64)>,
    all_apps: BTreeMap<Address, Rc<AppInfo>>,
    selected_apps: BTreeMap<Address, Rc<AppInfo>>,
    download_failures: BTreeMap<String, String>,
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
            last_metrics_report: Instant::now(),
        })
    }

    pub async fn maybe_register_worker(&self) -> Result<()> {
        let info = self.worker_client.operation().info().await?;
        let pubkey = Public(info.decode_pubkey()?);
        let worker_info_address = phaxt::phala::storage().phala_registry().workers(&pubkey);
        let worker_info = self
            .chain_client
            .storage()
            .at_latest()
            .await?
            .fetch(&worker_info_address)
            .await
            .context("failed to get worker info")?;
        if worker_info.is_some() {
            return Ok(());
        }
        register_with_client(
            &self.chain_client,
            &self.worker_client,
            &self.config.operator,
            &self.config.pccs_url,
        )
        .await
    }

    pub async fn maybe_update_session(&self) -> Result<()> {
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
            .context("failed to get worker session")?;

        if Some(info.session.as_slice()) == session.as_ref().map(|s| s.session_id.as_slice()) {
            return Ok(());
        }
        // if there is a session recorded on-chain, use the last_nonce to initialize the worker
        // else initialize the worker with an empty nonce
        let nonce = match &session {
            Some(session) => &session.last_nonce[..],
            None => &[],
        };
        info!("session mismatch, resetting the worker");
        self.worker_client
            .operation()
            .app_remove_all()
            .await
            .context("failed to remove all apps")?;
        info!("initializing worker with nonce: 0x{}", Hex(nonce));
        let response = self
            .worker_client
            .operation()
            .worker_init(InitArgs {
                nonce: nonce.to_vec(),
                reward_receiver: self.config.reward_receiver.clone(),
            })
            .await?;
        let update = response.decode_session_update()?;
        info!(?update, "updating worker session");
        let tx = phaxt::phala::tx()
            .phala_wapod_workers()
            .update_session(
                pubkey.0,
                SessionUpdate {
                    session: update.session,
                    seed: update.seed,
                },
                response.signature,
            )
            .unvalidated();
        self.chain_client
            .submit_tx(tx, true)
            .await
            .context("failed to update session")?;
        info!("worker session updated");
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

        let apps = self.get_running_apps().await?;
        let mut to_deploy = vec![];
        let mut to_remove = vec![];

        for (address, plan) in self.planning_state.selected_apps.iter() {
            if !apps.contains_key(address) {
                to_deploy.push((*address, plan));
            }
        }
        for (address, _running_instances) in apps.iter() {
            if !self.planning_state.selected_apps.contains_key(address) {
                to_remove.push(*address);
            }
        }

        info!(
            tickets_onchain = self.chain_state.tickets.len(),
            tickets_for_worker = self.planning_state.tickets.len(),
            apps = self.planning_state.all_apps.len(),
            selected_apps = self.planning_state.selected_apps.len(),
            deployed = info.deployed_apps,
            running = info.running_instances,
            to_deploy = to_deploy.len(),
            to_remove = to_remove.len(),
            "applying plan"
        );

        'next_app: for (address, info) in to_deploy {
            let deps = info
                .associated_tickets
                .iter()
                .map(|id| {
                    self.planning_state.tickets[id]
                        .manifest
                        .required_blobs
                        .clone()
                        .into_iter()
                })
                .flatten()
                .collect::<BTreeSet<_>>();
            for (hash, cid_str) in deps {
                let uploaded = self
                    .worker_client
                    .operation()
                    .blob_exists(Blob {
                        hash: hash.clone(),
                        body: vec![],
                    })
                    .await?
                    .value;
                if uploaded {
                    continue;
                }
                let cid: Cid = cid_str.parse().context("invalid blob cid")?;
                let blob = self
                    .ipfs_downloader
                    .read(&cid)
                    .await?
                    .context("blob not found")?;
                info!(?hash, ?cid, address=%Hex(address), "uploading blob");
                let result = self
                    .worker_client
                    .operation()
                    .blob_put(Blob { hash, body: blob })
                    .await;
                if let Err(err) = result {
                    error!("failed to upload blob: {:?}", err);
                    continue 'next_app;
                }
            }
            info!("deploying app 0x{}", Hex(address));
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
            info!("removing app 0x{}", Hex(address));
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
            if let Some(err) = self
                .planning_state
                .download_failures
                .get(&ticket_info.manifest_cid)
            {
                bail!("failed to download manifest: {err}");
            }
            self.ipfs_downloader.download(&cid, false)?;
            return Ok(None);
        };
        let manifest: AppManifest =
            serde_json::from_slice(&manifest_data).context("invalid manifest")?;
        for (_hash, cid_str) in manifest.required_blobs.iter() {
            let cid: Cid = cid_str.parse().context("invalid blob cid")?;
            if let Some(err) = self.planning_state.download_failures.get(cid_str) {
                bail!("failed to download blob: {err}");
            }
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

    async fn maybe_sync_bench_app(&self) -> Result<()> {
        let (address, instances) = match self.planning_state.bench_app {
            Some((address, instances)) => (Some(address), instances),
            None => (None, 0),
        };
        info!(
            "setting bench app to {:?} with {} instances",
            address.as_ref().map(Hex),
            instances
        );
        let request = SetBenchAppArgs::new(address, instances);
        self.worker_client
            .operation()
            .set_bench_app(request)
            .await
            .context("failed to set bench app")?;
        Ok(())
    }

    async fn update_plan(&mut self) -> Result<()> {
        self.try_resolve_deps().await?;
        let worker_info = self.worker_client.operation().info().await?;
        let mut all_apps = BTreeMap::new();
        for (id, ticket) in self.planning_state.tickets.iter() {
            let info = &ticket.info;
            let manifest = &ticket.manifest;
            let address = manifest.address(sp_core::hashing::blake2_256);
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
                manifest: manifest.clone(),
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
        let todo = "better strategy to select apps.";
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
        self.apply_plan().await?;
        Ok(())
    }

    async fn maybe_report_app_metrics(&mut self) -> Result<()> {
        let todo = "report app metrics";
        if self.last_metrics_report.elapsed() < self.config.metrics_interval {
            return Ok(());
        }
        self.last_metrics_report = Instant::now();
        let response = self
            .worker_client
            .operation()
            .app_metrics(Default::default())
            .await?;
        let metrics = response.decode_metrics()?;
        let signature = response.signature;
        let VersionedAppsMetrics::V0(all_metrics) = &metrics;

        let mut claim_map = BoundedVec::default();

        for m in all_metrics.apps.0.iter() {
            let Some(info) = self.planning_state.all_apps.get(&m.address) else {
                debug!(
                    "app 0x{} not found, skipping to claim settlement",
                    Hex(m.address)
                );
                continue;
            };
            let ids = info
                .associated_tickets
                .iter()
                .cloned()
                .take(MAX_CLAIM_TICKETS)
                .collect::<Vec<_>>();
            if claim_map.push((m.address, ids.into())).is_err() {
                break;
            }
        }
        if claim_map.is_empty() {
            return Ok(());
        }

        let signed =
            SignedAppsMetrics::new(metrics, signature.into(), self.worker_pubkey, claim_map);
        let tx = phaxt::phala::tx()
            .phala_wapod_workers()
            .submit_app_metrics(signed.recode_to().context("failed to encode app metrics")?);
        self.chain_client
            .submit_tx(tx, false)
            .await
            .context("failed to submit app metrics")?;
        Ok(())
    }

    async fn maybe_report_bench_score(&self) -> Result<()> {
        let Some(challenge) = &self.chain_state.heartbeat_challenge else {
            return Ok(());
        };
        if !is_challenging_the_worker(challenge, &self.worker_pubkey) {
            return Ok(());
        }
        let todo = "avoid report if the worker is not attached to any pool.";
        let Some((address, _instances)) = &self.planning_state.bench_app else {
            debug!("no bench app");
            return Ok(());
        };
        let signed_score = self
            .worker_client
            .operation()
            .app_query(QueryArgs::new(
                *address,
                "/signedScore".into(),
                vec![],
                None,
            ))
            .await
            .context("bench app is not running")?
            .output;
        let tx = phaxt::phala::tx()
            .phala_wapod_workers()
            .submit_bench_message(Decode::decode(&mut &signed_score[..])?);
        info!("submitting bench score");
        self.chain_client
            .submit_tx(tx, false)
            .await
            .context("failed to submit bench score")?;
        Ok(())
    }

    async fn bridge(mut self) -> Result<()> {
        // things the bridge does:
        //  init worker if needed
        //  sync chain state
        //  hunt for new tickets
        //  hunt for heartbeat and response it
        //  hunt for new bench app
        //  monitor worker state, schedule jobs
        //  submit bench score
        //  submit app metrics
        let node_url = self.config.node_url.clone();
        let (chain_state_tx, mut chain_state_rx) = mpsc::channel(1);
        let mut chain_state_monitor = pin!(monitor_chain_state(node_url, chain_state_tx));
        let mut downloader_events = self.ipfs_downloader.subscribe_events();
        self.maybe_register_worker().await?;
        self.maybe_update_session().await?;
        loop {
            tokio::select! {
                _ = &mut chain_state_monitor => {}
                state = chain_state_rx.recv() => {
                    self.maybe_report_bench_score().await.ignore_error("failed to report bench score");
                    self.maybe_report_app_metrics().await.ignore_error("failed to report app metrics");
                    self.set_chain_state(state.context("chain state monitor ended")?);
                    self.maybe_sync_bench_app().await.ignore_error("failed to sync bench app");
                }
                event = downloader_events.recv() => {
                    let event = event.context("downloader event channel closed")?;
                    use crate::ipfs_downloader::Event as DownloaderEvent;
                    match event {
                        DownloaderEvent::Downloaded { cid: _ } => {}
                        DownloaderEvent::DownloadFailure { cid, error } => {
                            warn!("download {cid} failed: {error}");
                            self.planning_state.download_failures.insert(cid, error);
                            continue;
                        }
                    }
                }
            }
            self.update_plan().await?;
        }
    }
}

pub fn is_challenging_the_worker(heartbeat: &HeartbeatChallenge, worker: &Address) -> bool {
    let pkh = sp_core::blake2_256(worker);
    let hashed_id: sp_core::U256 = pkh.into();
    let seed = sp_core::U256(heartbeat.seed.0);
    let online_target = sp_core::U256(heartbeat.online_target.0);
    let x = hashed_id ^ seed;
    x <= online_target
}

pub async fn run_bridge(config: BridgeConfig) -> Result<()> {
    let pair = sr25519::Pair::from_string(&config.tx_signer, None).context("invalid tx signer")?;
    let chain_api = phaxt::connect(&config.node_url.clone())
        .await
        .context("connect to chain failed")?;
    let chain_client = ChainClient::new(chain_api, pair.into());
    let worker_client = WorkerClient::new(config.worker_url.clone(), config.worker_token.clone());
    let ipfs_downloader =
        IpfsDownloader::new(config.ipfs_base_url.clone(), config.ipfs_cache_dir.clone());
    let state = BridgeState::create(config, worker_client, chain_client, ipfs_downloader)
        .await
        .context("failed to create bridge")?;
    state.bridge().await
}
