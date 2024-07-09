use std::{collections::BTreeMap, mem::size_of};

use anyhow::{bail, Context, Result};
use phaxt::phala::phala_computation::events::HeartbeatChallenge;
use phaxt::phala::runtime_types::phala_pallets::wapod_workers::pallet::{
    BenchAppInfo, TicketInfo, WorkerListInfo,
};
use scale::Decode;
use tokio::{
    sync::mpsc::{Receiver, Sender},
    time::{timeout, Duration},
};
use tracing::{error, info, trace};
use wapod_rpc::types::Address;

pub use chain_client::ChainClient;

mod chain_client;

pub type TicketId = u64;
pub type WorkerListId = u64;

#[derive(Default)]
pub struct ChainState {
    pub tickets: BTreeMap<TicketId, TicketInfo>,
    pub worker_lists: BTreeMap<WorkerListId, WorkerListInfo>,
    pub worker_list_workers: BTreeMap<WorkerListId, Vec<Address>>,
    pub bench_app_address: Option<Address>,
    pub valid_bench_apps: BTreeMap<Address, BenchAppInfo>,
    pub heartbeat_challenge: Option<HeartbeatChallenge>,
}

/// Timeout for network connecting and handshaking, etc.
const NET_TIMEOUT: Duration = Duration::from_secs(60);
/// Timeout for data transfering.
const DATA_TIMEOUT: Duration = Duration::from_secs(120);
/// Timeout for block subscription.
const BLOCK_TIMEOUT: Duration = Duration::from_secs(60);

pub fn heartbeat_hit_worker(heartbeat: &HeartbeatChallenge, worker: &Address) -> bool {
    let pkh = sp_core::blake2_256(worker);
    let hashed_id: sp_core::U256 = pkh.into();
    let seed = sp_core::U256(heartbeat.seed.0);
    let online_target = sp_core::U256(heartbeat.online_target.0);
    let x = hashed_id ^ seed;
    x <= online_target
}

pub async fn monitor_chain_state(uri: String, state_tx: Sender<ChainState>) {
    loop {
        if let Err(err) = monitor(&uri, state_tx.clone()).await {
            error!("monitoring chain state error: {err}");
            tokio::time::sleep(Duration::from_secs(5)).await;
        }
    }
}

// This is a workaround for the issue that the subxt generated code always set the iter Keys to `()`
fn decode_key<K: Decode>(key_bytes: &[u8]) -> Result<K> {
    if key_bytes.len() < size_of::<K>() {
        bail!("invalid key");
    }
    let tail = &key_bytes[key_bytes.len() - size_of::<K>()..];
    K::decode(&mut &*tail).context("invalid key")
}

async fn monitor(uri: &str, tx: Sender<ChainState>) -> Result<()> {
    let client = timeout(NET_TIMEOUT, phaxt::connect(&uri))
        .await
        .context("connect to chain timeout")?
        .context("connect to chain failed")?;
    let mut sub = timeout(NET_TIMEOUT, client.client().blocks().subscribe_finalized())
        .await
        .context("block subscription timeout")?
        .context("block subscription failed")?;
    loop {
        info!("waiting for new block");
        let block = timeout(BLOCK_TIMEOUT, sub.next())
            .await
            .context("block subscription timeout")?
            .context("block subscription ended")?
            .context("block subscription failed")?;
        let block_hash = block.hash();
        let block_number = block.number();
        info!("new block: {block_number} {block_hash}");

        timeout(DATA_TIMEOUT, async {
            let pallet = phaxt::phala::storage().phala_wapod_workers();

            let tickets = {
                let mut tickets = BTreeMap::<TicketId, TicketInfo>::new();

                let query_tickets = pallet.tickets_iter();
                let mut tickets_iter = block.storage().iter(query_tickets).await?;
                while let Some(pair) = tickets_iter
                    .next()
                    .await
                    .transpose()
                    .context("failed to fetch tickets")?
                {
                    let ticket_id = decode_key(&pair.key_bytes)?;
                    trace!("found ticket {ticket_id}: {:?}", pair.value);
                    tickets.insert(ticket_id, pair.value);
                }
                tickets
            };
            let (worker_lists, worker_list_workers) = {
                let mut worker_lists = BTreeMap::<WorkerListId, WorkerListInfo>::new();
                let mut worker_list_workers = BTreeMap::<WorkerListId, Vec<Address>>::new();

                let query_worker_lists = pallet.worker_lists_iter();
                let mut worker_lists_iter = block.storage().iter(query_worker_lists).await?;
                while let Some(pair) = worker_lists_iter
                    .next()
                    .await
                    .transpose()
                    .context("failed to fetch worker lists")?
                {
                    let worker_list_id = decode_key(&pair.key_bytes)?;
                    trace!("found worker list {worker_list_id}: {:?}", pair.value);
                    worker_lists.insert(worker_list_id, pair.value);

                    let mut list: Vec<Address> = vec![];
                    let query_workers = pallet.worker_list_workers_iter1(worker_list_id);
                    let mut workers_iter = block.storage().iter(query_workers).await?;
                    while let Some(worker) = workers_iter
                        .next()
                        .await
                        .transpose()
                        .context("failed to fetch workers of list")?
                    {
                        let worker_address = decode_key(&worker.key_bytes)?;
                        list.push(worker_address);
                    }
                    worker_list_workers.insert(worker_list_id, list);
                }
                (worker_lists, worker_list_workers)
            };

            let bench_app_address = {
                let query_bench_app = pallet.recommended_benchmark_app();
                let bench_app = block.storage().fetch(&query_bench_app).await?;
                trace!("found bench app: {:?}", bench_app);
                bench_app
            };

            let valid_bench_apps = {
                let mut valid_bench_apps = BTreeMap::<Address, BenchAppInfo>::new();

                let query_valid_bench_apps = pallet.benchmark_apps_iter();
                let mut valid_bench_apps_iter =
                    block.storage().iter(query_valid_bench_apps).await?;
                while let Some(pair) = valid_bench_apps_iter
                    .next()
                    .await
                    .transpose()
                    .context("failed to fetch bench apps")?
                {
                    let bench_app_address = decode_key(&pair.key_bytes)?;
                    valid_bench_apps.insert(bench_app_address, pair.value);
                }
                valid_bench_apps
            };
            let heartbeat_challenge = {
                let events = block.events().await.context("failed to fetch events")?;
                events
                    .find_first::<HeartbeatChallenge>()
                    .context("failed to find heartbeat challenge")?
            };
            let state = ChainState {
                tickets,
                worker_lists,
                worker_list_workers,
                bench_app_address,
                valid_bench_apps,
                heartbeat_challenge,
            };
            tx.send(state).await?;
            Ok::<_, anyhow::Error>(())
        })
        .await
        .context("fetch chain state timeout")??;
    }
}
