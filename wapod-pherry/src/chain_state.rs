use std::{collections::BTreeMap, mem::size_of};

use anyhow::{bail, Context, Result};
use phaxt::phala::runtime_types::phala_pallets::wapod_workers::pallet::{
    BenchAppInfo, TicketInfo, WorkerListInfo,
};
use scale::Decode;
use tokio::{
    sync::mpsc::{Receiver, Sender},
    time::Duration,
};
use tracing::{error, info, trace};

pub type TicketId = u64;
pub type WorkerListId = u64;
pub type Address = [u8; 32];

pub struct ChainState {
    pub tickets: BTreeMap<TicketId, TicketInfo>,
    pub worker_lists: BTreeMap<WorkerListId, WorkerListInfo>,
    pub bench_app: Option<Address>,
    pub valid_bench_apps: BTreeMap<Address, BenchAppInfo>,
}

pub fn monitor_chain_state(uri: String) -> Receiver<ChainState> {
    let (tx, rx) = tokio::sync::mpsc::channel(1);
    tokio::spawn(async move {
        loop {
            let client = match phaxt::connect(&uri).await {
                Ok(client) => client,
                Err(err) => {
                    error!("failed to connect to chain: {err}");
                    tokio::time::sleep(Duration::from_secs(5)).await;
                    continue;
                }
            };
            if let Err(err) = monitor(client, tx.clone()).await {
                error!("monitoring chain state error: {err}");
                tokio::time::sleep(Duration::from_secs(5)).await;
            }
        }
    });
    rx
}

async fn monitor(client: phaxt::ChainApi, tx: Sender<ChainState>) -> Result<()> {
    let mut sub = client.client().blocks().subscribe_finalized().await?;
    loop {
        info!("waiting for new block");
        let block = sub
            .next()
            .await
            .context("block subscription ended")?
            .context("block subscription failed")?;
        let block_hash = block.hash();
        let block_number = block.number();

        info!("new block: {block_number} {block_hash}");

        let pallet = phaxt::phala::storage().phala_wapod_workers();
        let tickets = {
            let mut tickets = BTreeMap::<TicketId, TicketInfo>::new();

            let query_tickets = pallet.tickets_iter();
            let mut tickets_iter = block.storage().iter(query_tickets).await?;
            while let Some(pair) = tickets_iter.next().await {
                let pair = pair?;
                if pair.key_bytes.len() < size_of::<TicketId>() {
                    bail!("invalid ticket id");
                }
                let tail = &pair.key_bytes[pair.key_bytes.len() - size_of::<TicketId>()..];
                let ticket_id = TicketId::decode(&mut &*tail).context("invalid ticket id")?;
                trace!("found ticket {ticket_id}: {:?}", pair.value);
                tickets.insert(ticket_id, pair.value);
            }
            tickets
        };
        let worker_lists = {
            let mut worker_lists = BTreeMap::<WorkerListId, WorkerListInfo>::new();

            let query_worker_lists = pallet.worker_lists_iter();
            let mut worker_lists_iter = block.storage().iter(query_worker_lists).await?;
            while let Some(pair) = worker_lists_iter.next().await {
                let pair = pair?;
                if pair.key_bytes.len() < size_of::<WorkerListId>() {
                    bail!("invalid worker list id");
                }
                let tail = &pair.key_bytes[pair.key_bytes.len() - size_of::<WorkerListId>()..];
                let worker_list_id =
                    WorkerListId::decode(&mut &*tail).context("invalid worker list id")?;
                trace!("found worker list {worker_list_id}: {:?}", pair.value);
                worker_lists.insert(worker_list_id, pair.value);
            }
            worker_lists
        };

        let bench_app = {
            let query_bench_app = pallet.recommended_benchmark_app();
            let bench_app = block.storage().fetch(&query_bench_app).await?;
            trace!("found bench app: {:?}", bench_app);
            bench_app
        };

        let valid_bench_apps = {
            let mut valid_bench_apps = BTreeMap::<Address, BenchAppInfo>::new();

            let query_valid_bench_apps = pallet.benchmark_apps_iter();
            let mut valid_bench_apps_iter = block.storage().iter(query_valid_bench_apps).await?;
            while let Some(pair) = valid_bench_apps_iter.next().await {
                let pair = pair?;
                if pair.key_bytes.len() != size_of::<Address>() {
                    bail!("invalid bench app address");
                }
                let tail = &pair.key_bytes[pair.key_bytes.len() - size_of::<Address>()..];
                let bench_app_address =
                    Address::decode(&mut &*tail).context("invalid bench app address")?;
                valid_bench_apps.insert(bench_app_address, pair.value);
            }
            valid_bench_apps
        };
        let state = ChainState {
            tickets,
            worker_lists,
            bench_app,
            valid_bench_apps,
        };
        tx.send(state).await?;
    }
}
