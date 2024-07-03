use std::collections::BTreeMap;

use phaxt::phala::{
    phala_wapod_workers::storage::types::tickets::Tickets,
    runtime_types::phala_pallets::wapod_workers::pallet::{
        BenchAppInfo, TicketInfo, WorkerListInfo,
    },
};

type TicketId = u32;
type WorkerListId = u32;
type Address = [u8; 32];

pub struct ChainState {
    tickets: BTreeMap<TicketId, TicketInfo>,
    worker_lists: BTreeMap<WorkerListId, WorkerListInfo>,
    bench_app: Option<Address>,
    valid_bench_apps: BTreeMap<Address, BenchAppInfo>,
}

impl ChainState {
    pub fn get_tickets_for(worker: &Address) -> Vec<TicketInfo> {
        todo!()
    }
}
