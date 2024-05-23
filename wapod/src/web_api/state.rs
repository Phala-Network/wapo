use anyhow::{anyhow, bail, Context, Result};

use rand::Rng as _;
use sp_core::blake2_256;
use tokio::sync::oneshot;
use tracing::{field::display, info, warn, Instrument};
use wapo_host::{blobs::BlobLoader, Metrics};
use wapo_host::{ShortId, VmStatus, VmStatusReceiver};
use wapod_crypto::ContentType;
use wapod_rpc::prpc::{self as pb};

use std::collections::HashMap;

use std::ops::Add;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, Weak};
use std::time::Instant;

use service::{Command, CommandSender, ServiceHandle};

use wapo_host::service::{self, VmHandle};
use wapod_rpc::prpc::Manifest;

use crate::paths::blobs_dir;
use crate::worker_key::worker_identity_key;
use crate::Args;

type Address = [u8; 32];

struct Instance {
    sequence_number: u64,
    vm_handle: VmHandle,
}

#[derive(Debug, Clone)]
pub struct AppInfo {
    pub sn: u64,
    pub address: Address,
    pub session: [u8; 32],
    pub running_instances: usize,
    pub last_query_elapsed_secs: u64,
    pub manifest: Manifest,
}

pub struct AppState {
    sn: u64,
    pub session: [u8; 32],
    manifest: Manifest,
    hist_metrics: Metrics,
    instances: Vec<Instance>,
    on_going_queries: usize,
    last_query_done: Instant,
}

impl AppState {
    /// Returns the metrics of the app during the session.
    /// If there are any instance running, the metrics are merged with the current run's metrics.
    pub(crate) fn metrics(&self) -> Metrics {
        let init = self.hist_metrics.clone();
        self.instances
            .iter()
            .map(|run| run.vm_handle.meter().to_metrics())
            .fold(init, Add::add)
    }
    pub(crate) fn on_going_query_inc(&mut self) {
        self.on_going_queries += 1;
    }
    pub(crate) fn on_going_query_dec(&mut self) -> usize {
        self.on_going_queries -= 1;
        self.last_query_done = Instant::now();
        self.on_going_queries
    }

    fn info(&self, address: Address) -> AppInfo {
        AppInfo {
            address,
            sn: self.sn,
            session: self.session,
            running_instances: self.instances.len(),
            last_query_elapsed_secs: self.last_query_done.elapsed().as_secs(),
            manifest: self.manifest.clone(),
        }
    }
}

pub struct QueryGuard {
    worker: Worker,
    address: Address,
}

impl Drop for QueryGuard {
    fn drop(&mut self) {
        if let Err(err) = self.worker.end_query(self.address) {
            info!("end query error: {err}");
        }
    }
}

struct WorkerState {
    weak_self: Weak<Mutex<WorkerState>>,
    apps: HashMap<Address, AppState>,
    args: Args,
    service: ServiceHandle,
    blob_loader: BlobLoader,
    session: Option<[u8; 32]>,
}

#[derive(Clone)]
pub struct Worker {
    inner: Arc<Mutex<WorkerState>>,
}

impl Worker {
    pub fn new(service: ServiceHandle, args: Args) -> Self {
        Self {
            inner: Arc::new_cyclic(|weak_self| {
                Mutex::new(WorkerState {
                    weak_self: weak_self.clone(),
                    blob_loader: BlobLoader::new(blobs_dir()),
                    apps: HashMap::new(),
                    service,
                    args,
                    session: None,
                })
            }),
        }
    }

    fn lock(&self) -> MutexGuard<'_, WorkerState> {
        self.inner.lock().expect("worker lock poisoned")
    }

    pub fn sender_for(&self, vmid: Address, index: usize) -> Option<CommandSender> {
        let handle = self
            .lock()
            .apps
            .get(&vmid)?
            .instances
            .get(index)?
            .vm_handle
            .command_sender()
            .clone();
        Some(handle)
    }

    pub fn info(&self, admin: bool) -> pb::WorkerInfo {
        let worker = self.lock();
        let max_instances = worker.args.max_instances() as u64;
        let deployed_apps = worker.apps.len() as u64;
        let running_instances = worker
            .apps
            .values()
            .map(|state| state.instances.len())
            .sum::<usize>() as u64;
        let instance_memory_size = worker.args.instance_memory_size;
        let info = worker.service.module_loader().info();
        let module_loader_info = if admin {
            Some(pb::ModuleLoaderInfo {
                max_compilation_tasks: info.max_compilation_tasks as _,
                queue_cap: info.queue_cap as _,
                queue_used: info.queue_used as _,
                cache_cap: info.cache_cap as _,
                cache_used: info.cache_used as _,
                compiling_handles_len: info.compiling_handles_len as _,
                compiling_tasks: info.compiling_tasks as _,
            })
        } else {
            None
        };
        pb::WorkerInfo {
            pubkey: worker_identity_key().public().as_bytes().to_vec(),
            deployed_apps,
            running_instances,
            max_instances,
            instance_memory_size,
            session: worker.session.map(|s| s.to_vec()).unwrap_or_default(),
            memory_usage: Some(crate::allocator::mem_usage()),
            module_loader_info,
            vm_instances: wapo_host::vm_count() as _,
        }
    }

    pub fn blob_loader(&self) -> BlobLoader {
        self.lock().blob_loader.clone()
    }

    pub async fn prepare_query(&self, address: Address, query_size: usize) -> Result<QueryGuard> {
        // If the app is start-on-demand, we need to start an instance to serve the query if it is not already.
        let mut start_needed = false;
        let guard = {
            let mut state = self.lock();
            let app = state
                .apps
                .get_mut(&address)
                .ok_or(anyhow::Error::msg("App not found"))?;
            if query_size > app.manifest.max_query_size as usize {
                bail!("query size exceeds the limit");
            }
            if app.instances.is_empty() && app.manifest.on_demand {
                start_needed = true;
            }
            app.on_going_query_inc();
            QueryGuard {
                address,
                worker: self.clone(),
            }
        };
        if start_needed {
            self.resize_app_instances(address, 1, true)
                .await
                .context("failed to start app on-demand")?;
        }
        Ok(guard)
    }

    fn end_query(&self, address: Address) -> Result<()> {
        let mut state = self.lock();
        let app = state
            .apps
            .get_mut(&address)
            .ok_or(anyhow::Error::msg("App not found"))?;
        let rest = app.on_going_query_dec();
        if rest == 0 && app.manifest.on_demand {
            app.instances.clear();
        }
        Ok(())
    }

    pub async fn query(
        &self,
        origin: Option<[u8; 32]>,
        address: Address,
        path: String,
        payload: Vec<u8>,
    ) -> Result<Vec<u8>> {
        info!(address=%ShortId(address), "incomming query");
        let query_size = payload.len() + path.as_bytes().len();
        let _guard = self
            .prepare_query(address, query_size)
            .await
            .context("failed to prepare query")?;
        let cmd_sender = {
            let state = self.lock();
            let app = state
                .apps
                .get(&address)
                .ok_or(anyhow::Error::msg("App not found"))?;
            let instance = match app.instances.first() {
                Some(instance) => instance,
                None => {
                    bail!("instance not found");
                }
            };
            instance.vm_handle.command_sender().clone()
        };
        let (reply_tx, rx) = oneshot::channel();
        cmd_sender
            .send(Command::PushQuery {
                path,
                origin,
                payload,
                reply_tx,
            })
            .await
            .context("failed to send query to instance")?;
        info!("waiting app to reply the query");
        let reply = rx.await.context("failed to receive query response");
        match &reply {
            Ok(data) => info!(len = data.len(), "received reply Ok from app"),
            Err(_) => info!("received reply Err from app"),
        }
        reply
    }

    pub async fn start_app(&self, address: Address, demand: bool) -> Result<()> {
        self.resize_app_instances(address, 1, demand).await
    }

    pub async fn stop_app(&self, address: Address) -> Result<()> {
        self.resize_app_instances(address, 0, false).await
    }

    pub async fn resize_app_instances(
        &self,
        address: Address,
        count: usize,
        demand: bool,
    ) -> Result<()> {
        let (created, removed) = self.lock().resize_app_instances(address, count, demand)?;
        let total = removed.len();
        for (i, mut handle) in removed.into_iter().enumerate() {
            info!("stopping instances ({}/{total})...", i + 1);
            handle.stop().await?;
        }
        for (i, mut status) in created.into_iter().enumerate() {
            info!("waiting instance ({}/{count}) to start", i + 1);
            loop {
                if status.changed().await.is_err() {
                    anyhow::bail!("failed to start instance: {:?}", *status.borrow());
                }
                match &*status.borrow_and_update() {
                    VmStatus::Running => break,
                    VmStatus::Stopped { reason, error } => {
                        return if let Some(error) = error.clone() {
                            Err(error.into())
                        } else {
                            Err(anyhow::Error::msg(reason.clone()))
                        }
                        .context("instance stopped unexpectedly");
                    }
                    _ => {}
                }
            }
        }
        Ok(())
    }

    pub async fn deploy_app(&self, manifest: Manifest) -> Result<AppInfo> {
        if manifest.version != 1 {
            bail!("unsupported manifest version {}", manifest.version);
        }
        if manifest.resizable && manifest.on_demand {
            bail!("on-demand app can not be resizable");
        }
        if manifest.label.len() > 64 {
            bail!("label too long");
        }
        let encoded = scale::Encode::encode(&manifest);
        const MAX_MANIFEST_SIZE: usize = 1024 * 16;
        if encoded.len() > MAX_MANIFEST_SIZE {
            bail!(
                "manifest too large, max={MAX_MANIFEST_SIZE}, actual={}",
                encoded.len()
            );
        }
        let address = blake2_256(&encoded);
        tracing::Span::current().record("addr", display(ShortId(&address)));
        let on_demand = manifest.on_demand;
        {
            let mut worker = self.lock();
            if worker.apps.contains_key(&address) {
                bail!("app already exists")
            }
            let session: [u8; 32] = rand::thread_rng().gen();

            static NEXT_APP_SN: AtomicU64 = AtomicU64::new(0);
            let state = AppState {
                sn: NEXT_APP_SN.fetch_add(1, Ordering::Relaxed),
                session,
                manifest,
                hist_metrics: Default::default(),
                instances: vec![],
                on_going_queries: 0,
                last_query_done: Instant::now(),
            };
            worker.apps.insert(address, state);
        }
        if !on_demand {
            self.resize_app_instances(address, 1, false).await?;
        }
        let worker = self.lock();
        let app = worker
            .apps
            .get(&address)
            .ok_or(anyhow!("BUG: App not found after deployed"))?;
        Ok(app.info(address))
    }

    pub async fn remove_app(&self, address: Address) -> Result<()> {
        let Some(app) = self.lock().apps.remove(&address) else {
            bail!("app not found")
        };
        let n = app.instances.len();
        for (i, instance) in app.instances.into_iter().enumerate() {
            let mut handle = instance.vm_handle;
            if !handle.is_stopped() {
                info!("stopping instance ({}/{n})...", i + 1);
                if let Err(err) = handle.stop().await {
                    warn!("failed to stop instance: {err:?}");
                }
            }
        }
        Ok(())
    }

    pub fn for_each_app<F>(&self, addresses: Option<&[Address]>, mut f: F)
    where
        F: FnMut(Address, &AppState),
    {
        let inner = self.lock();
        if let Some(addresses) = addresses {
            for address in addresses {
                if let Some(state) = inner.apps.get(address) {
                    f(*address, state);
                }
            }
        } else {
            for (address, state) in inner.apps.iter() {
                f(*address, state);
            }
        }
    }

    pub fn session(&self) -> Option<[u8; 32]> {
        self.lock().session
    }

    pub fn init(&self, salt: &[u8]) -> Result<[u8; 32]> {
        self.lock().init(salt)
    }

    pub fn num_instances_of(&self, address: Address) -> Option<usize> {
        self.lock()
            .apps
            .get(&address)
            .map(|app| app.instances.len())
    }

    pub fn list(&self, start: usize, count: usize) -> Vec<AppInfo> {
        let inner = self.lock();
        inner
            .apps
            .iter()
            .skip(start)
            .take(count)
            .map(|(address, state)| state.info(*address))
            .collect()
    }

    pub fn clear(&self) {
        self.lock().apps.clear();
    }
}

fn to_pages(size: u64) -> u64 {
    let page_size = 1024 * 64u64;
    (size + page_size - 1) / page_size
}

impl WorkerState {
    fn start_app(&mut self, address: Address) -> Result<VmStatusReceiver> {
        let vmid = ShortId(address);
        let app = self
            .apps
            .get_mut(&address)
            .ok_or(anyhow!("Instance not found"))?;
        if !app.manifest.resizable && !app.instances.is_empty() {
            return Err(anyhow!("Instance already started"));
        }
        let config = service::InstanceStartConfig::builder()
            .auto_restart(true)
            .max_memory_pages(to_pages(self.args.instance_memory_size) as _)
            .id(address)
            .weight(1)
            .blobs_dir(blobs_dir())
            .runtime_calls(AppRuntimeCalls::new(address))
            .build();
        let (vm_handle, join_handle) = self
            .service
            .start(
                &app.manifest.code_hash,
                &app.manifest.hash_algorithm,
                config,
            )
            .context("failed to start instance")?;
        let status = vm_handle.subscribe_status();
        let instance = Instance {
            sequence_number: {
                static NEXT_RUN_SN: AtomicU64 = AtomicU64::new(0);
                NEXT_RUN_SN.fetch_add(1, Ordering::Relaxed)
            },
            vm_handle,
        };
        let sn = instance.sequence_number;
        app.instances.push(instance);
        // Clean up the instance when it stops.
        let weak_self = self.weak_self.clone();
        self.service.spawn(
            async move {
                if let Ok(reason) = join_handle.await {
                    info!(?reason, "app stopped");
                } else {
                    warn!("app stopped unexpectedly");
                }
                if let Some(inner) = weak_self.upgrade() {
                    let mut inner = inner.lock().expect("worker lock poisoned");
                    let Some(app) = inner.apps.get_mut(&address) else {
                        info!("app was removed before stopping");
                        return;
                    };
                    let mut found = None;
                    app.instances = app
                        .instances
                        .drain(..)
                        .filter_map(|instance| {
                            if instance.sequence_number == sn {
                                found = Some(instance);
                                None
                            } else {
                                Some(instance)
                            }
                        })
                        .collect();
                    let Some(instance) = found else {
                        warn!("instance was removed before stopping");
                        return;
                    };
                    app.hist_metrics += instance.vm_handle.meter().to_metrics();
                }
            }
            .instrument(tracing::info_span!(parent: None, "wapo", id = %vmid)),
        );
        Ok(status)
    }

    fn reserve_slot_if_needed(&mut self, for_address: Address) -> Result<Option<VmHandle>> {
        if !self
            .apps
            .get(&for_address)
            .ok_or(anyhow!("App not found"))?
            .instances
            .is_empty()
        {
            // Already running, no need to reserve slots.
            return Ok(None);
        }

        let available_slots = self.available_slots();
        if available_slots > 0 {
            return Ok(None);
        }

        // Seek if there is any bench mark instance to stop.
        for app in self.apps.values_mut() {
            if app.manifest.resizable {
                if let Some(instance) = app.instances.pop() {
                    let handle = instance.vm_handle;
                    return Ok(Some(handle));
                }
            }
        }
        Err(anyhow!("No available slots"))
    }

    fn resize_app_instances(
        &mut self,
        address: Address,
        count: usize,
        demand: bool,
    ) -> Result<(Vec<VmStatusReceiver>, Vec<VmHandle>)> {
        let mut created = vec![];
        let mut removed = vec![];
        if demand {
            if let Some(handle) = self.reserve_slot_if_needed(address)? {
                removed.push(handle);
            }
        }
        let app = self
            .apps
            .get_mut(&address)
            .ok_or(anyhow!("App not found"))?;
        let current = app.instances.len();
        let max_allowed = if app.manifest.resizable { count } else { 1 };
        info!(current, count, max_allowed, "changing number of instances");

        use std::cmp::Ordering::*;
        match current.cmp(&count) {
            Less => {
                let on_demand = app.manifest.on_demand;
                if on_demand && !demand {
                    bail!("on-demand app cannot be started directly");
                }
                let available_slots = self.available_slots();
                let creating = available_slots.min(count - current);
                info!(available_slots, creating, "creating instances");
                for i in 0..creating {
                    info!("starting instance ({}/{creating})...", i + 1);
                    created.push(self.start_app(address)?);
                }
            }
            Equal => (),
            Greater => {
                let stop_count = current - count;
                info!(stop_count, "stopping instances");
                removed = app
                    .instances
                    .drain(count..)
                    .map(|run| run.vm_handle)
                    .collect();
            }
        }
        Ok((created, removed))
    }

    fn available_slots(&self) -> usize {
        let max = self.args.max_instances();
        max.saturating_sub(self.running_instances())
    }

    fn running_instances(&self) -> usize {
        self.apps.values().map(|app| app.instances.len()).sum()
    }

    fn init(&mut self, salt: &[u8]) -> Result<[u8; 32]> {
        if !self.apps.is_empty() {
            bail!("init session failed, apps already deployed")
        }
        let seed: [u8; 32] = rand::thread_rng().gen();
        let message = [salt, &seed].concat();
        let session = blake2_256(&message);
        self.session = Some(session);
        Ok(seed)
    }
}

#[derive(Clone)]
struct AppRuntimeCalls {
    address: Address,
}

impl AppRuntimeCalls {
    fn new(address: Address) -> Self {
        Self { address }
    }

    fn wrap_message(&self, message: impl AsRef<[u8]>) -> Vec<u8> {
        let mut final_message = self.address.to_vec();
        final_message.extend(message.as_ref());
        final_message
    }
}

impl wapo_host::RuntimeCalls for AppRuntimeCalls {
    fn worker_pubkey(&self) -> Vec<u8> {
        worker_identity_key().public().as_bytes().to_vec()
    }

    fn sign_app_data(&self, data: &[u8]) -> Vec<u8> {
        worker_identity_key().sign(ContentType::AppData, self.wrap_message(data))
    }

    fn sgx_quote_app_data(&self, data: &[u8]) -> Option<Vec<u8>> {
        crate::sgx::quote(ContentType::AppData, &self.wrap_message(data))
    }
}
