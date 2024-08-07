use anyhow::{anyhow, bail, Context, Result};

use rand::Rng as _;
use scale::Encode;
use tokio::sync::{broadcast, oneshot};
use tracing::{field::display, info, warn, Instrument};
use wapo_host::{blobs::BlobLoader, Metrics};
use wapo_host::{MetricsToken, ShortId, SniTlsListener, VmStatus, VmStatusReceiver};
use wapod_crypto::wapod_types::session::SessionUpdate;
use wapod_crypto::wapod_types::ticket::AppManifest;
use wapod_crypto::{ContentType, SpCoreHash};
use wapod_rpc::prpc::{self as pb};

use std::collections::{BTreeMap, HashMap, HashSet};

use std::marker::PhantomData;
use std::ops::{Add, RangeInclusive};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, Weak};
use std::time::{Duration, Instant};

use service::{Command, CommandSender, ServiceHandle};

use wapo_host::service::{self, Report, VmHandle};
use wapod_rpc::prpc::Manifest;

use crate::config::{AddressGenerator, KeyProvider, Paths, WorkerConfig};
use crate::tcp_acl::HostFilter;

type Address = [u8; 32];
#[derive(Clone, Debug, typed_builder::TypedBuilder)]
pub struct WorkerArgs {
    /// Maximum memory size for each instance.
    pub instance_memory_size: u64,
    /// Maximum number of instances to run. If not specified, it will be determined by the enclave
    /// size and instance memory size.
    pub max_instances: usize,
    /// Number of compiled WebAssembly modules that can be cached (default: 16).
    pub module_cache_size: usize,
    /// Disable memory pool for instances.
    pub no_mem_pool: bool,
    /// Disable memory pool for instances.
    #[builder(default)]
    pub use_winch: bool,
    /// The port range to allow the worker to listen on.
    pub tcp_listen_port_range: RangeInclusive<u16>,
    /// The tcp port that SNI TLS listener to use.
    pub tls_port: Option<u16>,
    /// Whether to verify the TLS server certificate when the app tries to listen on an SNI.
    pub verify_tls_server_cert: bool,
    /// The maximum instance execution time for handling a on-demand connection.
    pub on_demand_connection_timeout: Duration,
}

struct Instance {
    sequence_number: u64,
    vm_handle: VmHandle,
}

struct InstanceInfo {
    sn: u64,
    status: VmStatusReceiver,
    event_rx: broadcast::Receiver<Event>,
}

#[derive(Debug, Clone)]
pub struct AppInfo {
    pub sn: u64,
    pub address: Address,
    pub session: [u8; 32],
    pub running_instances: usize,
    pub last_query_elapsed_secs: u64,
    pub reuse_instances: bool,
    pub manifest: Manifest,
}

pub struct AppState {
    sn: u64,
    pub session: [u8; 32],
    manifest: AppManifest,
    hist_metrics: Metrics,
    instances: BTreeMap<u64, Instance>,
    on_going_queries: usize,
    last_query_done: Instant,
    auto_restart: bool,
    reuse_instance: bool,
}

impl AppState {
    /// Returns the metrics of the app during the session.
    /// If there are any instance running, the metrics are merged with the current run's metrics.
    pub(crate) fn metrics(&self) -> Metrics {
        let init = self.hist_metrics.clone();
        self.instances
            .values()
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
            reuse_instances: self.reuse_instance,
            manifest: self.manifest.clone().into(),
        }
    }
}

pub struct QueryGuard<T: WorkerConfig> {
    worker: Worker<T>,
    address: Address,
    reuse: bool,
    instance_id: Option<u64>,
}

impl<T: WorkerConfig> Drop for QueryGuard<T> {
    fn drop(&mut self) {
        if let Err(err) = self.worker.end_query(self.address, self.instance_id) {
            info!("end query error: {err}");
        }
    }
}

type WeakWorker<T> = Weak<Mutex<WorkerState<T>>>;

struct WorkerState<T> {
    weak_self: WeakWorker<T>,
    apps: HashMap<Address, AppState>,
    args: WorkerArgs,
    service: ServiceHandle,
    blob_loader: BlobLoader,
    session: Option<[u8; 32]>,
    sni_tls_listener: Option<SniTlsListener>,
    host_filter: Arc<HostFilter>,
    metrics_sn: u64,
    bench_app: Option<Address>,
    bench_instances: u64,
}

pub struct Worker<T> {
    inner: Arc<Mutex<WorkerState<T>>>,
}

impl<T> Clone for Worker<T> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

impl<T: WorkerConfig> Worker<T> {
    pub async fn create_running(args: WorkerArgs) -> Result<Self> {
        let n_threads = args.max_instances.saturating_add(2);
        let max_memory = args
            .instance_memory_size
            .try_into()
            .context("invalid memory size")?;
        SniTlsListener::install_ring_provider();
        let sni_tcp_listener = match args.tls_port {
            Some(port) => Some({
                SniTlsListener::bind("0.0.0.0", port, args.verify_tls_server_cert)
                    .await
                    .context("failed to bind sni tls listener")?
            }),
            None => None,
        };
        let (run, spawner) = service::service(
            n_threads,
            args.module_cache_size,
            &T::Paths::blobs_dir(),
            max_memory,
            if args.no_mem_pool {
                0
            } else {
                args.max_instances
            },
            args.use_winch,
        )
        .context("failed to create service")?;
        std::thread::spawn(move || {
            run.blocking_run(|evt| match evt {
                Report::VmTerminated { id, reason } => {
                    info!(target: "wapod", id=%ShortId(id), ?reason, "instance terminated");
                }
            });
        });
        Ok(Self::new(spawner, args, sni_tcp_listener))
    }

    pub fn new(
        service: ServiceHandle,
        args: WorkerArgs,
        sni_tls_listener: Option<SniTlsListener>,
    ) -> Self {
        Self {
            inner: Arc::new_cyclic(|weak_self| {
                Mutex::new(WorkerState {
                    weak_self: weak_self.clone(),
                    blob_loader: BlobLoader::new(T::Paths::blobs_dir()),
                    apps: HashMap::new(),
                    service,
                    args,
                    session: None,
                    sni_tls_listener,
                    host_filter: Arc::new(HostFilter::from_config_file()),
                    metrics_sn: 0,
                    bench_app: None,
                    bench_instances: 0,
                })
            }),
        }
    }

    fn lock(&self) -> MutexGuard<'_, WorkerState<T>> {
        self.inner.lock().expect("worker lock poisoned")
    }

    pub fn sender_for(&self, vmid: Address, index: usize) -> Option<CommandSender> {
        let handle = self
            .lock()
            .apps
            .get(&vmid)?
            .instances
            .get(&(index as u64))?
            .vm_handle
            .command_sender()
            .clone();
        Some(handle)
    }

    pub fn blob_loader(&self) -> BlobLoader {
        self.lock().blob_loader.clone()
    }

    pub fn set_bench_app(&self, address: Option<Address>, instances: u64) {
        let mut state = self.lock();
        state.bench_app = address;
        state.bench_instances = instances;
    }
}

impl<T: WorkerConfig> Worker<T> {
    pub fn info(&self, admin: bool) -> pb::WorkerInfo {
        let worker = self.lock();
        let max_instances = worker.args.max_instances as u64;
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
            pubkey: T::KeyProvider::get_key().public().as_bytes().to_vec(),
            deployed_apps,
            running_instances,
            max_instances,
            instance_memory_size,
            session: worker.session.map(|s| s.to_vec()).unwrap_or_default(),
            memory_usage: Some(crate::allocator::mem_usage()),
            module_loader_info,
            vm_instances: wapo_host::vm_count() as _,
            tcp_listen_port_range: {
                if worker.args.tcp_listen_port_range.is_empty() {
                    "".to_string()
                } else {
                    let (start, end) = worker.args.tcp_listen_port_range.clone().into_inner();
                    format!("{start}-{end}")
                }
            },
            bench_app_address: worker.bench_app.map(|a| a.to_vec()).unwrap_or_default(),
            bench_app_instances: worker.bench_instances,
        }
    }

    pub async fn prepare_instance_for_query(
        &self,
        address: Address,
        query_size: usize,
    ) -> Result<QueryGuard<T>> {
        // If the app is start-on-demand, we need to start an instance to serve the query if it is not already.
        let mut start_needed = false;
        let mut guard = {
            let mut state = self.lock();
            let app = state
                .apps
                .get_mut(&address)
                .ok_or(anyhow::Error::msg("App not found"))?;
            if query_size > app.manifest.max_query_size as usize {
                bail!("query size exceeds the limit");
            }
            if !app.reuse_instance || (app.instances.is_empty() && app.manifest.on_demand) {
                start_needed = true;
            }
            app.on_going_query_inc();
            QueryGuard {
                address,
                worker: self.clone(),
                reuse: app.reuse_instance,
                instance_id: None,
            }
        };
        if start_needed {
            if guard.reuse {
                info!("resizing instances to 1 for query");
                self.resize_app_instances(address, 1, true)
                    .await
                    .context("failed to start app on-demand")?;
            } else {
                info!("increasing 1 instance for query");
                let mut info = self.try_inc_instances(address)?;
                if let Some(info) = &mut info {
                    // Wait for the instance to be ready for query.
                    let result = tokio::time::timeout(Duration::from_secs(1), async {
                        loop {
                            let Ok(event) = info.event_rx.recv().await else {
                                break;
                            };
                            match event {
                                Event::QueryListened => {
                                    break;
                                }
                            }
                        }
                    })
                    .await;
                    if result.is_err() {
                        warn!("wait instance to listen query timeout");
                    }
                }
                guard.instance_id = info.map(|x| x.sn);
            }
        }
        Ok(guard)
    }

    fn end_query(&self, address: Address, instance_id: Option<u64>) -> Result<()> {
        let mut state = self.lock();
        let app = state
            .apps
            .get_mut(&address)
            .ok_or(anyhow::Error::msg("App not found"))?;
        match instance_id {
            Some(id) => {
                app.instances
                    .remove(&id)
                    .ok_or(anyhow!("Instance not found"))?;
            }
            None => {
                let rest = app.on_going_query_dec();
                if rest == 0 && app.manifest.on_demand {
                    app.instances.clear();
                }
            }
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
        let guard = self
            .prepare_instance_for_query(address, query_size)
            .await
            .context("failed to prepare query")?;
        let cmd_sender = {
            let state = self.lock();
            let app = state
                .apps
                .get(&address)
                .ok_or(anyhow::Error::msg("App not found"))?;
            let instance = match guard.instance_id {
                Some(id) => app
                    .instances
                    .get(&id)
                    .ok_or(anyhow::Error::msg("Instance not found"))?,
                None => match app.instances.values().next() {
                    Some(instance) => instance,
                    None => {
                        bail!("instance not found");
                    }
                },
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
            Ok(Ok(data)) => info!(len = data.len(), "received reply Ok from app"),
            Ok(Err(_)) | Err(_) => info!("received reply Err from app"),
        }
        reply.and_then(|x| x.map_err(anyhow::Error::msg))
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
        let (created, removed) = {
            let mut state = self.lock();
            let timeout = if demand {
                Some(state.args.on_demand_connection_timeout)
            } else {
                None
            };
            state.resize_app_instances(address, count, timeout)?
        };
        let total = removed.len();
        for (i, mut handle) in removed.into_iter().enumerate() {
            info!("stopping instances ({}/{total})...", i + 1);
            handle.stop().await?;
        }
        for (i, info) in created.into_iter().enumerate() {
            let mut status = info.status;
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

    fn try_inc_instances(&self, address: Address) -> Result<Option<InstanceInfo>> {
        self.lock().try_inc_instances(address)
    }

    pub async fn deploy_app(
        &self,
        manifest: AppManifest,
        auto_restart: bool,
        reuse_instances: bool,
    ) -> Result<AppInfo> {
        if manifest.version != 1 {
            bail!("unsupported manifest version {}", manifest.version);
        }
        if manifest.resizable && manifest.on_demand {
            bail!("on-demand app can not be resizable");
        }
        if manifest.label.len() > 64 {
            bail!("label too long");
        }
        const MAX_MANIFEST_SIZE: usize = 1024 * 16;
        if manifest.size_hint() > MAX_MANIFEST_SIZE {
            bail!(
                "manifest too large, max={MAX_MANIFEST_SIZE}, size_hint={}",
                manifest.size_hint()
            );
        }
        let address = T::AddressGenerator::generate_address(&manifest);
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
                instances: Default::default(),
                on_going_queries: 0,
                last_query_done: Instant::now(),
                auto_restart,
                reuse_instance: reuse_instances,
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
        for (i, (_id, instance)) in app.instances.into_iter().enumerate() {
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

    pub fn init(&self, pnonce: &[u8], recipient: Address) -> Result<SessionUpdate> {
        self.lock().init(pnonce, recipient)
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

    pub fn bump_metrics_sn(&self) -> u64 {
        self.lock().bump_metrics_sn()
    }
}

fn to_pages(size: u64) -> u64 {
    let page_size = 1024 * 64u64;
    (size + page_size - 1) / page_size
}

impl<T: WorkerConfig> WorkerState<T> {
    fn start_app(
        &mut self,
        address: Address,
        time_limit: Option<Duration>,
    ) -> Result<InstanceInfo> {
        let vmid = ShortId(address);
        let app_name = hex::encode(address);
        let app = self
            .apps
            .get_mut(&address)
            .ok_or(anyhow!("Instance not found"))?;
        if !app.manifest.resizable && !app.instances.is_empty() && time_limit.is_none() {
            return Err(anyhow!("Instance already started"));
        }
        let runtime_calls =
            AppRuntimeCalls::<T>::new(address, self.host_filter.clone(), self.weak_self.clone());
        let event_rx = runtime_calls.event_tx.subscribe();
        let config = service::InstanceStartConfig::builder()
            .auto_restart(app.auto_restart)
            .max_memory_pages(to_pages(self.args.instance_memory_size) as _)
            .id(address)
            .weight(1)
            .blobs_dir(T::Paths::blobs_dir())
            .runtime_calls(runtime_calls)
            .args(
                [app_name]
                    .into_iter()
                    .chain(app.manifest.args.iter().cloned())
                    .collect(),
            )
            .envs(app.manifest.env_vars.to_vec())
            .tcp_listen_port_range(self.args.tcp_listen_port_range.clone())
            .sni_tls_listener({
                let weak_self = self.weak_self.clone();
                let create_instance_fn = move || {
                    let Some(inner) = weak_self.upgrade() else {
                        return;
                    };
                    let Ok(Some(_info)) = inner.lock().unwrap().try_inc_instances(address) else {
                        return;
                    };
                };
                self.sni_tls_listener.as_ref().map(|l| {
                    let connect_timeout = Duration::from_secs(5);
                    l.agent(create_instance_fn, app.reuse_instance, connect_timeout)
                })
            })
            .time_limit(time_limit)
            .build();
        let (vm_handle, join_handle) = self
            .service
            .start(&app.manifest.code_hash, config)
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
        app.instances.insert(sn, instance);
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
                    let Some(instance) = app.instances.remove(&sn) else {
                        warn!("instance was removed before stopping");
                        return;
                    };
                    app.hist_metrics += instance.vm_handle.meter().to_metrics();
                }
            }
            .instrument(tracing::info_span!(parent: None, "wapo", id = %vmid)),
        );
        Ok(InstanceInfo {
            sn,
            status,
            event_rx,
        })
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
                if let Some((_, instance)) = app.instances.pop_last() {
                    let handle = instance.vm_handle;
                    app.hist_metrics += handle.meter().to_metrics();
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
        on_demand_timeout: Option<Duration>,
    ) -> Result<(Vec<InstanceInfo>, Vec<VmHandle>)> {
        let mut created = vec![];
        let mut removed = vec![];
        if on_demand_timeout.is_some() {
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
                if on_demand && on_demand_timeout.is_none() {
                    bail!("on-demand app cannot be started directly");
                }
                let available_slots = self.available_slots();
                let creating = available_slots.min(count - current);
                info!(available_slots, creating, "creating instances");
                for i in 0..creating {
                    info!("starting instance ({}/{creating})...", i + 1);
                    created.push(self.start_app(address, on_demand_timeout)?);
                }
            }
            Equal => (),
            Greater => {
                let stop_count = current - count;
                info!(stop_count, "stopping instances");
                for i in 0..stop_count {
                    let (_sn, instance) =
                        app.instances.pop_last().expect("BUG: instance not found");
                    info!("stopping instance ({}/{stop_count})...", i + 1);
                    app.hist_metrics += instance.vm_handle.meter().to_metrics();
                    removed.push(instance.vm_handle);
                }
            }
        }
        Ok((created, removed))
    }

    fn try_inc_instances(&mut self, address: Address) -> Result<Option<InstanceInfo>> {
        match self.apps.get_mut(&address) {
            Some(app) => {
                let num = app
                    .instances
                    .len()
                    .checked_add(1)
                    .ok_or(anyhow!("too many instances"))?;
                let time_limit = self.args.on_demand_connection_timeout;
                info!(num, "increasing instances");
                let (new, _) = self.resize_app_instances(address, num, Some(time_limit))?;
                Ok(new.into_iter().next())
            }
            None => {
                bail!("app not found");
            }
        }
    }

    fn available_slots(&self) -> usize {
        let max = self.args.max_instances;
        max.saturating_sub(self.running_instances())
    }

    fn running_instances(&self) -> usize {
        self.apps.values().map(|app| app.instances.len()).sum()
    }

    fn init(&mut self, pnonce: &[u8], recipient: Address) -> Result<SessionUpdate> {
        if !self.apps.is_empty() {
            bail!("init session failed, apps already deployed")
        }
        let cnonce: [u8; 32] = rand::thread_rng().gen();
        let update = SessionUpdate::new::<SpCoreHash>(cnonce, pnonce, recipient);
        self.session = Some(update.session);
        self.metrics_sn = 0;
        Ok(update)
    }

    fn bump_metrics_sn(&mut self) -> u64 {
        self.metrics_sn += 1;
        self.metrics_sn
    }
}

#[derive(Debug, Clone)]
enum Event {
    QueryListened,
}

#[derive(Default)]
struct SharedState {
    locks: HashSet<String>,
}

struct AppRuntimeCalls<T> {
    event_tx: broadcast::Sender<Event>,
    address: Address,
    host_filter: Arc<HostFilter>,
    worker: WeakWorker<T>,
    shared: Arc<Mutex<SharedState>>,
    _phantom: PhantomData<fn() -> T>,
}

impl<T> Clone for AppRuntimeCalls<T> {
    fn clone(&self) -> Self {
        Self {
            event_tx: self.event_tx.clone(),
            address: self.address,
            host_filter: self.host_filter.clone(),
            worker: self.worker.clone(),
            shared: self.shared.clone(),
            _phantom: self._phantom,
        }
    }
}

impl<T: WorkerConfig> AppRuntimeCalls<T> {
    fn new(address: Address, host_filter: Arc<HostFilter>, worker: WeakWorker<T>) -> Self {
        Self {
            event_tx: broadcast::channel(1).0,
            address,
            host_filter,
            worker,
            shared: Default::default(),
            _phantom: PhantomData,
        }
    }

    fn wrap_message(&self, message: impl AsRef<[u8]>) -> Vec<u8> {
        let mut final_message = self.address.to_vec();
        final_message.extend(message.as_ref());
        final_message
    }
}

impl<T: WorkerConfig + 'static> wapo_host::RuntimeCalls for AppRuntimeCalls<T> {
    fn worker_pubkey(&self) -> [u8; 32] {
        *T::KeyProvider::get_key().public().as_ref()
    }

    fn sign_app_data(&self, data: &[u8]) -> Vec<u8> {
        T::KeyProvider::get_key().sign(ContentType::AppData, self.wrap_message(data))
    }

    fn sgx_quote_app_data(&self, data: &[u8]) -> Option<Vec<u8>> {
        crate::sgx::quote(ContentType::AppData, &self.wrap_message(data))
    }

    fn emit_output(&self, _output: &[u8]) {}

    fn tcp_connect_allowed(&self, host: &str) -> bool {
        self.host_filter.is_host_allowed(host)
    }

    fn app_metrics(&self) -> (Metrics, MetricsToken) {
        self.worker
            .upgrade()
            .map_or_else(Default::default, |inner| {
                let mut inner = inner.lock().expect("worker lock poisoned");
                let metrics = inner
                    .apps
                    .get(&self.address)
                    .map_or_else(Metrics::default, |app| app.metrics());
                let token = MetricsToken {
                    session: inner.session.unwrap_or_default(),
                    nonce: rand::thread_rng().gen(),
                    sn: inner.bump_metrics_sn(),
                };
                (metrics, token)
            })
    }

    fn derive_secret(&self, path: &[u8]) -> [u8; 64] {
        let path_hash = sp_core::hashing::blake2_256(path);
        T::KeyProvider::get_key()
            .derive([self.address, path_hash])
            .dump()
    }

    fn query_listened(&self) {
        self.event_tx.send(Event::QueryListened).ok();
    }

    fn try_lock(&self, path: &str) -> bool {
        if path.as_bytes().len() > 64 {
            return false;
        }
        let mut state = self.shared.lock().unwrap();
        if state.locks.len() > 64 {
            return false;
        }
        if state.locks.contains(path) {
            return false;
        }
        state.locks.insert(path.to_string());
        true
    }

    fn unlock(&self, path: &str) -> bool {
        self.shared.lock().unwrap().locks.remove(path)
    }
}
