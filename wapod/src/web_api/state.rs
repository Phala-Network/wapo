use anyhow::{anyhow, bail, Context, Result};

use rand::Rng as _;
use sp_core::hashing::blake2_256;
use tracing::{info, warn};
use wapo_host::ShortId;
use wapo_host::{blobs::BlobLoader, Metrics};
use wapod_rpc::prpc::WorkerInfo;

use std::collections::HashMap;

use std::ops::Add;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, Weak};

use service::{Command, CommandSender, ServiceHandle};

use wapo_host::service::{self, VmHandle};
use wapod_rpc::prpc::Manifest;

use crate::worker_key::load_or_generate_key;
use crate::Args;

type Address = [u8; 32];

struct Instance {
    sequence_number: u64,
    vm_handle: VmHandle,
}

#[derive(Debug, Clone)]
pub struct AppInfo {
    pub address: Address,
    pub session: [u8; 32],
}

pub struct AppState {
    pub session: [u8; 32],
    manifest: Manifest,
    hist_metrics: Metrics,
    instances: Vec<Instance>,
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
                    blob_loader: BlobLoader::new(&args.blobs_dir),
                    apps: HashMap::new(),
                    service,
                    args,
                    session: None,
                })
            }),
        }
    }

    fn lock(&self) -> MutexGuard<'_, WorkerState> {
        self.inner.lock().expect("Worker lock poisoned")
    }

    pub async fn send(
        &self,
        vmid: Address,
        index: usize,
        message: Command,
    ) -> Result<(), (u16, &'static str)> {
        self.sender_for(vmid, index)
            .ok_or((404, "App not found"))?
            .send(message)
            .await
            .or(Err((500, "Failed to send message")))?;
        Ok(())
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

    pub async fn info(&self) -> WorkerInfo {
        let worker = self.lock();
        let todo = "Limit the max instances";
        let max_instances = worker.args.max_instances as u64;
        let deployed_apps = worker.apps.len() as u64;
        let running_instances = worker
            .apps
            .values()
            .map(|state| state.instances.len())
            .sum::<usize>() as u64;
        let instance_memory_size = worker.args.max_memory_pages as u64 * 64 * 1024;
        WorkerInfo {
            pubkey: load_or_generate_key().public().as_bytes().to_vec(),
            deployed_apps,
            running_instances,
            max_instances,
            instance_memory_size,
            session: worker.session.map(|s| s.to_vec()).unwrap_or_default(),
        }
    }

    pub fn blob_loader(&self) -> BlobLoader {
        self.lock().blob_loader.clone()
    }

    pub async fn start_app(&self, vmid: Address) -> Result<()> {
        self.lock().start_app(vmid)
    }

    pub async fn stop_app(&self, address: Address) -> Result<()> {
        let handles = self.lock().stop_app(address)?;
        let total = handles.len();
        let vmid = ShortId(address);
        for (i, mut handle) in handles.into_iter().enumerate() {
            info!("Stopping {vmid} ({i}/{total})...");
            handle.stop().await?;
        }
        Ok(())
    }

    pub async fn deploy_app(&self, manifest: Manifest) -> Result<AppInfo> {
        let immediate = manifest.start_mode == 0;
        let address = sp_core::blake2_256(&scale::Encode::encode(&manifest));
        let mut worker = self.lock();
        if worker.apps.contains_key(&address) {
            bail!("App already exists")
        }
        let session: [u8; 32] = rand::thread_rng().gen();
        let state = AppState {
            session,
            manifest,
            hist_metrics: Default::default(),
            instances: vec![],
        };
        worker.apps.insert(address, state);
        if immediate {
            worker.start_app(address)?;
        }
        Ok(AppInfo { address, session })
    }

    pub async fn remove_app(&self, address: Address) -> Result<()> {
        let Some(app) = self.lock().apps.remove(&address) else {
            bail!("App not found")
        };
        let vmid = ShortId(address);
        let n = app.instances.len();
        for (i, instance) in app.instances.into_iter().enumerate() {
            let mut handle = instance.vm_handle;
            if !handle.is_stopped() {
                info!("Removing VM {vmid}, ({i}/{n})...");
                if let Err(err) = handle.stop().await {
                    warn!("Failed to stop {vmid}: {err:?}");
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
}

impl WorkerState {
    fn start_app(&mut self, address: Address) -> Result<()> {
        let vmid = ShortId(address);
        println!("Starting {vmid}...");

        let app = self
            .apps
            .get_mut(&address)
            .ok_or(anyhow!("Instance not found"))?;
        if !app.instances.is_empty() {
            return Err(anyhow!("Instance already started"));
        }
        let config = service::InstanceStartConfig::builder()
            .max_memory_pages(self.args.max_memory_pages)
            .id(address)
            .weight(1)
            .blobs_dir(self.args.blobs_dir.as_str().into())
            .build();
        let (vm_handle, join_handle) = self
            .service
            .start(
                &app.manifest.code_hash,
                &app.manifest.hash_algorithm,
                config,
            )
            .context("Failed to start instance")?;
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
        self.service.spawn(async move {
            let todo = "Restart the instance if it stopped unexpectedly";
            if let Ok(reason) = join_handle.await {
                info!("VM {vmid} stopped: {reason}");
            } else {
                warn!("VM {vmid} stopped unexpectedly");
            }
            if let Some(inner) = weak_self.upgrade() {
                let mut inner = inner.lock().expect("Worker lock poisoned");
                let Some(app) = inner.apps.get_mut(&address) else {
                    info!("App was removed before stopping");
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
                    warn!("Instance was removed before stopping");
                    return;
                };
                app.hist_metrics += instance.vm_handle.meter().to_metrics();
            }
        });
        Ok(())
    }

    fn stop_app(&mut self, address: Address) -> Result<Vec<VmHandle>> {
        let instance = self
            .apps
            .get_mut(&address)
            .ok_or(anyhow!("App not found"))?;
        let handles = instance
            .instances
            .drain(..)
            .map(|run| run.vm_handle)
            .collect();
        Ok(handles)
    }

    fn init(&mut self, salt: &[u8]) -> Result<[u8; 32]> {
        if !self.apps.is_empty() {
            bail!("Init session failed, apps already deployed")
        }
        let seed: [u8; 32] = rand::thread_rng().gen();
        let message = [salt, &seed].concat();
        let session = blake2_256(&message);
        self.session = Some(session);
        Ok(seed)
    }
}
