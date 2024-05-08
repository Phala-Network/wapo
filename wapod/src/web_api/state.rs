use anyhow::{anyhow, bail, Context, Result};

use rand::Rng as _;
use sp_core::hashing::blake2_256;
use tracing::{info, warn};
use wapo_host::ShortId;
use wapo_host::{blobs::BlobLoader, Metrics};
use wapod_rpc::prpc::WorkerInfo;

use std::collections::HashMap;

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, Weak};

use service::{Command, CommandSender, ServiceHandle};

use wapo_host::service::{self, VmHandle};
use wapod_rpc::prpc::Manifest;

use crate::worker_key::load_or_generate_key;
use crate::Args;

type Address = [u8; 32];

struct CurrentRun {
    sequence_number: u64,
    vm_handle: VmHandle,
}

#[derive(Debug, Clone)]
pub struct InstanceInfo {
    pub address: Address,
    pub session: [u8; 32],
    pub running: bool,
}

pub struct InstanceState {
    pub session: [u8; 32],
    manifest: Manifest,
    hist_metrics: Metrics,
    current_run: Option<CurrentRun>,
}

impl InstanceState {
    /// Returns the metrics of the instance during the session.
    /// If the instance is running, the metrics are merged with the current run's metrics.
    pub(crate) fn metrics(&self) -> Metrics {
        let current = self
            .current_run
            .as_ref()
            .map(|run| run.vm_handle.meter().to_metrics())
            .unwrap_or_default();
        self.hist_metrics.merged(&current)
    }
}

struct WorkerState {
    weak_self: Weak<Mutex<WorkerState>>,
    instances: HashMap<Address, InstanceState>,
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
                    instances: HashMap::new(),
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

    pub async fn send(&self, vmid: Address, message: Command) -> Result<(), (u16, &'static str)> {
        self.sender_for(vmid)
            .ok_or((404, "Instance not found"))?
            .send(message)
            .await
            .or(Err((500, "Failed to send message")))?;
        Ok(())
    }

    pub fn sender_for(&self, vmid: Address) -> Option<CommandSender> {
        let handle = self
            .lock()
            .instances
            .get(&vmid)?
            .current_run
            .as_ref()?
            .vm_handle
            .command_sender()
            .clone();
        Some(handle)
    }

    pub async fn info(&self) -> WorkerInfo {
        let worker = self.lock();
        let todo = "Limit the max instances";
        let max_instances = worker.args.max_instances;
        let deployed_instances = worker.instances.len() as u32;
        let running_instances = worker
            .instances
            .values()
            .filter(|state| state.current_run.is_some())
            .count() as u32;
        let instance_memory_size = worker.args.max_memory_pages * 64 * 1024;
        WorkerInfo {
            pubkey: load_or_generate_key().public().as_bytes().to_vec(),
            deployed_instances,
            running_instances,
            max_instances,
            instance_memory_size,
            session: worker.session.map(|s| s.to_vec()).unwrap_or_default(),
        }
    }

    pub fn blob_loader(&self) -> BlobLoader {
        self.lock().blob_loader.clone()
    }

    pub async fn start_instance(&self, vmid: Address) -> Result<()> {
        self.lock().start_instance(vmid)
    }

    pub async fn stop_instance(&self, vmid: Address) -> Result<()> {
        let mut handle = self.lock().stop_instance(vmid)?;
        handle.stop().await?;
        Ok(())
    }

    pub async fn create_instance(&self, manifest: Manifest) -> Result<InstanceInfo> {
        let immediate = manifest.start_mode == 0;
        let address = sp_core::blake2_256(&scale::Encode::encode(&manifest));
        let mut worker = self.lock();
        if worker.instances.contains_key(&address) {
            bail!("Instance already exists")
        }
        let session: [u8; 32] = rand::thread_rng().gen();
        let state = InstanceState {
            session,
            manifest,
            hist_metrics: Default::default(),
            current_run: None,
        };
        worker.instances.insert(address, state);
        if immediate {
            worker.start_instance(address)?;
        }
        let running = worker
            .instances
            .get(&address)
            .expect("Just inserted")
            .current_run
            .is_some();
        Ok(InstanceInfo {
            address,
            session,
            running,
        })
    }

    pub async fn remove_instance(&self, address: Address) -> Result<()> {
        let Some(mut handle) = self
            .lock()
            .instances
            .remove(&address)
            .map(|state| state.current_run)
            .flatten()
            .map(|run| run.vm_handle)
        else {
            bail!("Instance not found")
        };
        let vmid = ShortId(address);
        if !handle.is_stopped() {
            info!("Removing VM {vmid}...");
            if let Err(err) = handle.stop().await {
                warn!("Failed to stop {vmid}: {err:?}");
            }
        }
        Ok(())
    }

    pub fn for_each_instance<F>(&self, addresses: Option<&[Address]>, mut f: F)
    where
        F: FnMut(Address, &InstanceState),
    {
        let inner = self.lock();
        if let Some(addresses) = addresses {
            for address in addresses {
                if let Some(state) = inner.instances.get(address) {
                    f(*address, state);
                }
            }
        } else {
            for (address, state) in inner.instances.iter() {
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
    fn start_instance(&mut self, address: Address) -> Result<()> {
        let vmid = ShortId(address);
        println!("Starting {vmid}...");

        let instance = self
            .instances
            .get_mut(&address)
            .ok_or(anyhow!("Instance not found"))?;
        if instance.current_run.is_some() {
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
                &instance.manifest.code_hash,
                &instance.manifest.hash_algorithm,
                config,
            )
            .context("Failed to start instance")?;
        let run_state = CurrentRun {
            sequence_number: {
                static NEXT_RUN_SN: AtomicU64 = AtomicU64::new(0);
                NEXT_RUN_SN.fetch_add(1, Ordering::Relaxed)
            },
            vm_handle,
        };
        let sn = run_state.sequence_number;
        instance.current_run = Some(run_state);
        // Clean up the instance when it stops.
        let weak_self = self.weak_self.clone();
        self.service.spawn(async move {
            if let Ok(reason) = join_handle.await {
                info!("VM {vmid} stopped: {reason}");
            } else {
                warn!("VM {vmid} stopped unexpectedly");
            }
            if let Some(inner) = weak_self.upgrade() {
                let mut inner = inner.lock().expect("Worker lock poisoned");
                let Some(instance) = inner.instances.get_mut(&address) else {
                    warn!("Instance was removed while stopping");
                    return;
                };
                if let Some(current_run) = instance.current_run.take() {
                    if current_run.sequence_number == sn {
                        instance
                            .hist_metrics
                            .merge(&current_run.vm_handle.meter().to_metrics());
                    } else {
                        // The instance has been restarted.
                        instance.current_run = Some(current_run);
                    }
                }
            }
        });
        Ok(())
    }

    fn stop_instance(&mut self, address: Address) -> Result<VmHandle> {
        let instance = self
            .instances
            .get_mut(&address)
            .ok_or(anyhow!("Instance not found"))?;
        instance
            .current_run
            .take()
            .map(|run| run.vm_handle)
            .ok_or_else(|| anyhow!("Instance is not running"))
    }

    fn init(&mut self, salt: &[u8]) -> Result<[u8; 32]> {
        if !self.instances.is_empty() {
            bail!("Init session failed, instances already deployed")
        }
        let seed: [u8; 32] = rand::thread_rng().gen();
        let message = [salt, &seed].concat();
        let session = blake2_256(&message);
        self.session = Some(session);
        Ok(seed)
    }
}
