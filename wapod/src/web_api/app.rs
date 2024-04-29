use anyhow::{anyhow, Context, Result};
use tokio::task::JoinHandle;

use tracing::{info, warn};
use wapo_host::ShortId;
use wapo_host::{objects::ObjectLoader, Meter};
use wapod_rpc::prpc::NodeInfo;

use std::collections::HashMap;

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use tokio::sync::mpsc::Sender;
use tokio::sync::Mutex;

use service::{Command, CommandSender, ServiceHandle};

use wapo_host::service::{self, ExitReason, VmHandle};
use wapod_rpc::prpc::Manifest;

use crate::Args;

type Address = [u8; 32];

struct CurrentRun {
    sequence_number: u64,
    vm_handle: VmHandle,
}

pub struct InstanceState {
    manifest: Manifest,
    hist_metrics: Meter,
    current_run: Option<CurrentRun>,
}

impl InstanceState {
    /// Returns the metrics of the instance during the session.
    /// If the instance is running, the metrics are merged with the current run's metrics.
    fn metrics(&self) -> Meter {
        self.current_run
            .as_ref()
            .map(|run| run.vm_handle.meter())
            .unwrap_or_default()
            .merged(&self.hist_metrics)
    }
}

struct AppInner {
    instances: HashMap<Address, InstanceState>,
    args: Args,
    service: ServiceHandle,
    object_loader: ObjectLoader,
}

#[derive(Clone)]
pub struct App {
    inner: Arc<Mutex<AppInner>>,
}

impl App {
    pub fn new(service: ServiceHandle, args: Args) -> Self {
        Self {
            inner: Arc::new(Mutex::new(AppInner {
                object_loader: ObjectLoader::new(&args.objects_path),
                instances: HashMap::new(),
                service,
                args,
            })),
        }
    }

    pub async fn send(&self, vmid: Address, message: Command) -> Result<(), (u16, &'static str)> {
        self.sender_for(vmid)
            .await
            .ok_or((404, "Instance not found"))?
            .send(message)
            .await
            .or(Err((500, "Failed to send message")))?;
        Ok(())
    }

    pub async fn sender_for(&self, vmid: Address) -> Option<CommandSender> {
        let handle = self
            .inner
            .lock()
            .await
            .instances
            .get(&vmid)?
            .current_run
            .as_ref()?
            .vm_handle
            .command_sender()
            .clone();
        Some(handle)
    }

    pub(crate) async fn take_handle(&self, vmid: Address) -> Option<VmHandle> {
        let handle = self
            .inner
            .lock()
            .await
            .instances
            .remove(&vmid)?
            .current_run?
            .vm_handle;
        Some(handle)
    }

    pub async fn info(&self) -> NodeInfo {
        let app = self.inner.lock().await;
        let max_instances = app.args.max_instances;
        let running_instances = app.instances.len() as u32;
        let instance_memory_size = app.args.max_memory_pages * 64 * 1024;
        NodeInfo {
            running_instances,
            max_instances,
            instance_memory_size,
        }
    }

    pub async fn object_loader(&self) -> ObjectLoader {
        self.inner.lock().await.object_loader.clone()
    }

    pub async fn start_instance(&self, vmid: Address) -> Result<()> {
        self.inner.lock().await.start_instance(vmid).await
    }

    pub async fn create_instance(&self, manifest: Manifest) -> Result<Address> {
        let immediate = manifest.start_mode == 0;
        let address = sp_core::blake2_256(&scale::Encode::encode(&manifest));
        let vmid = ShortId(address);
        let mut inner = self.inner.lock().await;
        if let Some(mut handle) = inner
            .instances
            .remove(&address)
            .map(|state| state.current_run)
            .flatten()
            .map(|run| run.vm_handle)
        {
            info!("Stopping VM {vmid}...");
            if let Err(err) = handle.stop().await {
                warn!("Failed to stop the VM: {err:?}");
            }
            info!("Prev VM {vmid} stopped");
        };
        let state = InstanceState {
            manifest,
            hist_metrics: Default::default(),
            current_run: None,
        };
        inner.instances.insert(address, state);
        if immediate {
            inner.start_instance(address).await?;
        }
        Ok(address)
    }
}

impl AppInner {
    async fn start_instance(&mut self, address: Address) -> Result<()> {
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
            .objects_path(self.args.objects_path.as_str().into())
            .build();
        let (vm_handle, join_handle) = self
            .service
            .start(
                &instance.manifest.code_hash,
                &instance.manifest.hash_algorithm,
                config,
            )
            .context("Failed to start instance")?;
        instance.current_run = Some(CurrentRun {
            sequence_number: {
                static NEXT_RUN_SN: AtomicU64 = AtomicU64::new(0);
                NEXT_RUN_SN.fetch_add(1, Ordering::Relaxed)
            },
            vm_handle,
        });
        let todo = "Where to set to None?";
        Ok(())
    }
}
