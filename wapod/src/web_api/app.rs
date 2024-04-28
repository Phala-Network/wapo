use anyhow::{anyhow, Context, Result};
use tokio::task::JoinHandle;

use tracing::{info, warn};
use wapo_host::objects::ObjectLoader;
use wapo_host::ShortId;
use wapod_rpc::prpc::NodeInfo;

use std::collections::HashMap;

use std::sync::Arc;

use tokio::sync::mpsc::Sender;
use tokio::sync::Mutex;

use service::{Command, CommandSender, ServiceHandle};

use wapo_host::service::{self, ExitReason};
use wapod_rpc::prpc::Manifest;

use crate::Args;

type Address = [u8; 32];

pub struct VmHandle {
    pub sender: CommandSender,
    pub handle: JoinHandle<ExitReason>,
}

pub struct InstanceState {
    manifest: Manifest,
    metrics: (),
    handle: Option<VmHandle>,
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

    pub async fn sender_for(&self, vmid: Address) -> Option<Sender<Command>> {
        Some(
            self.inner
                .lock()
                .await
                .instances
                .get(&vmid)?
                .handle
                .as_ref()?
                .sender
                .clone(),
        )
    }

    pub(crate) async fn take_handle(&self, vmid: Address) -> Option<VmHandle> {
        self.inner.lock().await.instances.remove(&vmid)?.handle
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
        if let Some(handle) = inner
            .instances
            .remove(&address)
            .map(|state| state.handle)
            .flatten()
        {
            info!("Stopping VM {vmid}...");
            if let Err(err) = handle.sender.send(Command::Stop).await {
                warn!("Failed to send stop command to the VM: {err:?}");
            }
            match handle.handle.await {
                Ok(reason) => info!("VM exited: {reason:?}"),
                Err(err) => warn!("Failed to wait VM exit: {err:?}"),
            }
        };
        let state = InstanceState {
            manifest,
            metrics: (),
            handle: None,
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
        if instance.handle.is_some() {
            return Err(anyhow!("Instance already started"));
        }
        let config = service::InstanceStartConfig::builder()
            .max_memory_pages(self.args.max_memory_pages)
            .id(address)
            .weight(1)
            .objects_path(self.args.objects_path.as_str().into())
            .build();
        let (sender, handle) = self
            .service
            .start(
                &instance.manifest.code_hash,
                &instance.manifest.hash_algorithm,
                None,
                config,
            )
            .context("Failed to start instance")?;
        instance.handle = Some(VmHandle { sender, handle });
        let todo = "Where to set to None?";
        Ok(())
    }
}
