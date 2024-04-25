use tokio::task::JoinHandle;

use wapo_host::ShortId;
use wapod_rpc::prpc::NodeInfo;

use std::{collections::HashMap, path::PathBuf};

use std::sync::Arc;

use tokio::sync::mpsc::Sender;
use tokio::sync::Mutex;

use service::{Command, CommandSender, Spawner};

use wapo_host::service::{self, ExitReason};

use crate::Args;

type Address = [u8; 32];

pub struct VmHandle {
    pub sender: CommandSender,
    pub handle: JoinHandle<ExitReason>,
}

struct AppInner {
    instances: HashMap<Address, VmHandle>,
    args: Args,
    spawner: Spawner,
}

#[derive(Clone)]
pub struct App {
    inner: Arc<Mutex<AppInner>>,
}

impl App {
    pub fn new(spawner: Spawner, args: Args) -> Self {
        Self {
            inner: Arc::new(Mutex::new(AppInner {
                instances: HashMap::new(),
                spawner,
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
        Some(self.inner.lock().await.instances.get(&vmid)?.sender.clone())
    }

    pub async fn take_handle(&self, vmid: Address) -> Option<VmHandle> {
        self.inner.lock().await.instances.remove(&vmid)
    }

    pub async fn run_wasm(
        &self,
        wasm_bytes: Vec<u8>,
        weight: u32,
        address: Address,
    ) -> anyhow::Result<()> {
        let mut inner = self.inner.lock().await;
        let vmid = ShortId(address);
        println!("VM {vmid} running...");
        let objects_path = inner.args.objects_path.clone();
        let config = service::InstanceStartConfig::builder()
            .max_memory_pages(inner.args.max_memory_pages)
            .id(address)
            .weight(weight)
            .objects_path(objects_path.into())
            .build();
        let (sender, handle) = inner.spawner.start(&wasm_bytes, None, config)?;
        inner.instances.insert(address, VmHandle { sender, handle });
        Ok(())
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

    pub async fn objects_path(&self) -> PathBuf {
        self.inner.lock().await.args.objects_path.clone().into()
    }
}
