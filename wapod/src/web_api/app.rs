use tokio::task::JoinHandle;

use wapod_rpc::prpc::NodeInfo;

use std::{collections::HashMap, path::PathBuf};

use std::sync::Arc;

use tokio::sync::mpsc::Sender;
use tokio::sync::Mutex;

use service::{Command, CommandSender, Spawner};

use wapo_host::service::{self, ExitReason};

use crate::Args;

pub struct VmHandle {
    pub sender: CommandSender,
    pub handle: JoinHandle<ExitReason>,
}
struct AppInner {
    next_id: u32,
    instances: HashMap<u32, VmHandle>,
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
                next_id: 0,
                spawner,
                args,
            })),
        }
    }

    pub async fn send(&self, vmid: u32, message: Command) -> Result<(), (u16, &'static str)> {
        self.sender_for(vmid)
            .await
            .ok_or((404, "Instance not found"))?
            .send(message)
            .await
            .or(Err((500, "Failed to send message")))?;
        Ok(())
    }

    pub async fn sender_for(&self, vmid: u32) -> Option<Sender<Command>> {
        Some(self.inner.lock().await.instances.get(&vmid)?.sender.clone())
    }

    pub async fn take_handle(&self, vmid: u32) -> Option<VmHandle> {
        self.inner.lock().await.instances.remove(&vmid)
    }

    pub async fn run_wasm(
        &self,
        wasm_bytes: Vec<u8>,
        weight: u32,
        id: Option<u32>,
    ) -> Result<u32, &'static str> {
        let mut inner = self.inner.lock().await;
        let id = match id {
            Some(id) => id,
            None => inner.next_id,
        };
        inner.next_id = id
            .checked_add(1)
            .ok_or("Too many instances")?
            .max(inner.next_id);

        let mut vmid = [0u8; 32];

        vmid[0..4].copy_from_slice(&id.to_be_bytes());

        println!("VM {id} running...");
        let (sender, handle) = inner
            .spawner
            .start(&wasm_bytes, inner.args.max_memory_pages, vmid, weight, None)
            .unwrap();
        inner.instances.insert(id, VmHandle { sender, handle });
        Ok(id)
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
