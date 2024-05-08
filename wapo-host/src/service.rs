use anyhow::Result;
use phala_scheduler::TaskScheduler;
use serde::{Deserialize, Serialize};
use std::future::Future;
use std::ops::Deref;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::io::DuplexStream;
use tokio::{
    sync::mpsc::{channel, unbounded_channel, Receiver, Sender, UnboundedSender},
    sync::oneshot::{Receiver as OneshotReceiver, Sender as OneshotSender},
    task::JoinHandle,
};
use tracing::{debug, error, info, warn, Instrument};
use wapo_env::messages::{AccountId, HttpHead, HttpResponseHead};

use crate::Meter;
use crate::{
    module_loader::ModuleLoader,
    blobs::BlobsLoader,
    run::{InstanceConfig, WasmEngine},
    ShortId, VmId,
};

pub struct VmHandle {
    cmd_sender: CommandSender,
    stop_signal: Option<OneshotReceiver<()>>,
    meter: Arc<Meter>,
}

impl VmHandle {
    pub async fn stop(&mut self) -> Result<()> {
        self.cmd_sender.ctl_tx.send(ControlCommand::Stop)?;
        if let Some(stop_signal) = self.stop_signal.take() {
            stop_signal.await?;
        }
        Ok(())
    }

    pub fn is_stopped(&self) -> bool {
        self.stop_signal.is_none()
    }

    pub fn command_sender(&self) -> &CommandSender {
        &self.cmd_sender
    }

    pub fn meter(&self) -> Arc<Meter> {
        self.meter.clone()
    }
}

#[derive(Clone)]
pub struct CommandSender {
    srv_tx: Sender<Command>,
    ctl_tx: UnboundedSender<ControlCommand>,
}

impl CommandSender {
    pub fn update_weight(&mut self, weight: u32) -> Result<()> {
        self.ctl_tx.send(ControlCommand::UpdateWeight(weight))?;
        Ok(())
    }
}

impl Deref for CommandSender {
    type Target = Sender<Command>;

    fn deref(&self) -> &Self::Target {
        &self.srv_tx
    }
}

impl Drop for CommandSender {
    fn drop(&mut self) {
        if let Err(err) = self.ctl_tx.send(ControlCommand::Stop) {
            warn!(target: "wapo", "Failed to send stop command to the VM: {err:?}");
        }
    }
}

#[derive(Debug)]
pub enum Report {
    VmTerminated { id: VmId, reason: ExitReason },
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, derive_more::Display)]
pub enum ExitReason {
    /// The program returned from `fn main`.
    Exited(i32),
    /// Stopped by an external Stop command.
    Stopped,
    /// The input channel has been closed, likely caused by a Stop command.
    InputClosed,
    /// The program panicked.
    Panicked,
    /// The task future has beed dropped, likely caused by a Stop command.
    Cancelled,
    /// When a previous running instance restored from a checkpoint.
    Restore,
    /// The instance was deployed without code, so it it waiting to a custom code uploading.
    WaitingForCode,
    /// The wasm code is too large.
    CodeTooLarge,
    /// Failed to create the guest instance.
    FailedToStart,
}

pub enum ControlCommand {
    // Stop the side VM instance.
    Stop,
    // Update the task scheduling weight
    UpdateWeight(u32),
}

pub enum Command {
    // Push a query from RPC to the instance.
    PushQuery {
        origin: Option<AccountId>,
        payload: Vec<u8>,
        reply_tx: OneshotSender<Vec<u8>>,
    },
    // An incoming HTTP request
    HttpRequest(IncomingHttpRequest),
}

pub struct IncomingHttpRequest {
    pub(crate) head: HttpHead,
    pub(crate) body_stream: DuplexStream,
    pub(crate) response_tx: OneshotSender<anyhow::Result<HttpResponseHead>>,
}

pub struct ServiceRun {
    runtime: tokio::runtime::Runtime,
    report_rx: Receiver<Report>,
}

#[derive(Clone)]
pub struct ServiceHandle {
    runtime_handle: tokio::runtime::Handle,
    report_tx: Sender<Report>,
    out_tx: crate::OutgoingRequestSender,
    scheduler: TaskScheduler<VmId>,
    module_loader: ModuleLoader,
}

pub fn service(
    worker_threads: usize,
    out_tx: crate::OutgoingRequestSender,
    blobs_dir: &str,
) -> (ServiceRun, ServiceHandle) {
    let worker_threads = worker_threads.max(1);
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .max_blocking_threads(16)
        // Reason for the additional 2 threads:
        // One for the blocking reactor thread, another one for receiving channel messages
        // from the external system
        .worker_threads(worker_threads + 2)
        .enable_all()
        .build()
        .unwrap();
    let runtime_handle = runtime.handle().clone();
    let (report_tx, report_rx) = channel(100);
    let run = ServiceRun { runtime, report_rx };
    let blobs_loader = BlobsLoader::new(blobs_dir);
    let module_loader = ModuleLoader::new(WasmEngine::default(), blobs_loader, 100);
    let spawner = ServiceHandle {
        runtime_handle,
        report_tx,
        out_tx,
        scheduler: TaskScheduler::new(worker_threads as _),
        module_loader,
    };
    (run, spawner)
}

impl ServiceRun {
    pub fn blocking_run(self, event_handler: impl FnMut(Report)) {
        let handle = self.runtime.handle().clone();
        handle.block_on(self.run(event_handler));
    }

    pub async fn run(mut self, mut event_handler: impl FnMut(Report)) {
        loop {
            match self.report_rx.recv().await {
                None => {
                    info!(target: "wapo", "The report channel is closed. Exiting service.");
                    break;
                }
                Some(report) => {
                    event_handler(report);
                }
            }
        }

        // To avoid: panicked at 'Cannot drop a runtime in a context where blocking is not allowed.'
        let handle = self.runtime.handle().clone();
        handle.spawn_blocking(move || drop(self));
    }
}

#[derive(typed_builder::TypedBuilder)]
pub struct InstanceStartConfig {
    max_memory_pages: u32,
    id: VmId,
    weight: u32,
    blobs_dir: PathBuf,
}

impl ServiceHandle {
    #[tracing::instrument(parent=None, name="wapo", fields(id = %ShortId(config.id)), skip_all)]
    pub fn start(
        &self,
        wasm_hash: &[u8],
        wasm_hash_alg: &str,
        config: InstanceStartConfig,
    ) -> Result<(VmHandle, JoinHandle<ExitReason>)> {
        let InstanceStartConfig {
            max_memory_pages,
            id,
            weight,
            blobs_dir,
        } = config;
        let event_tx = self.out_tx.clone();
        let (cmd_tx, mut cmd_rx) = channel(128);
        let (ctl_cmd_tx, mut ctl_cmd_rx) = unbounded_channel();
        let (stop_signal_tx, stop_signal_rx) = tokio::sync::oneshot::channel();

        let scheduler = self.scheduler.clone();
        let module = self.module_loader.load_module(wasm_hash, wasm_hash_alg)?;
        let meter = Arc::new(Meter::default());
        let meter_cloned = meter.clone();
        let handle = self.spawn(async move {
            macro_rules! push_msg {
                ($expr: expr, $level: ident, $msg: expr) => {{
                    $level!(target: "wapo", msg=%$msg, "Pushing message");
                    if let Err(err) = $expr {
                        error!(target: "wapo", msg=%$msg, %err, "Push message failed");
                    }
                }};
            }
            info!(target: "wapo", "Starting instance...");
            let config = InstanceConfig::builder()
                .id(id)
                .max_memory_pages(max_memory_pages)
                .scheduler(scheduler)
                .weight(weight)
                .event_tx(event_tx)
                .blobs_dir(blobs_dir)
                .meter(Some(meter_cloned))
                .build();
            let mut wasm_run = match module.run(config) {
                Ok(i) => i,
                Err(err) => {
                    error!(target: "wapo", "Failed to create instance: {err:?}");
                    return ExitReason::FailedToStart;
                }
            };

            let meter = wasm_run.meter();
            let meter_cloned = meter.clone();
            scopeguard::defer! {
                meter_cloned.stop();
            }

            loop {
                tokio::select! {
                    rv = &mut wasm_run => {
                        match rv {
                            Ok(ret) => {
                                info!(target: "wapo", ret, "The instance exited normally.");
                                break ExitReason::Exited(ret);
                            }
                            Err(err) => {
                                info!(target: "wapo", ?err, "The instance exited.");
                                break ExitReason::Panicked;
                            }
                        }
                    }
                    cmd = cmd_rx.recv() => {
                        match cmd {
                            None => {
                                info!(target: "wapo", "The command channel is closed. Exiting...");
                                break ExitReason::InputClosed;
                            }
                            Some(Command::PushQuery{ origin, payload, reply_tx }) => {
                                push_msg!(wasm_run.state_mut().push_query(origin, payload, reply_tx), debug, "query");
                            }
                            Some(Command::HttpRequest(request)) => {
                                push_msg!(wasm_run.state_mut().push_http_request(request), debug, "http request");
                            }
                        }
                    }
                    cmd = ctl_cmd_rx.recv() => {
                        match cmd {
                            None => {
                                info!(target: "wapo", "The control command channel is closed. Exiting...");
                                break ExitReason::InputClosed;
                            }
                            Some(ControlCommand::Stop) => {
                                info!(target: "wapo", "Received stop command. Exiting...");
                                break ExitReason::Stopped;
                            }
                            Some(ControlCommand::UpdateWeight(weight)) => {
                                wasm_run.state_mut().set_weight(weight);
                            }
                        }
                    }
                }
            }
        });
        let report_tx = self.report_tx.clone();
        let task_handle = self.spawn(async move {
            let reason = match handle.await {
                Ok(r) => r,
                Err(err) => {
                    warn!(target: "wapo", ?err, "The instance exited with error");
                    if err.is_cancelled() {
                        ExitReason::Cancelled
                    } else {
                        ExitReason::Panicked
                    }
                }
            };
            if let Err(err) = report_tx.send(Report::VmTerminated { id, reason }).await {
                warn!(target: "wapo", ?err, "Failed to send report to service");
            }
            let _ = stop_signal_tx.send(());
            reason
        });
        let cmd_sender = CommandSender {
            srv_tx: cmd_tx,
            ctl_tx: ctl_cmd_tx,
        };
        let vm_handle = VmHandle {
            cmd_sender: cmd_sender.clone(),
            stop_signal: Some(stop_signal_rx),
            meter,
        };
        Ok((vm_handle, task_handle))
    }

    pub fn spawn<O: Send + 'static>(
        &self,
        fut: impl Future<Output = O> + Send + 'static,
    ) -> JoinHandle<O> {
        self.runtime_handle.spawn(fut.in_current_span())
    }

    pub fn event_tx(&self) -> crate::OutgoingRequestSender {
        self.out_tx.clone()
    }
}
