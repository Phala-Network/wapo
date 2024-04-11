use crate::env::DynCacheOps;
use crate::run::{WasmEngine, WasmInstanceConfig};
use crate::{ShortId, VmId};
use anyhow::Result;
use phala_scheduler::TaskScheduler;
use serde::{Deserialize, Serialize};
use wapo_env::messages::{AccountId, HttpHead, HttpResponseHead};
use std::future::Future;
use tokio::io::DuplexStream;
use tokio::{
    sync::mpsc::{channel, Receiver, Sender},
    sync::oneshot::Sender as OneshotSender,
    sync::watch::Receiver as WatchReceiver,
    task::JoinHandle,
};
use tracing::{debug, error, info, warn, Instrument};

pub type CommandSender = Sender<Command>;

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
    /// The sidevm was deployed without code, so it it waiting to a custom code uploading.
    WaitingForCode,
    /// The Code of the sidevm is too large.
    CodeTooLarge,
    /// Failed to create the sidevm instance.
    FailedToStart,
}

pub enum Command {
    // Stop the side VM instance.
    Stop,
    // Push a query from RPC to the instance.
    PushQuery {
        origin: Option<AccountId>,
        payload: Vec<u8>,
        reply_tx: OneshotSender<Vec<u8>>,
    },
    // Update the task scheduling weight
    UpdateWeight(u32),
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
pub struct Spawner {
    runtime_handle: tokio::runtime::Handle,
    report_tx: Sender<Report>,
    out_tx: crate::OutgoingRequestChannel,
    scheduler: TaskScheduler<VmId>,
}

pub fn service(
    worker_threads: usize,
    out_tx: crate::OutgoingRequestChannel,
) -> (ServiceRun, Spawner) {
    let worker_threads = worker_threads.max(1);
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .max_blocking_threads(16)
        // Reason for the additional 2 threads:
        // One for the blocking reactor thread, another one for receiving channel messages
        // from the pink system
        .worker_threads(worker_threads + 2)
        .enable_all()
        .build()
        .unwrap();
    let runtime_handle = runtime.handle().clone();
    let (report_tx, report_rx) = channel(100);
    let run = ServiceRun { runtime, report_rx };
    let spawner = Spawner {
        runtime_handle,
        report_tx,
        out_tx,
        scheduler: TaskScheduler::new(worker_threads as _),
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
                    info!(target: "sidevm", "The report channel is closed. Exiting service.");
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

impl Spawner {
    #[tracing::instrument(parent=None, name="sidevm", fields(id = %ShortId(id)), skip_all)]
    #[allow(clippy::too_many_arguments)]
    pub fn start(
        &self,
        wasm_bytes: &[u8],
        max_memory_pages: u32,
        id: VmId,
        gas_per_breath: u64,
        cache_ops: DynCacheOps,
        weight: u32,
        prev_stopped: Option<WatchReceiver<bool>>,
    ) -> Result<(CommandSender, JoinHandle<ExitReason>)> {
        let event_tx = self.out_tx.clone();
        let (cmd_tx, mut cmd_rx) = channel(128);
        let scheduler = self.scheduler.clone();
        let wasm_bytes = wasm_bytes.to_vec();
        let handle = self.spawn(async move {
            macro_rules! push_msg {
                ($expr: expr, $level: ident, $msg: expr) => {{
                    $level!(target: "sidevm", msg=%$msg, "Pushing message");
                    if let Err(err) = $expr {
                        error!(target: "sidevm", msg=%$msg, %err, "Push message failed");
                    }
                }};
            }
            let mut weight = weight;
            if let Some(mut prev_stopped) = prev_stopped {
                if !*prev_stopped.borrow() {
                    info!(target: "sidevm", "Waiting for the previous instance to be stopped...");
                    tokio::select! {
                        _ = prev_stopped.changed() => {},
                        cmd = cmd_rx.recv() => {
                            match cmd {
                                None => {
                                    info!(target: "sidevm", "The command channel is closed. Exiting...");
                                    return ExitReason::InputClosed;
                                }
                                Some(Command::Stop) => {
                                    info!(target: "sidevm", "Received stop command. Exiting...");
                                    return ExitReason::Stopped;
                                }
                                Some(Command::UpdateWeight(w)) => {
                                    weight = w;
                                }
                                Some(
                                    Command::PushQuery { .. } |
                                    Command::HttpRequest(_)
                                ) => {
                                    info!(
                                        target: "sidevm",
                                        "Ignored command while waiting for the previous instance to be stopped"
                                    );
                                }
                            }
                        },
                    }
                }
            }
            info!(target: "sidevm", "Starting sidevm instance...");
            let engine = WasmEngine::new();
            let module = match engine.compile(&wasm_bytes) {
                Ok(m) => m,
                Err(err) => {
                    error!(target: "sidevm", ?err, "Failed to compile wasm module");
                    return ExitReason::FailedToStart;
                }
            };
            info!(target: "sidevm", "Wasm module compiled");
            let config = WasmInstanceConfig {
                max_memory_pages,
                id,
                gas_per_breath,
                cache_ops,
                scheduler: Some(scheduler),
                weight,
                event_tx,
                log_handler: None,
            };
            let mut wasm_run = match module.run(vec![], config) {
                Ok(i) => i,
                Err(err) => {
                    error!(target: "sidevm", "Failed to create sidevm instance: {err:?}");
                    return ExitReason::FailedToStart;
                }
            };
            loop {
                tokio::select! {
                    cmd = cmd_rx.recv() => {
                        match cmd {
                            None => {
                                info!(target: "sidevm", "The command channel is closed. Exiting...");
                                break ExitReason::InputClosed;
                            }
                            Some(Command::Stop) => {
                                info!(target: "sidevm", "Received stop command. Exiting...");
                                break ExitReason::Stopped;
                            }
                            Some(Command::PushQuery{ origin, payload, reply_tx }) => {
                                push_msg!(wasm_run.state_mut().push_query(origin, payload, reply_tx), debug, "query");
                            }
                            Some(Command::HttpRequest(request)) => {
                                push_msg!(wasm_run.state_mut().push_http_request(request), debug, "http request");
                            }
                            Some(Command::UpdateWeight(weight)) => {
                                wasm_run.state_mut().set_weight(weight);
                            }
                        }
                    }
                    rv = &mut wasm_run => {
                        match rv {
                            Ok(ret) => {
                                info!(target: "sidevm", ret, "The sidevm instance exited normally.");
                                break ExitReason::Exited(ret);
                            }
                            Err(err) => {
                                info!(target: "sidevm", ?err, "The sidevm instance exited.");
                                break ExitReason::Panicked;
                            }
                        }
                    }
                }
            }
        });
        let report_tx = self.report_tx.clone();
        let handle = self.spawn(async move {
            let reason = match handle.await {
                Ok(r) => r,
                Err(err) => {
                    warn!(target: "sidevm", ?err, "The sidevm instance exited with error");
                    if err.is_cancelled() {
                        ExitReason::Cancelled
                    } else {
                        ExitReason::Panicked
                    }
                }
            };
            if let Err(err) = report_tx.send(Report::VmTerminated { id, reason }).await {
                warn!(target: "sidevm", ?err, "Failed to send report to sidevm service");
            }
            reason
        });
        Ok((cmd_tx, handle))
    }

    pub fn spawn<O: Send + 'static>(
        &self,
        fut: impl Future<Output = O> + Send + 'static,
    ) -> JoinHandle<O> {
        self.runtime_handle.spawn(fut.in_current_span())
    }

    pub fn event_tx(&self) -> crate::OutgoingRequestChannel {
        self.out_tx.clone()
    }
}
