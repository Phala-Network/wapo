use anyhow::{Context, Result};
use scopeguard::ScopeGuard;
use serde::{Deserialize, Serialize};
use sni_tls_listener::SniTlsListener;
use std::future::Future;
use std::ops::{Deref, RangeInclusive};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::DuplexStream;
use tokio::{
    sync::mpsc::{channel, unbounded_channel, Receiver, Sender, UnboundedSender},
    sync::oneshot::{Receiver as OneshotReceiver, Sender as OneshotSender},
    task::JoinHandle,
};
use tracing::{debug, error, info, warn, Instrument};
use wapo_env::messages::{AccountId, HttpHead, HttpResponseHead};
use wasi_common::I32Exit;
use wasmtime::{Config, Strategy};

use crate::runtime::vm_context::RuntimeCalls;
use crate::Meter;
use crate::{
    blobs::BlobLoader,
    module_loader::ModuleLoader,
    run::{InstanceConfig, WasmEngine},
    ShortId, VmId,
};

use tokio::sync::watch;

#[derive(Debug)]
pub enum VmStatus {
    LoadingCode,
    CreatingInstance,
    Running,
    Stopped {
        reason: String,
        error: Option<crate::ArcError>,
    },
}

pub type VmStatusReceiver = watch::Receiver<VmStatus>;

pub struct VmHandle {
    cmd_sender: CommandSender,
    stop_signal: Option<OneshotReceiver<()>>,
    meter: Arc<Meter>,
    status: VmStatusReceiver,
}

impl VmHandle {
    pub fn subscribe_status(&self) -> VmStatusReceiver {
        self.status.clone()
    }

    pub async fn stop(&mut self) -> Result<()> {
        info!(target: "wapo", "stopping instance...");
        self.cmd_sender.inner.ctl_tx.send(ControlCommand::Stop)?;
        if let Some(stop_signal) = self.stop_signal.take() {
            stop_signal.await?;
        }
        info!(target: "wapo", "stopped");
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
    inner: Arc<CommandSenderInner>,
}

struct CommandSenderInner {
    srv_tx: Sender<Command>,
    ctl_tx: UnboundedSender<ControlCommand>,
}

impl CommandSender {
    pub fn update_weight(&mut self, weight: u32) -> Result<()> {
        self.inner
            .ctl_tx
            .send(ControlCommand::UpdateWeight(weight))?;
        Ok(())
    }
}

impl Deref for CommandSender {
    type Target = Sender<Command>;

    fn deref(&self) -> &Self::Target {
        &self.inner.srv_tx
    }
}

impl Drop for CommandSenderInner {
    fn drop(&mut self) {
        if self.ctl_tx.send(ControlCommand::Stop).is_err() {
            info!(target: "wapo", "instance already stopped");
        }
    }
}

pub enum Report {
    VmTerminated { id: VmId, reason: ExitReason },
}

impl std::fmt::Debug for Report {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::VmTerminated { id, reason } => f
                .debug_struct("VmTerminated")
                .field("id", &hex_fmt::HexFmt(id))
                .field("reason", reason)
                .finish(),
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, derive_more::Display)]
pub enum ExitReason {
    /// The program returned from `fn main`.
    Exited(i32),
    /// Stopped by an external Stop command.
    Stopped,
    /// The input channel has been closed, likely caused by a Stop command.
    InputClosed,
    /// The program trapped.
    Trap,
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
        path: String,
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
    pub(crate) response_tx: OneshotSender<Result<HttpResponseHead>>,
}

pub struct ServiceRun {
    runtime: tokio::runtime::Runtime,
    report_rx: Receiver<Report>,
}

#[derive(Clone)]
pub struct ServiceHandle {
    runtime_handle: tokio::runtime::Handle,
    report_tx: Sender<Report>,
    module_loader: ModuleLoader,
}

pub fn service(
    worker_threads: usize,
    module_cache_size: usize,
    blobs_dir: &PathBuf,
    mem_limit: usize,
    mem_pool_size: usize,
    use_winch: bool,
) -> Result<(ServiceRun, ServiceHandle)> {
    let worker_threads = worker_threads.max(1);
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .max_blocking_threads(16)
        // Reason for the additional 2 threads:
        // One for the blocking reactor thread, another one for receiving channel messages
        // from the external system
        .worker_threads(worker_threads + 2)
        .enable_all()
        .build()
        .context("failed to create tokio runtime")?;
    let runtime_handle = runtime.handle().clone();
    let (report_tx, report_rx) = channel(100);
    let run = ServiceRun { runtime, report_rx };
    let blob_loader = BlobLoader::new(blobs_dir);
    let config = Config::new()
        .strategy(if use_winch {
            Strategy::Winch
        } else {
            Strategy::Cranelift
        })
        .to_owned();
    let engine = WasmEngine::new(config, 10, mem_limit, mem_pool_size)
        .context("failed to create Wasm engine")?;
    let module_loader = ModuleLoader::new(engine, blob_loader, module_cache_size);
    let spawner = ServiceHandle {
        runtime_handle,
        report_tx,
        module_loader,
    };
    Ok((run, spawner))
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
                    info!(target: "wapo", "the report channel is closed. Exiting service.");
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
pub struct InstanceStartConfig<OCalls> {
    max_memory_pages: u32,
    id: VmId,
    weight: u32,
    blobs_dir: PathBuf,
    auto_restart: bool,
    runtime_calls: OCalls,
    args: Vec<String>,
    envs: Vec<(String, String)>,
    tcp_listen_port_range: RangeInclusive<u16>,
    sni_tls_listener: Option<SniTlsListener>,
    verify_tls_server_cert: bool,
}

impl ServiceHandle {
    #[tracing::instrument(parent=None, name="wapo", fields(id = %ShortId(config.id)), skip_all)]
    pub fn start<OCalls>(
        &self,
        wasm_hash: &[u8],
        wasm_hash_alg: &str,
        config: InstanceStartConfig<OCalls>,
    ) -> Result<(VmHandle, JoinHandle<ExitReason>)>
    where
        OCalls: RuntimeCalls + Clone,
    {
        let InstanceStartConfig {
            max_memory_pages,
            id,
            weight,
            blobs_dir,
            auto_restart,
            runtime_calls,
            args,
            envs,
            tcp_listen_port_range,
            sni_tls_listener,
            verify_tls_server_cert,
        } = config;
        let (cmd_tx, mut cmd_rx) = channel(128);
        let (ctl_cmd_tx, mut ctl_cmd_rx) = unbounded_channel();
        let (stop_signal_tx, stop_signal_rx) = tokio::sync::oneshot::channel();
        let (status_tx, status) = watch::channel(VmStatus::LoadingCode);
        let status_guard = scopeguard::guard(status_tx, |tx| {
            let _ = tx.send(VmStatus::Stopped {
                reason: "Unknown error".into(),
                error: None,
            });
        });

        let module_loader = self.module_loader.clone();
        let meter = Arc::new(Meter::default());
        let meter_cloned = meter.clone();
        let wasm_hash = wasm_hash.to_vec();
        let wasm_hash_alg = wasm_hash_alg.to_string();
        let handle = self.spawn(async move {
            macro_rules! push_msg {
                ($expr: expr, $level: ident, $msg: expr) => {{
                    $level!(target: "wapo", msg=%$msg, "pushing message");
                    if let Err(err) = $expr {
                        error!(target: "wapo", msg=%$msg, %err, "push message failed");
                    }
                }};
            }
            let result = module_loader
                .load_module(&wasm_hash, &wasm_hash_alg)
                .await
                .context("failed to load module");
            let module = match result {
                Ok(m) => m,
                Err(err) => {
                    error!(target: "wapo", ?err, "failed to load module");
                    _ = ScopeGuard::into_inner(status_guard).send(VmStatus::Stopped {
                        reason: format!("{err:?}"),
                        error: Some(err.into()),
                    });
                    return ExitReason::FailedToStart;
                }
            };

            _ = status_guard.send(VmStatus::CreatingInstance);

            info!(target: "wapo", "starting instance...");
            let config = InstanceConfig::builder()
                .id(id)
                .max_memory_pages(max_memory_pages)
                .weight(weight)
                .blobs_dir(blobs_dir)
                .meter(Some(meter_cloned))
                .runtime_calls(runtime_calls)
                .args(args)
                .envs(envs)
                .tcp_listen_port_range(tcp_listen_port_range)
                .sni_tls_listener(sni_tls_listener)
                .verify_tls_server_cert(verify_tls_server_cert)
                .build();
            let mut wasm_run = match module.run(config.clone()).context("failed to create instance") {
                Ok(i) => i,
                Err(err) => {
                    error!(target: "wapo", ?err, "failed to create instance");
                    _ = ScopeGuard::into_inner(status_guard).send(VmStatus::Stopped {
                        reason: format!("{err}"),
                        error: Some(err.into()),
                    });
                    return ExitReason::FailedToStart;
                }
            };

            let meter = wasm_run.meter();
            let meter_cloned = meter.clone();
            scopeguard::defer! {
                meter_cloned.stop();
            }

            _ = status_guard.send(VmStatus::Running);

            let mut start_time = Instant::now();
            const MIN_LIVE_TIME: Duration = Duration::from_secs(10);

            let reason = loop {
                tokio::select! {
                    rv = &mut wasm_run => {
                        match rv {
                            Ok(()) => {
                                info!(target: "wapo", "the instance returned from main.");
                                break ExitReason::Exited(0);
                            }
                            Err(err) => {
                                let live_time_allow_restart = start_time.elapsed() > MIN_LIVE_TIME;
                                match err.downcast() {
                                    Ok(I32Exit(code)) => {
                                        info!(target: "wapo", code, "the instance exited via proc_exit()");
                                        if code == 0 || !auto_restart || !live_time_allow_restart {
                                            break ExitReason::Exited(code);
                                        }
                                        // fallthrough to restart
                                    }
                                    Err(err) => {
                                        info!(target: "wapo", ?err, "the instance exited.");
                                        if !auto_restart || !live_time_allow_restart {
                                            break ExitReason::Trap;
                                        }
                                        // fallthrough to restart
                                    }
                                }
                            }
                        }
                        info!(target: "wapo", "restarting...");
                        start_time = Instant::now();
                        wasm_run = match module.run(config.clone()) {
                            Ok(run) => run,
                            Err(err) => {
                                error!(target: "wapo", ?err, "failed to rerestart instance");
                                break ExitReason::FailedToStart;
                            }
                        };
                        continue;
                    }
                    cmd = cmd_rx.recv() => {
                        match cmd {
                            None => {
                                info!(target: "wapo", "the command channel is closed. Exiting...");
                                break ExitReason::InputClosed;
                            }
                            Some(Command::PushQuery{ path, origin, payload, reply_tx }) => {
                                push_msg!(wasm_run.state_mut().push_query(origin, path, payload, reply_tx), debug, "query");
                            }
                            Some(Command::HttpRequest(request)) => {
                                push_msg!(wasm_run.state_mut().push_http_request(request), debug, "http request");
                            }
                        }
                    }
                    cmd = ctl_cmd_rx.recv() => {
                        match cmd {
                            None => {
                                info!(target: "wapo", "the control command channel is closed. Exiting...");
                                break ExitReason::InputClosed;
                            }
                            Some(ControlCommand::Stop) => {
                                info!(target: "wapo", "received stop command. Exiting...");
                                break ExitReason::Stopped;
                            }
                            Some(ControlCommand::UpdateWeight(weight)) => {
                                wasm_run.state_mut().set_weight(weight);
                            }
                        }
                    }
                }
            };
            _ = ScopeGuard::into_inner(status_guard).send(VmStatus::Stopped {
                reason: format!("{reason:?}"),
                error: None,
            });
            reason
        });
        let report_tx = self.report_tx.clone();
        let task_handle = self.spawn(async move {
            let reason = match handle.await {
                Ok(r) => r,
                Err(err) => {
                    warn!(target: "wapo", ?err, "the instance exited with error");
                    if err.is_cancelled() {
                        ExitReason::Cancelled
                    } else {
                        ExitReason::Trap
                    }
                }
            };
            if let Err(err) = report_tx.send(Report::VmTerminated { id, reason }).await {
                warn!(target: "wapo", ?err, "failed to send report to service");
            }
            let _ = stop_signal_tx.send(());
            reason
        });
        let cmd_sender = CommandSender {
            inner: Arc::new(CommandSenderInner {
                srv_tx: cmd_tx,
                ctl_tx: ctl_cmd_tx,
            }),
        };
        let vm_handle = VmHandle {
            cmd_sender,
            stop_signal: Some(stop_signal_rx),
            meter,
            status,
        };
        Ok((vm_handle, task_handle))
    }

    pub fn spawn<O: Send + 'static>(
        &self,
        fut: impl Future<Output = O> + Send + 'static,
    ) -> JoinHandle<O> {
        self.runtime_handle.spawn(fut.in_current_span())
    }

    pub fn module_loader(&self) -> &ModuleLoader {
        &self.module_loader
    }
}
