use anyhow::{bail, Context as _, Result};
use phala_scheduler::TaskScheduler;
use std::future::Future;
use std::ops::{Deref, DerefMut};
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tracing::{debug, info};
use wasi_common::sync::WasiCtxBuilder;
use wasi_common::WasiCtx;

use wasmtime::{
    AsContext, Config, Engine, Linker, Module, Store, StoreLimits, TypedFunc, UpdateDeadline,
};

use crate::runtime::{
    async_context,
    vm_context::{self as wapo_ctx, LogHandler, WapoCtx},
};
use crate::{OutgoingRequestSender, VmId};

type RuntimeError = anyhow::Error;

#[derive(Clone)]
pub struct WasmModule {
    engine: WasmEngine,
    module: Module,
}

#[derive(Clone)]
pub struct WasmEngine {
    inner: Engine,
}

impl Default for WasmEngine {
    fn default() -> Self {
        Self::new(Config::new(), 0)
    }
}

impl WasmEngine {
    pub fn new(mut config: Config, tick_time_ms: u64) -> Self {
        config
            .consume_fuel(true)
            .epoch_interruption(true)
            .static_memory_maximum_size(0)
            .guard_before_linear_memory(false);
        let engine = Engine::new(&config).expect("Failed to create Wasm engine");
        if tick_time_ms > 0 {
            let engine = engine.clone();
            std::thread::Builder::new()
                .name("wapo ticking".into())
                .spawn(move || loop {
                    std::thread::sleep(std::time::Duration::from_millis(tick_time_ms));
                    engine.increment_epoch();
                })
                .expect("Failed to start epoch ticking service");
        }
        Self { inner: engine }
    }

    pub fn compile(&self, wasm_code: &[u8]) -> Result<WasmModule> {
        Ok(WasmModule {
            engine: self.clone(),
            module: Module::new(&self.inner, wasm_code)?,
        })
    }
}

impl WasmModule {
    pub fn run(&self, config: InstanceConfig) -> Result<WasmRun> {
        let InstanceConfig {
            max_memory_pages,
            id,
            scheduler,
            weight,
            event_tx,
            log_handler,
            args,
            envs,
            epoch_deadline,
            objects_path,
        } = config;
        let engine = self.engine.inner.clone();
        let mut linker = Linker::<VmCtx>::new(&engine);

        let mut wapo_ctx = wapo_ctx::create_env(id, event_tx, log_handler, objects_path);
        wapo_ctx.set_weight(weight);
        wapo_ctx::add_ocalls_to_linker(&mut linker, |c| &mut c.wapo_ctx)?;

        let wasi_ctx = WasiCtxBuilder::new()
            .args(&args)
            .context("Failed to set args")?
            .envs(&envs)
            .context("Failed to set envs")?
            .build();
        wasi_common::sync::add_to_linker(&mut linker, |c| &mut c.wasi_ctx)?;

        let memory_size = (max_memory_pages as usize)
            .checked_mul(64 * 1024)
            .ok_or_else(|| anyhow::anyhow!("Memory size too large: {} pages", max_memory_pages))?;

        let limits = wasmtime::StoreLimitsBuilder::new()
            .memory_size(memory_size)
            .build();

        let vm_ctx = VmCtx {
            wapo_ctx,
            wasi_ctx,
            limits,
        };
        let mut store = Store::new(&engine, vm_ctx);
        store.limiter(move |ctx| &mut ctx.limits);
        store.set_fuel(u64::MAX).expect("Failed to set fuel");

        store.set_epoch_deadline(epoch_deadline);
        store.epoch_deadline_callback(move |ctx| {
            if ctx.data().meter().stopped() {
                info!(target: "wapo", "Instance stopped by meter");
                anyhow::bail!("stopped by meter")
            }
            debug!(target: "wapo", "Epoch update");
            sync_gas(&ctx);
            Ok(UpdateDeadline::Continue(epoch_deadline))
        });

        let instance = linker
            .instantiate(&mut store, &self.module)
            .context("Failed to create instance")?;
        let wasm_poll_entry = match instance.get_typed_func(&mut store, "wapo_poll") {
            Ok(entry) => {
                debug!(target: "wapo", "Using entry point wapo_poll in the WASM module");
                entry
            }
            Err(_) => {
                // Fallback to the old name
                let Ok(entry) = instance.get_typed_func(&mut store, "sidevm_poll") else {
                    bail!("No poll function found in the WASM module");
                };
                debug!(target: "wapo", "Using entry point sidevm_poll in the WASM module");
                entry
            }
        };
        if let Some(scheduler) = &scheduler {
            scheduler.reset(&id);
        }
        Ok(WasmRun {
            wasm_poll_entry,
            store,
            scheduler,
            id,
        })
    }
}

#[derive(typed_builder::TypedBuilder)]
pub struct InstanceConfig {
    #[builder(default)]
    id: VmId,
    max_memory_pages: u32,
    #[builder(default = None, setter(strip_option))]
    scheduler: Option<TaskScheduler<VmId>>,
    #[builder(default = 1)]
    weight: u32,
    event_tx: OutgoingRequestSender,
    #[builder(default = 10)]
    epoch_deadline: u64,
    #[builder(default = None, setter(strip_option))]
    log_handler: Option<LogHandler>,
    #[builder(default)]
    envs: Vec<(String, String)>,
    #[builder(default)]
    args: Vec<String>,
    objects_path: PathBuf,
}

pub struct WasmRun {
    id: VmId,
    store: Store<VmCtx>,
    wasm_poll_entry: TypedFunc<(), i32>,
    scheduler: Option<TaskScheduler<VmId>>,
}

struct VmCtx {
    wapo_ctx: WapoCtx,
    wasi_ctx: WasiCtx,
    limits: StoreLimits,
}

impl Deref for VmCtx {
    type Target = WapoCtx;

    fn deref(&self) -> &Self::Target {
        &self.wapo_ctx
    }
}

impl DerefMut for VmCtx {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.wapo_ctx
    }
}

impl Drop for WasmRun {
    fn drop(&mut self) {
        if let Some(scheduler) = &self.scheduler {
            scheduler.exit(&self.id);
        }
    }
}

impl Future for WasmRun {
    type Output = Result<i32, RuntimeError>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let _guard = match &self.scheduler {
            Some(scheduler) => Some(futures::ready!(scheduler.poll_resume(
                cx,
                &self.id,
                self.store.data().weight()
            ))),
            None => None,
        };
        let run = self.get_mut();
        let result =
            match async_context::set_task_cx(cx, || run.wasm_poll_entry.call(&mut run.store, ())) {
                Ok(rv) => {
                    if rv == 0 {
                        if run.store.data().has_more_ready_tasks() {
                            cx.waker().wake_by_ref();
                        }
                        Poll::Pending
                    } else {
                        Poll::Ready(Ok(rv))
                    }
                }
                Err(err) => Poll::Ready(Err(err)),
            };
        run.sync_gas();
        result
    }
}

impl WasmRun {
    pub(crate) fn state_mut(&mut self) -> &mut WapoCtx {
        self.store.data_mut()
    }

    pub fn meter(&self) -> Arc<crate::Meter> {
        self.store.data().meter()
    }

    pub fn sync_gas(&self) {
        sync_gas(&self.store);
    }
}

fn sync_gas(ctx: &impl AsContext<Data = VmCtx>) {
    let store = ctx.as_context();
    let rest_fuel = store.get_fuel().unwrap_or_default();
    let consumed = u64::MAX - rest_fuel;
    store.data().meter().set_gas_comsumed(consumed);
}
