use anyhow::{bail, Context as _, Result};
use phala_scheduler::TaskScheduler;
use std::future::Future;
use std::ops::{Deref, DerefMut};
use std::pin::Pin;
use std::task::{Context, Poll};
use tracing::debug;
use wasi_common::sync::WasiCtxBuilder;
use wasi_common::WasiCtx;

use wasmtime::{Config, Engine, Linker, Module, Store, StoreLimits, TypedFunc};

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
        Self::new(Config::new())
    }
}

impl WasmEngine {
    pub fn new(mut config: Config) -> Self {
        config
            .static_memory_maximum_size(0)
            .guard_before_linear_memory(false);
        let engine = Engine::new(&config).expect("Failed to create Wasm engine");
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
        } = config;
        let engine = self.engine.inner.clone();
        let mut linker = Linker::<VmCtx>::new(&engine);

        let mut wapo_ctx = wapo_ctx::create_env(id, event_tx, log_handler);
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
    #[builder(default = None, setter(strip_option))]
    log_handler: Option<LogHandler>,
    #[builder(default)]
    envs: Vec<(String, String)>,
    #[builder(default)]
    args: Vec<String>,
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
        }
    }
}

impl WasmRun {
    pub(crate) fn state_mut(&mut self) -> &mut WapoCtx {
        self.store.data_mut()
    }
}
