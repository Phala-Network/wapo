use anyhow::{bail, Context as _, Result};
use phala_scheduler::TaskScheduler;
use std::future::Future;
use std::ops::{Deref, DerefMut};
use std::pin::Pin;
use std::task::{Context, Poll};
use tracing::debug;
use wasi_common::sync::WasiCtxBuilder;
use wasi_common::WasiCtx;

use wasmtime::{Config, Engine, Linker, Module, Store, TypedFunc};

use crate::wapo_ctx::{LogHandler, WapoCtx};
use crate::{async_context, wapo_ctx, VmId};

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
        Self::new()
    }
}

impl WasmEngine {
    pub fn new() -> Self {
        let mut config = Config::new();
        config.async_support(false);

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
    pub fn run(&self, args: Vec<String>, config: WasmInstanceConfig) -> Result<WasmRun> {
        let WasmInstanceConfig {
            max_memory_pages,
            id,
            scheduler,
            weight,
            event_tx,
            log_handler,
        } = config;
        let todo = "memory limits";
        let engine = self.engine.inner.clone();
        let mut linker = Linker::<VmCtx>::new(&engine);

        let mut wapo_ctx = wapo_ctx::create_env(id, event_tx, log_handler);
        wapo_ctx.set_weight(weight);
        wapo_ctx::add_ocalls_to_linker(&mut linker, |c| &mut c.wapo_ctx)?;

        let todo = "set envs";
        let wasi_ctx = WasiCtxBuilder::new().args(&args)?.inherit_stdio().build();
        let vm_ctx = VmCtx::new(wapo_ctx, wasi_ctx);
        wasi_common::sync::add_to_linker(&mut linker, |c| &mut c.wasi_ctx)?;

        let mut store = Store::new(&engine, vm_ctx);
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

pub struct WasmInstanceConfig {
    pub max_memory_pages: u32,
    pub id: crate::VmId,
    pub scheduler: Option<TaskScheduler<VmId>>,
    pub weight: u32,
    pub event_tx: crate::OutgoingRequestChannel,
    pub log_handler: Option<LogHandler>,
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
}

impl VmCtx {
    fn new(wapo_ctx: WapoCtx, wasi_ctx: WasiCtx) -> Self {
        Self { wapo_ctx, wasi_ctx }
    }
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
                    if run.store.data().has_more_ready() {
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
