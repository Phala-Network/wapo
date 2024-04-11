use anyhow::{Context as _, Result};
use phala_scheduler::TaskScheduler;
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

use wasmtime::{Config, Engine, Instance, Linker, Module, Store, TypedFunc};

use crate::env::{DynCacheOps, LogHandler, VmState};
use crate::{async_context, env, VmId};

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
            gas_per_breath,
            cache_ops,
            scheduler,
            weight,
            event_tx,
            log_handler,
        } = config;
        let todo = "memory limits";
        let engine = self.engine.inner.clone();
        let mut linker = Linker::<VmState>::new(&engine);

        let mut state = env::create_env(id, cache_ops, event_tx, log_handler, args);
        state.set_weight(weight);
        let mut store = Store::new(&engine, state);
        env::add_to_linker(&mut linker, |c| c)?;

        let instance = Instance::new(&mut store, &self.module, &[])?;
        instance
            .get_memory(&mut store, "memory")
            .context("No memory exported")?;
        let wasm_poll_entry = instance.get_typed_func(&mut store, "sidevm_poll")?;
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
    pub gas_per_breath: u64,
    pub cache_ops: DynCacheOps,
    pub scheduler: Option<TaskScheduler<VmId>>,
    pub weight: u32,
    pub event_tx: crate::OutgoingRequestChannel,
    pub log_handler: Option<LogHandler>,
}

pub struct WasmRun {
    id: VmId,
    store: Store<VmState>,
    wasm_poll_entry: TypedFunc<(), i32>,
    scheduler: Option<TaskScheduler<VmId>>,
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
    pub(crate) fn state_mut(&mut self) -> &mut VmState {
        self.store.data_mut()
    }
}
