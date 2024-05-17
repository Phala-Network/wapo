use std::{
    collections::BTreeMap,
    num::NonZeroUsize,
    sync::{Arc, Mutex},
    time::Instant,
};

use anyhow::{anyhow, Context, Result};
use lru::LruCache;
use tokio::sync::broadcast::{channel, Sender};
use tracing::{debug, info};

use crate::{blobs::BlobLoader, ArcError, ShortId, WasmEngine, WasmModule};

pub struct ModuleLoaderInfo {
    pub max_compilation_tasks: usize,
    pub queue_cap: usize,
    pub queue_used: usize,
    pub cache_cap: usize,
    pub cache_used: usize,
    pub compiling_handles_len: usize,
    pub compiling_tasks: usize,
}

#[derive(Clone)]
pub struct ModuleLoader {
    engine: WasmEngine,
    blob_loader: BlobLoader,
    max_compilation_tasks: usize,
    queue_cap: usize,
    state: Arc<Mutex<ModuleLoaderState>>,
}

struct ModuleLoaderState {
    cache: LruCache<Vec<u8>, WasmModule>,
    compiling: BTreeMap<Vec<u8>, Sender<Result<WasmModule, ArcError>>>,
    compiling_tasks: usize,
    queue: BTreeMap<Vec<u8>, String>,
}

impl ModuleLoader {
    pub fn new(engine: WasmEngine, blob_loader: BlobLoader, cache_size: usize) -> Self {
        let cache = LruCache::new(
            NonZeroUsize::new(cache_size.max(1)).expect("BUG: cache size must be greater than 0"),
        );
        Self {
            engine,
            blob_loader,
            max_compilation_tasks: 2,
            queue_cap: 128,
            state: Arc::new(Mutex::new(ModuleLoaderState {
                cache,
                compiling: BTreeMap::new(),
                queue: BTreeMap::new(),
                compiling_tasks: 0,
            })),
        }
    }

    pub fn info(&self) -> ModuleLoaderInfo {
        let state = self
            .state
            .lock()
            .expect("BUG: ModuleLoaderState lock poisoned");
        ModuleLoaderInfo {
            max_compilation_tasks: self.max_compilation_tasks,
            queue_cap: self.queue_cap,
            queue_used: state.queue.len(),
            cache_cap: state.cache.cap().into(),
            cache_used: state.cache.len(),
            compiling_handles_len: state.compiling.len(),
            compiling_tasks: state.compiling_tasks,
        }
    }

    #[tracing::instrument(skip_all, fields(code = %ShortId(code_hash)))]
    pub async fn load_module(&self, code_hash: &[u8], hash_alg: &str) -> Result<WasmModule> {
        info!(target: "wapo", "loading module");

        let mut module_rx = {
            let mut state = self
                .state
                .lock()
                .expect("BUG: ModuleLoaderState lock poisoned");
            if let Some(module) = state.cache.get(code_hash) {
                info!(target: "wapo", "module found in cache");
                return Ok(module.clone());
            }
            match state.compiling.get(code_hash) {
                Some(tx) => tx.subscribe(),
                None => {
                    if state.queue.len() >= self.queue_cap {
                        anyhow::bail!("module compilation queue is full");
                    }
                    state.queue.insert(code_hash.to_vec(), hash_alg.to_string());
                    let (tx, rx) = channel(1);
                    state.compiling.insert(code_hash.to_vec(), tx);
                    if state.compiling_tasks < self.max_compilation_tasks {
                        state.compiling_tasks += 1;
                        let cloned_self = self.clone();
                        std::thread::Builder::new()
                            .name("wapo module compiler".into())
                            .spawn(move || {
                                cloned_self.serve_compilation();
                            })
                            .expect("failed to spawn module compiler thread");
                    }
                    rx
                }
            }
        };
        let module = module_rx
            .recv()
            .await
            .context("failed to receive compiled module")?;
        info!(target: "wapo", "received module compiled by another task");
        Ok(module?)
    }

    fn compile(&self, code_hash: &[u8], hash_alg: &str) -> Result<WasmModule> {
        info!(target: "wapo", "loading module code...");
        let wasm_code = self
            .blob_loader
            .get(code_hash, hash_alg)
            .context("failed to load module")?
            .ok_or_else(|| anyhow!("Wasm code not found"))?;
        let t0 = Instant::now();
        info!(target: "wapo", "compiling module...",);
        let module = self
            .engine
            .compile(&wasm_code)
            .context("failed to compile module")?;
        info!(target: "wapo", "module compiled, elapsed={:.2?}", t0.elapsed());
        Ok(module)
    }

    fn serve_compilation(&self) {
        info!(target: "wapo", "module compiler started");
        loop {
            let (code_hash, hash_alg) = {
                let mut state = self
                    .state
                    .lock()
                    .expect("BUG: ModuleLoaderState lock poisoned");
                let Some((hash, alg)) = state.queue.pop_first() else {
                    state.compiling_tasks -= 1;
                    info!(target: "wapo", "no more tasks to compile, exiting...");
                    break;
                };
                (hash, alg)
            };
            let _span = tracing::info_span!("compilation", code = %ShortId(&code_hash)).entered();
            let module = self.compile(&code_hash, &hash_alg);
            let mut state = self
                .state
                .lock()
                .expect("BUG: ModuleLoaderState lock poisoned");
            let Some(tx) = state.compiling.remove(&code_hash) else {
                info!(target: "wapo", "BUG: missing compiling task for code {}", ShortId(code_hash));
                continue;
            };
            if let Ok(ref module) = &module {
                state.cache.put(code_hash.to_vec(), module.clone());
            }
            match tx.send(module.map_err(Into::into)) {
                Ok(n) => info!(target: "wapo", "compiled module sent to {n} subscribers"),
                Err(_err) => {
                    debug!(target: "wapo", "failed to send compiled module")
                }
            }
        }
    }
}
