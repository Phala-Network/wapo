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

use crate::{blobs::BlobLoader, ShortId, WasmEngine, WasmModule};

#[derive(Clone)]
pub struct ModuleLoader {
    engine: WasmEngine,
    blob_loader: BlobLoader,
    max_compilation_tasks: usize,
    state: Arc<Mutex<ModuleLoaderState>>,
}

struct ModuleLoaderState {
    cache: LruCache<Vec<u8>, WasmModule>,
    compiling: BTreeMap<Vec<u8>, Sender<WasmModule>>,
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
            state: Arc::new(Mutex::new(ModuleLoaderState {
                cache,
                compiling: BTreeMap::new(),
            })),
        }
    }

    #[tracing::instrument(skip_all, fields(code = %ShortId(code_hash)))]
    pub async fn load_module(&self, code_hash: &[u8], hash_alg: &str) -> Result<WasmModule> {
        info!(target: "wapo", "Loading module");

        let mut compiling_signal = None;
        {
            let mut state = self
                .state
                .lock()
                .expect("BUG: ModuleLoaderState lock poisoned");
            let todo = "Also cache on fs";
            if let Some(module) = state.cache.get(code_hash) {
                info!(target: "wapo", "Module found in cache");
                return Ok(module.clone());
            }
            match state.compiling.get(code_hash) {
                None => {
                    if state.compiling.len() >= self.max_compilation_tasks {
                        let todo = "Queue the task";
                        anyhow::bail!("Too many compilation tasks");
                    }
                    let (tx, _rx) = channel(1);
                    state.compiling.insert(code_hash.to_vec(), tx);
                }
                Some(tx) => {
                    // due to Rust's lifetime calculation limitation, we can not await the signal here,
                    // even if `drop(state)` is called first.
                    compiling_signal = Some(tx.subscribe());
                }
            }
        }
        if let Some(mut rx) = compiling_signal {
            let module = rx
                .recv()
                .await
                .context("Failed to receive compiled module")?;
            info!(target: "wapo", "Received module compiled by another task");
            return Ok(module);
        }

        let blob_loader = self.blob_loader.clone();
        let engine = self.engine.clone();
        let owned_code_hash = code_hash.to_vec();
        let owned_hash_alg = hash_alg.to_string();

        let span = tracing::Span::current();
        let module = tokio::task::spawn_blocking(move || {
            let _grd = span.enter();

            info!(target: "wapo", "Loading module code...");
            let wasm_code = blob_loader
                .get(&owned_code_hash, &owned_hash_alg)
                .with_context(|| anyhow!("Failed to load module"))?
                .ok_or_else(|| anyhow!("Wasm code not found"))?;
            let t0 = Instant::now();
            info!(target: "wapo", "Compiling module...",);
            let module = engine
                .compile(&wasm_code)
                .with_context(|| anyhow!("Failed to compile module"))?;
            info!(target: "wapo", "Module compiled, elapsed={:.2?}", t0.elapsed());
            Result::<_, anyhow::Error>::Ok(module)
        })
        .await;

        let mut state = self
            .state
            .lock()
            .expect("BUG: ModuleLoaderState lock poisoned");

        let tx = state
            .compiling
            .remove(code_hash)
            .ok_or(anyhow!("BUG: missing compiling task"))?;

        let module = module
            .context("Module compilation task failed")?
            .context("Module compilation failed")?;

        state.cache.put(code_hash.to_vec(), module.clone());
        match tx.send(module.clone()) {
            Ok(n) => info!(target: "wapo", "Compiled module sent to {n} subscribers"),
            Err(_err) => {
                debug!(target: "wapo", "Failed to send compiled module, there should be no subscriber")
            }
        }
        Ok(module)
    }
}
