use std::{
    num::NonZeroUsize,
    sync::{Arc, Mutex},
    time::Instant,
};

use anyhow::{anyhow, Context, Result};
use lru::LruCache;
use tracing::info;

use crate::{blobs::BlobLoader, WasmEngine, WasmModule};

#[derive(Clone)]
pub struct ModuleLoader {
    state: Arc<Mutex<ModuleLoaderState>>,
}

struct ModuleLoaderState {
    engine: WasmEngine,
    blob_loader: BlobLoader,
    cache: LruCache<Vec<u8>, WasmModule>,
}

impl ModuleLoader {
    pub fn new(engine: WasmEngine, blob_loader: BlobLoader, cache_size: usize) -> Self {
        let cache = LruCache::new(
            NonZeroUsize::new(cache_size.max(1)).expect("cache size must be greater than 0"),
        );
        Self {
            state: Arc::new(Mutex::new(ModuleLoaderState {
                engine,
                blob_loader,
                cache,
            })),
        }
    }

    pub fn load_module(&self, code_hash: &[u8], hash_alg: &str) -> Result<WasmModule> {
        let mut state = self.state.lock().expect("ModuleLoaderState lock poisoned");
        if let Some(module) = state.cache.get(code_hash) {
            return Ok(module.clone());
        }
        let hex_hash = hex_fmt::HexFmt(code_hash);
        // TODO: don't lock while compiling
        let wasm_code = state
            .blob_loader
            .get(code_hash, hash_alg)
            .with_context(|| anyhow!("Failed to load module {hex_hash}"))?
            .ok_or_else(|| anyhow!("Wasm code not found: {hex_hash}"))?;
        let t0 = Instant::now();
        info!(target: "wapo", "Compiling module {hex_hash}...",);
        let module = state
            .engine
            .compile(&wasm_code)
            .with_context(|| anyhow!("Failed to compile module {hex_hash}"))?;
        info!(target: "wapo", "Module {hex_hash} compiled, elapsed={:.2?}", t0.elapsed());
        Ok(module)
    }
}
