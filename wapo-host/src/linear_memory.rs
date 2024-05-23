use anyhow::Result;
use std::{
    sync::{Arc, Mutex},
    vec,
};
use tracing::{info, warn};
use wasmtime::{LinearMemory, MemoryCreator, MemoryType};

type Pool = Arc<Mutex<Vec<Vec<u8>>>>;

pub struct MemoryPool {
    limit: usize,
    pool: Option<Pool>,
}

impl MemoryPool {
    pub fn new(limit: usize, pool_size: usize) -> Self {
        let mut pool = vec![];
        for index in 0..pool_size {
            info!(index, pool_size, "creating memory");
            pool.push(vec![0u8; limit]);
        }
        Self {
            limit,
            pool: if pool_size > 0 {
                Some(Arc::new(Mutex::new(pool)))
            } else {
                None
            },
        }
    }
}

struct Memory {
    limit: usize,
    memory: Vec<u8>,
    pool: Option<Pool>,
}

impl Drop for Memory {
    fn drop(&mut self) {
        if let Some(pool) = &self.pool {
            let memory = std::mem::take(&mut self.memory);
            pool.lock().expect("pool lock").push(memory);
        }
    }
}

unsafe impl LinearMemory for Memory {
    fn byte_size(&self) -> usize {
        self.memory.len()
    }

    fn maximum_byte_size(&self) -> Option<usize> {
        Some(self.limit)
    }

    fn grow_to(&mut self, new_size: usize) -> Result<()> {
        if new_size > self.limit {
            warn!(new_size, limit = self.limit, "memory limit exceeded");
            return Err(anyhow::anyhow!("memory limit exceeded"));
        }
        if new_size > self.memory.len() {
            self.memory.resize(new_size, 0);
        }
        Ok(())
    }

    fn as_ptr(&self) -> *mut u8 {
        self.memory.as_ptr() as *mut u8
    }

    fn wasm_accessible(&self) -> std::ops::Range<usize> {
        0..self.memory.len()
    }
}

unsafe impl MemoryCreator for MemoryPool {
    fn new_memory(
        &self,
        ty: MemoryType,
        minimum: usize,
        maximum: Option<usize>,
        reserved_size_in_bytes: Option<usize>,
        guard_size_in_bytes: usize,
    ) -> Result<Box<dyn LinearMemory>, String> {
        info!(
            ?ty,
            minimum,
            ?maximum,
            ?reserved_size_in_bytes,
            guard_size_in_bytes,
            "new memory"
        );
        if ty.is_64() || ty.is_shared() {
            return Err("unsupported memory type".to_string());
        }
        if self.pool.is_none() && reserved_size_in_bytes.is_some() {
            return Err("reserved size is not supported".to_string());
        }
        if self.pool.is_some() && reserved_size_in_bytes.unwrap_or_default() > self.limit {
            return Err("reserved size is too large".to_string());
        }
        if guard_size_in_bytes != 0 {
            return Err("guard size is not supported".to_string());
        }
        let limit = maximum.unwrap_or(self.limit).min(self.limit);

        if let Some(pool) = &self.pool {
            if let Some(mut memory) = pool.lock().expect("pool lock").pop() {
                memory.clear();
                memory.resize(minimum, 0);
                Ok(Box::new(Memory {
                    limit,
                    memory,
                    pool: Some(pool.clone()),
                }))
            } else {
                Err("mem pool: out of memory".to_string())
            }
        } else {
            let memory = vec![0u8; minimum];
            Ok(Box::new(Memory {
                limit,
                memory,
                pool: None,
            }))
        }
    }
}
