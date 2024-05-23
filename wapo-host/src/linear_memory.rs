use anyhow::Result;
use tracing::{info, warn};
use wasmtime::{LinearMemory, MemoryCreator, MemoryType};

pub struct VecMemoryCreator {
    limit: usize,
}

impl VecMemoryCreator {
    pub fn new(limit: usize) -> Self {
        Self { limit }
    }
}

struct VecMemory {
    limit: usize,
    memory: Vec<u8>,
}

unsafe impl LinearMemory for VecMemory {
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

unsafe impl MemoryCreator for VecMemoryCreator {
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
            "creating memory for instance"
        );
        if ty.is_64() || ty.is_shared() {
            return Err("unsupported memory type".to_string());
        }
        if reserved_size_in_bytes.unwrap_or_default() > self.limit {
            return Err("reserved size too large".to_string());
        }
        if guard_size_in_bytes != 0 {
            return Err("guard size is not supported".to_string());
        }
        let limit = maximum.unwrap_or(self.limit).min(self.limit);
        let mut memory = Vec::with_capacity(limit);
        memory.resize(minimum, 0);
        Ok(Box::new(VecMemory { limit, memory }))
    }
}
