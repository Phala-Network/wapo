use std::alloc::System;

use phala_allocator::StatSizeAllocator;
use wapod_rpc::prpc::MemoryUsage;

#[global_allocator]
static ALLOCATOR: StatSizeAllocator<System> = StatSizeAllocator::new(System);

pub fn mem_usage() -> MemoryUsage {
    let stats = ALLOCATOR.stats();
    MemoryUsage {
        rust_used: stats.current as _,
        rust_peak: stats.peak as _,
        rust_spike: stats.spike as _,
        peak: vm_peak().unwrap_or(0) as _,
        free: mem_free().unwrap_or(0) as _,
        used: mem_used().unwrap_or(0) as _,
    }
}

fn vm_peak() -> Option<usize> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    for line in status.lines() {
        if line.starts_with("VmPeak:") {
            let peak: usize = line.split_ascii_whitespace().nth(1)?.parse().ok()?;
            return Some(peak * 1024);
        }
    }
    None
}

fn mem_used() -> Option<usize> {
    Some(memory_stats::memory_stats()?.physical_mem)
}

fn mem_free() -> Option<usize> {
    let status = std::fs::read_to_string("/proc/meminfo").ok()?;
    for line in status.lines() {
        if line.starts_with("MemFree:") {
            let free: usize = line.split_ascii_whitespace().nth(1)?.parse().ok()?;
            return Some(free * 1024);
        }
    }
    None
}
