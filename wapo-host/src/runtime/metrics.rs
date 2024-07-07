use std::{
    ops::{Add, AddAssign},
    sync::atomic::{AtomicBool, AtomicU64, Ordering},
    time::{Duration, Instant},
};

#[derive(Default, Debug, Clone)]
pub struct Metrics {
    // unit: gas unint
    pub gas_consumed: u64,
    // unit: byte
    pub net_egress: u64,
    // unit: byte
    pub net_ingress: u64,
    // unit: byte
    pub storage_read: u64,
    // unit: byte
    pub storage_written: u64,
    // unit: MB * second
    pub storage_used: u64,
    // unit: MB * second
    pub memory_used: u64,
    // unit: count
    pub starts: u64,
    // unit: tip
    pub tip: u64,
    pub duration: Duration,
}

impl Metrics {
    /// Merges the other metrics into this one.
    pub fn merge(&mut self, other: &Metrics) {
        *self = Metrics {
            gas_consumed: self.gas_consumed.saturating_add(other.gas_consumed),
            net_egress: self.net_egress.saturating_add(other.net_egress),
            net_ingress: self.net_ingress.saturating_add(other.net_ingress),
            storage_read: self.storage_read.saturating_add(other.storage_read),
            storage_written: self.storage_written.saturating_add(other.storage_written),
            memory_used: self.memory_used.saturating_add(other.memory_used),
            storage_used: 0,
            starts: self.starts.saturating_add(other.starts),
            tip: self.tip.saturating_add(other.tip),
            duration: self.duration.saturating_add(other.duration),
        };
    }

    /// Returns a new metrics that is the sum of the two.
    pub fn merged(&self, other: &Metrics) -> Metrics {
        let mut result = self.clone();
        result.merge(other);
        result
    }
}

impl Add for Metrics {
    type Output = Self;

    fn add(self, other: Self) -> Self {
        self.merged(&other)
    }
}

impl Add<&Metrics> for Metrics {
    type Output = Self;

    fn add(self, other: &Self) -> Self {
        self.merged(other)
    }
}

impl AddAssign for Metrics {
    fn add_assign(&mut self, other: Self) {
        self.merge(&other);
    }
}

impl AddAssign<&Metrics> for Metrics {
    fn add_assign(&mut self, other: &Self) {
        self.merge(other);
    }
}

#[derive(Debug)]
pub struct Meter {
    created_at: Instant,
    gas_consumed: AtomicU64,
    memory_used: AtomicU64,
    net_egress: AtomicU64,
    net_ingress: AtomicU64,
    storage_read: AtomicU64,
    storage_written: AtomicU64,
    tip: AtomicU64,
    /// Whether the metering is stopped. Used to signal the epoch checker to stop the VM.
    stopped: AtomicBool,
}

impl Default for Meter {
    fn default() -> Self {
        Self {
            created_at: Instant::now(),
            gas_consumed: AtomicU64::new(0),
            memory_used: AtomicU64::new(0),
            net_egress: AtomicU64::new(0),
            net_ingress: AtomicU64::new(0),
            storage_read: AtomicU64::new(0),
            storage_written: AtomicU64::new(0),
            tip: AtomicU64::new(0),
            stopped: AtomicBool::new(false),
        }
    }
}

impl Meter {
    pub fn set_gas_comsumed(&self, gas: u64) {
        self.gas_consumed.store(gas, Ordering::Relaxed);
    }

    pub fn record_gas(&self, gas: u64) {
        self.gas_consumed.fetch_add(gas, Ordering::Relaxed);
    }

    pub fn record_net_egress(&self, bytes: u64) {
        self.net_egress.fetch_add(bytes, Ordering::Relaxed);
    }

    pub fn record_net_ingress(&self, bytes: u64) {
        self.net_ingress.fetch_add(bytes, Ordering::Relaxed);
    }

    pub fn record_storage_read(&self, bytes: u64) {
        self.storage_read.fetch_add(bytes, Ordering::Relaxed);
    }

    pub fn record_storage_written(&self, bytes: u64) {
        self.storage_written.fetch_add(bytes, Ordering::Relaxed);
    }

    pub fn record_tcp_connect_start(&self) {
        self.record_net_egress(512);
    }
    pub fn record_tls_connect_start(&self) {
        self.record_net_egress(4096);
    }
    pub fn record_tcp_connect_done(&self) {
        self.record_net_ingress(512);
    }
    pub fn record_tls_connect_done(&self) {
        self.record_net_ingress(4096);
    }
    pub fn record_tcp_shutdown(&self) {
        self.record_net_egress(128);
    }
    pub fn add_tip(&self, value: u64) {
        let previous = self.tip.fetch_add(value, Ordering::Relaxed);
        if previous.checked_add(value).is_none() {
            self.tip.store(u64::MAX, Ordering::Relaxed);
        }
    }
    pub fn stop(&self) {
        self.stopped.store(true, Ordering::Relaxed)
    }
    pub fn stopped(&self) -> bool {
        self.stopped.load(Ordering::Relaxed)
    }

    pub fn to_metrics(&self) -> Metrics {
        let todo = "check if Instant be modified";
        Metrics {
            gas_consumed: self.gas_consumed.load(Ordering::Relaxed),
            memory_used: self.memory_used.load(Ordering::Relaxed),
            net_egress: self.net_egress.load(Ordering::Relaxed),
            net_ingress: self.net_ingress.load(Ordering::Relaxed),
            storage_read: self.storage_read.load(Ordering::Relaxed),
            storage_written: self.storage_written.load(Ordering::Relaxed),
            storage_used: 0,
            tip: self.tip.load(Ordering::Relaxed),
            starts: 1,
            duration: self.created_at.elapsed(),
        }
    }
}
