use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

#[derive(Default, Debug, Clone)]
pub struct Metrics {
    pub gas_comsumed: u64,
    pub net_egress: u64,
    pub net_ingress: u64,
    pub storage_read: u64,
    pub storage_written: u64,
    pub starts: u64,
}

impl Metrics {
    /// Merges the other metrics into this one.
    pub fn merge(&mut self, other: &Metrics) {
        self.gas_comsumed += other.gas_comsumed;
        self.net_egress += other.net_egress;
        self.net_ingress += other.net_ingress;
        self.storage_read += other.storage_read;
        self.storage_written += other.storage_written;
    }

    /// Returns a new metrics that is the sum of the two.
    pub fn merged(&self, other: &Metrics) -> Metrics {
        let mut result = self.clone();
        result.merge(other);
        result
    }
}

#[derive(Default, Debug)]
pub struct Meter {
    pub gas_comsumed: AtomicU64,
    pub net_egress: AtomicU64,
    pub net_ingress: AtomicU64,
    pub storage_read: AtomicU64,
    pub storage_written: AtomicU64,
    /// Whether the metering is stopped. Used to signal the epoch checker to stop the VM.
    pub stopped: AtomicBool,
}

impl Meter {
    pub fn set_gas_comsumed(&self, gas: u64) {
        self.gas_comsumed.store(gas, Ordering::Relaxed);
    }

    pub fn record_gas(&self, gas: u64) {
        self.gas_comsumed.fetch_add(gas, Ordering::Relaxed);
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
    pub fn stop(&self) {
        self.stopped.store(true, Ordering::Relaxed)
    }
    pub fn stopped(&self) -> bool {
        self.stopped.load(Ordering::Relaxed)
    }

    pub fn to_metrics(&self) -> Metrics {
        Metrics {
            gas_comsumed: self.gas_comsumed.load(Ordering::Relaxed),
            net_egress: self.net_egress.load(Ordering::Relaxed),
            net_ingress: self.net_ingress.load(Ordering::Relaxed),
            storage_read: self.storage_read.load(Ordering::Relaxed),
            storage_written: self.storage_written.load(Ordering::Relaxed),
            starts: 1,
        }
    }
}
