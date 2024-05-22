#![no_std]

extern crate alloc;

use alloc::vec::Vec;

pub mod query;

#[derive(Clone, Copy, Debug)]
#[repr(u8)]
pub enum ContentType {
    RpcResponse = 1,
    EndpointInfo = 2,
    // A gap to avoid conflicts with pruntime v2
    Metrics = 100,
    AppData = 101,
    WorkerAttestation = 102,
}

impl ContentType {
    pub fn wrap_message(&self, message: impl AsRef<[u8]>) -> Vec<u8> {
        let mut wrapped = Vec::new();
        wrapped.push(*self as u8);
        wrapped.extend_from_slice(message.as_ref());
        wrapped
    }
}
