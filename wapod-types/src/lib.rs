#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

use alloc::vec::Vec;
use core::fmt::Debug;

pub use scale;

pub mod bench_app;
pub mod crypto;
pub mod primitives;
pub mod session;
pub mod ticket;

#[derive(Clone, Copy, Debug)]
#[repr(u8)]
pub enum ContentType {
    RpcResponse = 1,
    EndpointInfo = 2,
    // A gap to avoid conflicts with pruntime v2
    Metrics = 100,
    AppData = 101,
    WorkerAttestation = 102,
    WorkerDescription = 103,
    SessionUpdate = 104,
}

impl ContentType {
    pub fn wrap_message(&self, message: impl AsRef<[u8]>) -> Vec<u8> {
        self.wrap_message_iter(message.as_ref().iter().copied())
    }
    pub fn wrap_message_iter(&self, message: impl IntoIterator<Item = u8>) -> Vec<u8> {
        [0xff_u8, *self as u8]
            .into_iter()
            .chain(message.into_iter())
            .collect()
    }
}
