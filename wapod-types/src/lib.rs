#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

use alloc::vec::Vec;
use core::fmt::Debug;

pub use scale;

pub mod bench_app;
pub mod crypto;
pub mod metrics;
pub mod primitives;
pub mod session;
pub mod ticket;
pub mod worker;

mod helpers;

pub type Bytes32 = [u8; 32];
pub type Address = Bytes32;
pub type Pubkey = Bytes32;
pub type Hash = Bytes32;

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
        [0xff_u8, *self as u8].into_iter().chain(message).collect()
    }
}
