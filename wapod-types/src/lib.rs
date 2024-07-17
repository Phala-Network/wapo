//! Types that third-party softwares can use to talk to a wapod worker.

#![cfg_attr(not(feature = "std"), no_std)]
#![deny(missing_docs)]

extern crate alloc;

use alloc::vec::Vec;
use core::fmt::Debug;

pub use primitives::{Address, Bytes32, Hash, WorkerPubkey};
pub use scale;

pub mod bench_app;
pub mod crypto;
pub mod metrics;
pub mod primitives;
pub mod session;
pub mod ticket;
pub mod worker;

mod helpers;

/// The content type of a signed message.
#[derive(Clone, Copy, Debug)]
#[repr(u8)]
pub enum ContentType {
    /// A response to an RPC request.
    RpcResponse = 1,
    /// An endpoint info message.
    EndpointInfo = 2,
    // A gap to avoid conflicts with pruntime v2
    /// Metrics of applications.
    Metrics = 100,
    /// App requested worker signed data.
    AppData = 101,
    /// Worker attestation.
    WorkerAttestation = 102,
    /// Worker description.
    WorkerDescription = 103,
    /// Worker session update.
    SessionUpdate = 104,
}

impl ContentType {
    /// Wrap a message with the content type to create a signed message.
    pub fn wrap_message(&self, message: impl AsRef<[u8]>) -> Vec<u8> {
        self.wrap_message_iter(message.as_ref().iter().copied())
    }

    /// Wrap a message with the content type to create a signed message.
    pub fn wrap_message_iter(&self, message: impl IntoIterator<Item = u8>) -> Vec<u8> {
        [0xff_u8, *self as u8].into_iter().chain(message).collect()
    }
}
