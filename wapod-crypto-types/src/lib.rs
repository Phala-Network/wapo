#![no_std]

extern crate alloc;

use alloc::vec::Vec;
use core::fmt::Debug;

pub mod query;
pub mod worker_signed_message;

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

pub trait CryptoProvider {
    fn sr25519_verify(public_key: &[u8], message: &[u8], signature: &[u8]) -> bool;
    fn keccak_256(data: &[u8]) -> [u8; 32];
    fn blake2b_256(data: &[u8]) -> [u8; 32];
}
