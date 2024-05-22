#![no_std]

extern crate alloc;

use alloc::vec::Vec;
use scale::{Decode, Encode};
use scale_info::TypeInfo;

pub mod query;

#[derive(Clone, Copy, Debug, Encode, Decode, TypeInfo)]
pub enum ContentType {
    RpcResponse,
    RegisterInfo,
    Metrics,
    AppData,
}

impl ContentType {
    pub fn wrap_message(&self, message: impl AsRef<[u8]>) -> Vec<u8> {
        let mut wrapped = Vec::new();
        wrapped.extend_from_slice(&self.encode());
        wrapped.extend_from_slice(message.as_ref());
        wrapped
    }
}
