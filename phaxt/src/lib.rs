use anyhow::Result;
use scale_encode::EncodeAsType;

use scale::{Decode, Encode};
use scale_info::TypeInfo;
use subxt::{
    backend::rpc::RpcClient,
    config::polkadot::{PolkadotExtrinsicParams, PolkadotExtrinsicParamsBuilder},
};

pub use client::{connect, ChainApi};
pub use rpc_ext::{ExtraRpcClient, ExtraRpcExt};

mod client;
pub mod dynamic;
mod rpc_ext;
pub mod signer;

#[derive(Encode, Decode, Clone, PartialEq, Eq, TypeInfo, PartialOrd, Ord, Debug, EncodeAsType)]
pub struct ParaId(pub u32);

pub type StorageProof = Vec<Vec<u8>>;
pub type StorageState = Vec<(Vec<u8>, Vec<u8>)>;
pub type ExtrinsicParams = PolkadotExtrinsicParams<Config>;
pub type ExtrinsicParamsBuilder = PolkadotExtrinsicParamsBuilder<Config>;
pub use subxt::PolkadotConfig as Config;
pub type OnlineClient = subxt::OnlineClient<Config>;
pub type Index = u32;

pub use subxt;
pub type BlockNumber = u32;
pub type Hash = primitive_types::H256;
pub type AccountId = <Config as subxt::Config>::AccountId;
