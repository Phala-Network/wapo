use anyhow::Result;
use scale_encode::EncodeAsType;

use scale::{Decode, Encode};
use scale_info::TypeInfo;
use subxt::{backend::rpc::RpcClient, utils::MultiAddress, SubstrateConfig};

pub use client::{connect, ChainApi};
pub use rpc_ext::{ExtraRpcClient, ExtraRpcExt};

mod client;
pub mod dynamic;
mod extrinsic_params;
mod rpc_ext;
pub mod signer;

pub use phala_metadata::phala;
mod phala_metadata;
pub use encode_decode::RecodeTo;
mod encode_decode;

#[derive(Encode, Decode, Clone, PartialEq, Eq, TypeInfo, PartialOrd, Ord, Debug, EncodeAsType)]
pub struct ParaId(pub u32);

pub type StorageProof = Vec<Vec<u8>>;
pub type StorageState = Vec<(Vec<u8>, Vec<u8>)>;
pub type ExtrinsicParams = extrinsic_params::PhalaExtrinsicParams<Config>;
pub type ExtrinsicParamsBuilder = extrinsic_params::PhalaExtrinsicParamsBuilder<Config>;
pub type OnlineClient = subxt::OnlineClient<Config>;
pub type Index = u32;

#[derive(Clone, Copy, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
pub enum Config {}

impl subxt::Config for Config {
    type Hash = <SubstrateConfig as subxt::Config>::Hash;
    type AccountId = <SubstrateConfig as subxt::Config>::AccountId;
    type Address = MultiAddress<Self::AccountId, ()>;
    type Signature = <SubstrateConfig as subxt::Config>::Signature;
    type Hasher = <SubstrateConfig as subxt::Config>::Hasher;
    type Header = <SubstrateConfig as subxt::Config>::Header;
    type ExtrinsicParams = ExtrinsicParams;
    type AssetId = u32;
}

pub use subxt;
pub type BlockNumber = u32;
pub type Hash = primitive_types::H256;
pub type AccountId = <Config as subxt::Config>::AccountId;
