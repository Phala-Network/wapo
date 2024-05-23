use sp_core::Pair as PairT;
use sp_runtime::{
    traits::{IdentifyAccount, Verify},
    AccountId32 as SpAccountId32, MultiSignature as SpMultiSignature,
};
use subxt::Config;
use subxt::{tx::Signer, utils::MultiSignature};

/// A [`Signer`] implementation that can be constructed from an [`sp_core::Pair`].
#[derive(Clone, Debug)]
pub struct PairSigner<T: Config, Pair> {
    account_id: T::AccountId,
    signer: Pair,
    nonce: u64,
}

impl<T, Pair> PairSigner<T, Pair>
where
    T: Config,
    Pair: PairT,
    // We go via an `sp_runtime::MultiSignature`. We can probably generalise this
    // by implementing some of these traits on our built-in MultiSignature and then
    // requiring them on all T::Signatures, to avoid any go-between.
    <SpMultiSignature as Verify>::Signer: From<Pair::Public>,
    T::AccountId: From<SpAccountId32>,
{
    /// Creates a new [`Signer`] from an [`sp_core::Pair`].
    pub fn new(signer: Pair) -> Self {
        let account_id = <SpMultiSignature as Verify>::Signer::from(signer.public()).into_account();
        Self {
            account_id: account_id.into(),
            signer,
            nonce: 0,
        }
    }

    /// Returns the [`sp_core::Pair`] implementation used to construct this.
    pub fn signer(&self) -> &Pair {
        &self.signer
    }

    /// Return the account ID.
    pub fn account_id(&self) -> &T::AccountId {
        &self.account_id
    }

    pub fn increment_nonce(&mut self) {
        self.nonce += 1;
    }

    pub fn nonce(&self) -> u64 {
        self.nonce
    }

    pub fn set_nonce(&mut self, nonce: u64) {
        self.nonce = nonce;
    }
}

mod sealed {
    pub trait Sealed {}
}

pub trait ToMultiSignature: sealed::Sealed {
    fn to_multi_signature(&self) -> MultiSignature;
}

impl sealed::Sealed for sp_core::sr25519::Signature {}
impl ToMultiSignature for sp_core::sr25519::Signature {
    fn to_multi_signature(&self) -> MultiSignature {
        MultiSignature::Sr25519((*self).into())
    }
}

impl<T, Pair> Signer<T> for PairSigner<T, Pair>
where
    T: Config<Signature = MultiSignature>,
    Pair: PairT,
    Pair::Signature: ToMultiSignature,
{
    fn account_id(&self) -> T::AccountId {
        self.account_id.clone()
    }

    fn address(&self) -> T::Address {
        self.account_id.clone().into()
    }

    fn sign(&self, signer_payload: &[u8]) -> T::Signature {
        self.signer.sign(signer_payload).to_multi_signature()
    }
}
