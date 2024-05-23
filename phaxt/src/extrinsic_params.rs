use subxt::{
    config::{
        signed_extensions::{self, CheckNonceParams},
        ExtrinsicParams, Header,
    },
    Config,
};

pub type PhalaExtrinsicParams<T> = signed_extensions::AnyOf<
    T,
    (
        signed_extensions::CheckSpecVersion,
        signed_extensions::CheckTxVersion,
        signed_extensions::CheckGenesis<T>,
        signed_extensions::CheckMortality<T>,
        signed_extensions::CheckNonce,
        signed_extensions::ChargeTransactionPayment,
    ),
>;

/// A builder that outputs the set of [`super::ExtrinsicParams::Params`] required for
/// [`PhalaExtrinsicParams`]. This may expose methods that aren't applicable to the current
/// chain; such values will simply be ignored if so.
pub struct PhalaExtrinsicParamsBuilder<T: Config> {
    /// `None` means the tx will be immortal.
    mortality: Option<Mortality<T::Hash>>,
    /// `None` means the nonce will be automatically set.
    nonce: Option<u64>,
    tip: u128,
}

struct Mortality<Hash> {
    /// Block hash that mortality starts from
    checkpoint_hash: Hash,
    /// Block number that mortality starts from (must
    // point to the same block as the hash above)
    checkpoint_number: u64,
    /// How many blocks the tx is mortal for
    period: u64,
}

impl<T: Config> Default for PhalaExtrinsicParamsBuilder<T> {
    fn default() -> Self {
        Self {
            mortality: None,
            tip: 0,
            nonce: None,
        }
    }
}

impl<T: Config> PhalaExtrinsicParamsBuilder<T> {
    /// Configure new extrinsic params. We default to providing no tip
    /// and using an immortal transaction unless otherwise configured
    pub fn new() -> Self {
        Default::default()
    }

    /// Make the transaction mortal, given a block header that it should be mortal from,
    /// and the number of blocks (roughly; it'll be rounded to a power of two) that it will
    /// be mortal for.
    pub fn mortal(mut self, from_block: &T::Header, for_n_blocks: u64) -> Self {
        self.mortality = Some(Mortality {
            checkpoint_hash: from_block.hash(),
            checkpoint_number: from_block.number().into(),
            period: for_n_blocks,
        });
        self
    }

    /// Provide a specific nonce for the submitter of the extrinsic
    pub fn nonce(mut self, nonce: u64) -> Self {
        self.nonce = Some(nonce);
        self
    }

    /// Make the transaction mortal, given a block number and block hash (which must both point to
    /// the same block) that it should be mortal from, and the number of blocks (roughly; it'll be
    /// rounded to a power of two) that it will be mortal for.
    ///
    /// Prefer to use [`DefaultExtrinsicParamsBuilder::mortal()`], which ensures that the block hash
    /// and number align.
    pub fn mortal_unchecked(
        mut self,
        from_block_number: u64,
        from_block_hash: T::Hash,
        for_n_blocks: u64,
    ) -> Self {
        self.mortality = Some(Mortality {
            checkpoint_hash: from_block_hash,
            checkpoint_number: from_block_number,
            period: for_n_blocks,
        });
        self
    }

    /// Provide a tip to the block author in the chain's native token.
    pub fn tip(mut self, tip: u128) -> Self {
        self.tip = tip;
        self
    }

    /// Build the extrinsic parameters.
    pub fn build(self) -> <PhalaExtrinsicParams<T> as ExtrinsicParams<T>>::Params {
        let check_mortality_params = if let Some(mortality) = self.mortality {
            signed_extensions::CheckMortalityParams::mortal(
                mortality.period,
                mortality.checkpoint_number,
                mortality.checkpoint_hash,
            )
        } else {
            signed_extensions::CheckMortalityParams::immortal()
        };
        let check_nonce_params = CheckNonceParams(self.nonce);
        let charge_transaction_params =
            signed_extensions::ChargeTransactionPaymentParams::tip(self.tip);
        (
            (),
            (),
            (),
            check_mortality_params,
            check_nonce_params,
            charge_transaction_params,
        )
    }
}
