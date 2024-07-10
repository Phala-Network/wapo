use scale::{Decode, Encode};

use crate::phala::runtime_types as rt;
use paste::paste;

pub trait RecodeTo<To>: Encode
where
    To: Decode,
{
    fn recode_to(&self) -> Result<To, scale::Error> {
        let encoded = self.encode();
        To::decode(&mut &encoded[..])
    }
}

macro_rules! impl_recode_for {
    ($t: path) => {
        paste! {
            impl RecodeTo<rt::$t> for $t {}
        }
    };
}

impl_recode_for!(wapod_types::ticket::Prices);
impl_recode_for!(wapod_types::ticket::WorkerDescription);
impl_recode_for!(wapod_types::ticket::SignedWorkerDescription);
impl_recode_for!(wapod_types::metrics::SignedAppsMetrics);
