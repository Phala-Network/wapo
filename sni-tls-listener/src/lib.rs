pub use listener::{wrap_certified_key, SniTlsListener};

pub type Agent = agent::Agent<agent::DefaultConfig>;
pub type Subscription = agent::Subscription<agent::DefaultConfig>;

pub use traits::{Generate, Subscribe};

mod agent;
mod listener;
mod traits;
