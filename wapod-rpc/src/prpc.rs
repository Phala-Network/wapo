pub use ::prpc::*;
pub use generated::*;
mod generated;

use wapod_types::ticket::AppManifest;

impl From<Manifest> for AppManifest {
    fn from(other: Manifest) -> Self {
        AppManifest {
            version: other.version,
            code_hash: other.code_hash,
            args: other.args,
            env_vars: other
                .env_vars
                .into_iter()
                .map(|pair| (pair.key, pair.value))
                .collect(),
            on_demand: other.on_demand,
            resizable: other.resizable,
            max_query_size: other.max_query_size,
            label: other.label,
        }
    }
}

impl From<AppManifest> for Manifest {
    fn from(other: AppManifest) -> Self {
        Manifest {
            version: other.version,
            code_hash: other.code_hash,
            args: other.args,
            env_vars: other
                .env_vars
                .into_iter()
                .map(|(key, value)| StringPair { key, value })
                .collect(),
            on_demand: other.on_demand,
            resizable: other.resizable,
            max_query_size: other.max_query_size,
            label: other.label,
        }
    }
}
