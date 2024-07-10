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
            env_vars: other.env_vars.into_iter().map(Into::into).collect(),
            on_demand: other.on_demand,
            resizable: other.resizable,
            max_query_size: other.max_query_size,
            label: other.label,
            required_blobs: other.required_blobs.into_iter().map(Into::into).collect(),
        }
    }
}

impl From<AppManifest> for Manifest {
    fn from(other: AppManifest) -> Self {
        Manifest {
            version: other.version,
            code_hash: other.code_hash,
            args: other.args,
            env_vars: other.env_vars.into_iter().map(Into::into).collect(),
            on_demand: other.on_demand,
            resizable: other.resizable,
            max_query_size: other.max_query_size,
            label: other.label,
            required_blobs: other.required_blobs.into_iter().map(Into::into).collect(),
        }
    }
}

impl From<(String, String)> for StringPair {
    fn from(other: (String, String)) -> Self {
        Self {
            key: other.0,
            value: other.1,
        }
    }
}

impl From<StringPair> for (String, String) {
    fn from(other: StringPair) -> Self {
        (other.key, other.value)
    }
}
