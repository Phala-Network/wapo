mod async_context;
mod wapo_ctx;
mod resource;
#[cfg(feature = "rocket-stream")]
pub mod rocket_stream;
mod run;
pub mod service;
mod tls;

pub use wapo_ctx::{vm_count, OutgoingRequest, OutgoingRequestChannel, ShortId};

pub type VmId = [u8; 32];
pub use run::{WasmEngine, WasmInstanceConfig, WasmModule, WasmRun};
pub use wasmtime;

pub use service::IncomingHttpRequest;
pub use wapo_env::OcallError;
