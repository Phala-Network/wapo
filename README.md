## Wapo: A WebAssembly Runtime with Networking Support

**Wapo** is a poll-based async WebAssembly runtime that provides extended networking support for guest WASM applications. It is originally a module called SideVM in Phala pruntime, now independent, and the execution engine has been switched from `wasmer` to `wasmtime`.

### Why Wapo?

WASI, the standard WebAssembly system interface, does not yet fully support networking operations, and its ecosystem development is still slow. Wapo addresses this issue by providing a set of extended host APIs that support asynchronous network requests from guest WASM applications.

### Features

* **Extended networking support:** Wapo provides a Rust SDK that allows guest WASM applications to make asynchronous network requests. It supports native hyper to send network requests.

  Wapo has successfully run the QuickJS WASM version and supported asynchronous network APIs such as fetch in QuickJS.

* **Efficient runtime:** Wapo is a poll-based WASM runtime on the host side, which builds an asynchronous framework on top of the synchronous calls of wasmer or wasmtime. This is a different path from the async calls natively supported by wasmtime.

### Getting Started

TODO

### License

Wapo is licensed under the Apache License 2.0.