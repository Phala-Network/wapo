## Wapo: A WebAssembly Runtime with Networking Support

**Wapo** is a **poll-based** async WebAssembly runtime that provides extended networking support for guest WASM applications. It originated as a module called SideVM in Phala PRuntime, now independent, and the execution engine has been switched from `wasmer` to `wasmtime`.

### Why Wapo?

Wapo is mainly designed as the next version of the Phat Contract execution engine. However, it can be used as a general-purpose WebAssembly runtime with networking support. The Phat Contract execution engine today is based on Substrate's pallet-contracts, which is not flexible enough and also has many limitations. Here is the table of comparison between 2.3 and 3.0:

|  | Phat Contract 2.0 | Phat Contract 3.0 |
| --- | --- | --- |
| **Program type** | WebAssembly | WebAssembly |
| **VM Engine** | wasmi | wasmtime (faster) |
| **Incoming Networking** | Query RPC | Query RPC or Listening on TCP port |
| **Outgoing Networking** | HTTP requests (with time and size limit) | Arbitrary TCP connections |
| **Execution mode** | Transaction/query-based, 10s limit | Long-running or query-based, no tx |
| **App Memory** | 4MB for ink / 16 MB for JS | Up to 4GB due to wasm32 limit |

### Getting Started

```bash
git clone https://github.com/Phala-Network/wapo.git --recursive
cd wapo/wapod
cargo run --release -- -m 1g
```

The above instructions will build and run the wapod, where `-m 1g` means the memory size of the WASM instance is 1GB.
By default, the wapod will listen on `http://127.0.0.1:8001/` for admin RPC requests. You can open this URL in your browser to see a simple debug console, deploy the [examples](/examples/).

[WapoJS](https://github.com/Phala-Network/phat-quickjs/tree/master/WapoJS) is another example which ports QuickJS to Wapo.

### Build and Run in SGX

To run wapod in SGX, you need to install the Gramine SDK. See [Gramine](https://gramine.readthedocs.io/en/latest/installation.html) for more information.

Then you can build and run wapod in SGX as follows:

```bash
git clone https://github.com/Phala-Network/wapo.git --recursive
cd wapo/wapod/gramine-build
make dist
cd ../bin/
./gramine-sgx wapod
```

### License

Wapo is licensed under the Apache License 2.0.