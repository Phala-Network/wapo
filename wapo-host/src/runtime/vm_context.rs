use std::{
    borrow::Cow,
    collections::VecDeque,
    fmt, io,
    net::SocketAddr,
    ops::RangeInclusive,
    path::PathBuf,
    sync::{Arc, Mutex},
    task::Poll::{Pending, Ready},
    time::{Duration, Instant},
};

use anyhow::Context;
use sni_tls_listener::{verify_certifacate, wrap_certified_key, SniTlsListener};
use tokio::{
    net::{TcpListener, TcpStream},
    sync::oneshot::Sender as OneshotSender,
    sync::{mpsc::Sender, oneshot},
};
use tracing::{debug, info, warn, Instrument, Span};

use env::{
    messages::{AccountId, HttpRequest, HttpResponseHead, QueryRequest},
    tls::{TlsClientConfig, TlsServerConfig},
    IntPtr, IntRet, OcallError, Result, RetEncode,
};
use scale::{Decode, Encode};
use wapo_env as env;

use wasmtime::Caller;

use super::{
    async_context::{get_task_cx, poll_in_task_cx, set_task_env, GuestWaker},
    metrics::Meter,
    resource::{PollContext, Resource, ResourceTable, TcpListenerResource},
    tls::{load_tls_config, TlsStream},
};
use crate::{blobs::BlobLoader, IncomingHttpRequest, Metrics, VmId};

#[derive(Clone, Copy)]
pub struct ShortId<T>(pub T);

impl<T: AsRef<[u8]>> fmt::Display for ShortId<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let len = self.0.as_ref().len();
        let slice = hex_fmt::HexFmt(&self.0.as_ref()[..len.min(6)]);
        write!(f, "{}..", slice)
    }
}

// Let the compiler check IntPtr is 32bit sized.
fn _sizeof_i32_must_eq_to_intptr() {
    let _ = core::mem::transmute::<i32, IntPtr>;
}

pub(crate) struct TaskSet {
    awake_tasks: dashmap::DashSet<i32>,
    /// Guest waker ids that are ready to be woken up, or to be dropped if negative.
    pub(crate) awake_wakers: Mutex<VecDeque<i32>>,
}

impl TaskSet {
    fn with_task0() -> Self {
        let awake_tasks = dashmap::DashSet::new();
        awake_tasks.insert(0);
        Self {
            awake_tasks,
            awake_wakers: Default::default(),
        }
    }

    pub(crate) fn push_task(&self, task_id: i32) {
        self.awake_tasks.insert(task_id);
    }

    pub(crate) fn pop_task(&self) -> Option<i32> {
        let item = self.awake_tasks.iter().next().map(|task_id| *task_id);
        match item {
            Some(task_id) => {
                self.awake_tasks.remove(&task_id);
                Some(task_id)
            }
            None => None,
        }
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.awake_tasks.is_empty() && self.awake_wakers.lock().unwrap().is_empty()
    }
}

pub trait RuntimeCalls: Send + 'static {
    fn log(&self, level: log::Level, message: &str) {
        log::log!(target: "wapo::guest", level, "{message}");
    }
    fn worker_pubkey(&self) -> Vec<u8>;
    fn sign_app_data(&self, data: &[u8]) -> Vec<u8>;
    fn sgx_quote_app_data(&self, data: &[u8]) -> Option<Vec<u8>>;
    fn emit_output(&self, _output: &[u8]);
    fn tcp_connect_allowed(&self, _host: &str) -> bool {
        true
    }
    fn app_metrics(&self) -> Metrics;
}

impl RuntimeCalls for () {
    fn worker_pubkey(&self) -> Vec<u8> {
        vec![]
    }

    fn sign_app_data(&self, _data: &[u8]) -> Vec<u8> {
        vec![]
    }

    fn sgx_quote_app_data(&self, _data: &[u8]) -> Option<Vec<u8>> {
        None
    }

    fn emit_output(&self, _output: &[u8]) {}

    fn app_metrics(&self) -> Metrics {
        Metrics::default()
    }
}

#[derive(typed_builder::TypedBuilder, Debug)]
pub struct WapoVmConfig {
    pub tcp_listen_port_range: RangeInclusive<u16>,
    pub sni_tls_listener: Option<SniTlsListener>,
    pub verify_tls_server_cert: bool,
}

pub(crate) struct WapoCtx {
    id: VmId,
    resources: ResourceTable,
    temp_return_value: Option<Vec<u8>>,
    ocall_trace_enabled: bool,
    query_tx: Option<Sender<Vec<u8>>>,
    http_connect_tx: Option<Sender<Vec<u8>>>,
    awake_tasks: Arc<TaskSet>,
    weight: u32,
    runtime_calls: Box<dyn RuntimeCalls>,
    _counter: vm_counter::Counter,
    meter: Arc<Meter>,
    blob_loader: BlobLoader,
    config: WapoVmConfig,
}

impl WapoCtx {
    pub(crate) fn new<OCalls>(
        id: VmId,
        runtime_calls: OCalls,
        blobs_dir: PathBuf,
        meter: Option<Arc<Meter>>,
        config: WapoVmConfig,
    ) -> Self
    where
        OCalls: RuntimeCalls,
    {
        Self {
            id,
            resources: Default::default(),
            temp_return_value: Default::default(),
            ocall_trace_enabled: false,
            query_tx: None,
            http_connect_tx: None,
            awake_tasks: Arc::new(TaskSet::with_task0()),
            weight: 1,
            runtime_calls: Box::new(runtime_calls),
            _counter: Default::default(),
            meter: meter.unwrap_or_default(),
            blob_loader: BlobLoader::new(blobs_dir),
            config,
        }
    }

    pub(crate) fn close(&mut self, resource_id: i32) -> Result<()> {
        match self.resources.take(resource_id) {
            None => Err(OcallError::NotFound),
            Some(_res) => Ok(()),
        }
    }

    pub fn has_more_ready_tasks(&self) -> bool {
        !self.awake_tasks.is_empty()
    }

    pub fn weight(&self) -> u32 {
        self.weight
    }

    fn make_poll_context(&self, waker_id: i32) -> PollContext {
        PollContext {
            waker: GuestWaker::from_id(waker_id),
            meter: self.meter.clone(),
        }
    }

    pub fn meter(&self) -> Arc<Meter> {
        self.meter.clone()
    }
}

impl env::OcallEnv for WapoCtx {
    fn put_return(&mut self, rv: Vec<u8>) -> usize {
        let len = rv.len();
        self.temp_return_value = Some(rv);
        len
    }

    fn take_return(&mut self) -> Option<Vec<u8>> {
        self.temp_return_value.take()
    }
}

impl env::OcallFuncs for WapoCtx {
    fn close(&mut self, resource_id: i32) -> Result<()> {
        self.meter.record_gas(200);
        self.close(resource_id)
    }

    fn poll(&mut self, waker_id: i32, resource_id: i32) -> Result<Vec<u8>> {
        self.meter.record_gas(200);
        let ctx = self.make_poll_context(waker_id);
        self.resources.get_mut(resource_id)?.poll(ctx)
    }

    fn poll_read(&mut self, waker_id: i32, resource_id: i32, data: &mut [u8]) -> Result<u32> {
        self.meter.record_gas(200);
        let ctx = self.make_poll_context(waker_id);
        self.resources.get_mut(resource_id)?.poll_read(ctx, data)
    }

    fn poll_write(&mut self, waker_id: i32, resource_id: i32, data: &[u8]) -> Result<u32> {
        self.meter.record_gas(200);
        let ctx = self.make_poll_context(waker_id);
        self.resources.get_mut(resource_id)?.poll_write(ctx, data)
    }

    fn poll_shutdown(&mut self, waker_id: i32, resource_id: i32) -> Result<()> {
        self.meter.record_gas(200);
        let ctx = self.make_poll_context(waker_id);
        self.resources.get_mut(resource_id)?.poll_shutdown(ctx)
    }

    fn poll_res(&mut self, waker_id: i32, resource_id: i32) -> Result<i32> {
        self.meter.record_gas(200);
        let ctx = self.make_poll_context(waker_id);
        let res = self.resources.get_mut(resource_id)?.poll_res(ctx)?;
        self.resources.push(res)
    }

    fn mark_task_ready(&mut self, task_id: i32) -> Result<()> {
        self.meter.record_gas(200);
        self.awake_tasks.push_task(task_id);
        Ok(())
    }

    fn next_ready_task(&mut self) -> Result<i32> {
        self.meter.record_gas(200);
        self.awake_tasks.pop_task().ok_or(OcallError::NotFound)
    }

    fn create_timer(&mut self, timeout: i32) -> Result<i32> {
        self.meter.record_gas(500);
        let sleep = tokio::time::sleep(Duration::from_millis(timeout as u64));
        self.resources.push(Resource::Sleep(Box::pin(sleep)))
    }

    fn reset_timer(&mut self, id: i32, timeout: i32) -> Result<()> {
        self.meter.record_gas(300);
        let res = self.resources.get_mut(id)?;
        let Resource::Sleep(sleep) = res else {
            return Err(OcallError::InvalidParameter);
        };
        let deadline = Instant::now()
            .checked_add(Duration::from_millis(timeout as u64))
            .ok_or(OcallError::InvalidParameter)?;
        sleep.as_mut().reset(deadline.into());
        Ok(())
    }

    fn enable_ocall_trace(&mut self, enable: bool) -> Result<()> {
        self.meter.record_gas(100);
        self.ocall_trace_enabled = enable;
        Ok(())
    }

    fn tcp_listen(&mut self, addr: Cow<str>, tls_config: Option<TlsServerConfig>) -> Result<i32> {
        self.meter.record_gas(1000);
        let address: SocketAddr = addr.parse().or(Err(OcallError::InvalidParameter))?;
        if !self.config.tcp_listen_port_range.contains(&address.port()) {
            return Err(OcallError::Forbiden);
        }
        let std_listener = std::net::TcpListener::bind(&*addr).or(Err(OcallError::IoError))?;
        std_listener
            .set_nonblocking(true)
            .or(Err(OcallError::IoError))?;
        let listener = TcpListener::from_std(std_listener).or(Err(OcallError::IoError))?;
        let tls_config = tls_config.map(load_tls_config).transpose()?.map(Arc::new);
        self.resources
            .push(Resource::TcpListener(Box::new(TcpListenerResource {
                listener,
                tls_config,
            })))
    }

    fn tcp_accept(&mut self, waker_id: i32, tcp_res_id: i32) -> Result<(i32, String)> {
        self.meter.record_gas(1000);
        let ctx = self.make_poll_context(waker_id);
        let waker = ctx.waker;
        let (res, remote_addr) = {
            let res = self.resources.get_mut(tcp_res_id)?;
            match res {
                Resource::TcpListener(res) => {
                    let (stream, addr) = match get_task_cx(waker, |ct| res.listener.poll_accept(ct))
                    {
                        Pending => return Err(OcallError::Pending),
                        Ready(result) => result.or(Err(OcallError::IoError))?,
                    };
                    // A typical tcp connect consumes hundreds of bytes.
                    ctx.meter.record_net_ingress(128);
                    let res = match &res.tls_config {
                        Some(tls_config) => {
                            ctx.meter.record_net_ingress(1024);
                            ctx.meter.record_net_egress(1024);
                            Resource::TlsStream(Box::new(TlsStream::accept(
                                stream,
                                tls_config.clone(),
                            )))
                        }
                        None => Resource::TcpStream(Box::new(stream)),
                    };
                    (res, addr)
                }
                Resource::SniSubscription(res) => {
                    let fut = res.next();
                    futures::pin_mut!(fut);
                    let (stream, addr) = match poll_in_task_cx(waker, fut) {
                        Ready(Some(data)) => data,
                        Ready(None) => return Err(OcallError::EndOfFile),
                        Pending => return Err(OcallError::Pending),
                    };
                    ctx.meter.record_net_ingress(1024);
                    ctx.meter.record_net_egress(1024);
                    let res = Resource::TlsStream(Box::new(TlsStream::ServerStreaming(stream)));
                    (res, addr)
                }
                _ => return Err(OcallError::UnsupportedOperation),
            }
        };
        self.resources
            .push(res)
            .map(|res_id| (res_id, remote_addr.to_string()))
    }

    fn tcp_accept_no_addr(&mut self, waker_id: i32, resource_id: i32) -> Result<i32> {
        self.tcp_accept(waker_id, resource_id)
            .map(|(res_id, _)| res_id)
    }

    fn tcp_connect(&mut self, host: &str, port: u16) -> Result<i32> {
        self.meter.record_gas(1000);
        if host.len() > 253 {
            return Err(OcallError::InvalidParameter);
        }
        if !self.runtime_calls.tcp_connect_allowed(host) {
            return Err(OcallError::Forbiden);
        }
        let host = host.to_owned();
        let fut = async move { tcp_connect(&host, port).await };
        self.meter.record_tcp_connect_start();
        self.resources.push(Resource::TcpConnect(Box::pin(fut)))
    }

    fn tcp_connect_tls(&mut self, host: String, port: u16, config: TlsClientConfig) -> Result<i32> {
        self.meter.record_gas(1000);
        if host.len() > 253 {
            return Err(OcallError::InvalidParameter);
        }
        if !self.runtime_calls.tcp_connect_allowed(&host) {
            return Err(OcallError::Forbiden);
        }
        let domain = host
            .clone()
            .try_into()
            .or(Err(OcallError::InvalidParameter))?;
        let TlsClientConfig::V0 = config;
        let fut = async move {
            tcp_connect(&host, port)
                .await
                .map(move |stream| TlsStream::connect(domain, stream))
        };
        self.meter.record_tls_connect_start();
        self.resources.push(Resource::TlsConnect(Box::pin(fut)))
    }

    fn tls_listen_sni(&mut self, sni: Cow<str>, config: TlsServerConfig) -> Result<i32> {
        self.meter.record_gas(1000);
        let (cert, key) = match config {
            TlsServerConfig::V0 { cert, key } => (cert, key),
        };
        let listener = self
            .config
            .sni_tls_listener
            .as_ref()
            .ok_or(OcallError::Forbiden)?;
        let listener = listener.clone();
        let subscription = {
            let certified_key =
                wrap_certified_key(cert.as_bytes(), key.as_bytes()).map_err(|e| {
                    warn!(target: "wapo::tls", "failed to wrap certified key: {e}");
                    OcallError::InvalidParameter
                })?;
            if self.config.verify_tls_server_cert {
                verify_certifacate(&certified_key, &sni).map_err(|e| {
                    warn!(target: "wapo::tls", "failed to verify certificate: {e}");
                    OcallError::InvalidParameter
                })?;
            }
            listener
                .subscribe(sni.as_ref(), certified_key)
                .map_err(|e| {
                    warn!(target: "wapo::tls", "failed to subscribe TLS connection: {e}");
                    OcallError::InvalidParameter
                })?
        };
        self.meter.record_gas(10000);
        self.resources
            .push(Resource::SniSubscription(Box::new(subscription)))
    }

    fn log(&mut self, level: log::Level, message: &str) -> Result<()> {
        self.meter.record_gas(message.as_bytes().len() as u64);
        self.runtime_calls.log(level, message);
        Ok(())
    }

    fn awake_wakers(&mut self) -> Result<Vec<i32>> {
        self.meter.record_gas(500);
        Ok(self
            .awake_tasks
            .awake_wakers
            .lock()
            .unwrap()
            .drain(..)
            .collect())
    }

    fn getrandom(&mut self, buf: &mut [u8]) -> Result<()> {
        self.meter.record_gas(buf.len() as u64 * 10);
        use rand::RngCore;
        rand::thread_rng().fill_bytes(buf);
        Ok(())
    }

    fn oneshot_send(&mut self, resource_id: i32, data: &[u8]) -> Result<()> {
        self.meter.record_gas(1000 + data.len() as u64 / 128);
        let res = self.resources.get_mut(resource_id)?;
        match res {
            Resource::OneshotTx(sender) => match sender.take() {
                Some(sender) => sender.send(data.to_vec()).or(Err(OcallError::IoError))?,
                None => return Err(OcallError::IoError),
            },
            _ => return Err(OcallError::UnsupportedOperation),
        }
        Ok(())
    }

    fn create_input_channel(&mut self, ch: env::InputChannel) -> Result<i32> {
        self.meter.record_gas(1000);
        use env::InputChannel::*;
        macro_rules! create_channel {
            ($field: expr) => {{
                if $field.is_some() {
                    return Err(OcallError::AlreadyExists);
                }
                let (tx, rx) = tokio::sync::mpsc::channel(20);
                let res = self.resources.push(Resource::ChannelRx(rx))?;
                $field = Some(tx);
                Ok(res)
            }};
        }
        match ch {
            Query => create_channel!(self.query_tx),
            HttpRequest => create_channel!(self.http_connect_tx),
        }
    }

    /// Returns the vmid of the current instance.
    fn vmid(&mut self) -> Result<[u8; 32]> {
        self.meter.record_gas(100);
        Ok(self.id)
    }

    fn emit_program_output(&mut self, output: &[u8]) -> Result<()> {
        self.meter.record_gas(output.len() as u64 / 128);
        self.runtime_calls.emit_output(output);
        Ok(())
    }

    fn blob_get(&mut self, hash: &[u8], hash_algorithm: &str) -> Result<Vec<u8>> {
        self.meter.record_gas(100);
        let obj = self
            .blob_loader
            .get(hash, hash_algorithm)
            .or(Err(OcallError::IoError))?
            .ok_or(OcallError::NotFound)?;
        self.meter.record_gas(obj.len() as u64 / 128);
        Ok(obj)
    }

    fn sign(&mut self, data: &[u8]) -> Result<Vec<u8>> {
        if data.len() > 64 {
            self.meter.record_gas(100);
            return Err(OcallError::InvalidParameter);
        }
        self.meter.record_gas(1000);
        Ok(self.runtime_calls.sign_app_data(data))
    }

    fn worker_pubkey(&mut self) -> Result<Vec<u8>> {
        self.meter.record_gas(100);
        Ok(self.runtime_calls.worker_pubkey())
    }

    fn sgx_quote(&mut self, data: &[u8]) -> Result<Option<Vec<u8>>> {
        if data.len() > 64 {
            self.meter.record_gas(100);
            return Err(OcallError::InvalidParameter);
        }
        self.meter.record_gas(1000);
        Ok(self.runtime_calls.sgx_quote_app_data(data))
    }

    fn tip(&mut self, value: u64) -> Result<()> {
        self.meter.record_gas(100);
        self.meter.add_tip(value);
        Ok(())
    }

    fn app_gas_consumed(&mut self) -> Result<u64> {
        self.meter.record_gas(1000);
        Ok(self.runtime_calls.app_metrics().gas_consumed)
    }
}

fn is_ip(host: &str) -> bool {
    host.parse::<std::net::IpAddr>().is_ok()
}

async fn tcp_connect(host: &str, port: u16) -> io::Result<TcpStream> {
    fn get_proxy(key: &str) -> Option<String> {
        std::env::var(key).ok().and_then(|uri| {
            if uri.trim().is_empty() {
                None
            } else {
                Some(uri)
            }
        })
    }

    let proxy_url = if host.ends_with(".i2p") {
        get_proxy("i2p_proxy")
    } else {
        None
    };

    if let Some(proxy_url) = proxy_url.or_else(|| get_proxy("all_proxy")) {
        phala_tokio_proxy::connect((host, port), proxy_url).await
    } else if is_ip(host) {
        TcpStream::connect((host, port)).await
    } else {
        // By default, tokio uses the blocking DNS resovler from libc and run them in a thread pool.
        // That would cause problem such as run out of thread-pool in some poor network situation.
        // So, we use trust-dns async resolver here.
        let resolver = hickory_resolver::TokioAsyncResolver::tokio_from_system_conf()
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
        let ips = resolver
            .lookup_ip(host)
            .await
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
        let mut last_err = None;
        for ip in ips {
            match TcpStream::connect((ip, port)).await {
                Ok(stream) => return Ok(stream),
                Err(e) => last_err = Some(e),
            }
        }
        match last_err {
            Some(e) => Err(e),
            None => Err(io::Error::new(
                io::ErrorKind::Other,
                "DNS: No address found",
            )),
        }
    }
}

pub fn add_ocalls_to_linker<State>(
    linker: &mut wasmtime::Linker<State>,
    get_cx: impl Fn(&mut State) -> &mut WapoCtx + Send + Sync + Copy + 'static,
) -> anyhow::Result<()> {
    add_wapo_ocalls_to_linker(linker, get_cx)?;
    // To be compatible with the old version, we also add the sidevm ocalls.
    add_sidevm_ocalls_to_linker(linker, get_cx)
}

fn add_wapo_ocalls_to_linker<State>(
    linker: &mut wasmtime::Linker<State>,
    get_cx: impl Fn(&mut State) -> &mut WapoCtx + Send + Sync + Copy + 'static,
) -> anyhow::Result<()> {
    linker
        .func_wrap(
            "wapo",
            "ocall_fast_return",
            move |caller: Caller<'_, State>,
                  task_id: i32,
                  func_id: i32,
                  p0: IntPtr,
                  p1: IntPtr,
                  p2: IntPtr,
                  p3: IntPtr|
                  -> anyhow::Result<IntRet> {
                do_ocall(caller, task_id, func_id, p0, p1, p2, p3, true, get_cx).map_err(Into::into)
            },
        )
        .context("failed to add wapo.ocall_fast_return to linker")?;
    linker
        .func_wrap(
            "wapo",
            "ocall",
            move |caller: Caller<'_, State>,
                  task_id: i32,
                  func_id: i32,
                  p0: IntPtr,
                  p1: IntPtr,
                  p2: IntPtr,
                  p3: IntPtr|
                  -> anyhow::Result<IntRet> {
                do_ocall(caller, task_id, func_id, p0, p1, p2, p3, false, get_cx)
                    .map_err(Into::into)
            },
        )
        .context("failed to add wapo.ocall to linker")?;
    Ok(())
}

fn add_sidevm_ocalls_to_linker<State>(
    linker: &mut wasmtime::Linker<State>,
    get_cx: impl Fn(&mut State) -> &mut WapoCtx + Send + Sync + Copy + 'static,
) -> anyhow::Result<()> {
    linker
        .func_wrap(
            "env",
            "sidevm_ocall_fast_return",
            move |caller: Caller<'_, State>,
                  task_id: i32,
                  func_id: i32,
                  p0: IntPtr,
                  p1: IntPtr,
                  p2: IntPtr,
                  p3: IntPtr|
                  -> anyhow::Result<IntRet> {
                do_ocall(caller, task_id, func_id, p0, p1, p2, p3, true, get_cx).map_err(Into::into)
            },
        )
        .context("failed to add env.sidevm_ocall_fast_return to linker")?;
    linker
        .func_wrap(
            "env",
            "sidevm_ocall",
            move |caller: Caller<'_, State>,
                  task_id: i32,
                  func_id: i32,
                  p0: IntPtr,
                  p1: IntPtr,
                  p2: IntPtr,
                  p3: IntPtr|
                  -> anyhow::Result<IntRet> {
                do_ocall(caller, task_id, func_id, p0, p1, p2, p3, false, get_cx)
                    .map_err(Into::into)
            },
        )
        .context("failed to add env.sidevm_ocall to linker")?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
#[tracing::instrument(name="ocall", fields(tid=task_id), skip_all)]
fn do_ocall<State>(
    mut caller: Caller<State>,
    task_id: i32,
    func_id: i32,
    p0: IntPtr,
    p1: IntPtr,
    p2: IntPtr,
    p3: IntPtr,
    fast_return: bool,
    get_cx: impl Fn(&mut State) -> &mut WapoCtx + Send + Sync + Copy + 'static,
) -> Result<IntRet, OcallError> {
    let export = caller.get_export("memory");
    let (mem, state) = match &export {
        Some(wasmtime::Extern::Memory(m)) => {
            let (mem, ctx) = m.data_and_store_mut(&mut caller);
            let ctx = get_cx(ctx);
            (wiggle::wasmtime::WasmtimeGuestMemory::new(mem), ctx)
        }
        Some(wiggle::wasmtime_crate::Extern::SharedMemory(m)) => {
            let ctx = get_cx(caller.data_mut());
            (wiggle::wasmtime::WasmtimeGuestMemory::shared(m.data()), ctx)
        }
        _ => return Err(OcallError::NoMemory),
    };

    let result = set_task_env(state.awake_tasks.clone(), task_id, || {
        env::dispatch_ocall(fast_return, state, &mem, func_id, p0, p1, p2, p3)
    });

    if state.ocall_trace_enabled {
        let func_name = env::ocall_id2name(func_id);
        tracing::trace!(target: "wapo", "{func_name}({p0}, {p1}, {p2}, {p3}) = {result:?}");
    }
    Ok(result.encode_ret())
}

pub use vm_counter::vm_count;
mod vm_counter {
    use std::sync::atomic::{AtomicUsize, Ordering};

    pub fn vm_count() -> usize {
        Counter::current()
    }

    static COUNTER: AtomicUsize = AtomicUsize::new(0);
    pub struct Counter(());
    impl Counter {
        pub fn current() -> usize {
            COUNTER.load(Ordering::Relaxed)
        }
    }
    impl Default for Counter {
        fn default() -> Self {
            COUNTER.fetch_add(1, Ordering::Relaxed);
            Self(())
        }
    }
    impl Drop for Counter {
        fn drop(&mut self) {
            COUNTER.fetch_sub(1, Ordering::Relaxed);
        }
    }
}

impl WapoCtx {
    /// Push a contract query to the wapo guest.
    pub fn push_query(
        &mut self,
        origin: Option<AccountId>,
        path: String,
        payload: Vec<u8>,
        reply_tx: OneshotSender<Vec<u8>>,
    ) -> anyhow::Result<()> {
        let Some(tx) = self.query_tx.clone() else {
            debug!(target: "wapo", "query dropped: no query channel");
            return Ok(());
        };
        let reply_tx = self.resources.push(Resource::OneshotTx(Some(reply_tx)));
        let reply_tx = reply_tx?;
        let query = QueryRequest {
            path,
            origin,
            payload,
            reply_tx,
        };
        let result = tx.try_send(query.encode());
        if result.is_err() {
            let _ = self.close(reply_tx);
        }
        result?;
        Ok(())
    }

    /// Establish a incoming HTTP connection.
    pub fn push_http_request(&mut self, request: IncomingHttpRequest) -> anyhow::Result<()> {
        let IncomingHttpRequest {
            head,
            body_stream,
            response_tx,
        } = request;
        let Some(connect_tx) = self.http_connect_tx.clone() else {
            debug!(target: "wapo", "http request dropped: no http connect channel");
            return Ok(());
        };
        let (reply_tx, reply_rx) = oneshot::channel();
        let reply_tx = self.resources.push(Resource::OneshotTx(Some(reply_tx)));
        tokio::spawn(
            async move {
                let reply = reply_rx.await;
                let reply = reply
                    .context("failed to receive http response")
                    .and_then(|bytes| {
                        let response = HttpResponseHead::decode(&mut &bytes[..])?;
                        Ok(response)
                    });
                if response_tx.send(reply).is_err() {
                    info!(target: "wapo", "failed to send http response");
                }
            }
            .instrument(Span::current()),
        );
        let response_tx = reply_tx?;
        let body_stream = self.resources.push(Resource::DuplexStream(body_stream));
        let body_stream = match body_stream {
            Ok(stream) => stream,
            Err(e) => {
                let _ = self.close(response_tx);
                return Err(e.into());
            }
        };
        let query = HttpRequest {
            head,
            response_tx,
            io_stream: body_stream,
        };
        let result = connect_tx.try_send(query.encode());
        if result.is_err() {
            let _ = self.close(response_tx);
            let _ = self.close(body_stream);
        }
        Ok(result?)
    }

    /// Set scheduler weight.
    pub fn set_weight(&mut self, weight: u32) {
        self.weight = weight;
    }
}
