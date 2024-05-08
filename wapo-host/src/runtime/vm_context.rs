use std::{
    borrow::Cow,
    collections::VecDeque,
    fmt, io,
    path::PathBuf,
    sync::{Arc, Mutex},
    task::Poll::{Pending, Ready},
    time::{Duration, Instant},
};

use anyhow::Context;
use tokio::{
    net::{TcpListener, TcpStream},
    sync::oneshot::Sender as OneshotSender,
    sync::{
        mpsc::{Receiver, Sender},
        oneshot,
    },
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
    async_context::{get_task_cx, set_task_env, GuestWaker},
    metrics::Meter,
    resource::{PollContext, Resource, ResourceTable, TcpListenerResource},
    tls::{load_tls_config, TlsStream},
};
use crate::{blobs::BlobsLoader, IncomingHttpRequest, VmId};

#[derive(Clone, Copy)]
pub struct ShortId<T>(pub T);

impl<T: AsRef<[u8]>> fmt::Display for ShortId<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let len = self.0.as_ref().len();
        hex_fmt::HexFmt(&self.0.as_ref()[..len.min(6)]).fmt(f)
    }
}

// Let the compiler check IntPtr is 32bit sized.
fn _sizeof_i32_must_eq_to_intptr() {
    let _ = core::mem::transmute::<i32, IntPtr>;
}

pub fn create_env(
    id: VmId,
    out_tx: OutgoingRequestSender,
    log_handler: Option<LogHandler>,
    blobs_dir: PathBuf,
    meter: Option<Arc<Meter>>,
) -> WapoCtx {
    WapoCtx::new(id, out_tx, log_handler, blobs_dir, meter)
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

pub type LogHandler = Box<dyn Fn(VmId, u8, &str) + Send + Sync>;

pub type OutgoingRequestSender = Sender<(VmId, OutgoingRequest)>;
pub type OutgoingRequestReceiver = Receiver<(VmId, OutgoingRequest)>;
pub fn crate_outgoing_request_channel() -> (OutgoingRequestSender, OutgoingRequestReceiver) {
    tokio::sync::mpsc::channel(20)
}

pub enum OutgoingRequest {
    // Used by Js Engine to send js eval result
    Output(Vec<u8>),
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
    outgoing_request_tx: OutgoingRequestSender,
    log_handler: Option<LogHandler>,
    _counter: vm_counter::Counter,
    meter: Arc<Meter>,
    blobs_loader: BlobsLoader,
}

impl WapoCtx {
    fn new(
        id: VmId,
        outgoing_request_tx: OutgoingRequestSender,
        log_handler: Option<LogHandler>,
        blobs_dir: PathBuf,
        meter: Option<Arc<Meter>>,
    ) -> Self {
        Self {
            id,
            resources: Default::default(),
            temp_return_value: Default::default(),
            ocall_trace_enabled: false,
            query_tx: None,
            http_connect_tx: None,
            awake_tasks: Arc::new(TaskSet::with_task0()),
            weight: 1,
            outgoing_request_tx,
            log_handler,
            _counter: Default::default(),
            meter: meter.unwrap_or_default(),
            blobs_loader: BlobsLoader::new(blobs_dir),
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

impl<'a> env::OcallEnv for WapoCtx {
    fn put_return(&mut self, rv: Vec<u8>) -> usize {
        let len = rv.len();
        self.temp_return_value = Some(rv);
        len
    }

    fn take_return(&mut self) -> Option<Vec<u8>> {
        self.temp_return_value.take()
    }
}

impl<'a> env::OcallFuncs for WapoCtx {
    fn close(&mut self, resource_id: i32) -> Result<()> {
        self.close(resource_id)
    }

    fn poll(&mut self, waker_id: i32, resource_id: i32) -> Result<Vec<u8>> {
        let ctx = self.make_poll_context(waker_id);
        self.resources.get_mut(resource_id)?.poll(ctx)
    }

    fn poll_read(&mut self, waker_id: i32, resource_id: i32, data: &mut [u8]) -> Result<u32> {
        let ctx = self.make_poll_context(waker_id);
        self.resources.get_mut(resource_id)?.poll_read(ctx, data)
    }

    fn poll_write(&mut self, waker_id: i32, resource_id: i32, data: &[u8]) -> Result<u32> {
        let ctx = self.make_poll_context(waker_id);
        self.resources.get_mut(resource_id)?.poll_write(ctx, data)
    }

    fn poll_shutdown(&mut self, waker_id: i32, resource_id: i32) -> Result<()> {
        let ctx = self.make_poll_context(waker_id);
        self.resources.get_mut(resource_id)?.poll_shutdown(ctx)
    }

    fn poll_res(&mut self, waker_id: i32, resource_id: i32) -> Result<i32> {
        let ctx = self.make_poll_context(waker_id);
        let res = self.resources.get_mut(resource_id)?.poll_res(ctx)?;
        self.resources.push(res)
    }

    fn mark_task_ready(&mut self, task_id: i32) -> Result<()> {
        self.awake_tasks.push_task(task_id);
        Ok(())
    }

    fn next_ready_task(&mut self) -> Result<i32> {
        self.awake_tasks.pop_task().ok_or(OcallError::NotFound)
    }

    fn create_timer(&mut self, timeout: i32) -> Result<i32> {
        let sleep = tokio::time::sleep(Duration::from_millis(timeout as u64));
        self.resources.push(Resource::Sleep(Box::pin(sleep)))
    }

    fn reset_timer(&mut self, id: i32, timeout: i32) -> Result<()> {
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
        self.ocall_trace_enabled = enable;
        Ok(())
    }

    fn tcp_listen(&mut self, addr: Cow<str>, tls_config: Option<TlsServerConfig>) -> Result<i32> {
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
        let ctx = self.make_poll_context(waker_id);
        let waker = ctx.waker;
        let (res, remote_addr) = {
            let res = self.resources.get_mut(tcp_res_id)?;
            let res = match res {
                Resource::TcpListener(res) => res,
                _ => return Err(OcallError::UnsupportedOperation),
            };
            let (stream, addr) = match get_task_cx(waker, |ct| res.listener.poll_accept(ct)) {
                Pending => return Err(OcallError::Pending),
                Ready(result) => result.or(Err(OcallError::IoError))?,
            };
            // A typical tcp connect consumes hundreds of bytes.
            ctx.meter.record_net_ingress(128);
            let res = match &res.tls_config {
                Some(tls_config) => {
                    Resource::TlsStream(Box::new(TlsStream::accept(stream, tls_config.clone())))
                }
                None => Resource::TcpStream(Box::new(stream)),
            };
            (res, addr)
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
        if host.len() > 253 {
            return Err(OcallError::InvalidParameter);
        }
        let host = host.to_owned();
        let fut = async move { tcp_connect(&host, port).await };
        self.meter.record_tcp_connect_start();
        self.resources.push(Resource::TcpConnect(Box::pin(fut)))
    }

    fn tcp_connect_tls(&mut self, host: String, port: u16, config: TlsClientConfig) -> Result<i32> {
        if host.len() > 253 {
            return Err(OcallError::InvalidParameter);
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

    fn log(&mut self, level: log::Level, message: &str) -> Result<()> {
        log::log!(target: "wapo", level, "{message}");
        if let Some(log_handler) = &self.log_handler {
            log_handler(self.id, level as u8, message);
        }
        Ok(())
    }

    fn awake_wakers(&mut self) -> Result<Vec<i32>> {
        Ok(self
            .awake_tasks
            .awake_wakers
            .lock()
            .unwrap()
            .drain(..)
            .collect())
    }

    fn getrandom(&mut self, buf: &mut [u8]) -> Result<()> {
        use rand::RngCore;
        rand::thread_rng().fill_bytes(buf);
        Ok(())
    }

    fn oneshot_send(&mut self, resource_id: i32, data: &[u8]) -> Result<()> {
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
        Ok(self.id)
    }

    fn emit_program_output(&mut self, output: &[u8]) -> Result<()> {
        let from = self.id;
        let request = OutgoingRequest::Output(output.to_vec());
        self.outgoing_request_tx
            .try_send((from, request))
            .or(Err(OcallError::IoError))
    }

    fn object_get(&mut self, hash: &[u8], hash_algrithm: &str) -> Result<Vec<u8>> {
        let obj = self
            .blobs_loader
            .get_object(hash, hash_algrithm)
            .or(Err(OcallError::IoError))?
            .ok_or(OcallError::NotFound)?;
        Ok(obj)
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
        .context("Failed to add wapo.ocall_fast_return to linker")?;
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
        .context("Failed to add wapo.ocall to linker")?;
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
        .context("Failed to add env.sidevm_ocall_fast_return to linker")?;
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
        .context("Failed to add env.sidevm_ocall to linker")?;
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
        payload: Vec<u8>,
        reply_tx: OneshotSender<Vec<u8>>,
    ) -> anyhow::Result<()> {
        let Some(tx) = self.query_tx.clone() else {
            debug!(target: "wapo", "Query dropped: no query channel");
            return Ok(());
        };
        let reply_tx = self.resources.push(Resource::OneshotTx(Some(reply_tx)));
        let reply_tx = reply_tx?;
        let query = QueryRequest {
            origin,
            payload,
            reply_tx,
        };
        // TODO: event if returns Ok, it may still fail to send the query. The res would leak in this case.
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
            debug!(target: "wapo", "Http request dropped: no http connect channel");
            return Ok(());
        };
        let (reply_tx, reply_rx) = oneshot::channel();
        let reply_tx = self.resources.push(Resource::OneshotTx(Some(reply_tx)));
        tokio::spawn(
            async move {
                let reply = reply_rx.await;
                let reply = reply
                    .context("Failed to receive http response")
                    .and_then(|bytes| {
                        let response = HttpResponseHead::decode(&mut &bytes[..])?;
                        Ok(response)
                    });
                if response_tx.send(reply).is_err() {
                    info!(target: "wapo", "Failed to send http response");
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
        // TODO: event if returns Ok, it may still fail to send the query. The res would leak in this case.
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
