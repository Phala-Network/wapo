use std::future::Future;
use std::io::ErrorKind;
use std::pin::Pin;
use std::sync::Arc;
use std::task::Poll::*;
use tokio::io::{AsyncRead, AsyncWrite, DuplexStream};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc::Receiver;
use tokio::sync::oneshot::Sender;
use tokio::time::Sleep;
use tokio_rustls::rustls::ServerConfig;
use wapo_env::{OcallError, Result};
use Resource::*;

use super::async_context::{get_task_cx, poll_in_task_cx, GuestWaker};
use super::tls::TlsStream;

pub struct PollContext {
    pub waker: GuestWaker,
}

pub struct TcpListenerResource {
    pub listener: TcpListener,
    pub tls_config: Option<Arc<ServerConfig>>,
}

pub enum Resource {
    Sleep(Pin<Box<Sleep>>),
    ChannelRx(Receiver<Vec<u8>>),
    OneshotTx(Option<Sender<Vec<u8>>>),
    TcpListener(Box<TcpListenerResource>),
    TcpStream(Box<TcpStream>),
    TlsStream(Box<TlsStream>),
    TcpConnect(Pin<Box<dyn Future<Output = std::io::Result<TcpStream>> + Send>>),
    TlsConnect(Pin<Box<dyn Future<Output = std::io::Result<TlsStream>> + Send>>),
    DuplexStream(DuplexStream),
}

impl Resource {
    pub(crate) fn poll(&mut self, ctx: PollContext) -> Result<Vec<u8>> {
        let waker = ctx.waker;

        match self {
            ChannelRx(rx) => {
                let fut = rx.recv();
                futures::pin_mut!(fut);
                match poll_in_task_cx(waker, fut) {
                    Ready(Some(data)) => Ok(data),
                    Ready(None) => Err(OcallError::EndOfFile),
                    Pending => Err(OcallError::Pending),
                }
            }
            _ => Err(OcallError::UnsupportedOperation),
        }
    }

    pub(crate) fn poll_res(&mut self, ctx: PollContext) -> Result<Resource> {
        let waker = ctx.waker;
        match self {
            TcpConnect(fut) => {
                let rv = poll_in_task_cx(waker, fut.as_mut());
                match rv {
                    Pending => Err(OcallError::Pending),
                    Ready(Ok(stream)) => Ok(Resource::TcpStream(Box::new(stream))),
                    Ready(Err(err)) => {
                        log::error!("Tcp connect error: {}", err);
                        Err(OcallError::IoError)
                    }
                }
            }
            TlsConnect(fut) => {
                let rv = poll_in_task_cx(waker, fut.as_mut());
                match rv {
                    Pending => Err(OcallError::Pending),
                    Ready(Ok(stream)) => Ok(Resource::TlsStream(Box::new(stream))),
                    Ready(Err(err)) => {
                        log::error!("Tls connect error: {}", err);
                        Err(OcallError::IoError)
                    }
                }
            }
            _ => Err(OcallError::UnsupportedOperation),
        }
    }

    pub(crate) fn poll_read(&mut self, ctx: PollContext, buf: &mut [u8]) -> Result<u32> {
        let waker = ctx.waker;

        fn stream_poll_read(
            stream: &mut (impl AsyncRead + Unpin),
            waker: GuestWaker,
            buf: &mut [u8],
        ) -> Result<u32> {
            let stream = Pin::new(stream);
            let mut buf = tokio::io::ReadBuf::new(buf);
            match get_task_cx(waker, |cx| stream.poll_read(cx, &mut buf)) {
                Pending => Err(OcallError::Pending),
                Ready(Err(_err)) => Err(OcallError::IoError),
                Ready(Ok(())) => Ok(buf.filled().len() as _),
            }
        }
        match self {
            Sleep(handle) => match poll_in_task_cx(waker, handle.as_mut()) {
                Ready(_) => Ok(0),
                Pending => Err(OcallError::Pending),
            },
            TcpStream(stream) => loop {
                match stream.try_read(buf) {
                    Ok(sz) => break Ok(sz as _),
                    Err(err) => {
                        if err.kind() == ErrorKind::WouldBlock {
                            match get_task_cx(waker.clone(), |cx| stream.poll_read_ready(cx)) {
                                Pending => break Err(OcallError::Pending),
                                Ready(Err(_err)) => break Err(OcallError::IoError),
                                Ready(Ok(())) => continue,
                            }
                        } else {
                            break Err(OcallError::IoError);
                        }
                    }
                }
            },
            TlsStream(stream) => stream_poll_read(stream, waker, buf),
            DuplexStream(stream) => stream_poll_read(stream, waker, buf),
            _ => Err(OcallError::UnsupportedOperation),
        }
    }

    pub(crate) fn poll_write(&mut self, ctx: PollContext, buf: &[u8]) -> Result<u32> {
        let waker = ctx.waker;

        fn stream_poll_write(
            stream: &mut (impl AsyncWrite + Unpin),
            waker: GuestWaker,
            buf: &[u8],
        ) -> Result<u32> {
            let stream = Pin::new(stream);
            match get_task_cx(waker, |cx| stream.poll_write(cx, buf)) {
                Pending => Err(OcallError::Pending),
                Ready(Err(_err)) => Err(OcallError::IoError),
                Ready(Ok(sz)) => Ok(sz as _),
            }
        }
        match self {
            TcpStream(stream) => loop {
                match stream.try_write(buf) {
                    Ok(sz) => break Ok(sz as _),
                    Err(err) => {
                        if err.kind() == ErrorKind::WouldBlock {
                            match get_task_cx(waker.clone(), |cx| stream.poll_write_ready(cx)) {
                                Pending => break Err(OcallError::Pending),
                                Ready(Err(_err)) => break Err(OcallError::IoError),
                                Ready(Ok(())) => continue,
                            }
                        } else {
                            break Err(OcallError::IoError);
                        }
                    }
                }
            },
            TlsStream(stream) => stream_poll_write(stream, waker, buf),
            DuplexStream(stream) => stream_poll_write(stream, waker, buf),
            _ => Err(OcallError::UnsupportedOperation),
        }
    }

    pub(crate) fn poll_shutdown(&mut self, ctx: PollContext) -> Result<()> {
        let waker = ctx.waker;

        fn stream_poll_shutdown(
            stream: &mut (impl AsyncWrite + Unpin),
            waker: GuestWaker,
        ) -> Result<()> {
            let stream = Pin::new(stream);
            match get_task_cx(waker, |cx| stream.poll_shutdown(cx)) {
                Pending => Err(OcallError::Pending),
                Ready(Err(_err)) => Err(OcallError::IoError),
                Ready(Ok(())) => Ok(()),
            }
        }
        match self {
            TcpStream(stream) => stream_poll_shutdown(stream, waker),
            TlsStream(stream) => stream_poll_shutdown(stream, waker),
            DuplexStream(stream) => stream_poll_shutdown(stream, waker),
            _ => Err(OcallError::UnsupportedOperation),
        }
    }
}

#[derive(Default)]
pub struct ResourceTable {
    resources: Vec<Option<Resource>>,
}

const RESOURCE_ID_MAX: usize = 8192;

impl ResourceTable {
    pub fn get_mut(&mut self, id: i32) -> Result<&mut Resource> {
        self.resources
            .get_mut(id as usize)
            .and_then(Option::as_mut)
            .ok_or(OcallError::NotFound)
    }

    pub fn push(&mut self, resource: Resource) -> Result<i32> {
        for (i, res) in self.resources.iter_mut().enumerate() {
            if res.is_none() {
                let id = i.try_into().or(Err(OcallError::ResourceLimited))?;
                *res = Some(resource);
                return Ok(id);
            }
        }
        if self.resources.len() >= RESOURCE_ID_MAX.min(i32::MAX as _) {
            return Err(OcallError::ResourceLimited);
        }
        let id = self
            .resources
            .len()
            .try_into()
            .or(Err(OcallError::ResourceLimited))?;
        self.resources.push(Some(resource));
        Ok(id)
    }

    pub fn take(&mut self, resource_id: i32) -> Option<Resource> {
        let resource_id = resource_id as u32 as usize;
        if resource_id >= self.resources.len() {
            return None;
        }
        self.resources[resource_id].take()
    }
}
