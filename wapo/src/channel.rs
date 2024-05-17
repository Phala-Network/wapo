//! Multi-producer, single-consumer channel implementation.
use wapo_env::{
    messages::{
        AccountId, HttpHead, HttpRequest as MsgHttpReqeust, HttpResponseHead, QueryRequest,
    },
    InputChannel, OcallError,
};

use crate::net::TcpStream;

use super::{ocall, ResourceId};
use scale::{Decode, Encode};
use std::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};

use lazy_static::lazy_static;

/// A query from an external RPC request.
pub struct Query {
    /// The account sending the query.
    pub origin: Option<AccountId>,
    /// Resource path
    pub path: String,
    /// The query payload.
    pub payload: Vec<u8>,
    /// The reply channel. Invoke `send` on this channel to send the reply.
    pub reply_tx: OneshotSender,
}

/// A incoming HTTP request.
pub struct HttpRequest {
    /// The HTTP request head.
    pub head: HttpHead,
    /// The IO stream to read the request body and write the response body.
    pub io_stream: TcpStream,
    /// The reply channel to send the response head.
    pub response_tx: ScaleOneshotSender<HttpResponseHead>,
}

/// Sender end of a oneshot channel connected to host-side.
pub struct ScaleOneshotSender<M> {
    sender: OneshotSender,
    _marker: std::marker::PhantomData<M>,
}

impl<M: Encode> ScaleOneshotSender<M> {
    /// Send a message to the other end of the channel.
    pub fn send(self, msg: M) -> Result<(), OcallError> {
        self.sender.send(&msg.encode())
    }
}

impl<M: Encode> From<OneshotSender> for ScaleOneshotSender<M> {
    fn from(sender: OneshotSender) -> Self {
        Self {
            sender,
            _marker: std::marker::PhantomData,
        }
    }
}

/// Sender end of a oneshot channel connected to host-side.
pub struct OneshotSender {
    res_id: ResourceId,
}

impl OneshotSender {
    const fn new(res_id: ResourceId) -> Self {
        Self { res_id }
    }

    /// Send a message to the host-side.
    pub fn send(self, data: &[u8]) -> Result<(), OcallError> {
        ocall::oneshot_send(self.res_id.0, data)
    }
}

/// Receiver end of a channel connected to host-side.
pub struct Receiver<M> {
    res_id: ResourceId,
    _marker: std::marker::PhantomData<M>,
}

/// The future to get the next message from the channel.
pub struct Next<'a, M> {
    ch: &'a Receiver<M>,
}

impl<T> Receiver<T> {
    /// Create a new `Receiver` from a `ResourceId`.
    pub const fn new(res_id: ResourceId) -> Self {
        Self {
            res_id,
            _marker: std::marker::PhantomData,
        }
    }

    /// Get the next message from the channel.
    pub fn next(&self) -> Next<T> {
        Next { ch: self }
    }
}

impl Future for Next<'_, Query> {
    type Output = Option<Query>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let waker_id = crate::env::tasks::intern_waker(cx.waker().clone());
        match ocall::poll(waker_id, self.ch.res_id.0) {
            Ok(msg) => {
                let request =
                    QueryRequest::decode(&mut &msg[..]).expect("failed to decode QueryRequest");
                let reply_tx = OneshotSender::new(ResourceId(request.reply_tx));
                Poll::Ready(Some(Query {
                    origin: request.origin,
                    path: request.path,
                    payload: request.payload,
                    reply_tx,
                }))
            }
            Err(OcallError::EndOfFile) => Poll::Ready(None), // The tx dropped
            Err(OcallError::Pending) => Poll::Pending,
            Err(err) => panic!("unexpected error: {err:?}"),
        }
    }
}

macro_rules! singleton_channel {
    ($ch: ident) => {{
        lazy_static! {
            static ref RX: Receiver<$ch> = {
                let res_id = ocall::create_input_channel(InputChannel::$ch)
                    .expect("failed to create input channel");
                Receiver::new(ResourceId(res_id))
            };
        }
        &*RX
    }};
}

/// Queries from RPC channel.
pub fn incoming_queries() -> &'static Receiver<Query> {
    singleton_channel!(Query)
}

impl Future for Next<'_, HttpRequest> {
    type Output = Option<HttpRequest>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let waker_id = crate::env::tasks::intern_waker(cx.waker().clone());
        match ocall::poll(waker_id, self.ch.res_id.0) {
            Ok(msg) => {
                let request =
                    MsgHttpReqeust::decode(&mut &msg[..]).expect("failed to decode MsgHttpReqeust");
                let response_tx = OneshotSender::new(ResourceId(request.response_tx)).into();
                let io_stream = TcpStream::new(ResourceId(request.io_stream));
                Poll::Ready(Some(HttpRequest {
                    head: request.head,
                    io_stream,
                    response_tx,
                }))
            }
            Err(OcallError::EndOfFile) => Poll::Ready(None), // The tx dropped
            Err(OcallError::Pending) => Poll::Pending,
            Err(err) => panic!("unexpected error: {err:?}"),
        }
    }
}

/// Incoming HTTP connections.
pub fn incoming_http_connections() -> &'static Receiver<HttpRequest> {
    singleton_channel!(HttpRequest)
}
