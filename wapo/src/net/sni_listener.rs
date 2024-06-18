use core::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};
use std::net::SocketAddr;

use wapo_env::tls::TlsServerConfig;

use super::{ocall, ResourceId, Result, TcpStream};

/// An incomming TLS connection listener.
pub struct SniTlsListener {
    res_id: ResourceId,
}

impl SniTlsListener {
    /// Bind to a given SNI and listen for incoming connections.
    pub fn bind(sni: &str, config: TlsServerConfig) -> Result<Self> {
        let raw_res = ocall::tls_listen_sni(sni.into(), config)?;
        let res_id = ResourceId(raw_res);
        Ok(Self { res_id })
    }

    /// Accept a new incoming connection.
    pub fn accept(&self) -> SniTlsAcceptor {
        SniTlsAcceptor { listener: self }
    }
}

/// A future that resolves to a new incoming connection.
pub struct SniTlsAcceptor<'a> {
    listener: &'a SniTlsListener,
}

impl<'a> Future for SniTlsAcceptor<'a> {
    type Output = Result<(TcpStream, SocketAddr)>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        super::poll_tcp_accept(&self.listener.res_id, cx)
    }
}
