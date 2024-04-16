use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use futures::ready;
use once_cell::sync::Lazy;
use rustls_pemfile::Item;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio_rustls::{
    client::TlsStream as ClientTlsStream,
    rustls::{
        self,
        pki_types::{CertificateDer, PrivateKeyDer, ServerName},
        ClientConfig, ServerConfig,
    },
    server::TlsStream as ServerTlsStream,
    Accept, Connect, TlsAcceptor, TlsConnector,
};
use wapo_env::tls::TlsServerConfig;
use wapo_env::OcallError;

pub enum TlsStream {
    ServerHandshaking(Accept<TcpStream>),
    ServerStreaming(ServerTlsStream<TcpStream>),
    ClientHandshaking(Connect<TcpStream>),
    ClientStreaming(ClientTlsStream<TcpStream>),
    Closed,
}

impl From<ClientTlsStream<TcpStream>> for TlsStream {
    fn from(stream: ClientTlsStream<TcpStream>) -> Self {
        TlsStream::ClientStreaming(stream)
    }
}

impl From<ServerTlsStream<TcpStream>> for TlsStream {
    fn from(stream: ServerTlsStream<TcpStream>) -> Self {
        TlsStream::ServerStreaming(stream)
    }
}

fn default_client_config() -> Arc<ClientConfig> {
    static CLIENT_CONFIG: Lazy<Arc<ClientConfig>> = Lazy::new(|| {
        let root_store =
            rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let config = ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();
        Arc::new(config)
    });
    CLIENT_CONFIG.clone()
}

impl TlsStream {
    pub(crate) fn accept(stream: TcpStream, config: Arc<ServerConfig>) -> TlsStream {
        let accept = TlsAcceptor::from(config).accept(stream);
        TlsStream::ServerHandshaking(accept)
    }

    pub(crate) fn connect(domain: ServerName<'static>, stream: TcpStream) -> TlsStream {
        let client_config = default_client_config();
        let connector = TlsConnector::from(client_config);
        TlsStream::ClientHandshaking(connector.connect(domain, stream))
    }
}

impl AsyncRead for TlsStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context,
        buf: &mut ReadBuf,
    ) -> Poll<io::Result<()>> {
        let me = self.get_mut();
        macro_rules! poll_handshake {
            ($inner: expr) => {
                match ready!(Pin::new($inner).poll(cx)) {
                    Ok(mut stream) => {
                        let result = Pin::new(&mut stream).poll_read(cx, buf);
                        *me = stream.into();
                        result
                    }
                    Err(err) => {
                        *me = Self::Closed;
                        Poll::Ready(Err(err))
                    }
                }
            };
        }
        macro_rules! poll_read {
            ($stream: expr) => {{
                let rv = Pin::new($stream).poll_read(cx, buf);
                if let Poll::Ready(Err(_)) = &rv {
                    *me = Self::Closed;
                }
                rv
            }};
        }
        match me {
            Self::ClientHandshaking(connect) => poll_handshake!(connect),
            Self::ServerHandshaking(accept) => poll_handshake!(accept),
            Self::ClientStreaming(stream) => poll_read!(stream),
            Self::ServerStreaming(stream) => poll_read!(stream),
            Self::Closed => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::Other,
                "TlsStream is closed",
            ))),
        }
    }
}

impl AsyncWrite for TlsStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let me = self.get_mut();
        macro_rules! poll_handshake {
            ($inner: expr) => {
                match ready!(Pin::new($inner).poll(cx)) {
                    Ok(mut stream) => {
                        let result = Pin::new(&mut stream).poll_write(cx, buf);
                        *me = stream.into();
                        result
                    }
                    Err(err) => {
                        *me = Self::Closed;
                        Poll::Ready(Err(err))
                    }
                }
            };
        }
        macro_rules! poll_write {
            ($stream: expr) => {{
                let rv = Pin::new($stream).poll_write(cx, buf);
                if let Poll::Ready(Err(_)) = &rv {
                    *me = Self::Closed;
                }
                rv
            }};
        }
        match me {
            Self::ClientHandshaking(connect) => poll_handshake!(connect),
            Self::ServerHandshaking(accept) => poll_handshake!(accept),
            Self::ClientStreaming(stream) => poll_write!(stream),
            Self::ServerStreaming(stream) => poll_write!(stream),
            Self::Closed => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::Other,
                "TlsStream is closed",
            ))),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let me = self.get_mut();
        macro_rules! poll_flush {
            ($stream: expr) => {{
                let rv = Pin::new($stream).poll_flush(cx);
                if let Poll::Ready(Err(_)) = &rv {
                    *me = Self::Closed;
                }
                rv
            }};
        }
        match me {
            Self::ClientHandshaking(_) => Poll::Ready(Ok(())),
            Self::ServerHandshaking(_) => Poll::Ready(Ok(())),
            Self::ClientStreaming(stream) => poll_flush!(stream),
            Self::ServerStreaming(stream) => poll_flush!(stream),
            Self::Closed => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::Other,
                "TlsStream is closed",
            ))),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let me = self.get_mut();
        macro_rules! poll_shutdown {
            ($stream: expr) => {{
                let rv = Pin::new($stream).poll_shutdown(cx);
                if let Poll::Ready(_) = &rv {
                    *me = Self::Closed;
                }
                rv
            }};
        }
        match me {
            Self::ClientHandshaking(_) => {
                *me = Self::Closed;
                Poll::Ready(Ok(()))
            }
            Self::ServerHandshaking(_) => {
                *me = Self::Closed;
                Poll::Ready(Ok(()))
            }
            Self::ClientStreaming(stream) => poll_shutdown!(stream),
            Self::ServerStreaming(stream) => poll_shutdown!(stream),
            Self::Closed => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::Other,
                "TlsStream is closed",
            ))),
        }
    }
}

pub(crate) fn load_tls_config(config: TlsServerConfig) -> Result<ServerConfig, OcallError> {
    let (cert_pem, key_pem) = match &config {
        TlsServerConfig::V0 { cert, key } => (cert, key),
    };

    let certs = load_certs(cert_pem)?;
    let key = load_private_key(key_pem)?;

    tokio_rustls::rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .or(Err(OcallError::InvalidParameter))
}

fn load_certs(pem_str: &str) -> Result<Vec<CertificateDer<'static>>, OcallError> {
    rustls_pemfile::certs(&mut pem_str.as_bytes())
        .collect::<Result<Vec<_>, _>>()
        .or(Err(OcallError::InvalidParameter))
}

fn load_private_key(pem_str: &str) -> Result<PrivateKeyDer<'static>, OcallError> {
    let key = rustls_pemfile::read_all(&mut pem_str.as_bytes())
        .next()
        .ok_or(OcallError::InvalidParameter)?
        .or(Err(OcallError::InvalidParameter))?;
    let key = match key {
        Item::Pkcs1Key(key) => PrivateKeyDer::Pkcs1(key),
        Item::Pkcs8Key(key) => PrivateKeyDer::Pkcs8(key),
        Item::Sec1Key(key) => PrivateKeyDer::Sec1(key),
        _ => return Err(OcallError::InvalidParameter),
    };
    Ok(key)
}
