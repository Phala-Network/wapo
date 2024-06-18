use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{Arc, Mutex, Weak},
};

use anyhow::{Context, Result};
use rustls::{
    server::{ClientHello, ResolvesServerCert},
    sign::CertifiedKey,
};
use rustls_pemfile::Item;
use rustls_pki_types::PrivateKeyDer;
use tokio::{
    net::{TcpListener, TcpStream},
    sync::{
        mpsc::{error::TrySendError, Receiver, Sender},
        oneshot,
    },
};
use tokio_rustls::{server::TlsStream, TlsAcceptor};
use tracing::{info, warn};

pub struct Subscription {
    rx: Receiver<(TlsStream<TcpStream>, SocketAddr)>,
    sni: String,
    weak_listener: WeakSniTlsListener,
}

impl Subscription {
    pub async fn next(&mut self) -> Option<(TlsStream<TcpStream>, SocketAddr)> {
        self.rx.recv().await
    }
}

impl Drop for Subscription {
    fn drop(&mut self) {
        if let Some(listener) = self.weak_listener.state.upgrade() {
            let mut guard = listener.lock().unwrap();
            guard.subscribers.remove(&self.sni);
        }
    }
}

struct SubscribeInfo {
    key: Arc<CertifiedKey>,
    tx: Sender<(TlsStream<TcpStream>, SocketAddr)>,
}

struct SniTlsListenerState {
    _term_tx: oneshot::Sender<()>,
    subscribers: HashMap<String, SubscribeInfo>,
}

impl std::fmt::Debug for SniTlsListenerState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SniTlsListenerState").finish()
    }
}

#[derive(Clone, Debug)]
pub struct SniTlsListener {
    state: Arc<Mutex<SniTlsListenerState>>,
}

impl SniTlsListener {
    pub fn downgrade(&self) -> WeakSniTlsListener {
        WeakSniTlsListener {
            state: Arc::downgrade(&self.state),
        }
    }

    pub async fn bind(host: &str, port: u16) -> Result<Self> {
        let tcp_listener = TcpListener::bind((host, port))
            .await
            .context("failed to bind on tcp port")?;
        let (term_tx, term_rx) = tokio::sync::oneshot::channel();
        let this = Self {
            state: Arc::new(Mutex::new(SniTlsListenerState {
                _term_tx: term_tx,
                subscribers: HashMap::new(),
            })),
        };

        let service_task = listening_service(tcp_listener, this.downgrade());

        tokio::spawn(async move {
            tokio::select! {
                res = service_task => {
                    if let Err(err) = res {
                        warn!("Error in listening_service: {:?}", err);
                    }
                }
                _ = term_rx => {
                    info!("SniTlsListener terminated");
                }
            }
        });

        Ok(this)
    }

    pub fn subscribe(&self, server_name: &str, key: Arc<CertifiedKey>) -> Result<Subscription> {
        let todo = "verify the certificate and ensure the server_name matches the certificate's subject alternative name";
        let (tx, rx) = tokio::sync::mpsc::channel(32);
        let mut guard = self.state.lock().unwrap();
        if guard.subscribers.contains_key(server_name) {
            anyhow::bail!("server_name already subscribed");
        }
        guard
            .subscribers
            .insert(server_name.to_string(), SubscribeInfo { key, tx });
        Ok(Subscription {
            rx,
            sni: server_name.to_string(),
            weak_listener: self.downgrade(),
        })
    }
}

#[derive(Clone, Debug)]
pub struct WeakSniTlsListener {
    state: Weak<Mutex<SniTlsListenerState>>,
}

impl WeakSniTlsListener {
    pub fn upgrade(&self) -> Option<SniTlsListener> {
        Some(SniTlsListener {
            state: self.state.upgrade()?,
        })
    }
}

async fn listening_service(
    tcp_listener: TcpListener,
    sni_listner: WeakSniTlsListener,
) -> Result<()> {
    let config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(sni_listner.clone()));
    let tls_acceptor = TlsAcceptor::from(Arc::new(config));
    loop {
        let (tcp_stream, peer_addr) = tcp_listener.accept().await?;
        let tls_acceptor = tls_acceptor.clone();
        let sni_listener = sni_listner.clone();
        let Some(state) = sni_listener.state.upgrade() else {
            anyhow::bail!("sni_listener dropped, shutting down tcp_listener");
        };
        let tls_stream = tls_acceptor.accept(tcp_stream).await?;
        let server_name = tls_stream.get_ref().1.server_name().unwrap();
        let mut guard = state.lock().unwrap();
        if let Some(subscriber) = guard.subscribers.get(server_name) {
            if let Err(err) = subscriber.tx.try_send((tls_stream, peer_addr)) {
                match err {
                    TrySendError::Full(_) => {
                        warn!("subscriber buffer full, dropping connection");
                    }
                    TrySendError::Closed((stream, _)) => {
                        warn!("subscriber dropped, shutting down tcp_listener");
                        guard
                            .subscribers
                            .remove(stream.get_ref().1.server_name().unwrap_or_default());
                    }
                }
            }
        }
    }
}

impl ResolvesServerCert for WeakSniTlsListener {
    fn resolve(&self, client_hello: ClientHello) -> Option<Arc<CertifiedKey>> {
        let key = self
            .state
            .upgrade()?
            .lock()
            .unwrap()
            .subscribers
            .get(client_hello.server_name()?)?
            .key
            .clone();
        Some(key)
    }
}

pub fn wrap_certified_key(mut cert: &[u8], mut key: &[u8]) -> Result<Arc<CertifiedKey>> {
    let cert = rustls_pemfile::certs(&mut cert)
        .collect::<Result<Vec<_>, _>>()
        .context("Invalid certificate")?;
    let key = rustls_pemfile::read_all(&mut key)
        .next()
        .context("No key found")?
        .context("Invalid key")?;
    let key = match key {
        Item::Pkcs1Key(key) => PrivateKeyDer::Pkcs1(key),
        Item::Pkcs8Key(key) => PrivateKeyDer::Pkcs8(key),
        Item::Sec1Key(key) => PrivateKeyDer::Sec1(key),
        _ => anyhow::bail!("Invalid key"),
    };
    let key = rustls::crypto::ring::sign::any_supported_type(&key)?;
    let certified_key = rustls::sign::CertifiedKey::new(cert, key);

    Ok(Arc::new(certified_key))
}
