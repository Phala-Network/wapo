use anyhow::{anyhow, Context, Result};
use core::fmt;
use std::{
    collections::{BTreeMap, VecDeque},
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex, MutexGuard, Weak,
    },
    time::{Duration, Instant},
};
use tokio::sync::{
    mpsc::{self, error::TrySendError},
    oneshot,
};
use tracing::info;

use crate::{
    traits::{Generate, Subscribe},
    SniTlsListener,
};

#[cfg(test)]
mod tests;

static NEXT_SUB_ID: AtomicU64 = AtomicU64::new(0);

pub trait Config: Send + 'static {
    type Listener: Subscribe;
}

type ConnectionOf<T> = <<<T as Config>::Listener as Subscribe>::Sub as Generate>::Item;
type KeyOf<T> = <<T as Config>::Listener as Subscribe>::Key;
type SubscriptionOf<T> = <<T as Config>::Listener as Subscribe>::Sub;

pub struct DefaultConfig;

impl Config for DefaultConfig {
    type Listener = SniTlsListener;
}

pub struct Subscription<T: Config> {
    id: u64,
    domain: String,
    agent: WeakAgent<T>,
    rx: mpsc::Receiver<ConnectionOf<T>>,
}

impl<T: Config> Subscription<T> {
    fn new(domain: String, agent: WeakAgent<T>, rx: mpsc::Receiver<ConnectionOf<T>>) -> Self {
        Self {
            id: NEXT_SUB_ID.fetch_add(1, Ordering::Relaxed),
            agent,
            domain,
            rx,
        }
    }
}

impl<T: Config> Generate for Subscription<T>
where
    T::Listener: Send,
    ConnectionOf<T>: Send,
    SubscriptionOf<T>: Send,
{
    type Item = ConnectionOf<T>;
    async fn next(&mut self) -> Option<Self::Item> {
        self.rx.recv().await
    }
}

impl<T: Config> Drop for Subscription<T> {
    fn drop(&mut self) {
        if let Some(agent) = self.agent.upgrade() {
            if let Err(err) = agent.remove_sub(&self.domain, self.id) {
                info!(target: "wapo::tls", "remove sub error: {err:?}");
            }
        }
    }
}

#[derive(Debug)]
struct SubTx<T: Config> {
    tx: mpsc::Sender<ConnectionOf<T>>,
}

impl<T: Config> Clone for SubTx<T> {
    fn clone(&self) -> Self {
        Self {
            tx: self.tx.clone(),
        }
    }
}
impl<T: Config> SubTx<T> {
    pub fn send(&self, connection: ConnectionOf<T>) -> Result<()> {
        self.tx.try_send(connection).map_err(|err| match err {
            TrySendError::Full(_) => anyhow!("subscriber buffer full"),
            TrySendError::Closed(_) => anyhow!("subscriber closed"),
        })
    }
}

fn sub_channel<T: Config>(domain: String, agent: WeakAgent<T>) -> (SubTx<T>, Subscription<T>) {
    let (tx, rx) = mpsc::channel(1);
    (SubTx { tx }, Subscription::new(domain, agent, rx))
}

struct SubState<T: Config> {
    queue: VecDeque<(Instant, ConnectionOf<T>)>,
    subscriptions: BTreeMap<u64, SubTx<T>>,
    _cancel_tx: oneshot::Sender<()>,
}

impl<T: Config> SubState<T> {
    pub fn new(cancel_tx: oneshot::Sender<()>) -> Self {
        Self {
            queue: Default::default(),
            subscriptions: Default::default(),
            _cancel_tx: cancel_tx,
        }
    }

    fn clear_timeout_connections(&mut self, threshold: Duration) {
        self.queue
            .retain(|(instant, _)| instant.elapsed() < threshold);
    }
}

struct WeakAgent<T: Config> {
    state: Weak<Mutex<AgentState<T>>>,
}

impl<T: Config> Clone for WeakAgent<T> {
    fn clone(&self) -> Self {
        Self {
            state: self.state.clone(),
        }
    }
}

impl<T: Config> WeakAgent<T> {
    fn new(state: Weak<Mutex<AgentState<T>>>) -> Self {
        Self { state }
    }

    fn upgrade(&self) -> Option<Agent<T>> {
        self.state.upgrade().map(|state| Agent { state })
    }
}

pub struct Agent<T: Config> {
    state: Arc<Mutex<AgentState<T>>>,
}

impl<T: Config> Clone for Agent<T> {
    fn clone(&self) -> Self {
        Self {
            state: self.state.clone(),
        }
    }
}

impl<T: Config> fmt::Debug for Agent<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Agent").finish()
    }
}

struct AgentState<T: Config> {
    weak_self: WeakAgent<T>,
    listener: T::Listener,
    subscribers: BTreeMap<String, SubState<T>>,
    create_instance: Box<dyn Fn() + Send + Sync + 'static>,
    reuse_subscriber: bool,
    connect_timeout: Duration,
}

impl<T: Config> Agent<T> {
    pub fn new(
        listener: T::Listener,
        create_instance: impl Fn() + Send + Sync + 'static,
        reuse_subscriber: bool,
        connect_timeout: Duration,
    ) -> Self {
        Self {
            state: Arc::new_cyclic(|weak_self| {
                Mutex::new(AgentState {
                    weak_self: WeakAgent::new(weak_self.clone()),
                    listener,
                    subscribers: Default::default(),
                    create_instance: Box::new(create_instance) as _,
                    reuse_subscriber,
                    connect_timeout,
                })
            }),
        }
    }

    fn lock(&self) -> MutexGuard<AgentState<T>> {
        self.state.lock().unwrap()
    }

    fn remove_sub(&self, domain: &str, id: u64) -> Result<()> {
        self.lock().remove_sub(domain, id)
    }

    #[cfg(test)]
    fn queued_connections(&self, domain: &str) -> usize {
        self.lock()
            .subscribers
            .get(domain)
            .map_or(0, |sub| sub.queue.len())
    }

    #[cfg(test)]
    fn n_subs(&self, domain: &str) -> usize {
        self.lock()
            .subscribers
            .get(domain)
            .map_or(0, |sub| sub.subscriptions.len())
    }
}

impl<T: Config> Agent<T>
where
    T::Listener: Send,
    ConnectionOf<T>: Send,
    SubscriptionOf<T>: Send,
{
    fn dispatch_connection(&self, domain: &str, connection: ConnectionOf<T>) -> Result<()> {
        self.lock().dispatch_connection(domain, connection)
    }

    pub fn subscribe(&self, domain: &str, key: KeyOf<T>) -> Result<Subscription<T>> {
        self.lock().subscribe(domain, key)
    }

    pub fn unsubscribe(&self, domain: &str) -> Result<()> {
        self.lock().unsubscribe(domain)
    }
}

impl<T: Config> AgentState<T>
where
    T::Listener: Send,
    ConnectionOf<T>: Send,
    SubscriptionOf<T>: Send,
{
    fn subscribe(&mut self, domain: &str, key: KeyOf<T>) -> Result<Subscription<T>> {
        let sub = match self.subscribers.get_mut(domain) {
            Some(sub_state) => {
                self.listener.update_key(domain, key)?;
                let (tx, rx) = sub_channel(domain.to_string(), self.weak_self.clone());
                if let Some((_, conn)) = sub_state.queue.pop_front() {
                    if let Err(err) = tx.send(conn) {
                        info!(target: "wapo::tls", "send connection error: {err:?}");
                    }
                }
                sub_state.subscriptions.insert(rx.id, tx);
                rx
            }
            None => {
                let mut subscription = self.listener.subscribe(domain, key)?;

                let (tx, rx) = sub_channel(domain.to_string(), self.weak_self.clone());
                let (cancel_tx, cancel_rx) = oneshot::channel();
                let mut sub_state = SubState::<T>::new(cancel_tx);
                sub_state.subscriptions.insert(rx.id, tx);

                let weak_self = self.weak_self.clone();
                let owned_domain = domain.to_string();
                let task = async move {
                    loop {
                        match subscription.next().await {
                            Some(connection) => {
                                let Some(agent) = weak_self.upgrade() else {
                                    info!(target: "wapo::tls", "tls sub agent dropped");
                                    break;
                                };
                                if let Err(err) =
                                    agent.dispatch_connection(&owned_domain, connection)
                                {
                                    info!(target: "wapo::tls", "tls dispatch connection error: {err:?}");
                                    continue;
                                }
                            }
                            None => {
                                info!(target: "wapo::tls", "tls subscription dropped");
                                break;
                            }
                        }
                    }
                };
                let weak_self = self.weak_self.clone();
                let owned_domain = domain.to_string();
                let timeout = self.connect_timeout;
                let conn_timeout_checker = async move {
                    loop {
                        tokio::time::sleep(timeout / 2).await;
                        if let Some(agent) = weak_self.upgrade() {
                            let mut state = agent.lock();
                            if let Some(sub) = state.subscribers.get_mut(&owned_domain) {
                                sub.clear_timeout_connections(timeout);
                            }
                        }
                    }
                };
                tokio::spawn(async move {
                    tokio::select! {
                        _ = task => {}
                        _ = cancel_rx => {}
                        _ = conn_timeout_checker => {}
                    }
                });
                self.subscribers.insert(domain.to_string(), sub_state);
                rx
            }
        };
        Ok(sub)
    }

    fn dispatch_connection(&mut self, domain: &str, connection: ConnectionOf<T>) -> Result<()> {
        let sub = self.subscribers.get_mut(domain).context("no subscribers")?;

        let subscriber = match self.reuse_subscriber {
            true => sub.subscriptions.values().next().cloned(),
            false => None,
        };
        if let Some(subscriber) = subscriber {
            subscriber
                .send(connection)
                .context("failed to dispatch the connection")?;
        } else {
            sub.queue.push_back((Instant::now(), connection));
            (self.create_instance)();
        }
        Ok(())
    }
}

impl<T: Config> AgentState<T> {
    fn unsubscribe(&mut self, domain: &str) -> Result<()> {
        let _sub = self.subscribers.remove(domain).context("no subscribers")?;
        Ok(())
    }

    fn remove_sub(&mut self, domain: &str, id: u64) -> Result<()> {
        let sub = self.subscribers.get_mut(domain).context("no subscribers")?;
        sub.subscriptions.remove(&id).context("no subscription")?;
        if sub.subscriptions.is_empty() {
            self.unsubscribe(domain)?;
        }
        Ok(())
    }
}

impl SniTlsListener {
    pub fn agent(
        &self,
        create_instance: impl Fn() + Send + Sync + 'static,
        reuse: bool,
        timeout: Duration,
    ) -> Agent<DefaultConfig> {
        Agent::new(self.clone(), create_instance, reuse, timeout)
    }
}
