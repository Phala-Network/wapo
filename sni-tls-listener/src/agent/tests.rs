use core::task::Poll;
use std::pin::Pin;

use mpsc::error::TryRecvError;
use pin_project::pin_project;

use super::*;

type Subscriptions = Arc<Mutex<BTreeMap<String, (String, mpsc::Sender<TestConnection>)>>>;
struct TestConfig;

#[derive(Clone)]
struct TestListener {
    subscriptions: Subscriptions,
}

impl TestListener {
    fn send_connection(&self, domain: &str, connection: TestConnection) {
        let subs = self.subscriptions.lock().unwrap();
        if let Some((_, tx)) = subs.get(domain) {
            tx.try_send(connection).unwrap();
        }
    }

    fn n_subs(&self) -> usize {
        self.subscriptions.lock().unwrap().len()
    }

    fn key_of(&self, domain: &str) -> Option<String> {
        self.subscriptions
            .lock()
            .unwrap()
            .get(domain)
            .map(|(key, _)| key.clone())
    }
}

struct TestSub {
    domain: String,
    rx: mpsc::Receiver<TestConnection>,
    subscriptions: Subscriptions,
}

impl Drop for TestSub {
    fn drop(&mut self) {
        self.subscriptions.lock().unwrap().remove(&self.domain);
    }
}

type TestConnection = String;

impl Config for TestConfig {
    type Listener = TestListener;
}

impl Subscribe for TestListener {
    type Sub = TestSub;
    type Key = String;
    fn subscribe(&self, domain: &str, key: Self::Key) -> Result<Self::Sub> {
        let mut subs = self.subscriptions.lock().unwrap();
        if subs.contains_key(domain) {
            anyhow::bail!("domain already subscribed");
        }
        let (tx, rx) = mpsc::channel(32);
        subs.insert(domain.to_string(), (key, tx));
        Ok(TestSub {
            domain: domain.to_string(),
            rx,
            subscriptions: self.subscriptions.clone(),
        })
    }
    fn update_key(&self, domain: &str, key: Self::Key) -> Result<()> {
        let mut subs = self.subscriptions.lock().unwrap();
        let (_, tx) = subs.remove(domain).context("domain not found")?;
        subs.insert(domain.to_string(), (key, tx));
        Ok(())
    }
}

impl Generate for TestSub {
    type Item = TestConnection;
    async fn next(&mut self) -> Option<Self::Item> {
        self.rx.recv().await
    }
}

async fn sleep_ms(ms: u64) {
    tokio::time::sleep(Duration::from_millis(ms)).await;
}

#[pin_project]
struct ShouldReady<F>(#[pin] F);
impl<F: Future> Future for ShouldReady<F> {
    type Output = Result<F::Output>;
    fn poll(self: Pin<&mut Self>, cx: &mut core::task::Context<'_>) -> Poll<Self::Output> {
        match self.project().0.poll(cx) {
            Poll::Pending => Poll::Ready(Err(anyhow::anyhow!("future not ready"))),
            Poll::Ready(v) => Poll::Ready(Ok(v)),
        }
    }
}

fn should_ready<F: Future>(fut: F) -> ShouldReady<F> {
    ShouldReady(fut)
}

const EXAMPLE_DOMAIN: &str = "example.com";

#[tokio::test]
async fn subscribe_works() {
    let listener = TestListener {
        subscriptions: Default::default(),
    };

    let (inst_tx, _inst_rx) = mpsc::channel(32);

    let agent = Agent::<TestConfig>::new(
        listener.clone(),
        move || inst_tx.try_send(()).unwrap(),
        true,
        Duration::from_millis(1000),
    );

    let sub0 = agent.subscribe(EXAMPLE_DOMAIN, "key0".to_string()).unwrap();
    assert_eq!(listener.n_subs(), 1);
    assert_eq!(listener.key_of(EXAMPLE_DOMAIN), Some("key0".to_string()));
    assert_eq!(agent.n_subs(EXAMPLE_DOMAIN), 1);

    let sub1 = agent.subscribe(EXAMPLE_DOMAIN, "key1".to_string()).unwrap();
    assert_eq!(listener.n_subs(), 1);
    assert_eq!(listener.key_of(EXAMPLE_DOMAIN), Some("key1".to_string()));
    assert_eq!(agent.n_subs(EXAMPLE_DOMAIN), 2);

    drop(sub1);
    sleep_ms(10).await;
    assert_eq!(listener.n_subs(), 1);
    assert_eq!(agent.n_subs(EXAMPLE_DOMAIN), 1);

    drop(sub0);
    sleep_ms(10).await;
    assert_eq!(listener.n_subs(), 1);
    assert_eq!(agent.n_subs(EXAMPLE_DOMAIN), 0);

    agent.unsubscribe(EXAMPLE_DOMAIN).unwrap();
    assert_eq!(listener.n_subs(), 1);
    sleep_ms(10).await;
    assert_eq!(listener.n_subs(), 0);
}

#[tokio::test]
async fn dispatch_reusing_sub_works() {
    let listener = TestListener {
        subscriptions: Default::default(),
    };

    let (inst_tx, mut inst_rx) = mpsc::channel(32);

    let reuse = true;
    let agent = Agent::<TestConfig>::new(
        listener.clone(),
        move || inst_tx.try_send(()).unwrap(),
        reuse,
        Duration::from_millis(1000),
    );

    listener.send_connection(EXAMPLE_DOMAIN, "conn0".to_string());
    assert_eq!(inst_rx.try_recv(), Err(TryRecvError::Empty));

    let mut sub = agent.subscribe(EXAMPLE_DOMAIN, "key0".to_string()).unwrap();
    assert_eq!(listener.n_subs(), 1);
    assert_eq!(listener.key_of(EXAMPLE_DOMAIN), Some("key0".to_string()));

    listener.send_connection(EXAMPLE_DOMAIN, "conn1".to_string());
    sleep_ms(1).await;
    // Should reuse the subscriber
    assert_eq!(inst_rx.try_recv(), Err(TryRecvError::Empty));
    let conn = should_ready(sub.next()).await.unwrap().unwrap();
    assert_eq!(conn, "conn1");

    listener.send_connection(EXAMPLE_DOMAIN, "conn2".to_string());
    sleep_ms(1).await;
    // Should reuse again
    assert_eq!(inst_rx.try_recv(), Err(TryRecvError::Empty));
    let conn = should_ready(sub.next()).await.unwrap().unwrap();
    assert_eq!(conn, "conn2");
}

#[tokio::test]
async fn dispatch_exclusive_sub_works() {
    let listener = TestListener {
        subscriptions: Default::default(),
    };

    let (inst_tx, mut inst_rx) = mpsc::channel(32);
    let reuse = false;
    let agent = Agent::<TestConfig>::new(
        listener.clone(),
        move || inst_tx.try_send(()).unwrap(),
        reuse,
        Duration::from_millis(1000),
    );

    listener.send_connection(EXAMPLE_DOMAIN, "conn0".to_string());
    sleep_ms(1).await;
    assert_eq!(inst_rx.try_recv(), Err(TryRecvError::Empty));
    assert_eq!(agent.queued_connections(EXAMPLE_DOMAIN), 0);

    let mut sub0 = agent.subscribe(EXAMPLE_DOMAIN, "key0".to_string()).unwrap();
    listener.send_connection(EXAMPLE_DOMAIN, "conn1".to_string());
    sleep_ms(1).await;

    // Should request a new subscriber
    assert_eq!(agent.queued_connections(EXAMPLE_DOMAIN), 1);
    assert_eq!(inst_rx.try_recv(), Ok(()));
    assert!(should_ready(sub0.next()).await.is_err());

    // Should be able to receive the connection in a new subscriber
    let mut sub1 = agent.subscribe(EXAMPLE_DOMAIN, "key0".to_string()).unwrap();
    assert_eq!(agent.queued_connections(EXAMPLE_DOMAIN), 0);
    assert_eq!(should_ready(sub1.next()).await.unwrap().unwrap(), "conn1");
}

#[tokio::test]
async fn connect_timeout_works() {
    let listener = TestListener {
        subscriptions: Default::default(),
    };

    let (inst_tx, _inst_rx) = mpsc::channel(32);
    let reuse = false;
    let timeout = Duration::from_millis(100);
    let agent = Agent::<TestConfig>::new(
        listener.clone(),
        move || inst_tx.try_send(()).unwrap(),
        reuse,
        timeout,
    );

    let _sub0 = agent.subscribe(EXAMPLE_DOMAIN, "key0".to_string()).unwrap();
    listener.send_connection(EXAMPLE_DOMAIN, "conn1".to_string());
    sleep_ms(55).await;

    // Should be queued
    assert_eq!(agent.queued_connections(EXAMPLE_DOMAIN), 1);
    sleep_ms(100).await;

    // Should timed out
    assert_eq!(agent.queued_connections(EXAMPLE_DOMAIN), 0);
}
