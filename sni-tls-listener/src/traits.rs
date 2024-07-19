use anyhow::Result;
use core::future::Future;

pub trait Subscribe {
    type Sub: Generate;
    type Key;
    fn subscribe(&self, domain: &str, key: Self::Key) -> Result<Self::Sub>;
    fn update_key(&self, domain: &str, key: Self::Key) -> Result<()>;
}
pub trait Generate {
    type Item;
    fn next(&mut self) -> impl Future<Output = Option<Self::Item>> + Send;
}
