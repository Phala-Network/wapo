use std::sync::Arc;

#[derive(Clone, Debug)]
pub struct ArcError(Arc<anyhow::Error>);

impl From<anyhow::Error> for ArcError {
    fn from(err: anyhow::Error) -> Self {
        Self(Arc::new(err))
    }
}

impl std::fmt::Display for ArcError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self.0)
    }
}

impl std::error::Error for ArcError {}
