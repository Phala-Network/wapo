//! Provides functionalities in tokio::time.

use super::*;

use core::pin::Pin;
use derive_more::{Display, Error};
use std::future::Future;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use crate::ResourceId;

/// The future to sleep for a given duration.
pub struct Sleep {
    id: ResourceId,
}

impl Sleep {
    /// Reset the sleep duration.
    pub fn reset(&mut self, duration: Instant) {
        let now = Instant::now();
        let duration = duration.checked_duration_since(now).unwrap_or_default();
        ocall::reset_timer(self.id.0, duration.as_millis() as i32).expect("failed to reset timer");
    }
}

/// Sleep for the specified duration.
///
/// # Example
/// ```ignore
/// use wapo::time;
/// time::sleep(Duration::from_millis(100)).await;
/// ```
pub fn sleep(duration: Duration) -> Sleep {
    let id = ocall::create_timer(duration.as_millis() as i32).expect("failed to create timer");
    Sleep { id: ResourceId(id) }
}

/// Sleep until the specified instant.
///
/// # Example
/// ```ignore
/// use wapo::time;
/// use std::time::Instant;
/// time::sleep_until(Instant::now() + Duration::from_millis(100)).await;
/// ```
pub fn sleep_until(instant: Instant) -> Sleep {
    let now = Instant::now();
    let duration = instant.checked_duration_since(now).unwrap_or_default();
    sleep(duration)
}

impl Future for Sleep {
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        use env::OcallError;
        let waker_id = env::tasks::intern_waker(cx.waker().clone());
        let rv = ocall::poll_read(waker_id, self.id.0, &mut []);
        match rv {
            Ok(_) => Poll::Ready(()),
            Err(OcallError::Pending) => Poll::Pending,
            Err(err) => panic!("unexpected error: {err:?}"),
        }
    }
}

/// Indicates that a timeout has elapsed for `timeout(future)`.
#[derive(Display, Error, Debug)]
pub struct TimedOut;

/// Timeout the provided future for the specified duration.
pub async fn timeout<T: Future<Output = O>, O>(
    duration: Duration,
    future: T,
) -> Result<O, TimedOut> {
    use futures::FutureExt;
    futures::select! {
        v = future.fuse() => Ok(v),
        _ = sleep(duration).fuse() => Err(TimedOut),
    }
}

/// The future returned by `fn breath`.
pub struct Breath {
    pending: bool,
}

impl Breath {
    /// Creates a new `Breath` instance.
    pub fn new(pending: bool) -> Self {
        Breath { pending }
    }
}

impl Future for Breath {
    type Output = ();
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        if self.pending {
            // Return `Pending` and become Ready immediately.
            self.pending = false;
            cx.waker().wake_by_ref();
            Poll::Pending
        } else {
            Poll::Ready(())
        }
    }
}

/// Returns a future that yields the current task once and becomes ready immediately.
pub fn breath() -> Breath {
    Breath::new(true)
}
