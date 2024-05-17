//! Executors to bridge frameworks to wapo.

/// A hyper executor that executes futures with wapo::spawn.
#[derive(Clone, Copy, Debug)]
pub struct HyperExecutor;

#[cfg(feature = "hyper-v0")]
mod hyper_v0 {
    impl<Fut> ::hyper_v0::rt::Executor<Fut> for super::HyperExecutor
    where
        Fut: std::future::Future + 'static,
    {
        fn execute(&self, fut: Fut) {
            crate::spawn(fut);
        }
    }
}

#[cfg(feature = "hyper-v1")]
pub use hyper_v1::HyperTimer;
#[cfg(feature = "hyper-v1")]
mod hyper_v1 {
    //! IO integration for hyper
    use std::{
        future::Future,
        pin::Pin,
        task::{Context, Poll},
        time::{Duration, Instant},
    };

    use hyper::rt::{Executor, Sleep, Timer};
    use pin_project::pin_project;

    impl<F> Executor<F> for super::HyperExecutor
    where
        F: std::future::Future + 'static,
    {
        fn execute(&self, fut: F) {
            crate::spawn(fut);
        }
    }

    /// A Timer that uses the wapo runtime.
    #[non_exhaustive]
    #[derive(Default, Clone, Debug)]
    pub struct HyperTimer;

    // Use HyperSleep to get wapo::time::Sleep to implement Unpin.
    // see https://docs.rs/tokio/latest/tokio/time/struct.Sleep.html
    #[pin_project]
    struct HyperSleep {
        #[pin]
        inner: crate::time::Sleep,
    }

    // ==== impl HyperTimer =====
    impl Timer for HyperTimer {
        fn sleep(&self, duration: Duration) -> Pin<Box<dyn Sleep>> {
            Box::pin(HyperSleep {
                inner: crate::time::sleep(duration),
            })
        }

        fn sleep_until(&self, deadline: Instant) -> Pin<Box<dyn Sleep>> {
            Box::pin(HyperSleep {
                inner: crate::time::sleep_until(deadline),
            })
        }

        fn reset(&self, sleep: &mut Pin<Box<dyn Sleep>>, new_deadline: Instant) {
            if let Some(sleep) = sleep.as_mut().downcast_mut_pin::<HyperSleep>() {
                sleep.reset(new_deadline)
            }
        }
    }

    impl HyperTimer {
        /// Create a new `HyperTimer`.
        pub fn new() -> Self {
            Self {}
        }
    }

    impl Future for HyperSleep {
        type Output = ();

        fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
            self.project().inner.poll(cx)
        }
    }

    impl Sleep for HyperSleep {}

    impl HyperSleep {
        fn reset(self: Pin<&mut Self>, deadline: Instant) {
            self.project().inner.as_mut().reset(deadline);
        }
    }
}
