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
pub use hyper_v1::{HyperTimer, HyperTokioIo};
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

    /// Implement hyper::rt::{Read,Write} for tokio::io::{AsyncRead,AsyncWrite}.
    #[pin_project]
    #[derive(Debug)]
    pub struct HyperTokioIo<T> {
        #[pin]
        inner: T,
    }

    impl<T> HyperTokioIo<T> {
        /// Wrap a tokio::io::AsyncRead/AsyncWrite in a hyper::rt::Read/Write.
        pub fn new(inner: T) -> Self {
            Self { inner }
        }

        /// Get the inner AsyncRead/AsyncWrite.
        pub fn inner(self) -> T {
            self.inner
        }
    }

    impl<T> hyper::rt::Read for HyperTokioIo<T>
    where
        T: tokio::io::AsyncRead,
    {
        fn poll_read(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            mut buf: hyper::rt::ReadBufCursor<'_>,
        ) -> Poll<Result<(), std::io::Error>> {
            let n = unsafe {
                let mut tbuf = tokio::io::ReadBuf::uninit(buf.as_mut());
                match tokio::io::AsyncRead::poll_read(self.project().inner, cx, &mut tbuf) {
                    Poll::Ready(Ok(())) => tbuf.filled().len(),
                    other => return other,
                }
            };

            unsafe {
                buf.advance(n);
            }
            Poll::Ready(Ok(()))
        }
    }

    impl<T> hyper::rt::Write for HyperTokioIo<T>
    where
        T: tokio::io::AsyncWrite,
    {
        fn poll_write(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<Result<usize, std::io::Error>> {
            tokio::io::AsyncWrite::poll_write(self.project().inner, cx, buf)
        }

        fn poll_flush(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
        ) -> Poll<Result<(), std::io::Error>> {
            tokio::io::AsyncWrite::poll_flush(self.project().inner, cx)
        }

        fn poll_shutdown(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
        ) -> Poll<Result<(), std::io::Error>> {
            tokio::io::AsyncWrite::poll_shutdown(self.project().inner, cx)
        }

        fn is_write_vectored(&self) -> bool {
            tokio::io::AsyncWrite::is_write_vectored(&self.inner)
        }

        fn poll_write_vectored(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            bufs: &[std::io::IoSlice<'_>],
        ) -> Poll<Result<usize, std::io::Error>> {
            tokio::io::AsyncWrite::poll_write_vectored(self.project().inner, cx, bufs)
        }
    }

    impl<T> tokio::io::AsyncRead for HyperTokioIo<T>
    where
        T: hyper::rt::Read,
    {
        fn poll_read(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            tbuf: &mut tokio::io::ReadBuf<'_>,
        ) -> Poll<Result<(), std::io::Error>> {
            //let init = tbuf.initialized().len();
            let filled = tbuf.filled().len();
            let sub_filled = unsafe {
                let mut buf = hyper::rt::ReadBuf::uninit(tbuf.unfilled_mut());

                match hyper::rt::Read::poll_read(self.project().inner, cx, buf.unfilled()) {
                    Poll::Ready(Ok(())) => buf.filled().len(),
                    other => return other,
                }
            };

            let n_filled = filled + sub_filled;
            // At least sub_filled bytes had to have been initialized.
            let n_init = sub_filled;
            unsafe {
                tbuf.assume_init(n_init);
                tbuf.set_filled(n_filled);
            }

            Poll::Ready(Ok(()))
        }
    }

    impl<T> tokio::io::AsyncWrite for HyperTokioIo<T>
    where
        T: hyper::rt::Write,
    {
        fn poll_write(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<Result<usize, std::io::Error>> {
            hyper::rt::Write::poll_write(self.project().inner, cx, buf)
        }

        fn poll_flush(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
        ) -> Poll<Result<(), std::io::Error>> {
            hyper::rt::Write::poll_flush(self.project().inner, cx)
        }

        fn poll_shutdown(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
        ) -> Poll<Result<(), std::io::Error>> {
            hyper::rt::Write::poll_shutdown(self.project().inner, cx)
        }

        fn is_write_vectored(&self) -> bool {
            hyper::rt::Write::is_write_vectored(&self.inner)
        }

        fn poll_write_vectored(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            bufs: &[std::io::IoSlice<'_>],
        ) -> Poll<Result<usize, std::io::Error>> {
            hyper::rt::Write::poll_write_vectored(self.project().inner, cx, bufs)
        }
    }
}
