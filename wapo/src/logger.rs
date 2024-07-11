//! Logger for wapo programs.

use env_filter::{Builder, Filter};
use log::{Log, Metadata, Record};
use wapo_env::ocall_funcs_guest as ocall;

/// A logger working inside a wapo guest.
pub struct Logger {
    filter: Filter,
}

/// Initialize the logger with the filter set by the `WAPO_LOG` environment variable.
pub fn init() {
    let filter_str = std::env::var("RUST_LOG").unwrap_or_else(|_| "info".to_string());
    let filter = Builder::new().parse(&filter_str).build();
    Logger::new(filter).init();
}

impl Logger {
    /// Create a new logger with the given filter.
    pub fn new(filter: Filter) -> Self {
        Self { filter }
    }

    /// Install the logger as the global logger.
    pub fn init(self) {
        log::set_max_level(log::LevelFilter::Trace);
        log::set_boxed_logger(Box::new(self)).expect("failed to set logger");
    }

    /// Install the logger as the global logger, but for static lifetime.
    pub fn init_static(&'static self) {
        log::set_max_level(log::LevelFilter::Trace);
        log::set_logger(self).expect("failed to set logger");
    }
}

impl Log for Logger {
    fn enabled(&self, metadata: &Metadata) -> bool {
        self.filter.enabled(metadata)
    }

    fn log(&self, record: &Record) {
        if self.enabled(record.metadata()) {
            let message = format!("{}: {}", record.target(), record.args());

            let _ = ocall::log(record.level(), &message);
        }
    }

    fn flush(&self) {}
}

pub use poll_logging::{log_polling, LogFuture};
mod poll_logging {
    use std::future::Future;

    /// A future that logs polling.
    #[pin_project::pin_project]
    pub struct LogFuture<F> {
        label: String,
        #[pin]
        fut: F,
    }

    /// Create a future that logs polling.
    pub fn log_polling<F: Future>(label: &str, fut: F) -> LogFuture<F> {
        LogFuture {
            label: label.to_string(),
            fut,
        }
    }

    impl<F> Future for LogFuture<F>
    where
        F: Future,
    {
        type Output = F::Output;

        fn poll(
            self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Self::Output> {
            let this = self.project();
            let label = this.label;
            let output = this.fut.poll(cx);
            log::trace!("polled <{}>, ready={}", label, output.is_ready());
            output
        }
    }
}
