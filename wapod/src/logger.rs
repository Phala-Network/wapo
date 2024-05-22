use tracing::{
    info,
    level_filters::LevelFilter,
    span::{Attributes, Id, Record},
    subscriber::Interest,
    warn, Event, Metadata,
};
use tracing_subscriber::{
    layer::{Context, Filter, SubscriberExt},
    util::SubscriberInitExt,
    EnvFilter, Layer,
};

struct SanitizedFilter(EnvFilter);

impl<S> Filter<S> for SanitizedFilter {
    fn callsite_enabled(&self, metadata: &'static Metadata<'static>) -> Interest {
        if !target_allowed(metadata.target()) {
            return Interest::never();
        }
        <EnvFilter as Filter<S>>::callsite_enabled(&self.0, metadata)
    }

    fn enabled(&self, metadata: &Metadata<'_>, ctx: &Context<'_, S>) -> bool {
        if !target_allowed(metadata.target()) {
            return false;
        }
        <EnvFilter as Filter<S>>::enabled(&self.0, metadata, ctx)
    }

    fn event_enabled(&self, event: &Event<'_>, ctx: &Context<'_, S>) -> bool {
        <EnvFilter as Filter<S>>::event_enabled(&self.0, event, ctx)
    }

    fn max_level_hint(&self) -> Option<LevelFilter> {
        <EnvFilter as Filter<S>>::max_level_hint(&self.0)
    }

    fn on_new_span(&self, attrs: &Attributes<'_>, id: &Id, ctx: Context<'_, S>) {
        <EnvFilter as Filter<S>>::on_new_span(&self.0, attrs, id, ctx)
    }

    fn on_record(&self, id: &Id, values: &Record<'_>, ctx: Context<'_, S>) {
        <EnvFilter as Filter<S>>::on_record(&self.0, id, values, ctx)
    }

    fn on_enter(&self, id: &Id, ctx: Context<'_, S>) {
        <EnvFilter as Filter<S>>::on_enter(&self.0, id, ctx)
    }

    fn on_exit(&self, id: &Id, ctx: Context<'_, S>) {
        <EnvFilter as Filter<S>>::on_exit(&self.0, id, ctx)
    }

    fn on_close(&self, id: Id, ctx: Context<'_, S>) {
        <EnvFilter as Filter<S>>::on_close(&self.0, id, ctx)
    }
}

fn target_allowed(target: &str) -> bool {
    use MatchMode::*;
    enum MatchMode {
        Prefix,
        Eq,
    }

    // Keep more frequently targets in the front
    let whitelist = [
        ("wapo", Prefix),
        ("rocket::launch", Prefix),
        ("rocket::server", Eq),
        ("prpc_measuring", Eq),
    ];
    for (rule, mode) in whitelist.into_iter() {
        match mode {
            Prefix => {
                if target.starts_with(rule) {
                    return true;
                }
            }
            Eq => {
                if rule == target {
                    return true;
                }
            }
        }
    }
    false
}

pub fn init() {
    let default_fileter = EnvFilter::builder()
        .with_default_directive(LevelFilter::INFO.into())
        .from_env_lossy();
    if std::env::var("RUST_LOG_SANITIZED") == Ok("true".to_string()) {
        let filter = SanitizedFilter(default_fileter);
        let layer = tracing_subscriber::fmt::layer().with_filter(filter);
        tracing_subscriber::registry().with(layer).init();
        info!("sanitized logging enabled");
    } else {
        tracing_subscriber::fmt()
            .with_env_filter(default_fileter)
            .init();
        warn!("log is not sanitized");
    }
}
