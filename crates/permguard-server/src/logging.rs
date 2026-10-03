// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! Installs the process-wide subscriber the lifecycle records go to — and,
//! when the configuration asks for it, the OTLP pipeline spans leave over.
//!
//! Records go to standard output, which is where a container runtime collects them, and their shape
//! is whatever the effective configuration asked for: one JSON object per record by default, or
//! human-readable lines for a terminal someone is looking at.
//!
//! Spans are a separate concern with a separate failure posture: they leave from a dedicated
//! background thread with a bounded queue, so **a collector that is down means dropped spans and
//! a warning — never a slower or failing request**. Serving traffic is the job; describing it is
//! best-effort.
//!
//! Installing a subscriber is a process-global effect, so it happens once, from the entry point that
//! owns the process — not from a library path a test or a downstream command might take twice.

use anyhow::{Context, Result};
use tracing::{Level, info};
use tracing_subscriber::layer::SubscriberExt as _;
use tracing_subscriber::util::SubscriberInitExt as _;

use permguard_core::{Config, LogFormat, LogLevel, ProductIdentity};

/// Keeps the OTLP pipeline alive for the life of the process; dropping it
/// flushes what is buffered and shuts the exporter down. A build that did not
/// turn tracing on holds an empty guard and pays nothing.
pub struct TelemetryGuard(Option<opentelemetry_sdk::trace::SdkTracerProvider>);

impl Drop for TelemetryGuard {
    fn drop(&mut self) {
        if let Some(provider) = self.0.take() {
            // Best-effort by design: the process is leaving either way.
            let _ = provider.shutdown();
        }
    }
}

/// Installs the subscriber the effective config asks for, and the OTLP span
/// pipeline when `telemetry.otel.enabled` says so.
///
/// Fails when a subscriber is already installed, because that means two things in one process both
/// believe they decide where records go, and silently letting the first one win hides it.
pub fn install(config: &Config) -> Result<TelemetryGuard> {
    let level = tracing_subscriber::filter::LevelFilter::from_level(level_of(config.log_level()));

    let (provider, otel_layer) = if config.otel_enabled() {
        let provider = span_pipeline(config)?;
        let tracer = opentelemetry::trace::TracerProvider::tracer(&provider, "permguard");
        (
            Some(provider),
            Some(tracing_opentelemetry::layer().with_tracer(tracer)),
        )
    } else {
        (None, None)
    };

    let registry = tracing_subscriber::registry().with(level).with(otel_layer);

    // Every record goes through a bounded queue to a writer thread: a stdout nobody drains — a
    // full pipe, a stalled collector — fills the queue and costs dropped lines, never a decision.
    let lines = BoundedLines::new(LINE_QUEUE, std::io::stdout);
    match config.log_format() {
        LogFormat::Json => registry
            .with(
                tracing_subscriber::fmt::layer()
                    .json()
                    .flatten_event(true)
                    .with_current_span(false)
                    .with_writer(lines),
            )
            .try_init(),
        LogFormat::Terminal => registry
            .with(tracing_subscriber::fmt::layer().with_writer(lines))
            .try_init(),
    }
    .map_err(|error| anyhow::anyhow!(error))
    .context("installing the log subscriber")?;

    Ok(TelemetryGuard(provider))
}

/// How many formatted log records may wait for the writer thread before new ones are dropped.
const LINE_QUEUE: usize = 8_192;

/// Log records dropped because the queue to the writer was full.
pub const LOG_LINES_DROPPED: permguard_core::Metric = permguard_core::Metric::counter(
    "permguard_log_lines_dropped_total",
    "Log records dropped because the writer could not keep up; recording never waits for it.",
);

/// How many ended spans may wait for export before new ones are dropped. The SDK's batch queue is
/// sized to the same number, so it never overflows by itself: every span that does not reach the
/// exporter is dropped, and counted, here.
const SPAN_QUEUE: usize = 2_048;

/// Trace spans dropped because the export queue was full or their export failed.
pub const TRACE_SPANS_DROPPED: permguard_core::Metric = permguard_core::Metric::counter(
    "permguard_trace_spans_dropped_total",
    "Trace spans dropped because the export queue was full or the export failed; nothing waits for the exporter.",
);

/// Where dropped lines and spans are counted, once the process has a metrics registry. Logging is
/// installed before the registry exists, so the handle arrives later; until it does, drops are only
/// kept in [`dropped_lines`] and [`dropped_spans`].
static DROP_METRICS: std::sync::OnceLock<permguard_core::Metrics> = std::sync::OnceLock::new();
static DROPPED: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
static DROPPED_SPANS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Trace spans dropped since the process started.
pub fn dropped_spans() -> u64 {
    DROPPED_SPANS.load(std::sync::atomic::Ordering::Relaxed)
}

fn record_span_drops(spans: u64) {
    DROPPED_SPANS.fetch_add(spans, std::sync::atomic::Ordering::Relaxed);
    if let Some(metrics) = DROP_METRICS.get() {
        metrics.add(&TRACE_SPANS_DROPPED, &[], spans as f64);
    }
}

/// Counts dropped log lines and trace spans into `metrics` from now on.
pub fn count_drops_into(metrics: permguard_core::Metrics) {
    let _ = DROP_METRICS.set(metrics);
}

/// Log lines dropped since the process started.
pub fn dropped_lines() -> u64 {
    DROPPED.load(std::sync::atomic::Ordering::Relaxed)
}

fn record_drop() {
    DROPPED.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    if let Some(metrics) = DROP_METRICS.get() {
        metrics.count(&LOG_LINES_DROPPED, &[]);
    }
}

/// A `tracing` writer that never blocks the caller.
///
/// Each record is formatted into its own buffer and handed to a bounded queue when the record is
/// complete; one thread drains the queue into the sink. A sink that stops accepting bytes stalls
/// only that thread: the queue fills and later records are dropped and counted, while the code
/// that logged — a decision, an ingest — carries on. Required audit evidence does not travel
/// here: the durable audit trail is appended by its own sink.
#[derive(Clone)]
pub struct BoundedLines {
    queue: std::sync::mpsc::SyncSender<Vec<u8>>,
}

impl BoundedLines {
    /// A queue of `capacity` records, drained into the writer `sink` makes, on its own thread.
    pub fn new<W, F>(capacity: usize, sink: F) -> Self
    where
        W: std::io::Write,
        F: Fn() -> W + Send + 'static,
    {
        let (queue, records) = std::sync::mpsc::sync_channel::<Vec<u8>>(capacity);
        let spawned = std::thread::Builder::new()
            .name("permguard-log-writer".to_owned())
            .spawn(move || {
                for record in records {
                    let mut out = sink();
                    let _ = out.write_all(&record);
                    let _ = out.flush();
                }
            });
        if let Err(error) = spawned {
            // No thread, no writer: every record is dropped and counted, which is visible, rather
            // than written synchronously, which would bring back the blocking. Said once, on
            // standard error, because the log itself is what just failed.
            eprintln!(
                "permguard: the log writer could not start, every log record is dropped: {error}"
            );
        }

        Self { queue }
    }
}

/// One record being formatted; queued, or dropped, when the formatter is done with it.
pub struct BoundedLine {
    record: Vec<u8>,
    queue: std::sync::mpsc::SyncSender<Vec<u8>>,
}

impl std::io::Write for BoundedLine {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.record.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Drop for BoundedLine {
    fn drop(&mut self) {
        if self.record.is_empty() {
            return;
        }
        if self
            .queue
            .try_send(std::mem::take(&mut self.record))
            .is_err()
        {
            record_drop();
        }
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for BoundedLines {
    type Writer = BoundedLine;

    fn make_writer(&'a self) -> Self::Writer {
        BoundedLine {
            record: Vec::new(),
            queue: self.queue.clone(),
        }
    }
}

/// Builds the OTLP/gRPC span pipeline: batch export from its own thread,
/// bounded queue with every drop counted, parent-based ratio sampling. Building fails only on a
/// malformed endpoint — an unreachable one is a runtime drop, not an error,
/// because observability must never gate availability.
fn span_pipeline(config: &Config) -> Result<opentelemetry_sdk::trace::SdkTracerProvider> {
    use opentelemetry_otlp::WithExportConfig as _;
    use opentelemetry_sdk::trace::{Sampler, SdkTracerProvider};

    let exporter = opentelemetry_otlp::SpanExporter::builder()
        .with_tonic()
        .with_endpoint(config.otel_endpoint())
        .build()
        .context("building the OTLP span exporter")?;

    Ok(SdkTracerProvider::builder()
        .with_span_processor(counted_batch(exporter))
        .with_sampler(Sampler::ParentBased(Box::new(Sampler::TraceIdRatioBased(
            config.otel_sample_rate(),
        ))))
        .with_resource(
            opentelemetry_sdk::Resource::builder()
                .with_service_name("permguard")
                .build(),
        )
        .build())
}

/// The SDK's batch processor around `exporter`, with every drop counted.
///
/// The batch processor already exports from its own thread through a bounded queue, but a span it
/// drops is gone without a trace in any metric. So the spans waiting for export are counted on the
/// way in and on the way out: a span that would exceed [`SPAN_QUEUE`] is dropped here and counted,
/// which keeps the processor's own queue — sized the same — from ever dropping one by itself, and a
/// batch the exporter fails to deliver is counted too.
fn counted_batch<E>(exporter: E) -> CountedSpans<opentelemetry_sdk::trace::BatchSpanProcessor>
where
    E: opentelemetry_sdk::trace::SpanExporter + 'static,
{
    use opentelemetry_sdk::trace::{BatchConfigBuilder, BatchSpanProcessor};

    let waiting = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let processor = BatchSpanProcessor::builder(CountedExporter {
        inner: exporter,
        waiting: std::sync::Arc::clone(&waiting),
    })
    .with_batch_config(
        BatchConfigBuilder::default()
            .with_max_queue_size(SPAN_QUEUE)
            .build(),
    )
    .build();

    CountedSpans {
        inner: processor,
        waiting,
        capacity: SPAN_QUEUE,
    }
}

/// A span processor that admits at most `capacity` spans waiting for export and counts the rest.
#[derive(Debug)]
struct CountedSpans<P> {
    inner: P,
    waiting: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    capacity: usize,
}

impl<P: opentelemetry_sdk::trace::SpanProcessor> opentelemetry_sdk::trace::SpanProcessor
    for CountedSpans<P>
{
    fn on_start(&self, span: &mut opentelemetry_sdk::trace::Span, cx: &opentelemetry::Context) {
        self.inner.on_start(span, cx);
    }

    fn on_end(&self, span: opentelemetry_sdk::trace::SpanData) {
        use std::sync::atomic::Ordering;

        let admitted = self
            .waiting
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |held| {
                (held < self.capacity).then_some(held + 1)
            })
            .is_ok();
        if admitted {
            self.inner.on_end(span);
        } else {
            record_span_drops(1);
        }
    }

    fn force_flush(&self) -> opentelemetry_sdk::error::OTelSdkResult {
        self.inner.force_flush()
    }

    fn shutdown_with_timeout(
        &self,
        timeout: std::time::Duration,
    ) -> opentelemetry_sdk::error::OTelSdkResult {
        self.inner.shutdown_with_timeout(timeout)
    }

    fn set_resource(&mut self, resource: &opentelemetry_sdk::Resource) {
        self.inner.set_resource(resource);
    }
}

/// An exporter that releases what [`CountedSpans`] admitted, and counts a batch it fails to send.
#[derive(Debug)]
struct CountedExporter<E> {
    inner: E,
    waiting: std::sync::Arc<std::sync::atomic::AtomicUsize>,
}

impl<E: opentelemetry_sdk::trace::SpanExporter> opentelemetry_sdk::trace::SpanExporter
    for CountedExporter<E>
{
    fn export(
        &self,
        batch: Vec<opentelemetry_sdk::trace::SpanData>,
    ) -> impl std::future::Future<Output = opentelemetry_sdk::error::OTelSdkResult> + Send {
        use std::sync::atomic::Ordering;

        let size = batch.len();
        let _ = self
            .waiting
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |held| {
                Some(held.saturating_sub(size))
            });
        let exported = self.inner.export(batch);

        async move {
            let result = exported.await;
            if result.is_err() {
                record_span_drops(size as u64);
            }

            result
        }
    }

    fn shutdown_with_timeout(
        &self,
        timeout: std::time::Duration,
    ) -> opentelemetry_sdk::error::OTelSdkResult {
        self.inner.shutdown_with_timeout(timeout)
    }

    fn force_flush(&self) -> opentelemetry_sdk::error::OTelSdkResult {
        self.inner.force_flush()
    }

    fn set_resource(&mut self, resource: &opentelemetry_sdk::Resource) {
        self.inner.set_resource(resource);
    }
}

/// Records which build is running, as the first record of the stream.
///
/// In `json` there is no banner, so this record is the only thing that says which build produced
/// everything after it — and a stream nobody can attribute to a build is a stream nobody can act on.
/// In `terminal` the banner says the same thing to a human; the record is emitted either way so the
/// two formats carry the same information.
pub fn record_build(identity: &ProductIdentity, config: &Config, host: &str) {
    info!(
        event.name = "server.build",
        service.name = identity.binary_name(),
        service.version = config.version(),
        server.host = host,
        log.level = config.log_level().as_str(),
        log.format = config.log_format().as_str(),
        otel.enabled = config.otel_enabled(),
        process.pid = std::process::id(),
        "build"
    );
}

/// Maps the configured level onto the one `tracing` filters with.
fn level_of(level: LogLevel) -> Level {
    match level {
        LogLevel::Error => Level::ERROR,
        LogLevel::Warn => Level::WARN,
        LogLevel::Info => Level::INFO,
        LogLevel::Debug => Level::DEBUG,
        LogLevel::Trace => Level::TRACE,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_every_configured_level_maps_to_the_tracing_level_of_the_same_name() {
        assert_eq!(level_of(LogLevel::Error), Level::ERROR);
        assert_eq!(level_of(LogLevel::Warn), Level::WARN);
        assert_eq!(level_of(LogLevel::Info), Level::INFO);
        assert_eq!(level_of(LogLevel::Debug), Level::DEBUG);
        assert_eq!(level_of(LogLevel::Trace), Level::TRACE);
    }

    #[test]
    fn test_the_default_config_asks_for_info_and_json_and_no_export() {
        let config = Config::default();

        assert_eq!(level_of(config.log_level()), Level::INFO);
        assert_eq!(config.log_format(), LogFormat::Json);
        assert!(!config.otel_enabled());
    }

    #[tokio::test]
    async fn test_the_span_pipeline_builds_without_a_collector_listening() {
        // The failure posture in one assertion: building the pipeline needs no
        // collector — an unreachable endpoint is a runtime drop, never an
        // error. The tonic exporter wants a runtime to exist, which the server
        // guarantees by installing from its async entry point.
        let config = Config::default();
        let provider = span_pipeline(&config);
        assert!(provider.is_ok());
    }
}

#[cfg(test)]
mod bounded_tests {
    #![allow(clippy::expect_used)]

    use super::*;
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};
    use tracing_subscriber::fmt::MakeWriter as _;

    /// A sink that never returns from its first write: a stdout nobody drains.
    struct Blocked(Arc<Mutex<()>>);

    impl std::io::Write for Blocked {
        fn write(&mut self, _bytes: &[u8]) -> std::io::Result<usize> {
            let _held = self.0.lock();
            std::thread::sleep(Duration::from_secs(3_600));
            Ok(0)
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn test_a_blocked_sink_never_delays_the_caller_and_the_overflow_is_dropped_and_counted() {
        let gate = Arc::new(Mutex::new(()));
        let lines = BoundedLines::new(16, move || Blocked(Arc::clone(&gate)));
        let subscriber = tracing_subscriber::fmt().with_writer(lines).finish();
        let before = dropped_lines();

        let started = Instant::now();
        tracing::subscriber::with_default(subscriber, || {
            for record in 0..10_000 {
                tracing::info!(record, "a decision was made");
            }
        });
        let elapsed = started.elapsed();

        assert!(
            elapsed < Duration::from_secs(2),
            "10 000 records took {elapsed:?} against a sink that never returns"
        );
        assert!(
            dropped_lines() - before >= 10_000 - 17,
            "everything beyond the queue and the one record in the writer is dropped"
        );
    }

    #[test]
    fn test_a_draining_sink_receives_every_record_whole() {
        let held = Arc::new(Mutex::new(Vec::<u8>::new()));
        struct Shared(Arc<Mutex<Vec<u8>>>);
        impl std::io::Write for Shared {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                self.0
                    .lock()
                    .expect("not poisoned")
                    .extend_from_slice(bytes);
                Ok(bytes.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let sink = Arc::clone(&held);
        let lines = BoundedLines::new(1_024, move || Shared(Arc::clone(&sink)));
        {
            use std::io::Write as _;
            let mut one = lines.make_writer();
            one.write_all(b"first half, ").expect("buffered");
            one.write_all(b"second half\n").expect("buffered");
        }
        let deadline = Instant::now() + Duration::from_secs(5);
        while held.lock().expect("not poisoned").is_empty() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(5));
        }
        assert_eq!(
            &*held.lock().expect("not poisoned"),
            b"first half, second half\n"
        );
    }
}

#[cfg(test)]
mod span_tests {
    #![allow(clippy::expect_used)]

    use super::*;
    use opentelemetry::trace::{Tracer as _, TracerProvider as _};
    use std::sync::{Arc, Condvar, Mutex};
    use std::time::{Duration, Instant};

    /// A collector that accepts nothing until it is released: the export thread waits on it.
    #[derive(Debug, Clone, Default)]
    struct Stalled(Arc<(Mutex<bool>, Condvar)>);

    impl Stalled {
        fn release(&self) {
            let (released, wake) = &*self.0;
            *released.lock().expect("not poisoned") = true;
            wake.notify_all();
        }
    }

    impl opentelemetry_sdk::trace::SpanExporter for Stalled {
        fn export(
            &self,
            _batch: Vec<opentelemetry_sdk::trace::SpanData>,
        ) -> impl std::future::Future<Output = opentelemetry_sdk::error::OTelSdkResult> + Send
        {
            let gate = Arc::clone(&self.0);
            async move {
                let (released, wake) = &*gate;
                let mut held = released.lock().expect("not poisoned");
                while !*held {
                    held = wake.wait(held).expect("not poisoned");
                }

                Ok(())
            }
        }
    }

    /// A collector that refuses every batch.
    #[derive(Debug)]
    struct Refusing;

    impl opentelemetry_sdk::trace::SpanExporter for Refusing {
        async fn export(
            &self,
            _batch: Vec<opentelemetry_sdk::trace::SpanData>,
        ) -> opentelemetry_sdk::error::OTelSdkResult {
            Err(opentelemetry_sdk::error::OTelSdkError::InternalFailure(
                "the collector refused".to_owned(),
            ))
        }
    }

    // One test, not two: both read the process-wide drop count, and run in parallel they would
    // count each other's drops.
    #[test]
    fn test_a_stalled_collector_drops_and_counts_spans_and_never_delays_the_caller() {
        let stalled = Stalled::default();
        let provider = opentelemetry_sdk::trace::SdkTracerProvider::builder()
            .with_span_processor(counted_batch(stalled.clone()))
            .build();
        let tracer = provider.tracer("stalled");
        let before = dropped_spans();

        let started = Instant::now();
        for _ in 0..10_000 {
            tracer.in_span("decision", |_| {});
        }
        let elapsed = started.elapsed();

        let dropped = dropped_spans() - before;
        assert!(
            elapsed < Duration::from_secs(2),
            "ending spans waited for the collector: {elapsed:?}"
        );
        // At most the queue and one batch in the exporter's hands were admitted.
        assert!(
            dropped >= 10_000 - 2 * SPAN_QUEUE as u64,
            "only {dropped} spans were counted as dropped"
        );
        stalled.release();
        provider.shutdown().expect("the provider shuts down");

        let provider = opentelemetry_sdk::trace::SdkTracerProvider::builder()
            .with_span_processor(counted_batch(Refusing))
            .build();
        let tracer = provider.tracer("refusing");
        let before = dropped_spans();
        for _ in 0..10 {
            tracer.in_span("decision", |_| {});
        }
        assert!(
            provider.force_flush().is_err(),
            "the flush reports the refused batch"
        );
        assert_eq!(
            dropped_spans() - before,
            10,
            "spans the collector refused were not counted"
        );
        let _ = provider.shutdown();
    }
}
