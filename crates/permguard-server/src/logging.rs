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

    match config.log_format() {
        LogFormat::Json => registry
            .with(
                tracing_subscriber::fmt::layer()
                    .json()
                    .flatten_event(true)
                    .with_current_span(false),
            )
            .try_init(),
        LogFormat::Terminal => registry.with(tracing_subscriber::fmt::layer()).try_init(),
    }
    .map_err(|error| anyhow::anyhow!(error))
    .context("installing the log subscriber")?;

    Ok(TelemetryGuard(provider))
}

/// Builds the OTLP/gRPC span pipeline: batch export from its own thread,
/// bounded queue, parent-based ratio sampling. Building fails only on a
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
        .with_batch_exporter(exporter)
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
