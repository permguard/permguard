// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The Host's time guard, composed (WP-2.12): the key rings read it, readiness and the audit
//! trail hear of its anomalies, and a periodic pass reads it when nothing else does.

use std::sync::Arc;
use std::time::Duration;

use permguard_core::Subject;
use permguard_core::lifecycle::HOST;
use permguard_core::server::{AuditRecorder, Health};
use permguard_host::time::{
    AUDIT_CLOCK_ANOMALY, AUDIT_CLOCK_RESTORED, CAPABILITY, Observer, TimeGuard, Transition,
};

/// How often the periodic pass reads the clocks: a jump, or its end, is noticed within this even
/// when no request reads the time.
const TICK: Duration = Duration::from_secs(1);

/// A key ring's clock, read through the guard: rotation and retirement compare wall time like
/// every other expiry on the Host.
pub struct GuardedKeyClock(pub Arc<TimeGuard>);

impl permguard_std::keys::Clock for GuardedKeyClock {
    fn now(&self) -> u64 {
        self.0.now_secs()
    }
}

/// Tells readiness, the log and the audit trail of every transition of the guard.
pub struct HostClockObserver {
    health: Health,
    recorder: Option<AuditRecorder>,
}

impl HostClockObserver {
    /// An observer reporting on `health`, recording through `recorder` when one is composed.
    pub fn new(health: Health, recorder: Option<AuditRecorder>) -> Self {
        Self { health, recorder }
    }

    fn record(&self, action: &'static str, target: String) {
        let Some(recorder) = self.recorder.clone() else {
            return;
        };
        // The guard calls from whatever thread read the clock, and a record is async: written on
        // the runtime, its failure logged, since the transition itself is already in force.
        let Ok(runtime) = tokio::runtime::Handle::try_current() else {
            tracing::error!(
                event.name = "host.clock_unrecorded",
                component = HOST,
                action,
                "a clock transition was read outside the runtime and could not be recorded"
            );
            return;
        };
        runtime.spawn(async move {
            if let Err(error) = recorder
                .record_on(action, Subject::System(HOST), &target)
                .await
            {
                tracing::error!(
                    event.name = "host.clock_unrecorded",
                    component = HOST,
                    action,
                    error = %error,
                    "a clock transition could not be recorded"
                );
            }
        });
    }
}

impl Observer for HostClockObserver {
    fn transition(&self, transition: &Transition) {
        match transition {
            Transition::Opened(anomaly) => {
                tracing::error!(
                    event.name = AUDIT_CLOCK_ANOMALY,
                    component = HOST,
                    observed = anomaly.observed,
                    expected = anomaly.expected,
                    jump_seconds = anomaly.jump(),
                    bound_seconds = anomaly.bound,
                    "the wall clock stepped back beyond its bound: new leases and time-sensitive \
                     signatures are unavailable until it catches up"
                );
                self.health
                    .lifecycle()
                    .degrade(HOST, CAPABILITY, anomaly.to_string());
                self.record(
                    AUDIT_CLOCK_ANOMALY,
                    format!(
                        "observed={} expected={} jump={}s bound={}s",
                        anomaly.observed,
                        anomaly.expected,
                        anomaly.jump(),
                        anomaly.bound
                    ),
                );
            }
            Transition::Closed { anomaly, observed } => {
                tracing::info!(
                    event.name = AUDIT_CLOCK_RESTORED,
                    component = HOST,
                    observed,
                    expected = anomaly.expected,
                    "the wall clock caught up: leases and time-sensitive signatures are available"
                );
                self.health.lifecycle().restore(HOST, CAPABILITY);
                self.record(
                    AUDIT_CLOCK_RESTORED,
                    format!("observed={observed} expected={}", anomaly.expected),
                );
            }
        }
    }
}

/// The periodic pass, stopped when this is dropped: every way out of a serve ends it, an error
/// before the server runs included.
pub struct Ticking(tokio::task::JoinHandle<()>);

impl Drop for Ticking {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// Reads the guard every [`TICK`] until the handle is dropped.
pub fn tick(time: Arc<TimeGuard>) -> Ticking {
    Ticking(tokio::spawn(async move {
        let mut interval = tokio::time::interval(TICK);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            interval.tick().await;
            time.tick();
        }
    }))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use std::sync::Mutex;

    use permguard_core::{AuditError, AuditEvent, AuditSink, BoxFuture};
    use permguard_host::time::{ManualClock, ManualMonotonic};

    use super::*;

    /// Keeps the action and target of every record.
    #[derive(Default)]
    struct Kept(Mutex<Vec<(String, String)>>);

    impl AuditSink for Kept {
        fn name(&self) -> &'static str {
            "kept"
        }

        fn record<'a>(
            &'a self,
            event: &'a AuditEvent<'a>,
            _: Option<&'a dyn permguard_core::pseudonym::Pseudonymizer>,
        ) -> BoxFuture<'a, Result<(), AuditError>> {
            self.0.lock().expect("held").push((
                event.action().to_owned(),
                event.target().unwrap_or_default().to_owned(),
            ));
            permguard_core::ready(Ok(()))
        }
    }

    async fn settle() {
        for _ in 0..10 {
            tokio::task::yield_now().await;
        }
    }

    /// WP-2.12 step 2: the anomaly degrades `time` on the Host without touching readiness, and is
    /// recorded; its end restores the capability and is recorded too.
    #[tokio::test]
    async fn an_anomaly_degrades_time_keeps_readiness_and_is_recorded_both_ways() {
        let health = Health::new();
        health.set_ready(true);
        assert!(health.is_ready());
        let kept = Arc::new(Kept::default());
        let wall = Arc::new(ManualClock::at(1_800_000_000));
        let time = TimeGuard::new(
            wall.clone(),
            Arc::new(ManualMonotonic::default()),
            Duration::from_secs(30),
        );
        time.observe(Arc::new(HostClockObserver::new(
            health.clone(),
            Some(AuditRecorder::new(kept.clone())),
        )));

        wall.jump(-120);
        time.tick();
        settle().await;
        let report = health.lifecycle().report(HOST);
        assert_eq!(report.degraded.len(), 1, "{:?}", report.degraded);
        assert_eq!(report.degraded[0].capability, CAPABILITY);
        assert!(report.degraded[0].reason.contains("120s back"));
        assert!(health.is_ready(), "decisions keep being served");

        wall.jump(120);
        time.tick();
        settle().await;
        assert!(health.lifecycle().report(HOST).degraded.is_empty());
        let records = kept.0.lock().expect("held").clone();
        assert_eq!(
            records
                .iter()
                .map(|(action, _)| action.as_str())
                .collect::<Vec<_>>(),
            vec![AUDIT_CLOCK_ANOMALY, AUDIT_CLOCK_RESTORED]
        );
        assert!(records[0].1.contains("jump=120s"), "{records:?}");
    }
}
