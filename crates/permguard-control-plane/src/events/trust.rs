// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! Re-reading the producers' published key sets, on a schedule.
//!
//! # Why a timer and not only the unattributable batch
//!
//! A producer publishes its own keys into a file this plane reads, and it rotates them. The facade
//! already re-reads that file when a batch arrives it cannot attribute, which repairs a rotation
//! the moment it costs somebody a batch. That is the right reflex and the wrong only mechanism: it
//! makes "this plane trusts nobody" a state discovered by a producer failing, and on a first start
//! — a clean volume, a control plane scheduled before the plane that signs — there is no batch to
//! discover it with, because the producer is refusing to ship to a plane that would refuse it.
//!
//! So the same re-read runs on a timer. A file that appears is picked up without a restart, and a
//! plane whose trust set is empty says so on every tick rather than waiting to be asked.
//!
//! # What this deliberately does not do
//!
//! It does not install a partial set. The facade's re-read builds the whole set and
//! swaps it in one write, or fails and leaves the last good one in place — so a malformed rotation
//! keeps serving the keys that worked, and this service reports it rather than widening it.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::Result;
use permguard_core::metrics::Metrics;
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tracing::{info, warn};

use crate::events::http::EventFacade;

/// The `component` every record of the trust set carries.
const COMPONENT: &str = "event-trust";

/// How often the published sets are re-read when nothing says otherwise.
const DEFAULT_INTERVAL: Duration = Duration::from_secs(30);

/// Re-reads the producers' published key sets while the plane runs.
pub struct EventTrustService {
    /// An explicit cadence. `None` takes [`DEFAULT_INTERVAL`]; `Some` is for a test that cannot
    /// wait for it.
    every: Option<Duration>,
    facade: Option<Arc<Mutex<Option<EventFacade>>>>,
    running: Mutex<Option<Running>>,
}

struct Running {
    task: JoinHandle<()>,
    stop: watch::Sender<bool>,
}

impl Default for EventTrustService {
    fn default() -> Self {
        Self::new()
    }
}

impl EventTrustService {
    pub fn new() -> Self {
        Self {
            every: None,
            facade: None,
            running: Mutex::new(None),
        }
    }

    /// Re-reads at a fixed cadence regardless of the default.
    pub fn every(mut self, every: Duration) -> Self {
        self.every = Some(every);

        self
    }

    /// Watches the facade already composed for HTTP and gRPC.
    ///
    /// The same value, not a copy of its configuration: the trust set lives behind an `Arc`, so a
    /// set reloaded here is the set ingestion admits under.
    pub fn with_facade(mut self, facade: Arc<Mutex<Option<EventFacade>>>) -> Self {
        self.facade = Some(facade);

        self
    }
}

/// One pass, and what it changed.
///
/// `Ok(count)` is the number of producers now trusted. Reported by the caller rather than logged
/// here, so a steady state does not narrate itself once a tick.
pub(crate) fn reload_once(facade: &EventFacade) -> Result<usize, String> {
    facade.reload_producers()?;

    Ok(facade.accepted_producers().len())
}

impl permguard_core::Service for EventTrustService {
    fn name(&self) -> &'static str {
        "event-trust"
    }

    fn start<'a>(
        &'a self,
        context: &'a permguard_core::ServerContext<'a>,
    ) -> permguard_core::BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            let config = context.config();
            if !config.event_store_enabled() || !config.experimental_dogwood() {
                return Ok(());
            }
            let Some(shared) = self.facade.clone() else {
                return Ok(());
            };

            let every = self.every.unwrap_or(DEFAULT_INTERVAL);
            let metrics: Metrics = context.metrics().clone();
            let (stop, mut stopped) = watch::channel(false);
            let task = tokio::spawn(async move {
                // What the last tick found, so a steady state is silent and a change is not.
                let mut announced: Option<usize> = None;
                loop {
                    tokio::select! {
                        _ = tokio::time::sleep(every) => {
                            let facade = shared.lock().ok().and_then(|held| held.clone());
                            let Some(facade) = facade else { continue };
                            let outcome = tokio::task::spawn_blocking(move || {
                                let count = reload_once(&facade);
                                (count, facade)
                            })
                            .await;
                            let Ok((outcome, _facade)) = outcome else { continue };
                            match outcome {
                                Ok(count) => {
                                    metrics.set(&crate::events::measure::TRUSTED_PRODUCERS, &[], count as f64);
                                    if announced != Some(count) {
                                        info!(
                                            event.name = "events.trust_loaded",
                                            component = COMPONENT,
                                            producers = count,
                                            "the published producer key sets were read"
                                        );
                                        announced = Some(count);
                                    }
                                }
                                Err(why) => {
                                    // The previous set is still installed: this says what could
                                    // not be read, not that trust was widened or dropped.
                                    if announced != Some(0) {
                                        warn!(
                                            event.name = "events.trust_unreadable",
                                            component = COMPONENT,
                                            error = %why,
                                            "a producer's published key set could not be read: the \
                                             last set that loaded stays in force, and batches under \
                                             any other key are refused as unattributable"
                                        );
                                        announced = Some(0);
                                    }
                                }
                            }
                        }
                        _ = stopped.changed() => break,
                    }
                }
            });

            if let Ok(mut running) = self.running.lock() {
                *running = Some(Running { task, stop });
            }

            Ok(())
        })
    }

    fn stop<'a>(
        &'a self,
        _context: &'a permguard_core::ServerContext<'a>,
    ) -> permguard_core::BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            let running = self.running.lock().ok().and_then(|mut held| held.take());
            if let Some(running) = running {
                let _ = running.stop.send(true);
                let _ = running.task.await;
            }

            Ok(())
        })
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use crate::events::http::ProducerFile;

    const KEY: &str = r#"{"keys":[{"kid":"k1","kty":"OKP","crv":"Ed25519","x":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","alg":"EdDSA","use":"sig"}]}"#;
    const OTHER: &str = r#"{"keys":[{"kid":"k2","kty":"OKP","crv":"Ed25519","x":"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB","alg":"EdDSA","use":"sig"}]}"#;

    fn scratch(tag: &str) -> std::path::PathBuf {
        let directory = std::env::temp_dir().join(format!(
            "permguard-trust-{tag}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&directory);
        std::fs::create_dir_all(&directory).expect("the scratch volume exists");

        directory
    }

    fn facade(files: Vec<ProducerFile>) -> EventFacade {
        let root = scratch("store");
        EventFacade {
            store: Arc::new(crate::events::EventStore::open(&root).expect("the store opens")),
            producers: Arc::new(std::sync::RwLock::new(Vec::new())),
            producer_files: files,
            cursor_key: crate::decisions::cursorkey::load(&root).expect("a cursor key"),
            disclosure: permguard_core::Disclosure::default(),
            metrics: permguard_core::metrics::Metrics::default(),
            base_url: String::new(),
        }
    }

    /// The trust set as the ids it admits under: `ProducerTrust` is a production value and not
    /// worth an equality impl it has no other use for.
    fn kids(facade: &EventFacade) -> Vec<String> {
        facade
            .accepted_producers()
            .into_iter()
            .map(|held| held.key.kid)
            .collect()
    }

    fn source(path: &std::path::Path) -> ProducerFile {
        ProducerFile {
            path: path.to_path_buf(),
            producer: "data-plane-test".to_owned(),
            zone: "*".to_owned(),
            ledger: "*".to_owned(),
        }
    }

    /// The first start every deployment has: nobody has published yet.
    ///
    /// The whole reason this service exists — a file that appears has to be picked up without a
    /// restart, and without waiting for a producer to fail a batch against a plane that trusts
    /// nobody.
    #[test]
    fn a_key_set_published_after_the_plane_started_is_picked_up() {
        let directory = scratch("late");
        let path = directory.join("data-plane-events.jwks");
        let facade = facade(vec![source(&path)]);

        let refused = reload_once(&facade).expect_err("nothing is published yet");
        assert!(refused.contains("data-plane-events.jwks"), "{refused}");
        assert_eq!(facade.accepted_producers().len(), 0);

        std::fs::write(&path, KEY).expect("the producer publishes");
        assert_eq!(
            reload_once(&facade).expect("the published set loads"),
            1,
            "the file that appeared is in force without a restart"
        );
        assert_eq!(facade.accepted_producers().len(), 1);

        let _ = std::fs::remove_dir_all(&directory);
    }

    /// A rotation that cannot be read must not widen or empty the trust set.
    #[test]
    fn a_malformed_rotation_keeps_the_last_set_that_loaded() {
        let directory = scratch("rotation");
        let path = directory.join("events.jwks");
        std::fs::write(&path, KEY).expect("the producer publishes");
        let facade = facade(vec![source(&path)]);
        assert_eq!(reload_once(&facade).expect("the first set loads"), 1);
        let held = kids(&facade);

        std::fs::write(&path, "{ not a key set").expect("the rotation is written badly");
        let refused = reload_once(&facade).expect_err("a malformed rotation is refused");
        assert!(refused.contains("parsing"), "{refused}");
        assert_eq!(
            kids(&facade),
            held,
            "the set that worked stays in force rather than being dropped"
        );

        // And a good rotation replaces it.
        std::fs::write(&path, OTHER).expect("the rotation is written well");
        assert_eq!(reload_once(&facade).expect("the rotation loads"), 1);
        assert_ne!(kids(&facade), held, "the new key is in force");

        let _ = std::fs::remove_dir_all(&directory);
    }

    /// Two producers, one of them silent: a partial set is not installed.
    ///
    /// Accepting the half that read would be a plane that quietly trusts fewer producers than its
    /// operator configured, which is the failure this service exists to make visible.
    #[test]
    fn one_unpublished_source_holds_back_the_whole_set() {
        let directory = scratch("partial");
        let published = directory.join("a.jwks");
        let missing = directory.join("b.jwks");
        std::fs::write(&published, KEY).expect("the first producer publishes");
        let facade = facade(vec![source(&published), source(&missing)]);

        let refused = reload_once(&facade).expect_err("one source is silent");
        assert!(refused.contains("b.jwks"), "{refused}");
        assert_eq!(
            facade.accepted_producers().len(),
            0,
            "no partial set is installed"
        );

        std::fs::write(&missing, OTHER).expect("the second producer publishes");
        assert_eq!(
            reload_once(&facade).expect("both sets load"),
            2,
            "the whole set is installed at once"
        );

        let _ = std::fs::remove_dir_all(&directory);
    }
}
