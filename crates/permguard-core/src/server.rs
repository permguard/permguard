// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The server-side contracts: what a host is, what a service is, and what either one may reach.
//!
//! These live here rather than next to the default host on purpose. A build that replaces the host —
//! or adds a service — has to name these traits, and if naming them meant depending on the crate that
//! already implements them, replacing anything would mean linking the thing being replaced.
//!
//! The lifecycle methods are asynchronous, and the shutdown signal arrives as an opaque future rather
//! than a runtime type. That is what keeps a runtime out of this crate: the binary decides what a
//! shutdown signal *is* — a process signal, a test that resolves immediately, an orchestrator's
//! request — and everything here only knows that it eventually resolves.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use anyhow::Result;

use crate::audit::{AuditEvent, AuditSink, Subject};
use crate::catalog::Catalog;
use crate::config::Config;
use crate::future::{BoxFuture, ready};
use crate::identity::ProductIdentity;
use crate::keys::KeyManager;
use crate::metrics::Metrics;
use crate::pseudonym::Pseudonymizer;
use crate::realm::{Realm, Realms};
use crate::storage::Storage;

/// A way to record audit events that outlives the call it was obtained in.
///
/// [`ServerContext::record_audit`] covers everything that audits *during* a call. This covers what
/// does not: a request handler runs on a task spawned per connection, and a connection outlives the
/// borrow of the context that set the surface up. Rather than widen every collaborator to shared
/// ownership for the sake of one of them, the sink — and the policy that goes with it — are offered
/// again here in a form that can be cloned into a task.
///
/// It is the same sink and the same policy the context uses, so there is one destination and one
/// privacy decision, reachable two ways.
#[derive(Clone)]
pub struct AuditRecorder {
    sink: Arc<dyn AuditSink>,
    policy: Option<Arc<dyn Pseudonymizer>>,
}

impl AuditRecorder {
    /// Records to `sink`, with no pseudonymisation.
    pub fn new(sink: Arc<dyn AuditSink>) -> Self {
        Self { sink, policy: None }
    }

    /// Applies `policy` to every subject that has one applied.
    pub fn with_policy(mut self, policy: Arc<dyn Pseudonymizer>) -> Self {
        self.policy = Some(policy);

        self
    }

    /// Returns the pseudonymisation in force, so a second recorder of the same
    /// events applies the same one.
    ///
    /// The decision log needs it for exactly that reason: a subject that
    /// reaches the audit trail as a token and the decision log as a raw
    /// identifier would make the deployment's privacy decision depend on which
    /// file somebody read.
    pub fn pseudonymizer(&self) -> Option<Arc<dyn Pseudonymizer>> {
        self.policy.clone()
    }

    /// Returns the name of the sink events reach, for diagnostics.
    pub fn sink_name(&self) -> &'static str {
        self.sink.name()
    }

    /// Records one event under the policy in force.
    pub fn record<'a>(
        &'a self,
        action: &'a str,
        subject: Subject<'a>,
    ) -> BoxFuture<'a, std::result::Result<(), crate::error::AuditError>> {
        Box::pin(async move {
            let event = AuditEvent::new(action, subject);

            self.sink.record(&event, self.policy.as_deref()).await
        })
    }

    /// Records one event that names what it was done to.
    pub fn record_on<'a>(
        &'a self,
        action: &'a str,
        subject: Subject<'a>,
        target: &'a str,
    ) -> BoxFuture<'a, std::result::Result<(), crate::error::AuditError>> {
        Box::pin(async move {
            let event = AuditEvent::new(action, subject).on(target);

            self.sink.record(&event, self.policy.as_deref()).await
        })
    }
}

impl std::fmt::Debug for AuditRecorder {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AuditRecorder")
            .field("sink", &self.sink.name())
            .field("pseudonymised", &self.policy.is_some())
            .finish()
    }
}

/// Whether the process is alive, and whether it should be sent work.
///
/// The two are different questions and conflating them costs requests. *Live* means the process is
/// not wedged and restarting it would be pointless. *Ready* means it is willing to be sent work — and
/// it goes false at the very start of shutdown, before anything is actually closed, so a load
/// balancer stops routing while the server is still able to finish what it already has.
#[derive(Debug, Clone)]
pub struct Health {
    live: Arc<AtomicBool>,
    lifecycle: crate::lifecycle::Lifecycle,
}

impl Default for Health {
    fn default() -> Self {
        Self::new()
    }
}

impl Health {
    /// Builds a health state that is live but not yet ready: the Host is in Bootstrap.
    ///
    /// Not-ready is the honest starting point: the process exists, and nothing it serves is up.
    pub fn new() -> Self {
        Self {
            live: Arc::new(AtomicBool::new(true)),
            lifecycle: crate::lifecycle::Lifecycle::new(),
        }
    }

    /// Reports whether the process is alive.
    pub fn is_live(&self) -> bool {
        self.live.load(Ordering::SeqCst)
    }

    /// Reports whether the process is willing to be sent work: the Host and every required Plane
    /// are Ready or Serving. Derived from the lifecycle, never set on its own.
    pub fn is_ready(&self) -> bool {
        self.lifecycle.ready()
    }

    /// Records that the Host is or is no longer willing to be sent work: Serving, or Draining from
    /// a phase that accepted work.
    pub fn set_ready(&self, ready: bool) {
        use crate::lifecycle::{HOST, Phase};

        if ready {
            self.lifecycle.serve();
        } else if self.lifecycle.phase(HOST).is_some_and(Phase::accepts_work) {
            self.lifecycle.advance(HOST, Phase::Draining);
        }
    }

    /// Records that the process is or is no longer alive.
    pub fn set_live(&self, live: bool) {
        self.live.store(live, Ordering::SeqCst);
    }

    /// The lifecycle of the Host, every Plane and every service, which readiness is derived from.
    pub fn lifecycle(&self) -> &crate::lifecycle::Lifecycle {
        &self.lifecycle
    }
}

/// Everything a server host and its services are allowed to reach, assembled by the caller.
///
/// The context borrows its collaborators rather than owning them, so the same implementations are
/// shared by whatever else a binary composes. Only identity, configuration, storage, and audit are
/// required; the rest is added by builds that have it.
pub struct ServerContext<'a> {
    identity: ProductIdentity,
    config: &'a Config,
    storage: &'a dyn Storage,
    audit: &'a dyn AuditSink,
    pseudonymizer: Option<&'a dyn Pseudonymizer>,
    /// Shared rather than borrowed, unlike everything else here — see [`ServerContext::with_keys`].
    keys: Option<Arc<dyn KeyManager>>,
    /// Shared for the same reason the key ring is: the routes that serve zones and ledgers outlive
    /// the borrow a context could offer.
    catalog: Option<Arc<dyn Catalog>>,
    /// The Planes' signing rings, by role, for the Host's own maintenance pass only: the rotation
    /// that moves keys through their lifecycle. A Plane signs through its handles and never reads
    /// this; `scripts/check-composition-root.sh` refuses it in a Plane crate until the lifecycle
    /// engine (WP-2.6) gives the Planes a context without it.
    maintained_rings: Vec<(&'static str, Arc<dyn KeyManager>)>,
    /// Each Plane's handles, from the Host's registration of its declaration, by Plane id. Typed by
    /// the composition, which knows them; a Plane reads its own with [`ServerContext::plane_handles`].
    /// The Planes' signing rings, the audit recorder and the secret store are reached only through
    /// them (P1).
    plane_handles: std::collections::BTreeMap<&'static str, Arc<dyn std::any::Any + Send + Sync>>,
    services: &'a [Box<dyn Service>],
    health: Health,
    /// Shared rather than borrowed, for the same reason the key ring is: what records a number is
    /// usually work that outlives the call it was started from.
    metrics: Metrics,
    /// The issuers this deployment hosts, each with its own keys, trail and pseudonymisation. Empty
    /// for a plain single-issuer server. The collaborators above — `keys`, `audit`, `pseudonymizer` —
    /// are the **server's own** (the system trail, the key that signs it); a realm's are reached
    /// through here.
    realms: Realms,
}

/// The empty service list a context starts from.
const NO_SERVICES: &[Box<dyn Service>] = &[];

impl<'a> ServerContext<'a> {
    /// Assembles the context a host runs against.
    ///
    /// The identity is required rather than optional because a server that cannot say which product
    /// it is cannot write a log record a monitoring tool can attribute.
    pub fn new(
        identity: ProductIdentity,
        config: &'a Config,
        storage: &'a dyn Storage,
        audit: &'a dyn AuditSink,
    ) -> Self {
        Self {
            identity,
            config,
            storage,
            audit,
            pseudonymizer: None,
            keys: None,
            catalog: None,
            maintained_rings: Vec::new(),
            plane_handles: std::collections::BTreeMap::new(),
            services: NO_SERVICES,
            health: Health::new(),
            metrics: Metrics::none(),
            realms: Realms::default(),
        }
    }

    /// Adds the privacy policy audit subjects are recorded under.
    ///
    /// A context without one still records: principals reach the sink masked instead of pseudonymised,
    /// which costs correlation and discloses nothing.
    pub fn with_pseudonymizer(mut self, pseudonymizer: &'a dyn Pseudonymizer) -> Self {
        self.pseudonymizer = Some(pseudonymizer);

        self
    }

    /// Replaces the sink audit events are recorded to.
    ///
    /// The constructor takes one because a context without a destination cannot record at all; this
    /// exists because *which* destination is configuration, and a context is assembled by something
    /// that has read it.
    pub fn with_audit(mut self, audit: &'a dyn AuditSink) -> Self {
        self.audit = audit;

        self
    }

    /// Attaches the catalog of zones and ledgers this deployment keeps.
    ///
    /// Shared rather than borrowed, like the key ring and for the same reason: the routes serving
    /// it outlive the borrow a context could offer.
    pub fn with_catalog(mut self, catalog: Arc<dyn Catalog>) -> Self {
        self.catalog = Some(catalog);

        self
    }

    /// Attaches the key ring, shared rather than borrowed.
    ///
    /// Shared because a key ring is not only *used* for the length of a call: it is *maintained* by
    /// work that outlives any one call and therefore cannot hold a borrow of the context.
    pub fn with_keys(mut self, keys: Arc<dyn KeyManager>) -> Self {
        self.keys = Some(keys);

        self
    }

    /// Adds a Plane signing ring to the Host's maintenance pass, under `role`.
    pub fn with_maintained_ring(mut self, role: &'static str, keys: Arc<dyn KeyManager>) -> Self {
        self.maintained_rings.push((role, keys));

        self
    }

    /// Attaches the handles the Host registered for the Plane `plane`.
    pub fn with_plane_handles(
        mut self,
        plane: &'static str,
        handles: Arc<dyn std::any::Any + Send + Sync>,
    ) -> Self {
        self.plane_handles.insert(plane, handles);

        self
    }

    /// Adds the services the host is expected to start.
    pub fn with_services(mut self, services: &'a [Box<dyn Service>]) -> Self {
        self.services = services;

        self
    }

    /// Adds somewhere for the numbers this process records about itself to go.
    ///
    /// A context without one still runs, and every measurement in it becomes a branch and a return.
    /// That is the honest default: a build that publishes nothing should not pay to collect it.
    pub fn with_metrics(mut self, metrics: Metrics) -> Self {
        self.metrics = metrics;

        self
    }

    /// Shares an existing health state instead of the one this context made.
    ///
    /// A service that reports health — a telemetry surface, say — needs the same state the host
    /// flips, not a copy of it.
    pub fn with_health(mut self, health: Health) -> Self {
        self.health = health;

        self
    }

    /// Adds the issuers this deployment hosts, each with its own collaborators.
    ///
    /// Composed once at the root and never mutated: a surface resolving a realm reads this registry,
    /// and a read takes no lock. A deployment with no separate realm passes nothing and gets the
    /// empty registry the context starts with.
    pub fn with_realms(mut self, realms: Realms) -> Self {
        self.realms = realms;

        self
    }

    /// Returns the identity of the product this context belongs to.
    pub fn identity(&self) -> &ProductIdentity {
        &self.identity
    }

    /// Returns the effective configuration.
    pub fn config(&self) -> &Config {
        self.config
    }

    /// Returns the store the host and its services read and write.
    pub fn storage(&self) -> &dyn Storage {
        self.storage
    }

    /// Returns the sink audit events are recorded to.
    pub fn audit(&self) -> &dyn AuditSink {
        self.audit
    }

    /// Returns the privacy policy audit subjects are recorded under, when this build composed one.
    pub fn pseudonymizer(&self) -> Option<&dyn Pseudonymizer> {
        self.pseudonymizer
    }

    /// Returns the catalog of zones and ledgers, when this build composed one.
    pub fn catalog(&self) -> Option<&Arc<dyn Catalog>> {
        self.catalog.as_ref()
    }

    /// Returns the key ring, when this build composed one.
    pub fn keys(&self) -> Option<&Arc<dyn KeyManager>> {
        self.keys.as_ref()
    }

    /// The Planes' signing rings, by role, for the Host's maintenance pass; never a Plane's to read.
    pub fn maintained_rings(&self) -> &[(&'static str, Arc<dyn KeyManager>)] {
        &self.maintained_rings
    }

    /// Returns the handles the Host registered for the Plane `plane`, as the type the composition
    /// stored them as; `None` when the Plane was not registered or the type does not match.
    pub fn plane_handles<T: std::any::Any + Send + Sync>(&self, plane: &str) -> Option<Arc<T>> {
        self.plane_handles
            .get(plane)
            .and_then(|handles| Arc::clone(handles).downcast::<T>().ok())
    }

    /// Returns the services the host is expected to start, in registration order.
    pub fn services(&self) -> &[Box<dyn Service>] {
        self.services
    }

    /// Returns the liveness and readiness state of the process.
    pub fn health(&self) -> &Health {
        &self.health
    }

    /// Returns where the numbers this process records about itself go.
    ///
    /// Always a handle, never an `Option`: a build that installed nothing gets one that discards, so
    /// nothing has to guard a measurement.
    pub fn metrics(&self) -> &Metrics {
        &self.metrics
    }

    /// Returns every issuer this deployment hosts.
    ///
    /// The server-level `keys()`/`audit()`/`pseudonymizer()` above are **not** among these: they are
    /// the server's own, for the system trail. A realm's collaborators are reached through the realm.
    pub fn realms(&self) -> &Realms {
        &self.realms
    }

    /// Returns the realm called `name`, when this deployment hosts it.
    pub fn realm(&self, name: &str) -> Option<&Realm> {
        self.realms.by_name(name)
    }

    /// Records one audit event under the policy this context carries.
    ///
    /// Everything that audits goes through here rather than reaching the sink directly, so the policy
    /// is applied at one place instead of at every call site that happens to remember.
    pub fn record_audit<'e>(
        &'e self,
        action: &'e str,
        subject: Subject<'e>,
    ) -> BoxFuture<'e, std::result::Result<(), crate::error::AuditError>> {
        Box::pin(async move {
            let event = AuditEvent::new(action, subject);

            self.audit.record(&event, self.pseudonymizer).await
        })
    }
}

/// One surface the server exposes — an admin API, a discovery endpoint, anything with a lifecycle.
///
/// A service reads its own settings off the context's configuration, so adding one needs no change to
/// the host: the binary registers it, the host starts it.
///
/// `start` is expected to return once the service is *up* — listening, registered, ready — not to run
/// for the lifetime of the process. Whatever must keep running belongs on a task the service spawns
/// and cancels in `stop`; a `start` that never returned would stall every service after it.
pub trait Service: Send + Sync {
    /// Returns the name of this service, for banners, diagnostics, and audit records.
    fn name(&self) -> &'static str;

    /// Brings the service up, or reports why it could not come up.
    fn start<'a>(&'a self, context: &'a ServerContext<'a>) -> BoxFuture<'a, Result<()>>;

    /// Takes the service down, or reports why it could not go down cleanly.
    ///
    /// The host stops services in the reverse of the order it started them, so a service may assume
    /// everything registered after it is already down. A service with nothing to release keeps the
    /// default.
    fn stop<'a>(&'a self, context: &'a ServerContext<'a>) -> BoxFuture<'a, Result<()>> {
        let _ = context;

        ready(Ok(()))
    }

    /// The Plane this service belongs to, or `None` for the Host's own: the Host's services start
    /// first and the Host reaches Ready before any Plane leaves Bootstrap (P2).
    fn plane(&self) -> Option<&'static str> {
        None
    }
}

/// The runtime component a server-starting command executes.
///
/// Unlike the data-plane contracts, this one and [`Service`] keep an opaque error. The rule is which
/// caller branches: a store or a secret store is asked something and the answer changes what happens
/// next, so the answer is typed. A host that fails to run has failed terminally, and what its caller
/// needs is not a value to match on but the chain of context that says which of a dozen steps gave
/// out. A surface still builds a [`ServiceError`](crate::error::ServiceError) as the cause, so the
/// typed reason survives inside that chain.
pub trait ServerHost: Send + Sync {
    /// Returns the name of this implementation, for banners and diagnostics.
    fn name(&self) -> &'static str;

    /// Runs the host until `shutdown` resolves, then takes everything down and returns.
    ///
    /// The host writes nothing to any output stream: what it has to say goes to the log, where a
    /// collector can read it. `shutdown` is opaque on purpose — see the module documentation.
    fn run<'a>(
        &'a self,
        context: &'a ServerContext<'a>,
        shutdown: BoxFuture<'a, ()>,
    ) -> BoxFuture<'a, Result<()>>;
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;

    use std::sync::Mutex;

    use anyhow::anyhow;

    fn identity() -> ProductIdentity {
        ProductIdentity::new("demo-x", "Demo X", "A tagline", "Demo X CLI", "<art>")
    }

    #[derive(Default)]
    struct StubStorage;

    impl Storage for StubStorage {
        fn name(&self) -> &'static str {
            "stub-storage"
        }

        fn put<'a>(
            &'a self,
            _key: &'a str,
            _value: &'a [u8],
        ) -> BoxFuture<'a, crate::storage::Result<()>> {
            ready(Ok(()))
        }

        fn get<'a>(
            &'a self,
            _key: &'a str,
        ) -> BoxFuture<'a, crate::storage::Result<Option<Vec<u8>>>> {
            ready(Ok(None))
        }
    }

    #[derive(Default)]
    struct StubSink;

    impl AuditSink for StubSink {
        fn name(&self) -> &'static str {
            "stub-sink"
        }

        fn record<'a>(
            &'a self,
            _event: &'a AuditEvent<'a>,
            _policy: Option<&'a dyn Pseudonymizer>,
        ) -> BoxFuture<'a, crate::audit::Result<()>> {
            ready(Ok(()))
        }
    }

    struct StubPolicy;

    impl Pseudonymizer for StubPolicy {
        fn key_version(&self) -> &str {
            "v1"
        }

        fn pseudonymize(&self, value: &str) -> String {
            format!("v1:{}", value.len())
        }
    }

    /// A service written against the contract from outside any implementation crate.
    #[derive(Default)]
    struct StubService {
        started: Mutex<bool>,
    }

    impl Service for StubService {
        fn name(&self) -> &'static str {
            "stub-service"
        }

        fn start<'a>(&'a self, _context: &'a ServerContext<'a>) -> BoxFuture<'a, Result<()>> {
            Box::pin(async move {
                *self.started.lock().map_err(|_| anyhow!("poisoned"))? = true;

                Ok(())
            })
        }
    }

    #[test]
    fn test_a_bare_context_carries_the_required_set_and_nothing_else() {
        let config = Config::default();
        let storage = StubStorage;
        let audit = StubSink;

        let context = ServerContext::new(identity(), &config, &storage, &audit);

        assert_eq!(context.identity().binary_name(), "demo-x");
        assert_eq!(context.config().version(), config.version());
        assert_eq!(context.storage().name(), "stub-storage");
        assert_eq!(context.audit().name(), "stub-sink");
        assert!(context.pseudonymizer().is_none());
        assert!(context.services().is_empty());
    }

    #[test]
    fn test_a_new_process_is_live_but_not_yet_ready() {
        let health = Health::new();

        assert!(health.is_live());
        assert!(!health.is_ready());
    }

    #[test]
    fn test_health_is_shared_rather_than_copied() {
        let health = Health::new();
        let shared = health.clone();

        health.set_ready(true);
        assert!(shared.is_ready());

        shared.set_ready(false);
        assert!(!health.is_ready());
    }

    #[test]
    fn test_a_context_can_share_the_health_state_the_host_flips() {
        let config = Config::default();
        let storage = StubStorage;
        let audit = StubSink;
        let health = Health::new();

        let context =
            ServerContext::new(identity(), &config, &storage, &audit).with_health(health.clone());

        health.set_ready(true);
        assert!(context.health().is_ready());
    }

    #[test]
    fn test_a_composed_context_hands_back_the_services_and_plane_handles_it_was_given() {
        let config = Config::default();
        let storage = StubStorage;
        let audit = StubSink;
        let services: Vec<Box<dyn Service>> = vec![Box::new(StubService::default())];

        let context = ServerContext::new(identity(), &config, &storage, &audit)
            .with_services(&services)
            .with_plane_handles("control", Arc::new(String::from("control handles")));

        assert_eq!(
            context
                .plane_handles::<String>("control")
                .as_deref()
                .map(String::as_str),
            Some("control handles")
        );
        assert!(
            context.plane_handles::<u32>("control").is_none(),
            "another type"
        );
        assert!(
            context.plane_handles::<String>("data").is_none(),
            "another plane"
        );
        assert_eq!(context.services().len(), 1);
        assert_eq!(context.services()[0].name(), "stub-service");
    }

    #[tokio::test]
    async fn test_a_context_without_a_policy_still_records() {
        let config = Config::default();
        let storage = StubStorage;
        let audit = StubSink;
        let context = ServerContext::new(identity(), &config, &storage, &audit);

        assert!(context.pseudonymizer().is_none());
        context
            .record_audit("server.start", Subject::System("default"))
            .await
            .expect("the event is recorded");
    }

    #[test]
    fn test_a_composed_policy_reaches_the_sink_through_the_context() {
        let config = Config::default();
        let storage = StubStorage;
        let audit = StubSink;
        let policy = StubPolicy;
        let context =
            ServerContext::new(identity(), &config, &storage, &audit).with_pseudonymizer(&policy);

        assert_eq!(
            context.pseudonymizer().map(Pseudonymizer::key_version),
            Some("v1")
        );
    }

    #[tokio::test]
    async fn test_a_service_is_startable_through_the_context_it_is_registered_in() {
        let config = Config::default();
        let storage = StubStorage;
        let audit = StubSink;
        let services: Vec<Box<dyn Service>> = vec![Box::new(StubService::default())];
        let context =
            ServerContext::new(identity(), &config, &storage, &audit).with_services(&services);

        for service in context.services() {
            service.start(&context).await.expect("the service starts");
            service.stop(&context).await.expect("the service stops");
        }

        assert_eq!(context.services()[0].name(), "stub-service");
    }
}
