// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The Control Plane as a Plane of the Host: the stores and facades it composes from the handles
//! the Host registered, once per directory and shared by every surface; what it declares, the
//! content-addressed trees it keeps, the evidence streams it receives, what it requires of a
//! configuration, and the work it runs beside whatever serves it. Its routes, on both transports,
//! are `permguard-control-plane-server`'s.

use anyhow::Context as _;

use permguard_core::PlaneContext;

use crate::COMPONENT;
use crate::catalog::CatalogFacade;

/// The stores this plane composed, once per directory, for every surface that serves them.
///
/// # Why the stores live here and not in `routes()`
///
/// A server's HTTP and gRPC routes are both built for the same
/// plane — always, in the shipped single-port shape, where the two surfaces share one address.
/// Building a store inside each meant *two* [`crate::events::EventStore`] values over one
/// directory, and a store is not a stateless handle: it carries the per-stream write gate that
/// makes ingest's read-check-append atomic. Two gate maps are two locks that do not see each
/// other, so an HTTP batch and a gRPC batch for the same producer stream could interleave the
/// sequence the gate exists to serialise — a corruption reachable from the default configuration
/// and invisible to a test that exercises one transport at a time.
///
/// So the composition root is here: resolved once, keyed by the directory it opened, and handed to
/// both surfaces.
#[derive(Default)]
pub struct Composition {
    events: Composed<crate::events::facade::EventFacade>,
    event_store:
        std::sync::Arc<std::sync::Mutex<Option<std::sync::Arc<crate::events::EventStore>>>>,
    /// The composed facade, shared with the service that re-reads the producers' published keys.
    /// The trust set lives behind an `Arc` inside it, so what that service reloads is what
    /// ingestion admits under.
    event_trust: std::sync::Arc<std::sync::Mutex<Option<crate::events::facade::EventFacade>>>,
    decisions: Composed<crate::decisions::facade::DecisionFacade>,
    decision_state:
        std::sync::Arc<std::sync::Mutex<Option<crate::decisions::facade::DecisionFacade>>>,
    /// The NOTP facade, composed once: REST, gRPC and the `policy.mirror` task share its stores,
    /// so one gate serializes a ledger's compare-and-swap and its transfer sessions (WP-7.12).
    notp: Composed<crate::notp::NotpFacade>,
    /// Whether the `events.import` handler was offered to the Host, once (WP-6.2c1).
    import: std::sync::OnceLock<()>,
}

impl Composition {
    /// Serves `events.import` from the Host's event consumer, once, when the Host routes task
    /// sessions, consumes the event stream and composes this plane's signing ring (WP-6.2c1).
    pub fn serve_import(&self, context: &PlaneContext<'_>) {
        self.import.get_or_init(|| {
            let (Some(registration), Some(consumer), Some(signer), Some(coordinator)) = (
                crate::handles::registration(context),
                crate::handles::event_consumer(context),
                crate::handles::import_signer(context),
                crate::handles::host_id(context),
            ) else {
                tracing::warn!(
                    event.name = "events.import_unserved",
                    component = COMPONENT,
                    "the events.import task is not served: this Host routes no task sessions, \
                     consumes no event stream or composes no control.attest ring"
                );
                return;
            };
            let origins = std::sync::Arc::clone(&registration);
            let import = std::sync::Arc::new(crate::events::import::Import {
                consumer,
                origins: std::sync::Arc::new(move |resource| {
                    origins
                        .import_origins(resource)
                        .unwrap_or_else(|| Ok(Default::default()))
                }),
                signer,
                coordinator,
            });
            if let Err(error) = registration.serve_task(
                permguard_host::membership::record::TaskType::EventsImport,
                crate::events::import::VERSION,
                import,
            ) {
                tracing::error!(
                    event.name = "events.import_unserved",
                    component = COMPONENT,
                    error = %error,
                    "the events.import task is not served by this plane"
                );
            }
        });
    }

    /// The event store's facade, composed once and shared by both surfaces.
    pub fn event_facade(
        &self,
        context: &PlaneContext<'_>,
    ) -> Option<crate::events::facade::EventFacade> {
        let config = context.config();
        if !events_served(config) {
            return None;
        }
        let directory = config.event_store_directory();

        composed(&self.events, directory.clone(), || {
            build_event_facade(context, &directory, &self.event_store, &self.event_trust)
        })
    }

    /// The NOTP facade, composed once; its first composition serves the `policy.mirror` task.
    pub fn notp_facade(&self, context: &PlaneContext<'_>) -> Option<crate::notp::NotpFacade> {
        let directory = context.config().zones_directory();
        composed(&self.notp, directory, || {
            let facade = notp_facade(context)?;
            if let Some(registration) = crate::handles::registration(context) {
                let mirror = std::sync::Arc::new(crate::notp::mirror::Mirror {
                    facade: std::sync::Arc::new(facade.clone()),
                });
                if let Err(error) = registration.serve_task(
                    permguard_host::membership::record::TaskType::PolicyMirror,
                    crate::notp::mirror::VERSION,
                    mirror,
                ) {
                    tracing::error!(
                        event.name = "notp.mirror_unserved",
                        component = COMPONENT,
                        error = %error,
                        "the policy.mirror task is not served by this plane"
                    );
                }
            }
            Some(facade)
        })
    }

    /// The decision log's facade, composed the same way and for the same reason.
    pub fn decision_facade(
        &self,
        context: &PlaneContext<'_>,
    ) -> Option<crate::decisions::facade::DecisionFacade> {
        let config = context.config();
        if !config.decision_store_enabled() {
            return None;
        }
        let directory = config.working_dir().join(config.decision_store_directory());

        composed(&self.decisions, directory.clone(), || {
            build_decision_facade(context, &directory, &self.decision_state)
        })
    }

    /// The event store this plane composed, shared with its retention sweep.
    pub fn event_store(
        &self,
    ) -> &std::sync::Arc<std::sync::Mutex<Option<std::sync::Arc<crate::events::EventStore>>>> {
        &self.event_store
    }

    /// The composed event facade, for whatever reports the event capability's state.
    pub fn event_trust(
        &self,
    ) -> &std::sync::Arc<std::sync::Mutex<Option<crate::events::facade::EventFacade>>> {
        &self.event_trust
    }

    /// The composed decision facade, for whatever reports the decision capability's state.
    pub fn decision_state(
        &self,
    ) -> &std::sync::Arc<std::sync::Mutex<Option<crate::decisions::facade::DecisionFacade>>> {
        &self.decision_state
    }
}

/// A facade composed once per store directory, for every surface that serves it.
///
/// Successful composition is cached so every transport shares one set of write gates. A failed
/// attempt is not: HTTP and gRPC are assembled one after the other, and a transient filesystem
/// failure during the first must not permanently suppress the second. Disabled capabilities never
/// call this helper in the first place.
type Composed<T> = std::sync::Mutex<std::collections::HashMap<std::path::PathBuf, Option<T>>>;

/// Reads a composed facade, or builds and remembers it.
fn composed<T: Clone>(
    held: &Composed<T>,
    directory: std::path::PathBuf,
    build: impl FnOnce() -> Option<T>,
) -> Option<T> {
    let mut held = match held.lock() {
        Ok(held) => held,
        Err(poisoned) => poisoned.into_inner(),
    };
    if let Some(Some(known)) = held.get(&directory) {
        return Some(known.clone());
    }
    let built = build();
    match &built {
        Some(built) => {
            held.insert(directory, Some(built.clone()));
        }
        None => {
            held.remove(&directory);
        }
    }

    built
}

/// The catalog's mutation transaction (WP-7.3a), the operations a crash left open resolved
/// before the catalog takes a change: `None`, and every change refused `unavailable`, when the
/// Host composes none or the recovery fails.
fn catalog_mutations(
    context: &PlaneContext<'_>,
    catalog: &std::sync::Arc<dyn permguard_core::catalog::Catalog>,
) -> Option<permguard_host::composition::MutationHandle> {
    crate::catalog::recovered(crate::handles::catalog_mutations(context)?, catalog)
}

/// Assembles the NOTP facade, when this build composes everything it needs:
/// the catalog to resolve ledgers, and the git-like signing ring — never the
/// audit ring — to attest every served head.
/// The decision-log routes, when the deployment keeps a decision log.
/// Whether this deployment serves the event store at all.
///
/// # Two switches, not one
///
/// `controlPlane.events.enabled` is the operator's: *this plane receives and keeps other planes'
/// event history*. `experimental.dogwood.enabled` is a different statement: *this deployment
/// accepts a contract whose shape is not yet stable*. The records this store holds and the API
/// family that reads them are that contract, so it is served only where both have been said —
/// matching the data plane's own gate, so a deployment cannot have a producer that ships and a
/// receiver that does not, or the reverse, from one switch.
pub fn events_served(config: &permguard_core::Config) -> bool {
    config.event_store_enabled() && config.experimental_dogwood()
}

/// What this plane requires before it binds anything.
///
/// Said one of the two things and not the other is refused rather than quietly served as nothing:
/// an operator who turned on an event store and finds nothing answering has a plane that looks
/// configured and is not, and nothing in its logs to say which switch it is missing.
fn events_startup_check(config: &permguard_core::Config) -> anyhow::Result<()> {
    // Every `experimental.<name>` this deployment wrote down must name a runtime this build
    // actually gates, or the operator has enabled nothing while believing otherwise.
    permguard_languages::registry::check_opted_in(config.experimental_named())
        .map_err(|error| anyhow::anyhow!(error))?;

    if config.event_store_enabled() && !config.experimental_dogwood() {
        anyhow::bail!(
            "`controlPlane.events.enabled` is true and `experimental.dogwood.enabled` is not. The \
             event store holds records whose shape is not yet stable, and is served only where a \
             deployment has accepted that: set `experimental.dogwood.enabled: true` to serve it, \
             or `controlPlane.events.enabled: false` if this plane should not receive events"
        );
    }
    // Retired (WP-6.2b, owner decision of 2026-10-18): events arrive over the Host's
    // `events.ship`, and the ingest route trusts only the ring of the plane sharing this process
    // for its legacy journals. A configuration still naming key files is refused, so no
    // deployment believes they are in force.
    if config.event_producer_keys_declared() {
        anyhow::bail!(
            "`controlPlane.events.producer_keys` is retired: events arrive over the Host's \
             `events.ship`, verified under the memberships' pinned rings. Remove it"
        );
    }

    Ok(())
}

/// A configured decision store is a startup requirement, not an optional
/// route that may disappear behind a ready health endpoint.
fn decisions_startup_check(config: &permguard_core::Config) -> anyhow::Result<()> {
    // Retired (iteration 02, WP-10.4): decisions arrive over the Host's `decisions.ship`, verified
    // under the membership's pinned rings; no batch is accepted over a public route and no key
    // file is read. A configuration still naming one is refused, the store on or off, so no
    // deployment believes it is in force.
    if !config.decision_producer_keys().is_empty() {
        anyhow::bail!(
            "`controlPlane.decisions.producer_keys` is retired: decisions arrive over the Host's \
             `decisions.ship`, from the members of this plane's Host, verified under their \
             memberships' pinned rings. Remove it"
        );
    }
    if !config.decision_store_enabled() {
        return Ok(());
    }

    let directory = config.working_dir().join(config.decision_store_directory());
    // Open and drop as a preflight. The facade composed after startup owns the
    // actual per-stream gates; this pass establishes that the configured path
    // and its durable cursor key are usable before any listener reports ready.
    crate::decisions::DecisionStore::open(&directory).with_context(|| {
        format!(
            "opening the configured decision store at {}",
            directory.display()
        )
    })?;
    crate::decisions::cursorkey::load_root(&directory).with_context(|| {
        format!(
            "loading the decision store cursor key at {}",
            directory.display()
        )
    })?;

    Ok(())
}

/// The event store's facade, when this deployment receives events.
///
/// Built the same way the decision store's is, and for the same reasons: the producers' published
/// keys come from files rather than from dialling back, the offset key lives beside the store it
/// issues positions into, and a store that cannot be opened means the surface is not served rather
/// than served badly.
fn build_event_facade(
    context: &PlaneContext<'_>,
    directory: &std::path::Path,
    shared: &std::sync::Arc<std::sync::Mutex<Option<std::sync::Arc<crate::events::EventStore>>>>,
    facades: &std::sync::Arc<std::sync::Mutex<Option<crate::events::facade::EventFacade>>>,
) -> Option<crate::events::facade::EventFacade> {
    let config = context.config();
    let store = match crate::events::EventStore::open(directory) {
        Ok(store) => std::sync::Arc::new(store),
        Err(error) => {
            tracing::error!(
                event.name = "events.unavailable",
                component = COMPONENT,
                error = %error,
                "the event store is configured and could not be opened"
            );
            return None;
        }
    };
    let cursor_key = match crate::handles::host_id(context)
        .ok_or_else(|| {
            anyhow::anyhow!("no Host identity is composed: read offsets are keyed per Host")
        })
        .and_then(|host_id| crate::decisions::cursorkey::load(directory, host_id, "events"))
        .map(|keys| keys.with_lifetime(context.config().stream_cursor_ttl()))
    {
        Ok(key) => key,
        Err(error) => {
            tracing::error!(
                event.name = "events.unavailable",
                component = COMPONENT,
                error = %error,
                "the event store is configured and its read offsets cannot be signed: refusing to \
                 serve offsets a consumer could edit"
            );
            return None;
        }
    };

    let facade = crate::events::facade::EventFacade {
        catalog: context.catalog().map(std::sync::Arc::clone),
        store,
        host: crate::handles::event_consumer(context),
        cursor_key,
        disclosure: config.error_detail(),
        metrics: context.metrics().clone(),
        base_url: permguard_core::planes::discovery::plane_http_base(
            config,
            permguard_core::planes::discovery::PlaneId::Control,
        )
        .unwrap_or_default(),
        describer: permguard_core::stages::Describer::of_plane(context, "control-plane"),
        authorization: crate::handles::authorization(context),
        members: crate::handles::member_names(
            context,
            permguard_host::membership::record::TaskType::EventsShip,
        ),
    };
    if let Ok(mut held) = shared.lock() {
        *held = Some(std::sync::Arc::clone(&facade.store));
    }
    if let Ok(mut held) = facades.lock() {
        *held = Some(facade.clone());
    }

    Some(facade)
}

fn build_decision_facade(
    context: &PlaneContext<'_>,
    directory: &std::path::Path,
    shared: &std::sync::Arc<std::sync::Mutex<Option<crate::decisions::facade::DecisionFacade>>>,
) -> Option<crate::decisions::facade::DecisionFacade> {
    let config = context.config();
    let store = match crate::decisions::DecisionStore::open(directory) {
        Ok(store) => std::sync::Arc::new(store),
        Err(error) => {
            tracing::error!(
                event.name = "decisions.unavailable",
                component = COMPONENT,
                error = %error,
                "the decision log is configured but its store could not be opened"
            );
            return None;
        }
    };

    // The offset signing key lives beside the store it issues positions into, and is created on
    // first use. A store that cannot hold one cannot issue a resumable offset, so the decision log
    // is not served at all rather than served with offsets a consumer could edit.
    let cursor_key = match crate::handles::host_id(context)
        .ok_or_else(|| {
            anyhow::anyhow!("no Host identity is composed: read offsets are keyed per Host")
        })
        .and_then(|host_id| crate::decisions::cursorkey::load(directory, host_id, "decisions"))
        .map(|keys| keys.with_lifetime(context.config().stream_cursor_ttl()))
    {
        Ok(key) => key,
        Err(error) => {
            tracing::error!(
                event.name = "decisions.unavailable",
                component = COMPONENT,
                error = %error,
                "the decision log is configured and its read offsets cannot be signed: refusing to \
                 serve offsets a consumer could edit"
            );
            return None;
        }
    };

    let facade = crate::decisions::facade::DecisionFacade {
        store,
        ceiling: config.decision_ceiling(),
        cursor_key,
        disclosure: config.error_detail(),
        metrics: context.metrics().clone(),
        host: crate::handles::decision_consumer(context),
        catalog: context.catalog().map(std::sync::Arc::clone),
        base_url: permguard_core::planes::discovery::plane_http_base(
            config,
            permguard_core::planes::discovery::PlaneId::Control,
        )
        .unwrap_or_default(),
        describer: permguard_core::stages::Describer::of_plane(context, "control-plane"),
        authorization: crate::handles::authorization(context),
        members: crate::handles::member_names(
            context,
            permguard_host::membership::record::TaskType::DecisionsShip,
        ),
    };
    if let Ok(mut held) = shared.lock() {
        *held = Some(facade.clone());
    }

    Some(facade)
}

/// What exports a zone or a ledger (WP-7.10): `None` without the Host's `host.operations` signer
/// or a Host identity to name as the source authority.
fn exports_of(
    context: &PlaneContext<'_>,
) -> Option<std::sync::Arc<crate::catalog::exports::Exports>> {
    let signer = crate::handles::export_signer(context)?;
    let authority = crate::handles::host_id(context)?;
    let config = context.config();
    // The archive travels base64url in a JSON body and as bytes in a gRPC message: three quarters
    // of the ceiling both share.
    let max_bytes = grpc_message_ceiling(config) / 4 * 3;
    Some(std::sync::Arc::new(crate::catalog::exports::Exports::new(
        config.zones_directory(),
        signer,
        authority,
        max_bytes,
    )))
}

fn notp_facade(context: &PlaneContext<'_>) -> Option<crate::notp::NotpFacade> {
    let catalog = context.catalog()?;
    let Some(keys) = crate::handles::head_signer(context) else {
        tracing::warn!(
            event.name = "notp.disabled",
            component = COMPONENT,
            "the git-like store is not served: no signing ring is composed (controlPlane.keys)"
        );
        return None;
    };
    // Every head statement names the Host that signs it (WP-7.1): without a `host_id` there is
    // no authority to name, and the store is not served.
    let Some(authority) = crate::handles::host_id(context) else {
        tracing::warn!(
            event.name = "notp.disabled",
            component = COMPONENT,
            "the git-like store is not served: no Host identity names the signing authority"
        );
        return None;
    };
    let config = context.config();
    // Every ref update runs in the Host's mutation transaction (WP-3.6): without one the store is
    // not served, and the operations a crash left open are resolved before it is.
    let Some(mutations) = crate::handles::ref_mutations(context) else {
        tracing::warn!(
            event.name = "notp.disabled",
            component = COMPONENT,
            "the git-like store is not served: the Host composes no mutation transaction"
        );
        return None;
    };
    let domain = crate::store::RefDomain {
        zones_root: config.zones_directory(),
    };
    if let Err(error) = mutations.recover(&domain) {
        tracing::error!(
            event.name = "notp.disabled",
            component = COMPONENT,
            error = %error,
            "the git-like store is not served: the ref updates a crash left open could not be \
             resolved"
        );
        return None;
    }

    Some(crate::notp::NotpFacade::new(
        std::sync::Arc::clone(catalog),
        config.zones_directory(),
        keys,
        authority,
        crate::engine::EngineLimits {
            max_batch_bytes: config.notp_max_batch_bytes(),
            max_batch_objects: config.notp_max_batch_objects(),
            max_push_objects: config.notp_max_push_objects(),
            max_push_bytes: config.notp_max_push_bytes(),
            ledger_quota_bytes: config.notp_ledger_quota_bytes(),
        },
        crate::engine::TransferPolicy {
            ttl: config.notp_transfer_ttl(),
            grace: config.gc_grace(),
        },
        mutations,
        crate::handles::registration(context).and_then(|registration| registration.hints()),
        // The ingest gate reads the deployment's opt-ins, not the build's: a plane that has not
        // enabled a provisional runtime refuses the push rather than storing a ledger it would
        // then refuse to serve.
        permguard_languages::registry::Enabled::from_names(config.experimental_enabled_names()),
        config.notp_compression(),
        crate::handles::audit(context),
        config.error_detail(),
        config.audit_refusals(),
        context.metrics().clone(),
        crate::handles::authorization(context),
    ))
}

/// The catalog's facade under `context`, when this build composes a catalog: the same facade for
/// both transports.
pub fn catalog_facade(context: &PlaneContext<'_>) -> Option<CatalogFacade> {
    let catalog = context.catalog()?;
    Some(CatalogFacade {
        catalog: std::sync::Arc::clone(catalog),
        recorder: crate::handles::audit(context),
        disclosure: context.config().error_detail(),
        audit_refusals: context.config().audit_refusals(),
        metrics: context.metrics().clone(),
        authorization: crate::handles::authorization(context),
        host: crate::handles::registration(context),
        mutations: catalog_mutations(context, catalog),
        exports: exports_of(context),
    })
}

/// What this plane declares to the Host.
pub fn declaration() -> permguard_host::composition::Declaration {
    crate::handles::declaration()
}

/// The content-addressed trees this plane keeps on the volume, for deep verification.
pub fn verified_trees() -> Vec<permguard_host::storage::verify::VerifiedTree> {
    // `Config::zones_directory`, relative to the volume root: every ledger's objects.
    vec![(
        std::path::Path::new("data").join("zones"),
        std::sync::Arc::new(crate::store::object_check),
    )]
}

/// Background work this plane runs beside whatever serves it: measuring what it holds, checking a
/// sample of its objects, collecting and sweeping.
pub fn services(composition: &Composition) -> Vec<Box<dyn permguard_core::PlaneTask>> {
    vec![
        Box::new(crate::inventory::InventoryService::new()),
        // What startup does not read: a sample of the objects, checked in the background.
        Box::new(crate::verify::VerifyService::new()),
        Box::new(crate::gc::GcService::new()),
        Box::new(crate::decisions::retention::RetentionService::new()),
        // The event store's own sweep. Registered beside the decision store's rather than
        // relying on it: they are two stores with two windows, and the event one held a
        // `sweep` nothing ever called.
        Box::new(
            crate::events::retention::EventRetentionService::new()
                .with_store(std::sync::Arc::clone(composition.event_store())),
        ),
    ]
}

/// The evidence streams this plane receives under `config`, enabled or not.
pub fn streams(config: &permguard_core::Config) -> Vec<permguard_stream::StreamDescriptor> {
    let mut streams = Vec::new();

    // Declared whether or not the deployment turned them on: "not here" and "here, turned
    // off" are different answers, and discovery serves the second one too. Only enabled
    // streams own their directories.

    // The decision store: what the data planes ship, kept and served. The directory predates
    // the versioned layout and stays where recorded evidence already is.
    if let Ok(identity) = permguard_stream::StreamIdentity::new("control-plane", "decisions") {
        streams.push(permguard_stream::StreamDescriptor {
            identity,
            role: permguard_stream::Role::Consumer,
            record_type: permguard_core::domains::record::DECISION_V1.to_owned(),
            directory: config.working_dir().join(config.decision_store_directory()),
            legacy: true,
            enabled: config.decision_store_enabled(),
        });
    }

    // The event store, likewise. Its default directory nests under the root the data plane
    // journals in — the exact fragility the registry names at startup on an all-in-one.
    if let Ok(identity) = permguard_stream::StreamIdentity::new("control-plane", "events") {
        streams.push(permguard_stream::StreamDescriptor {
            identity,
            role: permguard_stream::Role::Consumer,
            record_type: permguard_events::RECORD_TYPE.to_owned(),
            directory: config.event_store_directory(),
            legacy: true,
            enabled: events_served(config),
        });
    }

    streams
}

/// What this plane requires before it binds anything.
pub fn startup_check(config: &permguard_core::Config) -> anyhow::Result<()> {
    // The languages this binary carries, before anything is ingested against them (LANG-12).
    permguard_languages::registry::check_registry().map_err(|collision| {
        anyhow::anyhow!("this build's language catalogue is inconsistent: {collision}")
    })?;
    events_startup_check(config)?;
    decisions_startup_check(config)
}

/// The smallest body ceiling under which every negotiated NOTP batch fits,
/// with headroom for the request's own framing.
pub fn body_floor(config: &permguard_core::Config) -> usize {
    let batch = usize::try_from(config.notp_max_batch_bytes()).unwrap_or(usize::MAX);

    batch.saturating_add(64 * 1024)
}

/// The gRPC codec ceiling: the same line the body limit holds.
pub fn grpc_message_ceiling(config: &permguard_core::Config) -> usize {
    body_floor(config).max(config.limits().body_bytes())
}
