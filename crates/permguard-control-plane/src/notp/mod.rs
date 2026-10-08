// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The NOTP domain: the git-like store behind every ledger, served by the
//! same layering the catalog set — a facade both transports call, with the
//! engine, auditing, quotas and the error taxonomy below them.
//!
//! One store instance per ledger, shared for the process's lifetime: the
//! ref compare-and-swap serialises on the store's own lock, so two pushes
//! against one ledger contend exactly there and nowhere else. Pulls never
//! wait.

pub(crate) mod grpc;
pub(crate) mod http;

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use permguard_core::catalog::{Catalog, CatalogError, Selector};
use permguard_core::keys::SigningRing;
use permguard_core::metrics::labels;
use permguard_core::metrics::{Metric, Metrics, SECONDS};
use permguard_core::{ApiError, Disclosure, ErrorClass, Subject};

use crate::engine::{Engine, EngineError, EngineLimits, LedgerIdentity};
use crate::store::FileObjectStore;
use permguard_notp::*;
use permguard_objects::statement::{HeadStatement, SignedHead};
use permguard_objects::{compress, limits};

/// NOTP operations answered — `op` is one of the six verbs, `outcome` is the
/// error class that ended it (`ok` when none did). Both label sets are small
/// and fixed: nothing here comes from a client.
const OPERATIONS: Metric = Metric::counter(
    "permguard_notp_operations_total",
    "NOTP operations answered, by operation and outcome.",
);

/// How long each verb took, end to end at the facade.
const OPERATION_SECONDS: Metric = Metric::histogram(
    "permguard_notp_operation_seconds",
    "How long NOTP operations took, by operation.",
    SECONDS,
);

/// Bucket boundaries for things counted per batch, up to the batch ceiling.
const COUNTS: &[f64] = &[1.0, 2.0, 5.0, 10.0, 25.0, 50.0, 100.0, 250.0, 500.0, 1000.0];

/// Objects carried by one transfer batch.
const BATCH_OBJECTS: Metric = Metric::histogram(
    "permguard_notp_batch_objects",
    "Objects carried by one upload or fetch batch, by operation.",
    COUNTS,
);

/// Bytes carried on the wire by transfer batches — what capacity planning
/// reads, and what shows whether compression is earning its keep.
const WIRE_BYTES: Metric = Metric::counter(
    "permguard_notp_wire_bytes_total",
    "Bytes carried by NOTP batches on the wire, by operation and encoding.",
);

/// What every NOTP operation runs with.
#[derive(Clone)]
pub(crate) struct NotpFacade {
    pub(crate) catalog: Arc<dyn Catalog>,
    /// `<volume>/data/zones` — the same root the catalog keeps, so a ledger's
    /// store is always beside its record.
    pub(crate) zones_root: PathBuf,
    /// The ring that signs head statements — the git-like ring, never the
    /// one sealing the audit trail.
    pub(crate) keys: Arc<dyn SigningRing>,
    pub(crate) limits: EngineLimits,
    /// What this deployment has opted into among the provisional contracts, for the ingest gate.
    pub(crate) enabled: permguard_languages::registry::Enabled,
    /// Whether batches ride deflate-compressed — advertised at negotiation,
    /// echoed per batch; the engine below only ever sees canonical bytes.
    pub(crate) compression: bool,
    pub(crate) recorder: Option<crate::handles::Audit>,
    pub(crate) disclosure: Disclosure,
    pub(crate) audit_refusals: bool,
    /// Where the numbers go; a handle that may hold nothing, costing a branch.
    pub(crate) metrics: Metrics,
    /// One store per ledger, shared: the CAS lock must be process-wide.
    stores: Arc<Mutex<HashMap<String, Arc<FileObjectStore>>>>,
    /// The Host's authorization, before anything is resolved (WP-2.4): `policy.push` on the exact
    /// ledger for a push, `catalog.read` on it for a ref read, a pull or a fetch until the Host
    /// task transport of WP-4.x carries pulls for `policy.mirror` members; the key ring stays open,
    /// being the public keys.
    pub(crate) authorization: Arc<permguard_host::composition::Authorization>,
}

/// A head statement's `signed_at` is the signing ring's time: the Host's time guard for the ring
/// the Host hands out (WP-2.12).
impl permguard_core::time::Clock for NotpFacade {
    fn now(&self) -> i64 {
        self.keys.signing_time()
    }
}

impl NotpFacade {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        catalog: Arc<dyn Catalog>,
        zones_root: PathBuf,
        keys: Arc<dyn SigningRing>,
        limits: EngineLimits,
        enabled: permguard_languages::registry::Enabled,
        compression: bool,
        recorder: Option<crate::handles::Audit>,
        disclosure: Disclosure,
        audit_refusals: bool,
        metrics: Metrics,
        authorization: Arc<permguard_host::composition::Authorization>,
    ) -> Self {
        Self {
            catalog,
            zones_root,
            keys,
            limits,
            enabled,
            compression,
            recorder,
            disclosure,
            audit_refusals,
            metrics,
            authorization,
            stores: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Whether `actor` may read the ledger `zone`/`ledger` names: `catalog.read` on the exact
    /// ledger, the interim operation for a pull until `policy.mirror` members arrive over the Host
    /// task transport (WP-4.x; owner decision, 2026-10-06). Two stages, as for a push.
    fn authorize_read(
        &self,
        actor: &permguard_core::authz::Actor,
        zone: &str,
        ledger: &str,
    ) -> Result<(), crate::wire::Refusal> {
        self.authorize_as(
            actor,
            permguard_core::authz::operations::CATALOG_READ,
            zone,
            ledger,
        )
    }

    /// Whether `actor` may push to the ledger `zone`/`ledger` names, by id or by name: a caller
    /// with nothing for `policy.push` under this plane is refused before any lookup, the exact
    /// ledger is authorized once resolved, and a name that resolves to nothing is out of scope
    /// unless the caller's grants cover the whole plane or zone (owner decision, 2026-10-06).
    fn authorize_push(
        &self,
        actor: &permguard_core::authz::Actor,
        zone: &str,
        ledger: &str,
    ) -> Result<(), crate::wire::Refusal> {
        self.authorize_as(
            actor,
            permguard_core::authz::operations::POLICY_PUSH,
            zone,
            ledger,
        )
    }

    fn authorize_as(
        &self,
        actor: &permguard_core::authz::Actor,
        operation: &str,
        zone: &str,
        ledger: &str,
    ) -> Result<(), crate::wire::Refusal> {
        use permguard_core::authz::Resource;

        let plane = Resource::plane(crate::service::PLANE);
        self.authorization.may_act_under(actor, operation, &plane)?;
        let zone = match self.catalog.get_zone(&Selector::parse(zone)) {
            Ok(zone) => zone,
            Err(error @ CatalogError::NotFound { .. }) => {
                self.authorization
                    .not_found_or_forbidden(actor, operation, &plane)?;
                return Err(crate::catalog::api_error(error).into());
            }
            Err(error) => return Err(crate::catalog::api_error(error).into()),
        };
        let scope = Resource::zone(crate::service::PLANE, &zone.id);
        self.authorization.may_act_under(actor, operation, &scope)?;
        match self
            .catalog
            .get_ledger(&Selector::Id(zone.id.clone()), &Selector::parse(ledger))
        {
            Ok(found) => self
                .authorization
                .authorize(
                    actor,
                    operation,
                    &Resource::ledger(crate::service::PLANE, &zone.id, &found.id),
                )
                .map_err(Into::into),
            Err(error @ CatalogError::NotFound { .. }) => {
                self.authorization
                    .not_found_or_forbidden(actor, operation, &scope)?;
                Err(crate::catalog::api_error(error).into())
            }
            Err(error) => Err(crate::catalog::api_error(error).into()),
        }
    }

    /// Counts one finished operation and observes how long it took. The
    /// outcome label is the error class, which is small and fixed by the
    /// taxonomy — never a message, never anything a client wrote.
    fn observed<T>(
        &self,
        op: &'static str,
        started: std::time::Instant,
        result: Result<T, ApiError>,
    ) -> Result<T, ApiError> {
        let outcome = match &result {
            Ok(_) => "ok",
            Err(error) => error.class().as_str(),
        };
        self.metrics
            .count(&OPERATIONS, &[(labels::OP, op), (labels::OUTCOME, outcome)]);
        self.metrics.observe(
            &OPERATION_SECONDS,
            &[(labels::OP, op)],
            started.elapsed().as_secs_f64(),
        );
        result
    }

    /// Observes one transfer batch: how many objects, and how many bytes as
    /// they actually rode the wire.
    fn observed_batch(&self, op: &'static str, objects: usize, wire_bytes: u64, encoding: &str) {
        self.metrics
            .observe(&BATCH_OBJECTS, &[(labels::OP, op)], objects as f64);
        self.metrics.add(
            &WIRE_BYTES,
            &[(labels::OP, op), (labels::ENCODING, encoding)],
            wire_bytes as f64,
        );
    }

    /// Resolves the ledger a request names — name or id, like every surface —
    /// and answers its identity plus its process-shared store.
    fn resolve(
        &self,
        zone: &str,
        ledger: &str,
    ) -> Result<(LedgerIdentity, Arc<FileObjectStore>), ApiError> {
        let zone = self
            .catalog
            .get_zone(&Selector::parse(zone))
            .map_err(crate::catalog::api_error)?;
        let ledger = self
            .catalog
            .get_ledger(&Selector::Id(zone.id.clone()), &Selector::parse(ledger))
            .map_err(crate::catalog::api_error)?;

        let mut stores = self
            .stores
            .lock()
            .map_err(|_| internal("the store table is poisoned"))?;
        let store = Arc::clone(stores.entry(ledger.id.clone()).or_insert_with(|| {
            Arc::new(FileObjectStore::new(
                self.zones_root
                    .join(&zone.id)
                    .join("ledgers")
                    .join(&ledger.id),
            ))
        }));

        Ok((
            LedgerIdentity {
                zone_id: zone.id,
                ledger_id: ledger.id,
            },
            store,
        ))
    }

    fn engine<'a>(&'a self, identity: LedgerIdentity, store: &'a FileObjectStore) -> Engine<'a> {
        Engine {
            store,
            identity,
            limits: self.limits,
            enabled: self.enabled.clone(),
            clock: self,
        }
    }

    /// Signs a head statement with the git-like ring: the active key names
    /// the `kid`, and the manager produces the raw Ed25519 signature over
    /// the COSE structure this closure never sees.
    fn signer(&self) -> impl Fn(&HeadStatement) -> Result<Vec<u8>, EngineError> + '_ {
        move |statement| {
            let kid = self
                .keys
                .active_key_id()
                .map_err(|e| EngineError::Internal {
                    detail: format!("resolving the signing key: {e}"),
                })?;
            // A refusal that passes on its own — the Host's clock in anomaly (WP-2.12), a ring not
            // ready yet — is answered `unavailable`, never as a store failure.
            let unavailable = std::cell::RefCell::new(None::<String>);
            let signed = SignedHead::sign_with(statement, kid.as_str().as_bytes(), |bytes| {
                let signature = self.keys.sign(bytes).map_err(|e| {
                    if e.is_retryable() {
                        *unavailable.borrow_mut() = Some(e.to_string());
                    }
                    permguard_objects::statement::StatementError::Signer(format!(
                        "signing the head statement: {e}"
                    ))
                })?;
                if signature.key_id() != &kid {
                    // The ring rotated between naming the key and signing:
                    // refuse rather than emit a kid the signature disowns.
                    return Err(permguard_objects::statement::StatementError::Signer(
                        "the signing key rotated mid-signature".to_string(),
                    ));
                }
                Ok(signature.bytes().to_vec())
            })
            .map_err(|e| match unavailable.take() {
                Some(message) => EngineError::SigningUnavailable { message },
                None => EngineError::Internal {
                    detail: e.to_string(),
                },
            })?;
            signed.encode().map_err(|e| EngineError::Internal {
                detail: e.to_string(),
            })
        }
    }

    // ---- the six operations, each: resolve, run, audit, map ----

    #[tracing::instrument(name = "notp.ref", skip_all, fields(zone = %zone, ledger = %ledger))]
    pub(crate) async fn get_ref(
        &self,
        actor: &permguard_core::authz::Actor,
        zone: &str,
        ledger: &str,
        name: &str,
    ) -> Result<GetRef, crate::wire::Refusal> {
        self.authorize_read(actor, zone, ledger)?;
        let started = std::time::Instant::now();
        let result = (|| {
            let (identity, store) = self.resolve(zone, ledger)?;
            let signer = self.signer();
            let engine = self.engine(identity, &store);
            let (state, statement) = engine.get_ref(name, &signer).map_err(api_error)?;
            Ok(GetRef {
                head: state.head.to_string(),
                counter: state.counter,
                statement,
            })
        })();
        self.observed("ref", started, result).map_err(Into::into)
    }

    #[tracing::instrument(name = "notp.push_negotiate", skip_all, fields(zone = %zone, ledger = %ledger))]
    pub(crate) async fn negotiate_push(
        &self,
        actor: &permguard_core::authz::Actor,
        zone: &str,
        ledger: &str,
        request: &NegotiatePushRequest,
    ) -> Result<NegotiatePushResponse, crate::wire::Refusal> {
        self.authorize_push(actor, zone, ledger)?;
        let started = std::time::Instant::now();
        let result = match self.resolve(zone, ledger) {
            Ok((identity, store)) => match self.engine(identity, &store).negotiate_push(request) {
                Ok(mut response) => {
                    response.compression = self.advertised();
                    Ok(response)
                }
                Err(error) => Err(self.refused("notp.push.negotiate.refused", error).await),
            },
            Err(error) => Err(error),
        };
        self.observed("push_negotiate", started, result)
            .map_err(Into::into)
    }

    #[tracing::instrument(name = "notp.upload", skip_all, fields(zone = %zone, ledger = %ledger))]
    pub(crate) async fn upload(
        &self,
        actor: &permguard_core::authz::Actor,
        zone: &str,
        ledger: &str,
        request: &UploadObjectsRequest,
    ) -> Result<UploadObjectsResponse, crate::wire::Refusal> {
        self.authorize_push(actor, zone, ledger)?;
        let started = std::time::Instant::now();
        let result = match self.resolve(zone, ledger) {
            Ok((identity, store)) => match self.decode_batch(request) {
                Ok(raw) => match self.engine(identity, &store).upload(&raw) {
                    Ok(response) => {
                        let wire: u64 = request.objects.iter().map(|o| o.len() as u64).sum();
                        self.observed_batch(
                            "upload",
                            request.objects.len(),
                            wire,
                            request.compression.as_deref().unwrap_or("raw"),
                        );
                        Ok(response)
                    }
                    Err(error) => Err(self.refused("notp.upload.refused", error).await),
                },
                Err(error) => Err(error),
            },
            Err(error) => Err(error),
        };
        self.observed("upload", started, result).map_err(Into::into)
    }

    #[tracing::instrument(name = "notp.push_commit", skip_all, fields(zone = %zone, ledger = %ledger))]
    pub(crate) async fn commit_push(
        &self,
        actor: &permguard_core::authz::Actor,
        zone: &str,
        ledger: &str,
        request: &CommitPushRequest,
    ) -> Result<CommitPushResponse, crate::wire::Refusal> {
        self.authorize_push(actor, zone, ledger)?;
        let started = std::time::Instant::now();
        let result = match self.resolve(zone, ledger) {
            Ok((identity, store)) => {
                let ledger_id = identity.ledger_id.clone();
                let signer = self.signer();
                match self.engine(identity, &store).commit_push(request, &signer) {
                    Ok(response) => self
                        .record(
                            "ledger.pushed",
                            &format!(
                                "{ledger_id} {} {} #{}",
                                request.r#ref, response.head, response.counter
                            ),
                        )
                        .await
                        .map(|()| response),
                    Err(error) => Err(self.refused("notp.push.commit.refused", error).await),
                }
            }
            Err(error) => Err(error),
        };
        self.observed("push_commit", started, result)
            .map_err(Into::into)
    }

    #[tracing::instrument(name = "notp.pull_negotiate", skip_all, fields(zone = %zone, ledger = %ledger))]
    pub(crate) async fn negotiate_pull(
        &self,
        actor: &permguard_core::authz::Actor,
        zone: &str,
        ledger: &str,
        request: &NegotiatePullRequest,
    ) -> Result<NegotiatePullResponse, crate::wire::Refusal> {
        self.authorize_read(actor, zone, ledger)?;
        let started = std::time::Instant::now();
        let result = (|| {
            let (identity, store) = self.resolve(zone, ledger)?;
            let signer = self.signer();
            let engine = self.engine(identity, &store);
            let mut response = engine.negotiate_pull(request, &signer).map_err(api_error)?;
            response.compression = self.advertised();
            Ok(response)
        })();
        self.observed("pull_negotiate", started, result)
            .map_err(Into::into)
    }

    #[tracing::instrument(name = "notp.fetch", skip_all, fields(zone = %zone, ledger = %ledger))]
    pub(crate) async fn fetch(
        &self,
        actor: &permguard_core::authz::Actor,
        zone: &str,
        ledger: &str,
        request: &FetchObjectsRequest,
    ) -> Result<FetchObjectsResponse, crate::wire::Refusal> {
        self.authorize_read(actor, zone, ledger)?;
        let started = std::time::Instant::now();
        let result = (|| {
            let (identity, store) = self.resolve(zone, ledger)?;
            let engine = self.engine(identity, &store);
            let mut response = engine.fetch(request).map_err(api_error)?;
            if self.compression && request.accept_compression.as_deref() == Some(compress::DEFLATE)
            {
                response.objects = response
                    .objects
                    .iter()
                    .map(|bytes| compress::deflate(bytes))
                    .collect();
                response.compression = Some(compress::DEFLATE.to_owned());
            }
            let wire: u64 = response.objects.iter().map(|o| o.len() as u64).sum();
            self.observed_batch(
                "fetch",
                response.objects.len(),
                wire,
                response.compression.as_deref().unwrap_or("raw"),
            );
            Ok(response)
        })();
        self.observed("fetch", started, result).map_err(Into::into)
    }

    /// The algorithm negotiate responses advertise, when one is on.
    fn advertised(&self) -> Option<String> {
        self.compression.then(|| compress::DEFLATE.to_owned())
    }

    /// An upload batch, decoded to the canonical bytes the engine ingests.
    /// Any batch may arrive raw; a compressed one must name the one
    /// algorithm this version speaks — named, checked, never guessed.
    ///
    /// The batch ceilings are enforced **while** inflating, not after: a
    /// small wire body must not be able to balloon past what the engine
    /// would have accepted — decompression amplifies bytes, never limits.
    fn decode_batch(
        &self,
        request: &UploadObjectsRequest,
    ) -> Result<UploadObjectsRequest, ApiError> {
        let rejected = |message: String| {
            ApiError::new(
                ErrorClass::Validation,
                permguard_core::codes::stream::BATCH_REJECTED,
                message,
            )
        };
        match request.compression.as_deref() {
            None => Ok(request.clone()),
            Some(compress::DEFLATE) => {
                if request.objects.len() as u64 > self.limits.max_batch_objects {
                    return Err(rejected(
                        "more objects than the advertised batch limit".to_owned(),
                    ));
                }
                let mut inflated_total = 0u64;
                let mut objects = Vec::with_capacity(request.objects.len());
                for bytes in &request.objects {
                    let raw =
                        compress::inflate(bytes, limits::MAX_OBJECT_BYTES).map_err(|error| {
                            rejected(format!("a batch object does not decompress: {error}"))
                        })?;
                    inflated_total += raw.len() as u64;
                    if inflated_total > self.limits.max_batch_bytes {
                        return Err(rejected(
                            "the batch inflates past the advertised batch limit".to_owned(),
                        ));
                    }
                    objects.push(raw);
                }
                Ok(UploadObjectsRequest {
                    objects,
                    compression: None,
                })
            }
            Some(other) => Err(rejected(format!(
                "`{other}` is not a negotiated compression"
            ))),
        }
    }

    /// The key ring, as the JWKS document both surfaces serve.
    pub(crate) fn keyring(&self) -> Result<Vec<u8>, ApiError> {
        let keys = self
            .keys
            .public_keys()
            .map_err(|e| internal(format!("reading the key ring: {e}")))?;
        let set = permguard_core::keys::JwkSet::new(keys);
        serde_json::to_vec(&set).map_err(|e| internal(format!("describing the key ring: {e}")))
    }

    // ---- auditing, the catalog's discipline verbatim ----

    /// A failed record does not undo the push, and is answered `mutation_unrecorded` rather than
    /// success (owner decision of 2026-10-07). `TODO(WP-15)`: the push becomes an operation of
    /// the Host's security-mutation transaction (WP-3.6).
    async fn record(&self, action: &'static str, target: &str) -> Result<(), ApiError> {
        let Some(recorder) = &self.recorder else {
            return Ok(());
        };
        recorder
            .record_on(action, Subject::System("control-plane"), target)
            .await
            .map_err(|error| {
                tracing::error!(
                    event.name = "notp.audit_failed",
                    component = "control-plane",
                    action = action,
                    error = %error,
                    "the ledger change was made and its audit record was not"
                );
                crate::unrecorded(error)
            })
    }

    async fn refused(&self, operation: &'static str, error: EngineError) -> ApiError {
        let error = api_error(error);
        if self.audit_refusals
            && matches!(
                error.class(),
                ErrorClass::Validation | ErrorClass::Conflict | ErrorClass::NotFound
            )
        {
            // A refusal changed nothing: its record failing is said in the log, not answered.
            let _ = self.record(operation, error.code()).await;
        }
        error
    }
}

/// The advertised ref, shaped for both surfaces.
pub(crate) struct GetRef {
    pub(crate) head: String,
    pub(crate) counter: u64,
    pub(crate) statement: Vec<u8>,
}

fn internal(detail: impl std::fmt::Display) -> ApiError {
    ApiError::new(
        ErrorClass::Internal,
        permguard_core::codes::notp::NOTP_FAILED,
        "the ledger store failed",
    )
    .with_internal(detail.to_string())
}

/// Translates the engine's vocabulary into the API's — the one place they meet.
pub(crate) fn api_error(error: EngineError) -> ApiError {
    match error {
        EngineError::Validation { code, message } => {
            ApiError::new(ErrorClass::Validation, leak_code(code), message)
        }
        EngineError::Conflict { current } => {
            let mut api = ApiError::new(
                ErrorClass::Conflict,
                permguard_core::codes::notp::REF_CONFLICT,
                "the ref moved: negotiate again from the current head",
            );
            if let Some(state) = current {
                api = api.with_internal(format!(
                    "current head {} counter {}",
                    state.head, state.counter
                ));
            }
            api
        }
        EngineError::NotFound { what } => ApiError::new(
            ErrorClass::NotFound,
            permguard_core::codes::common::NOT_FOUND,
            format!("nothing answers to {what}"),
        ),
        EngineError::Unavailable { message } => ApiError::new(
            ErrorClass::Unavailable,
            permguard_core::codes::stream::QUOTA_EXHAUSTED,
            message,
        ),
        EngineError::SigningUnavailable { message } => ApiError::new(
            ErrorClass::Unavailable,
            permguard_core::codes::common::UNAVAILABLE,
            format!("the head statement cannot be signed now: {message}"),
        ),
        EngineError::Internal { detail } => ApiError::new(
            ErrorClass::Internal,
            permguard_core::codes::notp::NOTP_FAILED,
            "the ledger store failed",
        )
        .with_internal(detail),
    }
}

/// The engine's codes are compile-time literals already shaped for the wire.
fn leak_code(code: &'static str) -> &'static str {
    code
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use std::sync::Arc;
    use std::time::Duration;

    use permguard_core::keys::{Jwk, KeyId, KeyManager, Maintenance, PublicSet, Sign, Signature};
    use permguard_core::time::Clock as _;
    use permguard_host::composition::{CONTROL_ATTEST, Declaration, HeadStatementV1, Host};
    use permguard_host::time::{ManualClock, ManualMonotonic, TimeGuard};
    use permguard_objects::digest::Digest;
    use permguard_std::catalog::FileCatalog;

    use super::*;

    struct Ring;

    impl Sign for Ring {
        fn active_key_id(&self) -> permguard_core::keys::Result<KeyId> {
            Ok(KeyId::new("control"))
        }
        fn sign(&self, payload: &[u8]) -> permguard_core::keys::Result<Signature> {
            Ok(Signature::new(
                KeyId::new("control"),
                "EdDSA",
                payload.to_vec(),
            ))
        }
    }

    impl PublicSet for Ring {
        fn public_keys(&self) -> permguard_core::keys::Result<Vec<Jwk>> {
            Ok(vec![Jwk::okp("control", "Ed25519", "EdDSA", "x")])
        }
    }

    impl KeyManager for Ring {
        fn name(&self) -> &'static str {
            "ring"
        }
        fn maintain(&self) -> permguard_core::keys::Result<Maintenance> {
            Ok(Maintenance::default())
        }
    }

    /// WP-2.12: a head statement is stamped with the Host's time and, with the Host's clock in
    /// anomaly, refused as `unavailable` — something a client retries — never as a store failure.
    #[test]
    fn a_clock_anomaly_refuses_a_head_statement_as_unavailable() {
        const START: i64 = 1_800_000_000;
        let wall = Arc::new(ManualClock::at(START));
        let time = Arc::new(TimeGuard::new(
            wall.clone(),
            Arc::new(ManualMonotonic::default()),
            Duration::from_secs(30),
        ));
        let signer = Host::builder()
            .ring(CONTROL_ATTEST, Arc::new(Ring))
            .time(time)
            .build()
            .register(Declaration::new("control").signs::<HeadStatementV1>())
            .expect("registers")
            .signer::<HeadStatementV1>()
            .expect("declared")
            .expect("composed");
        let root = std::env::temp_dir().join(format!(
            "permguard-notp-clock-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        let facade = NotpFacade::new(
            Arc::new(FileCatalog::new(root.join("zones"))),
            root.join("zones"),
            Arc::new(signer),
            EngineLimits {
                max_batch_bytes: 1024,
                max_batch_objects: 10,
                max_push_objects: 10,
                max_push_bytes: 1024,
                ledger_quota_bytes: 1024,
            },
            permguard_languages::registry::Enabled::everything(),
            false,
            None,
            Disclosure::Minimal,
            false,
            permguard_core::metrics::Metrics::none(),
            Arc::new(permguard_host::composition::Authorization::permissive()),
        );
        wall.jump(7);
        assert_eq!(facade.now(), START + 7, "signed_at is the Host's time");
        let statement = HeadStatement {
            zone: "0198f2aa-0000-7000-8000-000000000001".into(),
            ledger: "0198f3bb-0000-7000-8000-000000000002".into(),
            r#ref: "main".into(),
            digest: Digest::compute(b"commit"),
            counter: 1,
            signed_at: facade.now(),
        };
        facade.signer()(&statement).expect("a sound clock signs");

        wall.jump(-3_600);
        let refused = facade.signer()(&statement).expect_err("in anomaly");
        assert!(
            matches!(refused, EngineError::SigningUnavailable { .. }),
            "{refused}"
        );
        let answer = api_error(refused);
        assert_eq!(answer.class(), ErrorClass::Unavailable);
        assert_eq!(answer.code(), permguard_core::codes::common::UNAVAILABLE);
        let _ = std::fs::remove_dir_all(root);
    }
}
