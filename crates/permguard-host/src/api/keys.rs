// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The key rings on the Host API (WP-3.1).
//!
//! | Route                                   | Grant                     | Answer                                     |
//! | --------------------------------------- | ------------------------- | ------------------------------------------ |
//! | `GET /host/v1/keys`                     | `keys.read`               | every ring, its epoch and key-set digest   |
//! | `GET /host/v1/keys/{ring}`              | none: public keys         | the published set, epoch, digest, binding  |
//! | `GET /host/v1/ring-bindings`            | `identity.read`           | every identity-signed binding held         |
//! | `GET /host/v1/keys/bundle`              | `keys.read` on `resource` | one page of the verification bundle        |
//! | `POST /host/v1/keys/{ring}/rotate`      | `keys.admin`              | a successor prepublished; a receipt        |
//! | `POST /host/v1/keys/{ring}/revoke/plan` | `keys.admin`              | a plan bound to the key, reason and epoch  |
//! | `POST /host/v1/keys/{ring}/revoke/run`  | `keys.admin`              | the key revoked; a receipt                 |
//!
//! Rotation and revocation are security mutations of the domain `keys`; `host.identity` rotates
//! through `POST /host/v1/identity/rotate` only (owner decisions of 2026-10-08). The digest is
//! the ring's key-set digest, hex; the binding is its COSE_Sign1, base64url without padding.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::{Deserialize, Serialize};

use permguard_core::authz::{Actor, operations};
use permguard_core::keys::{Jwk, KEY_SET_MAX_AGE};
use permguard_core::{ErrorClass, codes};

use super::grants::{Planned, plan_digest, rfc3339};
use super::replay::{PLAN_LIFETIME, Plan, mint_id};
use super::{HostApi, Mutation, Receipt, Refusal};
use crate::keys::bundle::{self, BundleError, MAX_MANIFEST_BYTES, PAGE_DEFAULT, PAGE_MAX, Source};
use crate::keys::record::MAX_REASON_BYTES;
use crate::keys::ring::{
    AUDIT_REVOKE_PLANNED, AUDIT_REVOKED, AUDIT_ROTATED, DOMAIN, HOST_IDENTITY, HOST_OPERATIONS,
    REVOKE_PLAN, REVOKE_RUN, ROTATE, Ring, RingError, Statement,
};
use crate::operations::mutation::{Applied, Failure};

/// The operation a revocation plan names.
const REVOKE: &str = "keys.revoke";

/// One ring in the list.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RingSummary {
    /// The ring id: `host.identity`, `host.operations`, `control.attest`, `data.attest`.
    pub ring: String,
    /// How many public keys it publishes.
    pub keys: u32,
    /// The key-set digest of its published set, hex.
    pub digest: String,
    /// The ring epoch.
    pub epoch: u64,
}

/// `GET /host/v1/keys`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Rings {
    pub rings: Vec<RingSummary>,
}

/// One public key, as RFC 7517 spells it; the private half is never expressed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyView {
    pub kid: String,
    pub kty: String,
    pub crv: Option<String>,
    pub x: String,
    pub y: Option<String>,
    pub alg: String,
    #[serde(rename = "use")]
    pub usage: String,
}

impl From<Jwk> for KeyView {
    fn from(jwk: Jwk) -> Self {
        Self {
            kid: jwk.kid,
            kty: jwk.kty,
            crv: jwk.crv,
            x: jwk.x,
            y: jwk.y,
            alg: jwk.alg,
            usage: jwk.usage,
        }
    }
}

/// `GET /host/v1/keys/{ring}`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RingView {
    pub ring: String,
    /// The ring epoch.
    pub epoch: Option<u64>,
    /// The key-set digest of the published set, hex: what a peer persists with the epoch.
    pub digest: String,
    /// The identity-signed binding of this epoch, COSE_Sign1 in base64url; `null` for
    /// `host.identity`, which its chain authenticates, and until the identity signed one.
    pub binding: Option<String>,
    /// How long a client may cache the set, in seconds.
    pub cache_max_age: u32,
    pub keys: Vec<KeyView>,
}

/// One ring binding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RingBinding {
    pub ring: String,
    pub epoch: u64,
    /// COSE_Sign1 `permguard.host.ring-binding.v1`, base64url without padding.
    pub binding: String,
}

/// `GET /host/v1/ring-bindings`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RingBindings {
    pub bindings: Vec<RingBinding>,
}

/// `GET /host/v1/keys/bundle`'s query.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyBundleQuery {
    /// The resource the bundle covers, in the Host API's grammar: `host`, `plane/<p>`, …
    pub resource: String,
    /// The manifest a first page answered, which fixes the frontier; absent on the first page.
    #[serde(default)]
    pub frontier: Option<String>,
    /// Where the page starts, as the page before answered it; requires `frontier`.
    #[serde(default)]
    pub cursor: Option<String>,
    /// How many items the page carries: 1 to 500, 100 when absent.
    #[serde(default)]
    pub limit: Option<u32>,
}

/// One page of the verification bundle (WP-3.4, owner decisions of 2026-10-09).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyBundlePage {
    pub resource: String,
    /// The signed manifest, COSE_Sign1 `permguard.keys.bundle.v1` in base64url, the same bytes on
    /// every page of one frontier: a later page names it as `frontier`.
    pub manifest: String,
    /// The bundle digest, hex.
    pub bundle_digest: String,
    /// How many items the whole bundle holds.
    pub total: u64,
    /// This page's items, canonical CBOR in base64url, in the bundle's digest order.
    pub items: Vec<String>,
    /// The cursor of the next page; absent on the last one.
    pub next_cursor: Option<String>,
}

/// `POST /host/v1/keys/{ring}/rotate`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RotateRing {
    pub request_id: String,
    /// The epoch the caller read; the rotation produces the next one.
    pub expected_epoch: u64,
}

/// What a rotation answers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RingRotated {
    /// The receipt; its revision is the new epoch.
    pub receipt: Receipt,
    /// The successor prepublished: it signs once `publish_ahead` has passed.
    pub kid: String,
}

/// `POST /host/v1/keys/{ring}/revoke/plan`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlanKeyRevoke {
    #[serde(default)]
    pub request_id: String,
    /// The key to revoke.
    pub kid: String,
    /// Why: printable text of 1 to 256 bytes, kept in the journal and the audit.
    pub reason: String,
    /// RFC 3339: when the key is known or believed compromised.
    #[serde(default)]
    pub compromised_at: Option<String>,
    /// The ring epoch the caller read.
    #[serde(default)]
    pub expected_epoch: Option<u64>,
}

/// `POST /host/v1/keys/{ring}/revoke/run`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunKeyRevoke {
    #[serde(default)]
    pub request_id: String,
    pub plan_id: String,
    pub plan_digest: String,
}

/// What a run answers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyRevoked {
    /// The receipt; its revision is the ring epoch once the key left the set.
    pub receipt: Receipt,
    pub kid: String,
}

/// What a plan holds as its target: the key and the facts the run records, bound by the plan's
/// digest so the run cannot change them.
struct Revocation {
    ring: String,
    kid: String,
    reason: String,
    compromised_at: Option<u64>,
}

impl Revocation {
    fn target(&self) -> String {
        format!(
            "{}\n{}\n{}\n{}",
            self.ring,
            self.kid,
            self.reason,
            self.compromised_at
                .map(|at| at.to_string())
                .unwrap_or_default()
        )
    }

    fn parse(target: &str) -> Option<Self> {
        let mut parts = target.split('\n');
        let ring = parts.next()?.to_owned();
        let kid = parts.next()?.to_owned();
        let reason = parts.next()?.to_owned();
        let compromised_at = match parts.next()? {
            "" => None,
            at => Some(at.parse().ok()?),
        };
        parts.next().is_none().then_some(Self {
            ring,
            kid,
            reason,
            compromised_at,
        })
    }
}

impl HostApi {
    /// `GET /host/v1/keys`.
    pub fn rings(&self, actor: &Actor) -> Result<Rings, Refusal> {
        let _admitted = self.admit(actor, operations::KEYS_READ)?;
        let mut rings = Vec::new();
        for id in self.keys.ids() {
            let statement = self.statement(id)?;
            rings.push(RingSummary {
                ring: statement.ring,
                keys: u32::try_from(statement.keys.len()).unwrap_or(u32::MAX),
                digest: hex(&statement.key_set_digest),
                epoch: statement.epoch,
            });
        }
        Ok(Rings { rings })
    }

    /// `GET /host/v1/keys/{ring}`: public, no grant is checked.
    pub fn ring(&self, name: &str) -> Result<RingView, Refusal> {
        let statement = self.statement(name)?;
        Ok(RingView {
            ring: statement.ring,
            epoch: Some(statement.epoch),
            digest: hex(&statement.key_set_digest),
            binding: statement
                .binding
                .as_deref()
                .map(|bytes| URL_SAFE_NO_PAD.encode(bytes)),
            cache_max_age: u32::try_from(KEY_SET_MAX_AGE.as_secs()).unwrap_or(u32::MAX),
            keys: statement.keys.into_iter().map(Into::into).collect(),
        })
    }

    /// `GET /host/v1/ring-bindings`.
    pub fn ring_bindings(&self, actor: &Actor) -> Result<RingBindings, Refusal> {
        let _admitted = self.admit(actor, operations::IDENTITY_READ)?;
        let bindings = self
            .keys
            .bindings()
            .map_err(|error| unreadable("the rings", error))?;
        Ok(RingBindings {
            bindings: bindings
                .into_iter()
                .map(|(ring, epoch, bytes)| RingBinding {
                    ring,
                    epoch,
                    binding: URL_SAFE_NO_PAD.encode(bytes),
                })
                .collect(),
        })
    }

    /// `GET /host/v1/keys/bundle`: one page of the bundle at a fixed frontier, under `keys.read`
    /// on the resource. The first page fixes the frontier and signs the manifest once, under the
    /// `host.operations` key active there; later pages present that manifest and receive the same
    /// bytes; the items of all pages together are the ones it counts and digests (owner decisions
    /// of 2026-10-09).
    pub fn key_bundle(
        &self,
        actor: &Actor,
        query: &KeyBundleQuery,
    ) -> Result<KeyBundlePage, Refusal> {
        let invalid = |detail: String| {
            Refusal::new(
                ErrorClass::Validation,
                codes::common::INVALID_ARGUMENT,
                detail,
            )
        };
        let resource = permguard_core::authz::Resource::parse(&query.resource)
            .map_err(|error| invalid(format!("`resource`: {error}")))?;
        let _admitted = self.admit_on(actor, operations::KEYS_READ, &resource)?;
        let limit = match query.limit {
            None => PAGE_DEFAULT,
            Some(limit) => usize::try_from(limit)
                .ok()
                .filter(|limit| (1..=PAGE_MAX).contains(limit))
                .ok_or_else(|| invalid(format!("`limit` is 1 to {PAGE_MAX}")))?,
        };
        let identity = self.keys.identity().ok_or_else(|| {
            Refusal::new(
                ErrorClass::Unavailable,
                codes::host::IDENTITY_UNAVAILABLE,
                "no Host identity is open on this process",
            )
        })?;
        let operations_ring = self.keys.ring(HOST_OPERATIONS).ok_or_else(|| {
            Refusal::new(
                ErrorClass::Unavailable,
                codes::common::UNAVAILABLE,
                "the bundle's manifest is signed by `host.operations`, and this Host runs \
                 without `operations.keys`",
            )
        })?;
        let source = Source {
            identity,
            rings: self.keys.rings(),
            memberships: self
                .memberships
                .as_deref()
                .map(|memberships| memberships.store.as_ref()),
        };
        let resource = resource.to_string();
        let (built, manifest) = match (&query.frontier, &query.cursor) {
            // A later page: the manifest the first page answered, which the Host checks it signed.
            (Some(token), _) => {
                let bytes = Some(token)
                    .filter(|token| token.len() <= MAX_MANIFEST_BYTES.div_ceil(3) * 4)
                    .and_then(|token| URL_SAFE_NO_PAD.decode(token).ok())
                    .ok_or_else(|| {
                        invalid("`frontier` is the manifest a first page answered".to_owned())
                    })?;
                let built = source
                    .reopen(&bytes, &resource)
                    .map_err(|error| match error {
                        BundleError::Unreproducible(_) | BundleError::Ring(_) => {
                            bundle_refusal(error)
                        }
                        other => invalid(format!("`frontier`: {other}")),
                    })?;
                (built, bytes)
            }
            (None, Some(_)) => {
                return Err(invalid(
                    "`cursor` continues a frontier, and the query names none".to_owned(),
                ));
            }
            // A first page: the frontier now, signed once; fixed again when the operations key
            // turns between the two.
            (None, None) => {
                let mut again = true;
                loop {
                    let issued_at = self.time.now_secs();
                    let frontier = source
                        .frontier(&resource, issued_at)
                        .map_err(bundle_refusal)?;
                    let built = source
                        .build(&resource, &frontier, issued_at)
                        .map_err(bundle_refusal)?;
                    match bundle::sign(operations_ring, &built) {
                        Ok(manifest) => break (built, manifest),
                        Err(BundleError::Unreproducible(_)) if again => again = false,
                        Err(error) => return Err(bundle_refusal(error)),
                    }
                }
            }
        };
        let total = built.items.len();
        let start = match query.cursor.as_deref() {
            None => 0,
            Some(cursor) => cursor
                .parse::<usize>()
                .ok()
                .filter(|start| *start <= total && cursor == start.to_string())
                .ok_or_else(|| invalid("`cursor` is not one this bundle answered".to_owned()))?,
        };
        let end = start.saturating_add(limit).min(total);
        Ok(KeyBundlePage {
            resource,
            manifest: URL_SAFE_NO_PAD.encode(manifest),
            bundle_digest: hex(&built.manifest.bundle_digest),
            total: total as u64,
            items: built.items[start..end]
                .iter()
                .map(|item| URL_SAFE_NO_PAD.encode(item))
                .collect(),
            next_cursor: (end < total).then(|| end.to_string()),
        })
    }

    /// `POST /host/v1/keys/{ring}/rotate`.
    pub async fn rotate_ring(
        &self,
        actor: &Actor,
        name: &str,
        rotate: RotateRing,
    ) -> Result<RingRotated, Refusal> {
        let admitted = self.admit(actor, operations::KEYS_ADMIN)?;
        let ring = self.mutable_ring(name)?;
        let mutation = Mutation {
            request_id: rotate.request_id.clone(),
            expected_revision: Some(rotate.expected_epoch),
        };
        let expected = rotate.expected_epoch;
        let target = (name, &rotate);
        let check = || {
            let epoch = ring.epoch();
            if epoch != expected {
                return Err(Refusal::revision_mismatch(expected, epoch));
            }
            ring.check_rotatable().map_err(refusal_of)
        };
        self.transact(
            DOMAIN,
            &admitted.principal,
            ROTATE,
            AUDIT_ROTATED,
            &mutation,
            &target,
            Some(format!("{name}:epoch:{}", expected.saturating_add(1))),
            check,
            |applying| {
                let rotated = ring.rotate(applying, expected).map_err(failure_of)?;
                Ok(Applied {
                    revision: rotated.epoch,
                    target: Some(format!("{name}:epoch:{}", rotated.epoch)),
                    value: RingRotated {
                        receipt: self.receipt(applying.operation_id(), rotated.epoch),
                        kid: rotated.kid,
                    },
                })
            },
            |operation_id, epoch, _| {
                let kid = ring
                    .operation_kid(&operation_id)
                    .ok_or_else(|| super::grants::unreachable_reconciliation(ROTATE))?;
                Ok(RingRotated {
                    receipt: self.receipt(operation_id, epoch),
                    kid,
                })
            },
        )
    }

    /// `POST /host/v1/keys/{ring}/revoke/plan`.
    pub async fn plan_key_revoke(
        &self,
        actor: &Actor,
        name: &str,
        plan: PlanKeyRevoke,
    ) -> Result<Planned, Refusal> {
        let admitted = self.admit(actor, operations::KEYS_ADMIN)?;
        let ring = self.mutable_ring(name)?;
        if plan.reason.is_empty()
            || plan.reason.len() > MAX_REASON_BYTES
            || plan.reason.chars().any(char::is_control)
        {
            return Err(Refusal::new(
                ErrorClass::Validation,
                codes::common::INVALID_ARGUMENT,
                format!("`reason` is printable text of 1 to {MAX_REASON_BYTES} bytes"),
            ));
        }
        let compromised_at = match plan.compromised_at.as_deref() {
            None => None,
            Some(text) => Some(
                permguard_core::time::from_rfc3339(text)
                    .and_then(|at| u64::try_from(at).ok())
                    .ok_or_else(|| {
                        Refusal::new(
                            ErrorClass::Validation,
                            codes::common::INVALID_ARGUMENT,
                            "`compromised_at` is an RFC 3339 time",
                        )
                    })?,
            ),
        };
        let now = self.time.now_secs();
        if compromised_at.is_some_and(|at| at > now) {
            return Err(Refusal::new(
                ErrorClass::Validation,
                codes::common::INVALID_ARGUMENT,
                "`compromised_at` is in the future",
            ));
        }
        let mutation = Mutation {
            request_id: plan.request_id.clone(),
            expected_revision: plan.expected_epoch,
        };
        let target = (name, &plan);
        let current = || -> Result<u64, Refusal> {
            let epoch = ring.check_revocable(&plan.kid).map_err(refusal_of)?;
            if let Some(expected) = plan.expected_epoch
                && expected != epoch
            {
                return Err(Refusal::revision_mismatch(expected, epoch));
            }
            Ok(epoch)
        };
        let revocation = Revocation {
            ring: name.to_owned(),
            kid: plan.kid.clone(),
            reason: plan.reason.clone(),
            compromised_at,
        };
        self.transact(
            DOMAIN,
            &admitted.principal,
            REVOKE_PLAN,
            AUDIT_REVOKE_PLANNED,
            &mutation,
            &target,
            Some(plan.kid.clone()),
            || current().map(|_| ()),
            |applying| {
                let epoch = current().map_err(Failure::Refused)?;
                let expires = now.saturating_add(PLAN_LIFETIME.as_secs());
                let plan_id = mint_id().map_err(Failure::Refused)?;
                let held = revocation.target();
                let digest = plan_digest(
                    &plan_id,
                    REVOKE,
                    &held,
                    epoch,
                    admitted.principal.as_str(),
                    expires,
                );
                self.replay
                    .plan(
                        applying,
                        Plan {
                            plan_id: plan_id.clone(),
                            operation: REVOKE.to_owned(),
                            target: held,
                            revision: epoch,
                            digest: digest.clone(),
                            expires,
                            principal: admitted.principal.as_str().to_owned(),
                        },
                    )
                    .map_err(Failure::Refused)?;
                Ok(Applied {
                    revision: epoch,
                    target: Some(plan.kid.clone()),
                    value: Planned {
                        plan_id,
                        plan_digest: digest,
                        expires: rfc3339(expires),
                        revision: epoch,
                    },
                })
            },
            // A plan leaves no trace in the ring, so recovery never commits one: it is marked
            // failed, and the plan, which nobody was answered, expires unused.
            |_, _, _| Err(super::grants::unreachable_reconciliation(REVOKE_PLAN)),
        )
    }

    /// `POST /host/v1/keys/{ring}/revoke/run`.
    pub async fn run_key_revoke(
        &self,
        actor: &Actor,
        name: &str,
        run: RunKeyRevoke,
    ) -> Result<KeyRevoked, Refusal> {
        let admitted = self.admit(actor, operations::KEYS_ADMIN)?;
        let ring = self.mutable_ring(name)?;
        let mutation = Mutation {
            request_id: run.request_id.clone(),
            expected_revision: None,
        };
        let now = self.time.now_secs();
        let target = (name, &run);
        let presented = || -> Result<(Plan, Revocation), Refusal> {
            let plan = self
                .replay
                .plan_of(&admitted.principal, &run.plan_id, now)?;
            let revocation = Revocation::parse(&plan.target)
                .filter(|revocation| plan.operation == REVOKE && revocation.ring == name)
                .ok_or_else(|| {
                    Refusal::new(
                        ErrorClass::NotFound,
                        codes::host::PLAN_UNKNOWN,
                        "no plan of that id is held for this ring",
                    )
                })?;
            if plan.digest != run.plan_digest {
                return Err(Refusal::new(
                    ErrorClass::Validation,
                    codes::host::PLAN_DIGEST_MISMATCH,
                    "the plan digest presented is not the one the plan step answered",
                ));
            }
            Ok((plan, revocation))
        };
        let kid = presented().ok().map(|(_, revocation)| revocation.kid);
        self.transact(
            DOMAIN,
            &admitted.principal,
            REVOKE_RUN,
            AUDIT_REVOKED,
            &mutation,
            &target,
            kid,
            || presented().map(|_| ()),
            |applying| {
                let (plan, revocation) = presented().map_err(Failure::Refused)?;
                // The epoch is compared under the ring's lock: a ring changed since the plan is
                // refused with its current epoch.
                let revoked = ring
                    .revoke(
                        applying,
                        &revocation.kid,
                        &revocation.reason,
                        revocation.compromised_at,
                        plan.revision,
                    )
                    .map_err(failure_of)?;
                if let Err(error) = self
                    .replay
                    .consume(applying, &admitted.principal, &run.plan_id)
                {
                    tracing::warn!(
                        event.name = "host.plan_unconsumed",
                        component = super::COMPONENT,
                        error = %error,
                        "a run plan could not be marked consumed; its key is revoked"
                    );
                }
                Ok(Applied {
                    revision: revoked.epoch,
                    target: Some(revoked.kid.clone()),
                    value: KeyRevoked {
                        receipt: self.receipt(applying.operation_id(), revoked.epoch),
                        kid: revoked.kid,
                    },
                })
            },
            |operation_id, epoch, _| {
                let kid = ring
                    .operation_kid(&operation_id)
                    .ok_or_else(|| super::grants::unreachable_reconciliation(REVOKE_RUN))?;
                Ok(KeyRevoked {
                    receipt: self.receipt(operation_id, epoch),
                    kid,
                })
            },
        )
    }

    /// The statement of `name`, or `ring_unknown`, or `ring_unreadable`: never an empty set
    /// dressed as an answer.
    fn statement(&self, name: &str) -> Result<Statement, Refusal> {
        match self.keys.statement(name) {
            None => Err(Refusal::new(
                ErrorClass::NotFound,
                codes::host::RING_UNKNOWN,
                format!("no key ring `{name}` is composed in this process"),
            )),
            Some(Ok(statement)) => Ok(statement),
            Some(Err(error)) => Err(unreadable(name, error)),
        }
    }

    /// The ring `name` an operator may rotate and revoke.
    fn mutable_ring(&self, name: &str) -> Result<&std::sync::Arc<Ring>, Refusal> {
        if name == HOST_IDENTITY {
            return Err(Refusal::new(
                ErrorClass::Validation,
                codes::host::RING_NOT_MUTABLE,
                "`host.identity` rotates through POST /host/v1/identity/rotate",
            ));
        }
        self.keys.ring(name).ok_or_else(|| {
            Refusal::new(
                ErrorClass::NotFound,
                codes::host::RING_UNKNOWN,
                format!("no key ring `{name}` is composed in this process"),
            )
        })
    }
}

fn unreadable(ring: &str, error: RingError) -> Refusal {
    tracing::warn!(
        event.name = "host.keys.unreadable",
        component = super::COMPONENT,
        ring = ring,
        error = %error,
        "a key ring could not be read"
    );
    Refusal::Api(
        permguard_core::ApiError::new(
            ErrorClass::Unavailable,
            codes::host::RING_UNREADABLE,
            format!("the key ring `{ring}` could not be read"),
        )
        .with_internal(error.to_string()),
    )
}

fn refusal_of(error: RingError) -> Refusal {
    match error {
        RingError::Conflict { expected, current } => Refusal::revision_mismatch(expected, current),
        RingError::Pending(detail) => Refusal::new(
            ErrorClass::Conflict,
            codes::host::KEY_ROTATION_PENDING,
            detail,
        ),
        RingError::UnknownKey(detail) => {
            Refusal::new(ErrorClass::NotFound, codes::host::KEY_UNKNOWN, detail)
        }
        RingError::Revoked(detail) => {
            Refusal::new(ErrorClass::Conflict, codes::host::KEY_REVOKED, detail)
        }
        RingError::Refused(detail) => Refusal::new(
            ErrorClass::Validation,
            codes::common::INVALID_ARGUMENT,
            detail,
        ),
        other => unreadable("the ring", other),
    }
}

fn bundle_refusal(error: BundleError) -> Refusal {
    match error {
        BundleError::Unreproducible(detail) => Refusal::new(
            ErrorClass::Conflict,
            codes::host::FRONTIER_UNREPRODUCIBLE,
            format!("{detail}: ask again without a frontier"),
        ),
        BundleError::Ring(error) => unreadable("a ring", error),
        other => Refusal::Api(
            permguard_core::ApiError::new(
                ErrorClass::Unavailable,
                codes::common::UNAVAILABLE,
                "the verification bundle could not be built",
            )
            .with_internal(other.to_string()),
        ),
    }
}

fn failure_of(error: RingError) -> Failure<Refusal> {
    if error.is_indeterminate() {
        Failure::Indeterminate(refusal_of(error))
    } else {
        Failure::Refused(refusal_of(error))
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests;
