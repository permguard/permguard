// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! Authorization before evaluation (WP-2.4): `decision.evaluate` on the exact ledger, decided
//! before the request reaches a policy, on both transports the same way.
//!
//! The request names its store by zone and ledger, by name or by id (the native contract); the
//! grant names the ledger by id. So the check runs in two stages (owner decision, 2026-10-06):
//! a caller with nothing for `decision.evaluate` under this plane is refused before any mirror
//! is looked for; the mirror the names resolve to is then authorized exactly; and names that
//! resolve to no mirror are answered as out of scope unless the caller's grants cover the whole
//! plane, in which case the decision path answers its own not-found as before.

use std::path::Path;

use axum::Json;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use tonic::Status;
use tonic::metadata::MetadataValue;

use permguard_core::AccessDenial;
use permguard_core::authz::{Actor, Resource, operations};
use permguard_host::composition::Authorization;

use super::store;
use crate::service::PLANE;

/// Whether `actor` may ask for a decision against the store `zone`/`ledger` names. `Ok` carries
/// the ids that were authorized, when the names resolved: the decision path checks the mirror it
/// evaluates is that one, so a mirror replaced between the two never widens the grant.
pub(crate) fn evaluation(
    authorization: &Authorization,
    actor: &Actor,
    root: &Path,
    zone: Option<&str>,
    ledger: Option<&str>,
) -> Result<Option<(String, String)>, AccessDenial> {
    let plane = Resource::plane(PLANE);
    authorization.may_act_under(actor, operations::DECISION_EVALUATE, &plane)?;
    let (Some(zone), Some(ledger)) = (zone, ledger) else {
        // Nothing to resolve: the decision path refuses the missing store as a validation error,
        // which is not a lookup and discloses nothing.
        return Ok(None);
    };
    match located(root, zone, ledger) {
        Some((zone_id, ledger_id)) => {
            authorization.authorize(
                actor,
                operations::DECISION_EVALUATE,
                &Resource::ledger(PLANE, &zone_id, &ledger_id),
            )?;
            Ok(Some((zone_id, ledger_id)))
        }
        None => authorization
            .not_found_or_forbidden(actor, operations::DECISION_EVALUATE, &plane)
            .map(|()| None),
    }
}

/// How long a resolved name is remembered before the volume is asked again.
const LOCATED_FOR: std::time::Duration = std::time::Duration::from_secs(2);

type Located =
    std::collections::HashMap<(String, String), (std::time::Instant, Option<(String, String)>)>;

/// The ids the store names resolve to, remembered briefly: the decision path reads the volume
/// for the same names moments later, and a hot path must not walk the mirror directory twice per
/// request. Grants name ids, and the decision path refuses a mirror whose ids are not the ones
/// authorized, so a stale answer within the window costs a retry, never a widened grant. The
/// directory walk runs outside the lock.
fn located(root: &Path, zone: &str, ledger: &str) -> Option<(String, String)> {
    static LOCATED: std::sync::OnceLock<std::sync::Mutex<Located>> = std::sync::OnceLock::new();
    let memo = LOCATED.get_or_init(|| std::sync::Mutex::new(Located::new()));
    let key = (format!("{}\0{zone}", root.display()), ledger.to_owned());
    let now = std::time::Instant::now();
    {
        let remembered = memo
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some((at, found)) = remembered.get(&key)
            && now.duration_since(*at) < LOCATED_FOR
        {
            return found.clone();
        }
    }
    let found = store::find(root, zone, ledger)
        .map(|mirror| (mirror.identity.zone_id, mirror.identity.ledger_id));
    let mut remembered = memo
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if remembered.len() > 4096 {
        remembered.clear();
    }
    remembered.insert(key, (now, found.clone()));
    found
}

/// A denial over HTTP: the closed `{code, message}` body, `401` with the challenge or `403`.
pub(crate) fn http_denial(denial: &AccessDenial) -> Response {
    tracing::debug!(
        event.name = "authz.denied",
        component = "data-plane",
        error.code = denial.code(),
        "an evaluation was denied"
    );
    let status = StatusCode::from_u16(denial.http_status()).unwrap_or(StatusCode::FORBIDDEN);
    let mut response = (status, Json(denial.on_the_wire())).into_response();
    if let Some(challenge) = denial.challenge()
        && let Ok(value) = axum::http::HeaderValue::from_str(challenge)
    {
        response
            .headers_mut()
            .insert(axum::http::header::WWW_AUTHENTICATE, value);
    }
    response
}

/// A denial over gRPC: `UNAUTHENTICATED` or `PERMISSION_DENIED`, the code as metadata.
pub(crate) fn grpc_denial(denial: &AccessDenial) -> Status {
    tracing::debug!(
        event.name = "authz.denied",
        component = "data-plane",
        error.code = denial.code(),
        "an evaluation was denied"
    );
    let mut status = Status::new(
        tonic::Code::from(denial.grpc_code().number()),
        denial.message().to_owned(),
    );
    if let Ok(code) = MetadataValue::try_from(denial.code()) {
        status
            .metadata_mut()
            .insert(permguard_core::GRPC_ERROR_CODE, code);
    }
    status
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;
    use permguard_core::authz::{ActorContext, Credential, Principal, Selector};
    use permguard_host::authz::PublicGrant;

    fn scratch(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "pg-authz-gate-{tag}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("the scratch directory is created");
        dir
    }

    fn mirror(root: &Path, zone: &str, ledger: &str) {
        let path = root.join(format!("{zone}-id")).join(format!("{ledger}-id"));
        std::fs::create_dir_all(&path).expect("created");
        store::record(
            &path,
            &store::Identity {
                zone_id: format!("{zone}-id"),
                zone_name: zone.to_owned(),
                ledger_id: format!("{ledger}-id"),
                ledger_name: ledger.to_owned(),
                server: "http://cp".to_owned(),
            },
        )
        .expect("recorded");
    }

    fn actor(name: &str) -> Actor {
        Actor::Authenticated(ActorContext::new(
            Principal::new(name).expect("a principal"),
            Credential::SanUri,
            None,
        ))
    }

    #[test]
    fn the_memo_remembers_a_name_briefly_and_keeps_roots_apart() {
        let root = scratch("memo");
        let other = scratch("memo-other");
        mirror(&root, "acme", "main");
        assert_eq!(
            located(&root, "acme", "main"),
            Some(("acme-id".to_owned(), "main-id".to_owned()))
        );
        assert_eq!(
            located(&other, "acme", "main"),
            None,
            "another root, another answer"
        );
        // Within the window the volume is not asked again: a mirror added now is not yet seen.
        mirror(&other, "acme", "main");
        assert_eq!(located(&other, "acme", "main"), None);
        std::thread::sleep(LOCATED_FOR + std::time::Duration::from_millis(50));
        assert_eq!(
            located(&other, "acme", "main"),
            Some(("acme-id".to_owned(), "main-id".to_owned()))
        );
    }

    #[test]
    fn f21_nobody_is_401_and_a_public_grant_on_the_exact_ledger_admits_anonymous() {
        let root = scratch("f21");
        mirror(&root, "acme", "main");
        let closed = Authorization::closed();
        let denied = evaluation(
            &closed,
            &Actor::Anonymous,
            &root,
            Some("acme"),
            Some("main"),
        )
        .expect_err("deny by default");
        assert_eq!(denied.http_status(), 401);
        let public = Authorization::public_only(&[PublicGrant::new(
            &[operations::DECISION_EVALUATE],
            Selector::parse("plane/data/zone/acme-id/ledger/main-id").expect("a selector"),
        )]);
        assert!(
            evaluation(
                &public,
                &Actor::Anonymous,
                &root,
                Some("acme"),
                Some("main")
            )
            .is_ok()
        );
        assert!(
            evaluation(
                &public,
                &Actor::Anonymous,
                &root,
                Some("acme-id"),
                Some("main-id")
            )
            .is_ok(),
            "by id as well as by name"
        );
    }

    #[test]
    fn f22_a_ledger_outside_the_grant_is_403_and_indistinguishable_from_one_that_does_not_exist() {
        let root = scratch("f22");
        mirror(&root, "billing", "main");
        mirror(&root, "people", "main");
        let store = {
            let volume = permguard_host::storage::volume::Volume::claim(
                &scratch("f22-volume"),
                permguard_core::assurance::AssuranceProfile::Development,
            )
            .expect("claimed");
            let (store, _) = permguard_host::authz::GrantStore::open(&volume).expect("opens");
            store
                .issue(
                    permguard_host::authz::Issue {
                        principal: Principal::new("spiffe://acme/billing").expect("p"),
                        operations: vec![operations::DECISION_EVALUATE.to_owned()],
                        selector: Selector::parse("plane/data/zone/billing-id/*")
                            .expect("a selector"),
                        resource_types: vec!["*".to_owned()],
                        constraints: Default::default(),
                        issued_by: "test".to_owned(),
                        expires_at: None,
                    },
                    1,
                )
                .expect("issued");
            std::mem::forget(volume);
            store
        };
        let authorization = Authorization::new(store, &[]);
        let billing = actor("spiffe://acme/billing");
        assert!(
            evaluation(
                &authorization,
                &billing,
                &root,
                Some("billing"),
                Some("main")
            )
            .is_ok()
        );
        let foreign = evaluation(
            &authorization,
            &billing,
            &root,
            Some("people"),
            Some("main"),
        )
        .expect_err("F-22: billing cannot read people");
        assert_eq!(foreign.http_status(), 403);
        let unknown = evaluation(
            &authorization,
            &billing,
            &root,
            Some("nobody"),
            Some("main"),
        )
        .expect_err("an unknown name is not disclosed");
        assert_eq!(unknown, foreign, "the same denial, byte for byte");
        let stranger = evaluation(
            &authorization,
            &actor("spiffe://acme/other"),
            &root,
            Some("billing"),
            Some("main"),
        )
        .expect_err("nothing under the plane");
        assert_eq!(stranger.http_status(), 403);
    }
}
