// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! Everything a decision read or a signers answer means, shared by both transports: the facade
//! the routes over HTTP and gRPC call.

use std::sync::Arc;

use permguard_core::{ApiError, Disclosure, ErrorClass, Metrics};
use permguard_stream::Window;
use serde::Serialize;

use super::read;
use super::store::{DecisionStore, Scope};

/// Everything the routes need, resolved once.
#[derive(Clone)]
pub struct DecisionFacade {
    /// Where records are kept.
    /// The legacy store; `None` on a backend with no volume, which keeps none (decision X125).
    pub store: Option<Arc<DecisionStore>>,
    /// What a record may carry in clear to be kept here: `None` leaves it to the producers'
    /// inclusion (see [`permguard_core::Config::decision_ceiling`]).
    pub ceiling: Option<permguard_core::decisions::IncludeSection>,
    /// The secret read offsets are signed with.
    ///
    /// The server keeps no per-consumer cursor, so the only thing between a consumer and a
    /// position it was never given is this signature. Held here rather than read per request: it
    /// is the store's, it is stable across restarts, and reading a key file on the hot path would
    /// be a disk read per page.
    pub cursor_key: crate::decisions::cursorkey::CursorKeys,
    /// How much a refusal says about the inside.
    pub disclosure: Disclosure,
    /// What to count.
    pub metrics: Metrics,
    /// The Host's consumer of the decision stream: what the public reads answer from besides the
    /// legacy store (WP-6.1b). `None` when the Host composes none.
    pub host: Option<permguard_host::composition::StreamConsumer>,
    /// The catalog, turning a tenant route's names into the ids the consumer's streams are keyed
    /// by (owner decision of 2026-10-18).
    pub catalog: Option<Arc<dyn permguard_core::catalog::Catalog>>,
    /// Where this plane is reached, what its discovery document's endpoints are built on.
    pub base_url: String,
    /// Who serves the interface, its build and its phase: the discovery document's common header
    /// (WP-7.4a).
    pub describer: permguard_core::stages::Describer,
    /// The Host's authorization, every evidence read decides with before it looks anything up
    /// (WP-6.3c).
    pub authorization: Arc<permguard_host::composition::Authorization>,
    /// Who names the member a record's Host id belongs to, for the page's `members` (owner
    /// decision of 2026-11-15); `None` names nobody.
    pub members: Option<Arc<dyn crate::members::NamesMembers>>,
    /// What a tail waiting for its next record waits on (iteration 04, WP-33.1).
    pub arrivals: Arc<crate::arrivals::Arrivals>,
}

/// One producer stream's signer history, with the receiver's durable frontier.
#[derive(Debug, Clone, Serialize)]
pub struct StreamSignersView {
    /// Everything through this sequence is durable here.
    pub acked: u64,
    pub spans: Vec<permguard_stream::SignerSpan>,
}

impl DecisionFacade {
    /// Which key signed which stretch of one producer stream — the answer both transports serve,
    /// so REST and gRPC cannot drift apart about who signed what.
    ///
    /// `until_seq` of zero means "from `from_seq` onward"; both zero means the whole history.
    pub fn signers_of(
        &self,
        pdp_id: &str,
        instance: &str,
        from_seq: u64,
        until_seq: u64,
    ) -> Result<StreamSignersView, ApiError> {
        if !permguard_stream::is_portable_name(pdp_id)
            || !permguard_stream::is_portable_name(instance)
        {
            return Err(ApiError::new(
                ErrorClass::Validation,
                permguard_core::codes::stream::STREAM_MALFORMED,
                "`pdp` and `instance` are unchanged portable names",
            ));
        }
        // A Host run named by its `host_id` and run, as the read names it (WP-6.3b): answered from
        // the consumer's signer observations of the run's resource.
        if let Some(view) = self.host_signers(pdp_id, instance, from_seq, until_seq)? {
            return Ok(view);
        }
        // A stream this store never held is a `404`, not an empty manifest: an empty answer
        // reads as "held, nothing signed yet", and a typo in a producer name must not read as
        // that.
        let Some(store) = &self.store else {
            return Err(ApiError::new(
                ErrorClass::NotFound,
                permguard_core::codes::stream::STREAM_UNKNOWN,
                format!("this store holds no stream for `{pdp_id}/{instance}`"),
            ));
        };
        let exists = store.stream_exists(pdp_id, instance).map_err(|error| {
            ApiError::new(
                ErrorClass::Unavailable,
                permguard_core::codes::stream::STORE_UNAVAILABLE,
                error.to_string(),
            )
        })?;
        if !exists {
            return Err(ApiError::new(
                ErrorClass::NotFound,
                permguard_core::codes::stream::STREAM_UNKNOWN,
                format!("this store holds no stream for `{pdp_id}/{instance}`"),
            ));
        }

        let until = if until_seq == 0 { u64::MAX } else { until_seq };
        let state = store.stream_state(pdp_id, instance).map_err(|error| {
            ApiError::new(
                ErrorClass::Unavailable,
                permguard_core::codes::stream::STORE_UNAVAILABLE,
                error.to_string(),
            )
        })?;
        let signers = store.signers(pdp_id, instance).map_err(|error| {
            ApiError::new(
                ErrorClass::Unavailable,
                permguard_core::codes::stream::STORE_UNAVAILABLE,
                error.to_string(),
            )
        })?;

        let spans = signers.covering(from_seq, until);
        if spans.len() > permguard_stream::MAX_SIGNER_SPANS {
            return Err(ApiError::new(
                ErrorClass::Validation,
                permguard_core::codes::stream::SIGNER_RANGE_TOO_WIDE,
                format!(
                    "this range crosses more than {} signing-key spans; narrow `from_seq` and \
                     `until_seq`",
                    permguard_stream::MAX_SIGNER_SPANS
                ),
            ));
        }

        Ok(StreamSignersView {
            acked: state.acked,
            spans: spans.to_vec(),
        })
    }

    /// The signers of the Host run `pdp_id`/`instance` names in hex, when the consumer holds it
    /// (WP-6.3b); `None` for a pair naming no run it holds, which the legacy store then answers.
    fn host_signers(
        &self,
        pdp_id: &str,
        instance: &str,
        from_seq: u64,
        until_seq: u64,
    ) -> Result<Option<StreamSignersView>, ApiError> {
        let (Some(host), Some(producer), Some(run)) = (
            self.host.as_ref(),
            read::unhex16(pdp_id),
            read::unhex16(instance),
        ) else {
            return Ok(None);
        };
        let unavailable = |error: String| {
            ApiError::new(
                ErrorClass::Unavailable,
                permguard_core::codes::stream::STORE_UNAVAILABLE,
                error,
            )
        };
        let Some(resource) = host.locate(&producer, &run).map_err(unavailable)? else {
            return Ok(None);
        };
        let Some(held) = host
            .signers(&resource)
            .map_err(unavailable)?
            .into_iter()
            .find(|held| held.producer == producer && held.run == run)
        else {
            return Ok(None);
        };
        let mut signers = permguard_stream::Signers::empty();
        for (from, kid, jwk) in &held.spans {
            let jwk: serde_json::Value = serde_json::from_str(jwk)
                .map_err(|error| unavailable(format!("a signer of the Host's stream: {error}")))?;
            signers
                .observe(*from, kid, &jwk)
                .map_err(|error| unavailable(format!("{error:?}")))?;
        }
        let until = if until_seq == 0 { u64::MAX } else { until_seq };
        let spans = signers.covering(from_seq, until);
        if spans.len() > permguard_stream::MAX_SIGNER_SPANS {
            return Err(ApiError::new(
                ErrorClass::Validation,
                permguard_core::codes::stream::SIGNER_RANGE_TOO_WIDE,
                format!(
                    "this range crosses more than {} signing-key spans; narrow `from_seq` and \
                     `until_seq`",
                    permguard_stream::MAX_SIGNER_SPANS
                ),
            ));
        }
        Ok(Some(StreamSignersView {
            acked: held.acked,
            spans: spans.to_vec(),
        }))
    }

    /// Reads one bounded block of `scope` from the legacy store and the Host's consumer
    /// (WP-6.1b): what both transports answer.
    pub fn read(&self, scope: &Scope, window: &Window) -> Result<read::Page, read::ReadError> {
        read::read_with(
            &read::Sources {
                store: self.store.as_deref(),
                host: self.host.as_ref(),
                catalog: self.catalog.as_ref(),
            },
            scope,
            &self.cursor_key,
            window,
        )
    }

    /// The scope `actor` may read under `evidence.read`, resolved to ids (WP-6.3c): refused before
    /// any lookup when nothing is granted under the plane; an unknown scope `not_found` only
    /// under a whole-plane grant; a tenant on its ledger; a stream on the ledger of the Host run
    /// it names, or on the whole plane for a legacy stream mixing tenants.
    pub fn gate(
        &self,
        actor: &permguard_core::authz::Actor,
        scope: Scope,
    ) -> Result<Scope, crate::evidence::Gated<read::ReadError>> {
        use crate::evidence::{self, Gated};

        evidence::admitted(&self.authorization, actor).map_err(Gated::Denied)?;
        let sources = read::Sources {
            store: self.store.as_deref(),
            host: self.host.as_ref(),
            catalog: self.catalog.as_ref(),
        };
        let scope = match read::canonical(&sources, scope) {
            Ok(scope) => scope,
            Err(error @ read::ReadError::Unknown(_)) => {
                evidence::unknown(&self.authorization, actor).map_err(Gated::Denied)?;
                return Err(Gated::Refused(error));
            }
            Err(error) => return Err(Gated::Refused(error)),
        };
        let allowed = match &scope {
            Scope::Tenant { zone, ledger } => {
                evidence::on_ledger(&self.authorization, actor, zone, ledger)
            }
            Scope::Stream { pdp_id, instance } => {
                match self.run_ledger(pdp_id, instance).map_err(Gated::Refused)? {
                    Some((zone_id, ledger_id)) => {
                        evidence::on_ledger(&self.authorization, actor, &zone_id, &ledger_id)
                    }
                    None => evidence::on_plane(&self.authorization, actor),
                }
            }
        };
        allowed.map_err(Gated::Denied)?;
        Ok(scope)
    }

    /// The ledger of the Host run `pdp_id`/`instance` names in hex, when the consumer holds it.
    fn run_ledger(
        &self,
        pdp_id: &str,
        instance: &str,
    ) -> Result<Option<(String, String)>, read::ReadError> {
        let (Some(host), Some(producer), Some(run)) = (
            self.host.as_ref(),
            read::unhex16(pdp_id),
            read::unhex16(instance),
        ) else {
            return Ok(None);
        };
        Ok(
            match host
                .locate(&producer, &run)
                .map_err(read::ReadError::Unavailable)?
            {
                Some(permguard_core::authz::Resource::Ledger {
                    zone_id, ledger_id, ..
                }) => Some((zone_id, ledger_id)),
                _ => None,
            },
        )
    }

    /// Reads one bounded block of `scope` as `actor`, through the `evidence.read` gate (WP-6.3c):
    /// what both transports answer.
    pub fn read_as(
        &self,
        actor: &permguard_core::authz::Actor,
        scope: Scope,
        window: &Window,
    ) -> Result<read::Page, crate::evidence::Gated<read::ReadError>> {
        let scope = self.gate(actor, scope)?;
        self.read(&scope, window)
            .map_err(crate::evidence::Gated::Refused)
    }
}

/// One producer stream's records (iteration 02, D13: `/<interface>/<version>/<resource>`).
pub const RECORDS_PATH: &str = "/decisions/v1/streams/{pdp}/{instance}/records";
/// One tenant's records.
pub const TENANT_RECORDS_PATH: &str = "/decisions/v1/zones/{zone}/ledgers/{ledger}/records";
/// One producer stream's signing-key spans.
pub const SIGNERS_PATH: &str = "/decisions/v1/streams/{pdp}/{instance}/signers";
