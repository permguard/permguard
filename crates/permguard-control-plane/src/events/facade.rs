// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! Everything an event read or a signers answer means, shared by both transports: the facade the
//! routes over HTTP and gRPC call, and the views they answer with.

use std::sync::Arc;

use permguard_core::metrics::labels;
use permguard_core::{ApiError, Disclosure, ErrorClass, Jwk, Metrics};
use permguard_stream::Window;

use super::measure;
use super::read::{self, Filters};
use super::store::{EventStore, Scope};

/// Everything a request means, shared by both transports.
#[derive(Clone)]
pub struct EventFacade {
    /// Where events are kept.
    pub store: Arc<EventStore>,
    /// The Host's consumer of the event stream, which the public reads answer from beside the
    /// store (WP-6.2b); `None` when no engine consumes it.
    pub host: Option<permguard_host::composition::StreamConsumer>,
    /// The secret read offsets are signed with.
    pub cursor_key: crate::decisions::cursorkey::CursorKeys,
    /// The catalog, for turning the scope a reader named into the one records are keyed by.
    ///
    /// Optional because the contract makes it optional: a build that composes no catalog has no
    /// names to resolve, and a reader there addresses records by identity or not at all.
    pub catalog: Option<Arc<dyn permguard_core::catalog::Catalog>>,
    /// How much a refusal says about the inside.
    pub disclosure: Disclosure,
    /// Who names the member a record's producer belongs to, for the page's `members` (owner
    /// decision of 2026-11-15); `None` names nobody.
    pub members: Option<Arc<dyn crate::members::NamesMembers>>,
    /// What to count.
    pub metrics: Metrics,
    /// The base URL this plane is reached at, for the configuration document.
    ///
    /// The document's endpoints are absolute, because the producer that reads it is configured with
    /// one URL and has to arrive at four. A relative path would leave it joining strings.
    pub base_url: String,
    /// Who serves the interface, its build and its phase: the discovery document's common header
    /// (WP-7.4a).
    pub describer: permguard_core::stages::Describer,
    /// The Host's authorization, every evidence read decides with before it looks anything up
    /// (WP-6.3c).
    pub authorization: Arc<permguard_host::composition::Authorization>,
}

impl EventFacade {
    /// The scope `actor` may read under `evidence.read`, resolved to ids (WP-6.3c): refused before
    /// any lookup when nothing is granted under the plane; an unknown scope `not_found` only under
    /// a whole-plane grant; any other on its ledger, a tenant's or a stream's.
    pub fn gate(
        &self,
        actor: &permguard_core::authz::Actor,
        scope: Scope,
    ) -> Result<Scope, crate::evidence::Gated<read::ReadError>> {
        use crate::evidence::{self, Gated};

        evidence::admitted(&self.authorization, actor).map_err(Gated::Denied)?;
        let scope = match read::canonical(self.catalog.as_ref(), scope) {
            Ok(scope) => scope,
            Err(error @ read::ReadError::Unknown(_)) => {
                evidence::unknown(&self.authorization, actor).map_err(Gated::Denied)?;
                return Err(Gated::Refused(error));
            }
            Err(error) => return Err(Gated::Refused(error)),
        };
        let (Scope::Tenant { zone, ledger } | Scope::Stream { zone, ledger, .. }) = &scope;
        evidence::on_ledger(&self.authorization, actor, zone, ledger).map_err(Gated::Denied)?;
        Ok(scope)
    }

    /// Counts a read refused by the gate (WP-6.3c), as the decision reads do.
    pub fn denied(&self, kind: &'static str) {
        self.metrics.count(
            &measure::READS,
            &[(labels::SCOPE, kind), (labels::OUTCOME, "denied")],
        );
    }

    /// Where its reads find their events: the store, and the Host's consumer (WP-6.2b).
    pub fn sources(&self) -> read::Sources<'_> {
        read::Sources {
            store: &self.store,
            host: self.host.as_ref(),
        }
    }

    /// Every key that may verify evidence this store already holds.
    ///
    /// The published sets plus the archive. Read-only by construction: nothing that reaches this
    /// admits a record, it only re-checks records admitted earlier under keys that were current
    /// then.
    pub fn verification_keys(&self) -> Result<Vec<Jwk>, String> {
        let mut keys: Vec<Jwk> = Vec::new();
        let archived = self
            .store
            .archived_keys()
            .map_err(|error| error.to_string())?;
        for key in archived {
            // A key id is scoped to its producer. Two producers may legitimately publish
            // different material under the same label, and a verifier must try both.
            if !keys.iter().any(|held| held == &key) {
                keys.push(key);
            }
        }

        Ok(keys)
    }

    /// The event types this store accepts.
    ///
    /// Read off the language registry rather than configured: a type is accepted exactly when this
    /// build carries something that can validate it, and a list an operator could widen would be a
    /// way to store records nothing here understands.
    pub fn accepted_types(&self) -> Vec<&'static str> {
        permguard_languages::event::EVENT_TYPES.to_vec()
    }

    /// Accepts one batch.
    /// Which key signed which stretch of each producer stream of one ledger — the answer both
    /// transports serve, so REST and gRPC cannot drift apart about who signed what.
    ///
    /// `until_seq` of zero means "from `from_seq` onward"; both zero means the whole history.
    /// The filters narrow to one producer class, producer or incarnation; the answer is one
    /// bounded page of [`SIGNERS_STREAM_CEILING`] streams, walked and cut at the directory —
    /// never collected whole and trimmed — and a truncated page carries `next`, the cursor the
    /// following ask passes back as `after`.
    pub fn signers_of(
        &self,
        zone: &str,
        ledger: &str,
        from_seq: u64,
        until_seq: u64,
        ask: &StreamsAsked,
    ) -> Result<SignersDocument, ApiError> {
        let scope = super::read::canonical(
            self.catalog.as_ref(),
            Scope::Tenant {
                zone: zone.to_owned(),
                ledger: ledger.to_owned(),
            },
        )
        .map_err(|error| match error {
            super::read::ReadError::Unknown(detail) => ApiError::new(
                ErrorClass::NotFound,
                permguard_core::codes::stream::SCOPE_UNKNOWN,
                detail,
            ),
            other => ApiError::new(
                ErrorClass::Unavailable,
                permguard_core::codes::stream::STORE_UNAVAILABLE,
                other.to_string(),
            ),
        })?;
        let Scope::Tenant { zone, ledger } = scope else {
            return Err(ApiError::new(
                ErrorClass::Internal,
                permguard_core::codes::stream::SCOPE_MISMATCH,
                "a tenant scope resolved to something else",
            ));
        };
        let until = if until_seq == 0 { u64::MAX } else { until_seq };

        let page = self
            .store
            .producer_streams_page(
                &zone,
                &ledger,
                ask.producer_class.as_deref(),
                ask.producer.as_deref(),
                ask.instance.as_deref(),
                ask.after
                    .as_ref()
                    .map(permguard_stream::StreamPosition::as_tuple),
                SIGNERS_STREAM_CEILING,
            )
            .map_err(|error| {
                ApiError::new(
                    ErrorClass::Unavailable,
                    permguard_core::codes::stream::STORE_UNAVAILABLE,
                    error.to_string(),
                )
            })?;
        let mut truncated = page.truncated;
        let mut answered = Vec::with_capacity(page.streams.len());
        for stream in page.streams {
            let state = self.store.stream_state(&stream).map_err(|error| {
                ApiError::new(
                    ErrorClass::Unavailable,
                    permguard_core::codes::stream::STORE_UNAVAILABLE,
                    error.to_string(),
                )
            })?;
            let signers = self.store.signers(&stream).map_err(|error| {
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
            answered.push(StreamSignersView {
                producer_class: stream.producer.class,
                producer: stream.producer.id,
                instance: stream.producer.instance,
                acked: state.acked,
                spans: spans.to_vec(),
            });
        }

        // The Host consumer's runs of the ledger beside the legacy streams (WP-6.2b), in the same
        // `(class, producer, instance)` order: past `after`, and no further than the last legacy
        // stream of a truncated page, so the next page skips none of the streams in between.
        if let Some(host) = &self.host {
            let tuple = |view: &StreamSignersView| {
                (
                    view.producer_class.clone(),
                    view.producer.clone(),
                    view.instance.clone(),
                )
            };
            let after = ask
                .after
                .as_ref()
                .map(|after| permguard_stream::StreamPosition::clone(after).into_tuple());
            let reached = truncated.then(|| answered.last().map(tuple)).flatten();
            let unavailable = |error: String| {
                ApiError::new(
                    ErrorClass::Unavailable,
                    permguard_core::codes::stream::STORE_UNAVAILABLE,
                    error,
                )
            };
            let resource = permguard_core::authz::Resource::ledger("data", &zone, &ledger);
            for run in host.signers(&resource).map_err(unavailable)? {
                let view = StreamSignersView {
                    producer_class: permguard_events::PRODUCER_CLASS_DATA_PLANE.to_owned(),
                    producer: permguard_core::encoding::hex(&run.producer),
                    instance: permguard_core::encoding::hex(&run.run),
                    acked: run.acked,
                    spans: Vec::new(),
                };
                let asked = |filter: &Option<String>, held: &str| {
                    filter.as_deref().is_none_or(|filter| filter == held)
                };
                if !asked(&ask.producer_class, &view.producer_class)
                    || !asked(&ask.producer, &view.producer)
                    || !asked(&ask.instance, &view.instance)
                    || after.as_ref().is_some_and(|after| tuple(&view) <= *after)
                    || reached
                        .as_ref()
                        .is_some_and(|reached| tuple(&view) > *reached)
                {
                    continue;
                }
                let mut signers = permguard_stream::Signers::empty();
                for (from, kid, jwk) in &run.spans {
                    let jwk: serde_json::Value = serde_json::from_str(jwk).map_err(|error| {
                        unavailable(format!("a signer of the Host's stream: {error}"))
                    })?;
                    signers
                        .observe(*from, kid, &jwk)
                        .map_err(|error| unavailable(format!("{error:?}")))?;
                }
                let spans = signers.covering(from_seq, until);
                if spans.len() > permguard_stream::MAX_SIGNER_SPANS {
                    return Err(ApiError::new(
                        ErrorClass::Validation,
                        permguard_core::codes::stream::SIGNER_RANGE_TOO_WIDE,
                        format!(
                            "this range crosses more than {} signing-key spans; narrow \
                             `from_seq` and `until_seq`",
                            permguard_stream::MAX_SIGNER_SPANS
                        ),
                    ));
                }
                answered.push(StreamSignersView {
                    spans: spans.to_vec(),
                    ..view
                });
            }
            answered.sort_by_key(tuple);
            if answered.len() > SIGNERS_STREAM_CEILING {
                answered.truncate(SIGNERS_STREAM_CEILING);
                truncated = true;
            }
        }

        // The cursor is the last stream of a truncated page: the next ask passes it back as
        // `after` and the walk resumes strictly past it.
        let next = truncated
            .then(|| answered.last())
            .flatten()
            .map(|held| StreamCursor {
                producer_class: held.producer_class.clone(),
                producer: held.producer.clone(),
                instance: held.instance.clone(),
            });

        Ok(SignersDocument {
            streams: answered,
            truncated,
            next,
        })
    }

    /// Reads one bounded, filtered block.
    pub fn read(
        &self,
        scope: &Scope,
        filters: &Filters,
        window: &Window,
        kind: &'static str,
    ) -> Result<read::Page, read::ReadError> {
        let answered = read::read_with(&self.sources(), scope, filters, &self.cursor_key, window);
        match &answered {
            Ok(page) => {
                self.metrics.count(
                    &measure::READS,
                    &[(labels::SCOPE, kind), (labels::OUTCOME, "ok")],
                );
                self.metrics.add(
                    &measure::EXAMINED,
                    &[(labels::SCOPE, kind)],
                    page.coverage.examined as f64,
                );
                self.metrics.add(
                    &measure::RETURNED,
                    &[(labels::SCOPE, kind)],
                    page.records.len() as f64,
                );
            }
            Err(read::ReadError::Expired { .. }) => {
                self.metrics.count(
                    &measure::READS,
                    &[(labels::SCOPE, kind), (labels::OUTCOME, "expired")],
                );
            }
            Err(_) => {
                self.metrics.count(
                    &measure::READS,
                    &[(labels::SCOPE, kind), (labels::OUTCOME, "refused")],
                );
            }
        }

        answered
    }
}

/// The most producer streams one signers answer carries.
///
/// A ledger's incarnation count grows without bound over its lifetime; an answer must not. Past
/// the ceiling the response says `truncated`, and `producer`/`instance` narrow the next ask.
pub const SIGNERS_STREAM_CEILING: usize = 256;

/// The signers answer: one page of streams, and where the next page starts when there is one.
#[derive(Debug, Clone, serde::Serialize)]
pub struct SignersDocument {
    pub streams: Vec<StreamSignersView>,
    /// True when more streams matched than one page carries. Never a failure: `next` is the
    /// cursor, and the filters narrow the ask.
    pub truncated: bool,
    /// The position to resume from — passed back as `after`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next: Option<StreamCursor>,
}

/// A position in the `(class, producer, instance)` order of one ledger's streams.
#[derive(Debug, Clone, serde::Serialize)]
pub struct StreamCursor {
    pub producer_class: String,
    pub producer: String,
    pub instance: String,
}

/// What narrows a stream listing: filters, and the cursor of the previous page.
#[derive(Debug, Clone, Default)]
pub struct StreamsAsked {
    pub producer_class: Option<String>,
    pub producer: Option<String>,
    pub instance: Option<String>,
    /// Resume strictly after this `(class, producer, instance)`.
    pub after: Option<permguard_stream::StreamPosition>,
}

/// One producer stream's signer history, with the receiver's durable frontier — what a verifier
/// needs to check a range of that stream without reaching the producer.
#[derive(Debug, Clone, serde::Serialize)]
pub struct StreamSignersView {
    pub producer_class: String,
    pub producer: String,
    pub instance: String,
    /// Everything through this sequence is durable here.
    pub acked: u64,
    pub spans: Vec<permguard_stream::SignerSpan>,
}

/// One ledger's records (iteration 02, D13: `/<interface>/<version>/<resource>`); one producer
/// stream of it when the query names `producer_class`, `producer` and `instance`.
pub const RECORDS_PATH: &str = "/events/v1alpha1/zones/{zone}/ledgers/{ledger}/records";
/// One occurrence of a ledger, by the identifier its caller stated.
pub const RECORD_PATH: &str = "/events/v1alpha1/zones/{zone}/ledgers/{ledger}/records/{event_id}";
/// Which key signed which stretch of each producer stream of one ledger.
pub const SIGNERS_PATH: &str = "/events/v1alpha1/zones/{zone}/ledgers/{ledger}/signers";
