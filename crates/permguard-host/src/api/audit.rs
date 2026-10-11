// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The audit routes (WP-3.7, owner decisions of 2026-10-11): the records of one trail, its
//! checkpoints and its export, under `audit.read` on the trail's resource.
//!
//! | Route                                     | Answers                                                  |
//! | ----------------------------------------- | -------------------------------------------------------- |
//! | `GET /host/v1/audit/{class}/records`      | one page: records, gaps, frontier, cursor, anchor        |
//! | `GET /host/v1/audit/{class}/checkpoints`  | the signed checkpoints and the `host.operations` set     |
//! | `GET /host/v1/audit/{class}/export`       | one page up to a fixed frontier; the first page carries  |
//! |                                           | the checkpoints and the `host.operations` set too        |
//!
//! The resource is authorized before the class or any filter is read, so a caller without the
//! grant learns nothing of what the query names. Each record travels as its canonical bytes
//! beside its digest: a client checks the chain and the checkpoints without trusting the answer.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::{Deserialize, Serialize};

use permguard_core::authz::{Actor, Resource, operations};
use permguard_core::{ErrorClass, codes};

use crate::audit::Class;
use crate::audit::checkpoint::Anchor;
use crate::audit::query::{self, CheckpointFile, Gap, Page, QueryError};
use crate::keys::ring::HOST_OPERATIONS;

use super::keys::RingView;
use super::{HostApi, Refusal};

/// `GET /host/v1/audit/{class}/records`'s query.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditQuery {
    /// The trail's resource, in the Host API's grammar.
    pub resource: String,
    /// The earliest record time, seconds since the epoch, inclusive.
    #[serde(default)]
    pub from: Option<u64>,
    /// The latest record time, seconds since the epoch, inclusive.
    #[serde(default)]
    pub to: Option<u64>,
    /// Where the page starts, as the page before answered it.
    #[serde(default)]
    pub cursor: Option<String>,
    /// How many records the page carries: 1 to 1000, 100 when absent.
    #[serde(default)]
    pub limit: Option<u32>,
    /// A parameter the transport could not read, refused as `invalid_argument` once the resource
    /// is admitted, never before.
    #[serde(skip)]
    pub malformed: Option<String>,
}

/// `GET /host/v1/audit/{class}/export`'s query.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditExportQuery {
    pub resource: String,
    /// The sequence the export stops before; the trail's next one when absent. A later page
    /// repeats the first page's or names none.
    #[serde(default)]
    pub frontier: Option<u64>,
    #[serde(default)]
    pub cursor: Option<String>,
    #[serde(default)]
    pub limit: Option<u32>,
    /// A parameter the transport could not read, refused as `invalid_argument` once the resource
    /// is admitted, never before.
    #[serde(skip)]
    pub malformed: Option<String>,
}

/// `GET /host/v1/audit/{class}/checkpoints`'s query.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditCheckpointQuery {
    pub resource: String,
    /// One UTC day, `YYYY-MM-DD`; every day when absent.
    #[serde(default)]
    pub period: Option<String>,
}

/// One record: its canonical bytes and what a reader looks for first.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditRecordView {
    pub seq: u64,
    /// Seconds since the epoch.
    pub at: u64,
    pub action: String,
    pub outcome: String,
    /// `sha256:<hex>` over `permguard.audit.record.v1\n` and the bytes.
    pub digest: String,
    /// The canonical CBOR (`contracts/cbor/audit.json`), base64url without padding.
    pub record: String,
}

/// Something a page cannot show.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditGapView {
    /// `retention`, `dropped` or `missing`.
    pub kind: String,
    /// The first sequence absent: `0` for retention, the first missing one.
    pub from_seq: Option<u64>,
    /// The last sequence absent; for `dropped`, the record that marks the drop.
    pub to_seq: Option<u64>,
    /// How many records an `access` queue dropped.
    pub count: Option<u64>,
    /// The last day retention deleted.
    pub through: Option<String>,
}

/// What retention deleted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditAnchorView {
    pub low_watermark: u64,
    pub through: String,
    /// The digest of the seal of `through`.
    pub checkpoint: String,
}

/// One checkpoint, with the witness's co-signature when one was kept.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditCheckpointView {
    /// Its file name: `YYYY-MM-DD.cose`, or `YYYY-MM-DD.<seq>.cose` on demand.
    pub name: String,
    /// COSE_Sign1 `permguard.audit.checkpoint.v1`, base64url without padding.
    pub envelope: String,
    pub witness: Option<String>,
}

/// What `GET /host/v1/audit/{class}/records` answers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditRecordPage {
    pub class: String,
    pub resource: String,
    pub records: Vec<AuditRecordView>,
    pub gaps: Vec<AuditGapView>,
    /// The trail's next sequence when the first page was read.
    pub frontier: u64,
    pub next_cursor: Option<String>,
    pub anchor: Option<AuditAnchorView>,
}

/// What `GET /host/v1/audit/{class}/checkpoints` answers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditCheckpoints {
    pub class: String,
    pub resource: String,
    pub checkpoints: Vec<AuditCheckpointView>,
    /// How many older checkpoints the answer leaves out, beyond the newest 1000.
    pub omitted: u64,
    /// The `host.operations` set and its identity-signed binding, when the Host composes it.
    pub keys: Option<RingView>,
    /// What `keys export` prints for `host.operations`: the published and retained keys and the
    /// revocations, which `audit verify --keys` reads, so a checkpoint signed by a key since
    /// retired verifies too.
    pub verification_keys: Option<String>,
}

/// What `GET /host/v1/audit/{class}/export` answers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditExportPage {
    pub class: String,
    pub resource: String,
    pub records: Vec<AuditRecordView>,
    pub gaps: Vec<AuditGapView>,
    pub frontier: u64,
    pub next_cursor: Option<String>,
    pub anchor: Option<AuditAnchorView>,
    /// On the first page, the checkpoints of the trail below the frontier, the newest 1000;
    /// empty after it.
    pub checkpoints: Vec<AuditCheckpointView>,
    /// On the first page, how many older checkpoints below the frontier it leaves out.
    pub omitted: u64,
    /// On the first page, the `host.operations` set; absent after it.
    pub keys: Option<RingView>,
    /// On the first page, the `keys export` document of `host.operations`; absent after it.
    pub verification_keys: Option<String>,
}

fn invalid(detail: impl Into<String>) -> Refusal {
    Refusal::new(
        ErrorClass::Validation,
        codes::common::INVALID_ARGUMENT,
        detail,
    )
}

fn unavailable(detail: impl Into<String>) -> Refusal {
    Refusal::new(
        ErrorClass::Unavailable,
        codes::host::AUDIT_UNAVAILABLE,
        detail,
    )
}

fn refusal(error: QueryError) -> Refusal {
    match error {
        QueryError::Cursor(detail) | QueryError::Invalid(detail) => invalid(detail),
        QueryError::Storage(detail) => {
            unavailable(format!("the audit trail could not be read: {detail}"))
        }
    }
}

fn limit_of(limit: Option<u32>) -> Result<Option<usize>, Refusal> {
    match limit {
        None => Ok(None),
        Some(limit) => usize::try_from(limit)
            .ok()
            .filter(|limit| (1..=query::MAX_LIMIT).contains(limit))
            .map(Some)
            .ok_or_else(|| invalid(format!("`limit` is 1 to {}", query::MAX_LIMIT))),
    }
}

fn records(page: &Page) -> Result<Vec<AuditRecordView>, Refusal> {
    page.records
        .iter()
        .map(|record| {
            let bytes = record
                .encode()
                .map_err(|error| unavailable(error.to_string()))?;
            Ok(AuditRecordView {
                seq: record.seq,
                at: record.at,
                action: record.action.clone(),
                outcome: record.outcome.clone(),
                digest: crate::audit::record::digest_of(&bytes).to_string(),
                record: URL_SAFE_NO_PAD.encode(bytes),
            })
        })
        .collect()
}

fn gaps(page: &Page) -> Vec<AuditGapView> {
    page.gaps
        .iter()
        .map(|gap| match gap {
            Gap::Retention { below, through } => AuditGapView {
                kind: "retention".to_owned(),
                from_seq: Some(0),
                to_seq: below.checked_sub(1),
                count: None,
                through: Some(through.clone()),
            },
            Gap::Dropped { seq, count } => AuditGapView {
                kind: "dropped".to_owned(),
                from_seq: None,
                to_seq: Some(*seq),
                count: Some(*count),
                through: None,
            },
            Gap::Missing { from, to } => AuditGapView {
                kind: "missing".to_owned(),
                from_seq: Some(*from),
                to_seq: Some(*to),
                count: None,
                through: None,
            },
        })
        .collect()
}

fn anchor(anchor: Option<&Anchor>) -> Option<AuditAnchorView> {
    anchor.map(|anchor| AuditAnchorView {
        low_watermark: anchor.low_watermark,
        through: anchor.through.clone(),
        checkpoint: anchor.checkpoint.to_string(),
    })
}

fn checkpoints(files: Vec<CheckpointFile>) -> Vec<AuditCheckpointView> {
    files
        .into_iter()
        .map(|file| AuditCheckpointView {
            name: file.name,
            envelope: URL_SAFE_NO_PAD.encode(file.envelope),
            witness: file.witness.map(|witness| URL_SAFE_NO_PAD.encode(witness)),
        })
        .collect()
}

impl HostApi {
    /// The class and resource of an audit route, `audit.read` admitted on the resource first.
    fn audit_trail(
        &self,
        actor: &Actor,
        class: &str,
        resource: &str,
        malformed: Option<&str>,
    ) -> Result<(&crate::audit::Engine, Class, String, super::Admitted<'_>), Refusal> {
        let resource =
            Resource::parse(resource).map_err(|error| invalid(format!("`resource`: {error}")))?;
        let admitted = self.admit_on(actor, operations::AUDIT_READ, &resource)?;
        if let Some(malformed) = malformed {
            return Err(invalid(malformed.to_owned()));
        }
        let class = Class::parse(class).ok_or_else(|| {
            invalid(format!(
                "`{class}` is not an audit class: security, operations or access"
            ))
        })?;
        let engine = self
            .audit
            .as_deref()
            .ok_or_else(|| unavailable("no audit trail is open on this process"))?;
        Ok((engine, class, resource.to_string(), admitted))
    }

    /// The `host.operations` set the checkpoints are signed under, when the Host composes it.
    fn operations_keys(&self) -> Option<RingView> {
        self.ring(HOST_OPERATIONS).ok()
    }

    /// The `keys export` document of `host.operations`, retained keys and revocations included.
    fn verification_keys(&self) -> Option<String> {
        self.keys
            .ring(HOST_OPERATIONS)
            .and_then(|ring| ring.export_document().ok())
    }

    /// `GET /host/v1/audit/{class}/records`: one page under `audit.read` on the resource.
    pub fn audit_records(
        &self,
        actor: &Actor,
        class: &str,
        query: &AuditQuery,
    ) -> Result<AuditRecordPage, Refusal> {
        let (engine, class, resource, _admitted) =
            self.audit_trail(actor, class, &query.resource, query.malformed.as_deref())?;
        let page = engine
            .read(
                class,
                &resource,
                &query::Query {
                    from: query.from,
                    to: query.to,
                    limit: limit_of(query.limit)?,
                    cursor: query.cursor.clone(),
                    frontier: None,
                },
            )
            .map_err(refusal)?;
        Ok(AuditRecordPage {
            class: class.as_str().to_owned(),
            records: records(&page)?,
            gaps: gaps(&page),
            frontier: page.frontier,
            next_cursor: page.next.clone(),
            anchor: anchor(page.anchor.as_ref()),
            resource,
        })
    }

    /// `GET /host/v1/audit/{class}/checkpoints`: under `audit.read` on the resource.
    pub fn audit_checkpoints(
        &self,
        actor: &Actor,
        class: &str,
        query: &AuditCheckpointQuery,
    ) -> Result<AuditCheckpoints, Refusal> {
        let (engine, class, resource, _admitted) =
            self.audit_trail(actor, class, &query.resource, None)?;
        let list = engine
            .checkpoints(class, &resource, query.period.as_deref())
            .map_err(refusal)?;
        Ok(AuditCheckpoints {
            class: class.as_str().to_owned(),
            resource,
            checkpoints: checkpoints(list.files),
            omitted: list.omitted as u64,
            keys: self.operations_keys(),
            verification_keys: self.verification_keys(),
        })
    }

    /// `GET /host/v1/audit/{class}/export`: one page up to the frontier the first page fixed,
    /// under `audit.read` on the resource.
    pub fn audit_export(
        &self,
        actor: &Actor,
        class: &str,
        query: &AuditExportQuery,
    ) -> Result<AuditExportPage, Refusal> {
        let (engine, class, resource, _admitted) =
            self.audit_trail(actor, class, &query.resource, query.malformed.as_deref())?;
        let page = engine
            .export(
                class,
                &resource,
                &query::Query {
                    from: None,
                    to: None,
                    limit: limit_of(query.limit)?,
                    cursor: query.cursor.clone(),
                    frontier: query.frontier,
                },
            )
            .map_err(refusal)?;
        let first = query.cursor.is_none();
        let (held, omitted) = if first {
            let mut list = engine
                .checkpoints(class, &resource, None)
                .map_err(refusal)?;
            list.files.retain(|file| {
                crate::audit::checkpoint::read_unverified(&file.envelope)
                    .is_ok_and(|checkpoint| checkpoint.last_seq < page.frontier)
            });
            (checkpoints(list.files), list.omitted as u64)
        } else {
            (Vec::new(), 0)
        };
        Ok(AuditExportPage {
            class: class.as_str().to_owned(),
            records: records(&page)?,
            gaps: gaps(&page),
            frontier: page.frontier,
            next_cursor: page.next.clone(),
            anchor: anchor(page.anchor.as_ref()),
            checkpoints: held,
            omitted,
            keys: if first { self.operations_keys() } else { None },
            verification_keys: if first {
                self.verification_keys()
            } else {
                None
            },
            resource,
        })
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use std::sync::Arc;

    use permguard_core::authz::Selector;
    use permguard_core::{AuditEvent, Subject};

    use super::super::testing::{actor, admin, reopen};
    use super::*;
    use crate::audit::{Engine, Stamp};

    /// A facade with an audit engine holding three `security` records of `plane/control`, and an
    /// auditor allowed `audit.read` on `plane/control` alone.
    async fn audited(tag: &str) -> HostApi {
        let root = std::env::temp_dir().join(format!(
            "permguard-host-api-audit-{tag}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        let (mut api, _, volume) = reopen(&root, vec![HOST_OPERATIONS]);
        let engine = Engine::open(
            &volume,
            Stamp {
                host_id: [1; 16],
                boot_id: [2; 16],
                build: "9.9.9".to_owned(),
                config_revision: crate::audit::config_revision([]),
            },
            Arc::clone(&api.time),
            None,
        )
        .expect("the engine opens");
        for zone in ["z1", "z2", "z3"] {
            engine
                .append(
                    &AuditEvent::new("zone.created", Subject::System("catalog")).on(zone),
                    None,
                )
                .expect("a security record");
        }
        api.audit = Some(Arc::new(engine));
        api.create_grant(
            &admin(),
            super::super::CreateGrant {
                request_id: "auditor".to_owned(),
                expected_revision: None,
                principal: AUDITOR.to_owned(),
                operations: vec![operations::AUDIT_READ.to_owned()],
                selector: Selector::under(Resource::parse("plane/control").expect("a resource"))
                    .to_string(),
                resource_types: vec!["*".to_owned()],
                constraints: Default::default(),
                expires_at: None,
            },
        )
        .await
        .expect("the auditor is granted");
        std::mem::forget(volume);
        api
    }

    const AUDITOR: &str = "spiffe://acme/auditor";

    fn query(resource: &str) -> AuditQuery {
        AuditQuery {
            resource: resource.to_owned(),
            ..AuditQuery::default()
        }
    }

    #[tokio::test]
    async fn reading_needs_audit_read_on_the_resource_before_any_filter() {
        let api = audited("admitted").await;
        let auditor = actor(AUDITOR);
        // Outside the grant, whatever the class or the filters say: a denial, never a validation
        // answer that would tell the caller something of the query.
        for (class, from, to) in [("security", None, None), ("bogus", Some(9), Some(1))] {
            let refused = api
                .audit_records(
                    &auditor,
                    class,
                    &AuditQuery {
                        from,
                        to,
                        ..query("host")
                    },
                )
                .expect_err("outside the grant");
            assert!(
                matches!(&refused, Refusal::Denied(denial) if denial.http_status() == 403),
                "{refused:?}"
            );
        }
        let refused = api
            .audit_records(&Actor::Anonymous, "security", &query("plane/control"))
            .expect_err("nobody");
        assert!(matches!(refused, Refusal::Denied(denial) if denial.http_status() == 401));
        // Inside it, the class and the filters are read.
        let refused = api
            .audit_records(&auditor, "bogus", &query("plane/control"))
            .expect_err("no such class");
        assert_eq!(
            refused.error().map(|error| error.code()),
            Some(codes::common::INVALID_ARGUMENT)
        );
        let page = api
            .audit_records(&auditor, "security", &query("plane/control"))
            .expect("served");
        assert_eq!(page.records.len(), 3);
        assert_eq!(page.frontier, 3);
        let bytes = URL_SAFE_NO_PAD
            .decode(&page.records[0].record)
            .expect("base64url");
        assert_eq!(
            crate::audit::record::digest_of(&bytes).to_string(),
            page.records[0].digest
        );
        let held = api
            .audit_checkpoints(
                &auditor,
                "security",
                &AuditCheckpointQuery {
                    resource: "plane/control".to_owned(),
                    period: None,
                },
            )
            .expect("served");
        assert!(held.checkpoints.is_empty(), "nothing sealed yet");
        assert_eq!(
            held.keys.map(|keys| keys.ring),
            Some(HOST_OPERATIONS.to_owned())
        );
        // The export document `audit verify --keys` reads.
        let document = held.verification_keys.expect("the key document");
        crate::audit::checkpoint::Keys::from_document(&document).expect("the keys read");
    }

    #[tokio::test]
    async fn a_tampered_cursor_is_refused() {
        let api = audited("cursor").await;
        let first = api
            .audit_export(
                &actor(AUDITOR),
                "security",
                &AuditExportQuery {
                    resource: "plane/control".to_owned(),
                    limit: Some(1),
                    ..AuditExportQuery::default()
                },
            )
            .expect("served");
        assert!(first.keys.is_some(), "the first page carries the keys");
        let cursor = first.next_cursor.expect("a cursor");
        let next = api
            .audit_export(
                &actor(AUDITOR),
                "security",
                &AuditExportQuery {
                    resource: "plane/control".to_owned(),
                    limit: Some(1),
                    cursor: Some(cursor.clone()),
                    ..AuditExportQuery::default()
                },
            )
            .expect("served");
        assert_eq!(next.records[0].seq, 1);
        assert!(next.keys.is_none() && next.checkpoints.is_empty());
        let mut tampered = cursor.into_bytes();
        let last = tampered.len() - 1;
        tampered[last] = if tampered[last] == b'A' { b'B' } else { b'A' };
        let refused = api
            .audit_export(
                &actor(AUDITOR),
                "security",
                &AuditExportQuery {
                    resource: "plane/control".to_owned(),
                    cursor: Some(String::from_utf8(tampered).expect("text")),
                    ..AuditExportQuery::default()
                },
            )
            .expect_err("tampered");
        assert_eq!(
            refused.error().map(|error| error.code()),
            Some(codes::common::INVALID_ARGUMENT)
        );
    }
}
