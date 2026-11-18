// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! Decisions read from a Control Plane: pages of them, the lines `permguard decisions list`
//! prints, and what verifying a page establishes. The command is this module plus its arguments,
//! the target, the export archive and the rendering; a program that embeds the CLI reads the same
//! lines, so the JSON it keeps is the JSON the command prints.

use permguard_client::decisions::{DecisionLog, ReadError, ReadScope, ReadWindow};
use permguard_core::Jwk;
use permguard_decisions::envelope::Signed;
use permguard_decisions::{chain, merkle, record};
use serde::Serialize;
use serde_json::Value;

/// How many pages one read walks at most: an export of a store larger than this says it stopped.
pub const MAX_PAGES: usize = 10_000;

/// Which outcomes a read keeps.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// Only the requests that were allowed.
    Permit,
    /// Only the requests a policy refused or nothing permitted.
    Deny,
    /// Only the requests that could not be evaluated: refused, and not by a policy.
    Indeterminate,
}

impl Outcome {
    /// Whether a record of this outcome — `permit`, `deny`, `deny_by_default` or
    /// `indeterminate` — is one this filter keeps.
    pub fn admits(self, outcome: &str) -> bool {
        match self {
            Self::Permit => outcome == "permit",
            Self::Deny => outcome == "deny" || outcome == "deny_by_default",
            Self::Indeterminate => outcome == INDETERMINATE,
        }
    }
}

/// What a report keeps of a page, and whether it verifies it.
#[derive(Debug, Clone, Default)]
pub struct Filter {
    /// Only decisions at or after this RFC 3339 timestamp.
    pub since: Option<String>,
    /// Only decisions of this outcome.
    pub decision: Option<Outcome>,
    /// Verify the page: the chain or the inclusion paths, and the signatures when keys are given.
    pub verify: bool,
}

/// What [`read`] walked: the pages joined, and how many it took.
#[derive(Debug, Clone, Default)]
pub struct Read {
    pub page: Page,
    pub walked: usize,
}

/// Reads `scope` from `from`: `limit` decisions, or with `everything` the whole snapshot the first
/// page names, bounded by [`MAX_PAGES`]. `proof` asks for the envelopes and the paths a
/// verification needs. `snapshot` hears the high watermark an export is of, once.
pub fn read(
    reader: &dyn DecisionLog,
    scope: &ReadScope,
    from: Option<String>,
    limit: usize,
    proof: bool,
    everything: bool,
    mut snapshot: impl FnMut(&str),
) -> Result<Read, ReadError> {
    let mut read = Page::default();
    let mut window = ReadWindow {
        from,
        limit_records: limit,
        proof,
        ..ReadWindow::default()
    };
    let mut decisions_read = 0usize;
    let mut walked = 0usize;
    for page_number in 0..MAX_PAGES {
        walked = page_number + 1;
        let page = reader.read(scope, &window)?;
        if everything && page_number == 0 {
            // The snapshot this export is of. Every page after this one is bounded by it.
            window.until = Some(page.high_watermark.clone());
            snapshot(&page.high_watermark);
        }
        read.more = page.more;
        read.next.clone_from(&page.next);
        window.from = Some(page.next);
        decisions_read += page
            .records
            .iter()
            .filter(|record| record.get("kind").and_then(Value::as_str) == Some("decision"))
            .count();
        read.proof.extend(page.proof);
        read.inclusion.extend(page.inclusion);
        read.records.extend(page.records);
        read.members.extend(page.members);
        // An empty page is not the end: filtering and scan bounds mean a page may match nothing
        // while still advancing. The export stops from `more` against its own bound, and nothing
        // else.
        if !read.more {
            break;
        }
        if everything {
            continue;
        }
        // A page is `limit` decisions, not `limit` records. The stream carries marker events
        // beside the decisions, and a limit counted in records handed back one decision fewer
        // than asked. So the read goes on until the decisions add up, asking each time only for
        // what is still missing: the server bounds a page by records, so the last one cannot
        // overshoot and leave `next` past decisions that were never shown.
        if decisions_read >= limit {
            break;
        }
        window.limit_records = limit - decisions_read;
    }
    Ok(Read { page: read, walked })
}

/// A page of decisions, and what checking them concluded.
#[derive(Debug, Clone, Serialize)]
pub struct DecisionsReport {
    /// What was read: `acme/main-ledger`, or a producer stream.
    pub scope: String,
    /// One line per decision.
    pub decisions: Vec<DecisionLine>,
    /// Records that are not decisions — the epochs and the endings.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub events: Vec<EventLine>,
    /// The offset to resume from, which belongs to the caller.
    pub next: String,
    /// Whether the store holds more right now.
    pub more: bool,
    /// What verification concluded, when it was asked for.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verified: Option<Verified>,
}

/// One decision, as a reader sees it.
#[derive(Debug, Clone, Serialize)]
pub struct DecisionLine {
    /// Where it sits in its producer's history.
    pub seq: u64,
    /// When it was answered.
    pub at: String,
    /// The answer.
    pub decision: bool,
    /// Which of the algebra's results it was: `permit`, `deny`, `deny_by_default` or
    /// `indeterminate` — an evaluation that failed, which is not a deny.
    pub outcome: String,
    /// Who asked, as recorded — pseudonymised at the source.
    pub subject: String,
    /// What was asked for.
    pub action: String,
    /// What it was about.
    pub resource: String,
    /// The exact policy state that produced the answer.
    pub commit: String,
    /// Which policies decided.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub policies: Vec<String>,
    /// The partitions that declared an input and were addressed with none: they decided against
    /// an empty one.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub absent_inputs: Vec<String>,
    /// The context members the data plane's decision log names in `include.context`, in clear:
    /// absent when it names none.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context: Option<Value>,
    /// The subject's properties the data plane's decision log names in `include.subject_properties`,
    /// in clear: absent when it names none.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject_properties: Option<Value>,
    /// The resource's properties named in `include.resource_properties`, in clear.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource_properties: Option<Value>,
    /// The keyed commitment over the caller's whole context, which the record always carries
    /// when there was one: it proves what was asked without saying it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context_commitment: Option<String>,
    /// The decision's own identifier.
    pub id: String,
    /// How long the plane took.
    pub latency_us: u64,
    /// The data plane that answered: its Host id, the record's `stream.id`. What a reader joins to
    /// the members of a Control Plane's Host to name the plane.
    pub pdp: String,
    /// The incarnation of that plane the record belongs to: the record's `stream.instance`.
    pub instance: String,
    /// The member that plane is among the Control Plane's Host's members (owner decision of
    /// 2026-11-15): the id bound to `pdp` at its first approval, and its name, as the server named
    /// them beside the page; empty when no membership names it.
    pub member: String,
    pub member_name: String,
}

/// An object of members recorded in clear, or `None` when the record carries none: an empty
/// object says nothing.
fn members(value: Option<&Value>) -> Option<Value> {
    value
        .filter(|value| value.as_object().is_some_and(|members| !members.is_empty()))
        .cloned()
}

/// The `outcome` of an indeterminate decision.
pub const INDETERMINATE: &str = "indeterminate";

/// Which of the algebra's results a decision record holds: its `outcome`, or — for a record
/// written before the member existed — what its `decision` says, `permit` or `deny`.
pub fn outcome_of(record: &Value) -> String {
    if let Some(outcome) = record.get("outcome").and_then(Value::as_str) {
        return outcome.to_owned();
    }
    let permit = record
        .get("decision")
        .and_then(Value::as_bool)
        .unwrap_or_default();

    if permit { "permit" } else { "deny" }.to_owned()
}

/// A record that is not a decision: an epoch, or an ending.
#[derive(Debug, Clone, Serialize)]
pub struct EventLine {
    /// Where it sits.
    pub seq: u64,
    /// `marker` or `discontinuity`.
    pub kind: String,
    /// What it says, in one line.
    pub detail: String,
}

/// What `--verify` established, and what it did not.
///
/// Which of the two proofs applies is decided by the scope, not by preference.
/// A **producer stream** is a contiguous history, so the chain is what proves
/// it. A **tenant view** is a subsequence — the records in between belong to
/// other tenants and must not be disclosed — so the chain cannot be checked
/// across it, and the inclusion path is what proves each record instead.
/// Reporting a chain result for a tenant page would be reporting a failure of
/// arithmetic as a failure of integrity.
#[derive(Debug, Clone, Serialize)]
pub struct Verified {
    /// Which proof applies here: `chain` or `inclusion`.
    pub proof: &'static str,
    /// Whether the records are a contiguous, unaltered chain. Stream scope only.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub chain: Option<bool>,
    /// What broke it, when something did.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub chain_detail: Option<String>,
    /// How many records proved to be in a batch this producer signed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub included: Option<usize>,
    /// How many did not — each one is a record the store cannot account for.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub not_included: Option<usize>,
    /// How many batch signatures verified against the given key set.
    pub signatures: usize,
    /// How many did not.
    pub signatures_failed: usize,
    /// Stated rather than implied: without a key set, signatures are not checked.
    pub signatures_checked: bool,
    /// Each record a tenant view could not account for, and why: one proven by no batch of its
    /// own stream covering its sequence, or one that appears twice (BUG-0141, BUG-0143).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub refused: Vec<String>,
    /// The resources of the Host batches that proved a tenant view's records, the canonical text
    /// each signs: what an archive's binding is checked against (BUG-0142).
    #[serde(skip)]
    pub resources: std::collections::BTreeSet<String>,
    /// Whether some record of a tenant view was proven by a legacy envelope, which signs no
    /// resource.
    #[serde(skip)]
    pub unresourced: bool,
}

impl Verified {
    /// Whether everything checked held: the chain unbroken, every record in a signed batch, and
    /// no signature refused (TC-1).
    pub fn holds(&self) -> bool {
        self.chain != Some(false)
            && self.not_included.unwrap_or(0) == 0
            && self.signatures_failed == 0
    }
}

/// What one or more pages came back with: the records, the envelopes and the inclusion paths a
/// verification needs, the offset to resume from, and whether the store holds more.
#[derive(Debug, Clone, Default)]
pub struct Page {
    pub records: Vec<Value>,
    /// The members the server named beside the records: a `pdp` to the member's id and name.
    pub members: std::collections::BTreeMap<String, permguard_client::decisions::MemberName>,
    pub proof: Vec<Value>,
    pub inclusion: Vec<Value>,
    pub next: String,
    pub more: bool,
}

/// Turns records into the report, filtering and verifying as asked.
pub fn report(
    scope: &ReadScope,
    page: Page,
    filter: &Filter,
    keys: Option<&[Jwk]>,
) -> DecisionsReport {
    let Page {
        records,
        members: named_members,
        proof,
        inclusion,
        next,
        more,
    } = page;
    // Verification runs over everything that came back, before any filtering:
    // a chain with a record removed from it is not a chain, and filtering
    // first would make every filtered read look broken.
    let verified = filter
        .verify
        .then(|| verify(scope, &records, &proof, &inclusion, keys));

    let mut decisions = Vec::new();
    let mut events = Vec::new();
    for record in records {
        let kind = record
            .get("kind")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned();
        let seq = record
            .get("seq")
            .and_then(Value::as_u64)
            .unwrap_or_default();
        let at = string(&record, "at");
        if kind != "decision" {
            events.push(EventLine {
                seq,
                detail: describe(&kind, &record),
                kind,
            });
            continue;
        }
        if let Some(since) = &filter.since
            && at.as_str() < since.as_str()
        {
            continue;
        }
        let permit = record
            .get("decision")
            .and_then(Value::as_bool)
            .unwrap_or_default();
        let outcome = outcome_of(&record);
        if let Some(wanted) = filter.decision
            && !wanted.admits(&outcome)
        {
            continue;
        }

        let pdp = record
            .get("stream")
            .and_then(|stream| stream.get("id"))
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned();
        let named = named_members.get(&pdp);
        decisions.push(DecisionLine {
            seq,
            at,
            decision: permit,
            outcome,
            member: named
                .map(|member| member.member_id.clone())
                .unwrap_or_default(),
            member_name: named.map(|member| member.name.clone()).unwrap_or_default(),
            subject: party(&record, "subject"),
            action: record
                .get("action")
                .and_then(|action| action.get("name"))
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned(),
            resource: party(&record, "resource"),
            commit: record
                .get("store")
                .and_then(|store| store.get("commit"))
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned(),
            policies: record
                .get("policies")
                .and_then(Value::as_array)
                .map(|policies| {
                    policies
                        .iter()
                        .filter_map(|policy| policy.as_str().map(str::to_owned))
                        .collect()
                })
                .unwrap_or_default(),
            absent_inputs: record
                .get("inputs")
                .and_then(|inputs| inputs.get("absent"))
                .and_then(Value::as_array)
                .map(|names| {
                    names
                        .iter()
                        .filter_map(|name| name.as_str().map(str::to_owned))
                        .collect()
                })
                .unwrap_or_default(),
            context: members(record.get("context")),
            subject_properties: members(record.pointer("/subject/properties")),
            resource_properties: members(record.pointer("/resource/properties")),
            context_commitment: record
                .get("inputs")
                .and_then(|inputs| inputs.get("context"))
                .and_then(Value::as_str)
                .map(str::to_owned),
            id: string(&record, "id"),
            pdp,
            instance: record
                .get("stream")
                .and_then(|stream| stream.get("instance"))
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned(),
            latency_us: record
                .get("latency_us")
                .and_then(Value::as_u64)
                .unwrap_or_default(),
        });
    }

    DecisionsReport {
        scope: match scope {
            ReadScope::Tenant { zone, ledger } => format!("{zone}/{ledger}"),
            ReadScope::Stream { pdp_id, instance } => format!("{pdp_id} · {instance}"),
        },
        decisions,
        events,
        next,
        more,
        verified,
    }
}

/// Re-computes what the records and the envelopes say about themselves.
///
/// Which proof applies is decided by the scope, not by preference:
///
/// ```text
/// producer stream  →  a contiguous history      →  the chain proves it
/// tenant view      →  a subsequence of one      →  the inclusion path does
/// ```
///
/// Running the chain check over a tenant page would report a failure of
/// arithmetic as a failure of integrity: the records in between belong to
/// other tenants, and their absence is the design working, not a break.
pub fn verify(
    scope: &ReadScope,
    records: &[Value],
    proof: &[Value],
    inclusion: &[Value],
    keys: Option<&[Jwk]>,
) -> Verified {
    let (mut verified, mut failed) = (0, 0);
    let mut roots: Vec<Root> = Vec::new();
    // The batches the producing Hosts' engines sealed (WP-6.2b): their roots are attributed only
    // when their signatures verify under the keys given.
    let mut host_batches = Vec::new();
    for entry in proof {
        match crate::host_proof::host_batch(
            entry,
            keys,
            permguard_core::domains::protected::DECISION_BATCH,
        ) {
            Some(Ok(batch)) => {
                verified += usize::from(keys.is_some());
                roots.push(Root {
                    merkle_root: batch.merkle_root.clone(),
                    producer: batch.producer.clone(),
                    run: batch.run.clone(),
                    first_seq: batch.first_seq,
                    last_seq: batch.last_seq,
                    resource: Some(batch.resource.clone()),
                });
                host_batches.push(batch);
            }
            Some(Err(())) => failed += usize::from(keys.is_some()),
            None => {}
        }
    }
    let legacy: Vec<&Value> = proof
        .iter()
        .filter(|entry| {
            entry.get("format").and_then(Value::as_str) != Some(crate::host_proof::HOST_FORMAT)
        })
        .collect();
    if let Some(keys) = keys {
        for &envelope in &legacy {
            let signed = serde_json::from_value::<Signed>(envelope.clone())
                .ok()
                .map(|signed| signed.verify(keys));
            match signed {
                Some(Ok(attested)) => {
                    verified += 1;
                    roots.push(Root::legacy(attested));
                }
                Some(Err(_)) | None => failed += 1,
            }
        }
    } else {
        // Without a key set the roots are still usable for the arithmetic —
        // they simply are not *attributed*, and the report says so.
        for &envelope in &legacy {
            if let Ok(signed) = serde_json::from_value::<Signed>(envelope.clone())
                && let Ok(attested) = signed.envelope()
            {
                roots.push(Root::legacy(attested));
            }
        }
    }

    match scope {
        ReadScope::Stream { .. } => {
            let (chain_ok, detail) = match chain::verify(records, None) {
                // An empty page is not a broken chain: there is nothing to check.
                Err(chain::ChainError::Empty) => (true, None),
                Err(error) => (false, Some(error.to_string())),
                // A chain that holds is not yet a chain anybody *signed*. When
                // a proof came back, bind its head to a head the producer
                // attested — the whole point of reading a stream is to check it
                // without trusting the server that served it. With no proof
                // asked for, the chain result stands alone and the report says
                // signatures were not checked.
                Ok(_) if proof.is_empty() => (true, None),
                Ok(verified) if attested(&verified, records, proof, &host_batches) => (true, None),
                Ok(_) => (
                    false,
                    Some(
                        "the records form a chain, and no envelope in the proof attests its head: \
                         this run is well-formed and unattributed"
                            .to_owned(),
                    ),
                ),
            };

            Verified {
                proof: "chain",
                chain: Some(chain_ok),
                chain_detail: detail,
                included: None,
                not_included: None,
                signatures: verified,
                signatures_failed: failed,
                signatures_checked: keys.is_some(),
                refused: Vec::new(),
                resources: std::collections::BTreeSet::new(),
                unresourced: false,
            }
        }
        ReadScope::Tenant { .. } => {
            let inclusion = included(records, inclusion, &roots);

            Verified {
                proof: "inclusion",
                chain: None,
                chain_detail: None,
                included: Some(inclusion.proven),
                not_included: Some(inclusion.missing),
                signatures: verified,
                signatures_failed: failed,
                signatures_checked: keys.is_some(),
                refused: inclusion.refused,
                resources: inclusion.resources,
                unresourced: inclusion.unresourced,
            }
        }
    }
}

/// Whether the signed envelopes attest the run that was verified.
///
/// The chain proves the records follow one another; the envelope proves a
/// producer said so. Checking one without the other leaves the case that
/// matters: a store serving a well-formed history nobody signed — including a
/// *replaced* one, internally perfect, presented beside the genuine envelopes.
/// Range overlap alone would accept that, so the two are bound by digest:
/// every batch boundary that falls inside the run must name a head the run
/// actually digests to.
///
/// A run may still end mid-batch — a page boundary is not a batch boundary —
/// and its final records are then bound by the *next* page's chain check
/// rather than by a head of their own.
fn attested(
    verified: &permguard_decisions::Verified,
    records: &[Value],
    proof: &[Value],
    host_batches: &[crate::host_proof::HostBatch],
) -> bool {
    let digests: std::collections::BTreeMap<u64, String> = records
        .iter()
        .filter_map(|record| {
            let seq = record.get("seq").and_then(Value::as_u64)?;

            record::digest_of(record).ok().map(|digest| (seq, digest))
        })
        .collect();
    // `(first, last, head)` of each batch of the verified stream: a legacy envelope naming it, or
    // a Host batch naming its `host_id` and run.
    let mut envelopes: Vec<(u64, u64, String)> = proof
        .iter()
        .filter_map(|signed| {
            serde_json::from_value::<Signed>(signed.clone())
                .ok()
                .and_then(|signed| signed.envelope().ok())
        })
        .filter(|envelope| envelope.stream == verified.stream)
        .map(|envelope| (envelope.first_seq, envelope.last_seq, envelope.head))
        .collect();
    envelopes.extend(
        host_batches
            .iter()
            .filter(|batch| {
                batch.producer == verified.stream.id && batch.run == verified.stream.instance
            })
            .map(|batch| (batch.first_seq, batch.last_seq, batch.head.clone())),
    );

    // Every attested head inside the run must be a digest the run reaches.
    // One that is not means the records and the signatures describe two
    // different histories, and "verified" must not be the answer.
    for (_, last, head) in &envelopes {
        if (verified.first_seq..=verified.last_seq).contains(last)
            && digests.get(last) != Some(head)
        {
            return false;
        }
    }

    // And the run's own head must be under some signature: attested exactly,
    // or carried by a batch that extends past the page.
    envelopes
        .iter()
        .any(|(first, last, _)| (*first..=*last).contains(&verified.last_seq))
}

/// A Merkle root a proof entry attests, and what for: the stream, the run and the range of
/// sequences its batch covers, and the resource a Host batch signs.
struct Root {
    merkle_root: String,
    producer: String,
    run: String,
    first_seq: u64,
    last_seq: u64,
    /// `None` for a legacy envelope, which signs no resource.
    resource: Option<String>,
}

impl Root {
    fn legacy(envelope: permguard_decisions::envelope::Envelope) -> Self {
        Self {
            merkle_root: envelope.merkle_root,
            producer: envelope.stream.id,
            run: envelope.stream.instance,
            first_seq: envelope.first_seq,
            last_seq: envelope.last_seq,
            resource: None,
        }
    }

    /// Whether this root's batch is of `producer`'s run `run` and covers `seq`.
    fn covers(&self, producer: &str, run: &str, seq: u64) -> bool {
        same_id(&self.producer, producer)
            && same_id(&self.run, run)
            && (self.first_seq..=self.last_seq).contains(&seq)
    }
}

/// Whether two ids name the same thing, as hex or as UUID text.
fn same_id(left: &str, right: &str) -> bool {
    let plain = |id: &str| id.replace('-', "").to_ascii_lowercase();
    plain(left) == plain(right)
}

/// What the inclusion paths of a tenant view proved.
struct Inclusion {
    proven: usize,
    missing: usize,
    refused: Vec<String>,
    resources: std::collections::BTreeSet<String>,
    unresourced: bool,
}

/// How many records reach a root the producer attested, and how many do not.
///
/// A record is proven when its own digest, carried up its path, reaches a root that came from a
/// signed batch **of its own stream and run covering its sequence**: a root of another
/// producer's batch proves nothing about this record, however it was reached (BUG-0141).
/// Recomputing the leaf from the record itself is the part that matters: taking the leaf from the
/// proof would prove that the proof is consistent with itself. A record that appears twice is
/// counted once and refused the second time, so a copy is never another decision (BUG-0143).
fn included(records: &[Value], inclusion: &[Value], roots: &[Root]) -> Inclusion {
    let mut outcome = Inclusion {
        proven: 0,
        missing: 0,
        refused: Vec::new(),
        resources: std::collections::BTreeSet::new(),
        unresourced: false,
    };
    let mut seen = std::collections::BTreeSet::new();
    for record in records {
        let seq = record
            .get("seq")
            .and_then(Value::as_u64)
            .unwrap_or_default();
        let stream = |field: &str| {
            record
                .get("stream")
                .and_then(|stream| stream.get(field))
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned()
        };
        let (producer, run) = (stream("id"), stream("instance"));
        let named = format!("{producer}/{run} seq {seq}");
        let mut refuse = |why: &str| {
            outcome.missing += 1;
            outcome.refused.push(format!("{named}: {why}"));
        };
        if !seen.insert((
            producer.replace('-', "").to_ascii_lowercase(),
            run.replace('-', "").to_ascii_lowercase(),
            seq,
        )) {
            refuse("the record appears twice");
            continue;
        }
        let Ok(leaf) = record::digest_of(record) else {
            refuse("the record has no digest");
            continue;
        };
        // By its sequence and its leaf: a tenant page spans runs that each begin at 1, so a
        // sequence alone would take another run's path (WP-6.3b, after the review).
        let Some(path) = inclusion.iter().find(|entry| {
            entry.get("seq").and_then(Value::as_u64) == Some(seq)
                && entry.get("leaf").and_then(Value::as_str) == Some(leaf.as_str())
        }) else {
            refuse("no inclusion path names it");
            continue;
        };
        let steps: Vec<merkle::Step> = path
            .get("path")
            .cloned()
            .and_then(|steps| serde_json::from_value(steps).ok())
            .unwrap_or_default();
        let reached = merkle::recompute(&leaf, &steps);
        match roots
            .iter()
            .find(|root| root.merkle_root == reached && root.covers(&producer, &run, seq))
        {
            Some(root) => {
                outcome.proven += 1;
                match &root.resource {
                    Some(resource) => {
                        outcome.resources.insert(resource.clone());
                    }
                    None => outcome.unresourced = true,
                }
            }
            None => refuse("its path reaches no signed batch of its own stream covering it"),
        }
    }
    outcome
}

fn describe(kind: &str, record: &Value) -> String {
    match kind {
        "marker" => format!(
            "sampling permits={}, build {}",
            record
                .get("sampling")
                .and_then(|sampling| sampling.get("permits"))
                .and_then(Value::as_str)
                .unwrap_or("?"),
            record
                .get("pdp")
                .and_then(|pdp| pdp.get("version"))
                .and_then(Value::as_str)
                .unwrap_or("?")
        ),
        "discontinuity" => format!(
            "the stream ended ({}); {} record(s) lost, continues as {}",
            string(record, "reason"),
            record
                .get("lost")
                .and_then(|lost| lost.get("count_estimate"))
                .and_then(Value::as_u64)
                .unwrap_or_default(),
            string(record, "successor")
        ),
        other => other.to_owned(),
    }
}

fn party(record: &Value, member: &str) -> String {
    let Some(party) = record.get(member) else {
        return String::new();
    };

    format!(
        "{}:{}",
        party
            .get("type")
            .and_then(Value::as_str)
            .unwrap_or_default(),
        party.get("id").and_then(Value::as_str).unwrap_or_default()
    )
}

fn string(record: &Value, member: &str) -> String {
    record
        .get(member)
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned()
}
