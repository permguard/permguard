// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The third role a language plays: **evaluating** a decision.
//!
//! [`Language`](crate::role::Language) says what a policy *is*;
//! [`Authoring`](crate::role::Authoring) turns files into policies; this one
//! answers the only question a PDP is asked — *may this subject do this to
//! this?*
//!
//! # Compile once, evaluate many
//!
//! The role is split in two on purpose. [`Evaluating::compile`] does the
//! expensive work — parsing every policy, building the engine's own program,
//! checking it against the schema — and hands back an [`Evaluator`] that is
//! immutable, shareable and cheap to call. A data plane compiles a partition
//! when it loads it and then answers requests out of memory; nothing on the
//! decision path re-parses a policy.
//!
//! # Fail-closed, by construction
//!
//! [`Evaluator::evaluate`] cannot return "I do not know": a request the
//! language refuses is a [`Verdict`] that denies and carries the reason. The
//! caller reports it; it never turns into a permit, and it never turns into a
//! transport error either — a deny is an answer.

use std::collections::BTreeMap;

use serde_json::{Map, Value};

/// One entity the request names: the subject, or the resource.
///
/// `kind` is the entity *type* in the language's own namespace — `User`,
/// `acme::Document` — and `id` its identifier inside that type. `properties`
/// are the attributes a policy may read.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Entity {
    pub kind: String,
    pub id: String,
    pub properties: Map<String, Value>,
}

/// The operation being attempted.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Action {
    /// The action name — bare (`read`) or qualified (`acme::Action::"read"`
    /// written as `acme::Action::read`); a language resolves the shape it
    /// speaks.
    pub name: String,
    pub properties: Map<String, Value>,
}

/// One decision request, language-agnostic: the profile's own shape.
#[derive(Debug, Clone, Default)]
pub struct Query {
    pub subject: Entity,
    pub resource: Entity,
    pub action: Action,
    /// Environmental attributes — time, address, whatever a policy reads.
    pub context: Map<String, Value>,
    /// The entity graph, in the language's own JSON shape. The Permguard
    /// extension: what a policy traverses beyond the three entities above.
    pub entities: Vec<Value>,
}

/// One policy as the store holds it: its derived identity, the optional
/// authored alias, and the verbatim source bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredPolicy {
    /// The policy identity — what a decision cites, and what survives a
    /// rename.
    pub id: String,
    /// The authored handle, when the source declared one.
    pub alias: Option<String>,
    /// The verbatim authored bytes.
    pub source: Vec<u8>,
}

/// What one evaluation concluded.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Verdict {
    /// `true` permit, `false` deny. Nothing in between.
    pub permitted: bool,
    /// The identities of the policies that decided it — what the reason
    /// cites, so the audit trail stays whole across renames.
    pub determining: Vec<String>,
    /// Present when the request could not be evaluated. The verdict then
    /// denies: fail-closed is the contract, and this is the reason why.
    pub error: Option<String>,
}

impl Verdict {
    /// A permit, decided by these policies.
    pub fn permit(determining: Vec<String>) -> Self {
        Self {
            permitted: true,
            determining,
            error: None,
        }
    }

    /// A deny, decided by these policies.
    pub fn deny(determining: Vec<String>) -> Self {
        Self {
            permitted: false,
            determining,
            error: None,
        }
    }

    /// A deny because the request could not be evaluated at all.
    pub fn refused(reason: impl Into<String>) -> Self {
        Self {
            permitted: false,
            determining: Vec::new(),
            error: Some(reason.into()),
        }
    }
}

/// A compiled, immutable set of policies, ready to answer requests.
///
/// Shared across threads and across requests: everything expensive already
/// happened in [`Evaluating::compile`].
pub trait Evaluator: Send + Sync {
    /// Answers one request. Never errors: a request that cannot be evaluated
    /// is a [`Verdict::refused`], which denies.
    fn evaluate(&self, query: &Query) -> Verdict;

    /// Roughly how much memory this compiled program holds, for the cache
    /// that decides what to keep. An estimate — the sources it was built
    /// from plus what the engine keeps beside them.
    fn footprint(&self) -> usize;

    /// The policies it was compiled from, by identity, for a report that has
    /// to say what is loaded.
    fn policies(&self) -> Vec<String>;
}

/// The compiling half: sources in, an [`Evaluator`] out.
pub trait Evaluating: Send + Sync {
    /// Compiles a partition's policies, against its schema when it has one.
    ///
    /// A schema is not decoration: when the partition declares one, every
    /// policy is **validated against it** here, and a policy that does not
    /// type-check refuses the load. A ledger that would evaluate differently
    /// than it reads is not one to serve.
    fn compile(
        &self,
        policies: &[StoredPolicy],
        schema: Option<&[u8]>,
    ) -> Result<Box<dyn Evaluator>, String>;
}

/// The properties of the three named entities, as a language may want them
/// folded into its own entity graph.
///
/// Provided here rather than in each language because the mapping is the
/// profile's, not the language's: the request names three entities with
/// attributes, and whichever engine answers must see those attributes.
pub fn named_entities(query: &Query) -> BTreeMap<(String, String), Map<String, Value>> {
    let mut named = BTreeMap::new();
    named.insert(
        (query.subject.kind.clone(), query.subject.id.clone()),
        query.subject.properties.clone(),
    );
    named.insert(
        (query.resource.kind.clone(), query.resource.id.clone()),
        query.resource.properties.clone(),
    );

    named
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_refused_request_denies_and_says_why() {
        let refused = Verdict::refused("the action is empty");

        assert!(!refused.permitted, "fail-closed");
        assert_eq!(refused.error.as_deref(), Some("the action is empty"));
    }

    #[test]
    fn the_named_entities_carry_their_properties() {
        let mut query = Query::default();
        query.subject.kind = "User".to_owned();
        query.subject.id = "alice".to_owned();
        query
            .subject
            .properties
            .insert("department".to_owned(), Value::from("sales"));
        query.resource.kind = "Document".to_owned();
        query.resource.id = "budget".to_owned();

        let named = named_entities(&query);
        assert_eq!(named.len(), 2);
        assert_eq!(
            named[&("User".to_owned(), "alice".to_owned())]["department"],
            Value::from("sales")
        );
    }
}
