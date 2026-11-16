// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The decision alone: the supported surface of an application that embeds no Data Plane.
//!
//! ```text
//! Evaluator::builder() ── engine(..)          one engine a language, never two
//!        │ load(policies)                     validated by the language, now
//!        │ build()                            compiled, once
//!        ▼
//!   Evaluator ── evaluate(&request)           allow or deny, what decided it, why it failed
//! ```
//!
//! | Rule             | Here                                                                       |
//! | ---------------- | -------------------------------------------------------------------------- |
//! | side effects     | none: an evaluation reads the compiled policies and the request, and writes |
//! |                  | nothing, reaches nothing and records nothing                               |
//! | the runtime      | the caller's thread; nothing here starts one or awaits anything            |
//! | engines          | registered by value, one a language, a duplicate refused, the order fixed  |
//! | the policies     | validated by their language when loaded; refused, they load nothing        |
//! | their provenance | [`Provenance::Validated`]: an application's own, never a verified ledger   |
//! | the answer       | [`Decision`]: the algebra every Permguard decision point resolves with     |
//!
//! A ledger the Permguard protocol verified is the Data Plane's, with its `local-ledger`
//! capability: nothing loaded here is, or can be reported as, a verified snapshot. A language that
//! decides against history, Dogwood, is the Data Plane's too, with its event evidence: a question
//! with no past cannot be asked of it, and its policies are refused here by name.

use std::sync::Arc;

use permguard_language_core::artifact::Artifacts;
use permguard_language_core::evaluate::{
    Action, Entity, EvaluationError, Outcome, Query, Resolution, StoredPolicy, resolve,
};
use permguard_language_core::input::PartitionData;
use serde_json::{Map, Value};

use crate::Engine;

/// The policies an application hands over, in one language: validated when loaded, compiled when
/// the evaluator is built.
#[derive(Debug, Clone, Default)]
pub struct Policies {
    language: String,
    policies: Vec<StoredPolicy>,
    artifacts: Artifacts,
}

impl Policies {
    /// No policy yet, in `language`, as a manifest's runtime names it: `cedar`, `rego`.
    pub fn of(language: impl Into<String>) -> Self {
        Self {
            language: language.into(),
            ..Self::default()
        }
    }

    /// Adds one policy: `id` is what a decision cites, `source` the authored bytes.
    pub fn policy(mut self, id: impl Into<String>, source: impl Into<Vec<u8>>) -> Self {
        self.policies.push(StoredPolicy {
            id: id.into(),
            alias: None,
            source: source.into(),
        });
        self
    }

    /// The typed artifacts the policies are compiled with: a schema, say.
    pub fn artifacts(mut self, artifacts: Artifacts) -> Self {
        self.artifacts = artifacts;
        self
    }

    /// The language these policies are written in.
    pub fn language(&self) -> &str {
        &self.language
    }
}

/// Where the policies an evaluator decides with came from.
///
/// One answer today, and deliberately a type: policies an application validated and a snapshot the
/// Permguard protocol verified are different things, and only the ledger packages may say the
/// second. Nothing an application loads here is ever reported as a verified ledger.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Provenance {
    /// Policies the application supplied, validated by their language: their origin, integrity
    /// and currency are the application's to vouch for.
    Validated,
}

/// Why an evaluator was not built, or a question not asked.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Refused {
    /// Two engines were registered for one language: nothing is replaced.
    DuplicateEngine(String),
    /// Policies in a language no registered engine evaluates.
    NoEngine(String),
    /// Policies in a language loaded twice: one set of policies a language.
    DuplicateLanguage(String),
    /// A language that decides against history: its policies need the past, which nothing here
    /// keeps.
    Temporal(String),
    /// A policy its language refused, with why.
    Invalid { policy: String, reason: String },
    /// The policies did not compile, with why.
    Compile { language: String, reason: String },
    /// Nothing was loaded: an evaluator with no policy would deny everything, silently.
    NothingLoaded,
    /// The request's input is not what the policies' schema declares, with why.
    Input(String),
}

impl std::fmt::Display for Refused {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DuplicateEngine(language) => write!(
                formatter,
                "two engines were registered for `{language}`: one engine a language, and none \
                 is replaced"
            ),
            Self::NoEngine(language) => write!(
                formatter,
                "the policies are `{language}`, and no engine registered here evaluates it"
            ),
            Self::DuplicateLanguage(language) => write!(
                formatter,
                "policies in `{language}` were loaded twice: load every policy of a language at \
                 once"
            ),
            Self::Temporal(language) => write!(
                formatter,
                "`{language}` decides against what has already happened, and this evaluator keeps \
                 no history: its policies are a Data Plane's, with its event evidence"
            ),
            Self::Invalid { policy, reason } => {
                write!(formatter, "the policy `{policy}` is refused: {reason}")
            }
            Self::Compile { language, reason } => {
                write!(
                    formatter,
                    "the `{language}` policies do not compile: {reason}"
                )
            }
            Self::NothingLoaded => formatter.write_str(
                "no policy was loaded: an evaluator with nothing to decide with is not built",
            ),
            Self::Input(reason) => write!(formatter, "the request's input is refused: {reason}"),
        }
    }
}

impl std::error::Error for Refused {}

/// What starts an evaluator.
#[derive(Default)]
pub struct Builder {
    engines: Vec<Engine>,
    loaded: Vec<Policies>,
}

impl Builder {
    /// Registers an engine, both halves of one language: `permguard_language_cedar::engine()`.
    /// A second engine for the same language is refused when policies are loaded or the evaluator
    /// built, whichever comes first: nothing is replaced.
    pub fn engine(mut self, engine: Engine) -> Self {
        self.engines.push(engine);
        self
    }

    /// The engine registered for `language`, when exactly one is.
    fn engine_of(&self, language: &str) -> Result<Engine, Refused> {
        let mut found = self
            .engines
            .iter()
            .filter(|engine| engine.name() == language);
        match (found.next(), found.next()) {
            (Some(engine), None) => Ok(*engine),
            (Some(_), Some(_)) => Err(Refused::DuplicateEngine(language.to_owned())),
            (None, _) => Err(Refused::NoEngine(language.to_owned())),
        }
    }

    /// Loads `policies`, each validated by its language now: one refused loads none of them.
    pub fn load(mut self, policies: Policies) -> Result<Self, Refused> {
        let engine = self.engine_of(&policies.language)?;
        if engine.language().is_temporal() {
            return Err(Refused::Temporal(policies.language));
        }
        if self
            .loaded
            .iter()
            .any(|held| held.language == policies.language)
        {
            return Err(Refused::DuplicateLanguage(policies.language));
        }
        for policy in &policies.policies {
            engine
                .language()
                .validate_policy(&policy.source)
                .map_err(|reason| Refused::Invalid {
                    policy: policy.id.clone(),
                    reason,
                })?;
        }
        self.loaded.push(policies);
        Ok(self)
    }

    /// Compiles what was loaded, once: the evaluator answers from the compiled policies alone.
    pub fn build(self) -> Result<Evaluator, Refused> {
        // Every engine, whether or not policies were loaded for it: a duplicate is refused
        // wherever it sits.
        let mut names: Vec<&str> = self.engines.iter().map(Engine::name).collect();
        names.sort_unstable();
        if let Some(pair) = names.windows(2).find(|pair| pair[0] == pair[1]) {
            return Err(Refused::DuplicateEngine(pair[0].to_owned()));
        }
        if self.loaded.iter().all(|held| held.policies.is_empty()) {
            return Err(Refused::NothingLoaded);
        }

        // One fixed order, whatever order engines were registered or policies loaded in.
        let mut loaded = self.loaded;
        loaded.sort_by(|left, right| left.language.cmp(&right.language));
        let mut partitions = Vec::with_capacity(loaded.len());
        for held in loaded {
            let engine = self
                .engines
                .iter()
                .find(|engine| engine.name() == held.language)
                .ok_or_else(|| Refused::NoEngine(held.language.clone()))?;
            let compiled = engine
                .evaluating()
                .compile(&held.policies, &held.artifacts)
                .map_err(|reason| Refused::Compile {
                    language: held.language.clone(),
                    reason,
                })?;
            partitions.push(Partition {
                language: held.language,
                compiled: Arc::from(compiled),
            });
        }
        Ok(Evaluator { partitions })
    }
}

/// One language's compiled policies.
struct Partition {
    language: String,
    compiled: Arc<dyn permguard_language_core::evaluating::Evaluator>,
}

/// One question: who asks, to do what, to what, in which circumstances.
#[derive(Debug, Clone, Default)]
pub struct Request {
    /// Who asks.
    pub principal: Entity,
    /// What they ask to do.
    pub action: Action,
    /// What they ask to do it to.
    pub resource: Entity,
    /// The circumstances a policy may read: the time, an address.
    pub context: Map<String, Value>,
    /// What the policies' runtime reads beside the request, normalised: Cedar's entities, say.
    /// Empty when the policies read the request alone.
    pub input: PartitionData,
}

/// What a question concluded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decision {
    outcome: Outcome,
    provenance: Provenance,
}

impl Decision {
    /// Whether it is allowed: a policy permitted it, and nothing denied it or failed.
    pub fn permitted(&self) -> bool {
        self.outcome.resolution == Resolution::Permit
    }

    /// Which of the four results it reached: permit, deny, deny by default, or indeterminate.
    pub fn resolution(&self) -> Resolution {
        self.outcome.resolution
    }

    /// The policies that permitted it, by the identity each was loaded under.
    pub fn permits(&self) -> &[String] {
        &self.outcome.permits
    }

    /// The policies that refused it.
    pub fn denials(&self) -> &[String] {
        &self.outcome.denials
    }

    /// Every failure behind it, each with the stable code of its cause.
    pub fn errors(&self) -> &[EvaluationError] {
        &self.outcome.errors
    }

    /// The whole outcome, as every Permguard decision point resolves one.
    pub fn outcome(&self) -> &Outcome {
        &self.outcome
    }

    /// Where the policies that decided it came from.
    pub fn provenance(&self) -> Provenance {
        self.provenance
    }
}

/// Compiled policies, ready to answer: immutable, shared across threads, and nothing else.
pub struct Evaluator {
    partitions: Vec<Partition>,
}

impl Evaluator {
    /// A builder with no engine and no policy.
    pub fn builder() -> Builder {
        Builder::default()
    }

    /// The languages it decides with, in the order their answers are combined.
    pub fn languages(&self) -> Vec<&str> {
        self.partitions
            .iter()
            .map(|partition| partition.language.as_str())
            .collect()
    }

    /// The policies it was compiled from, by identity.
    pub fn policies(&self) -> Vec<String> {
        self.partitions
            .iter()
            .flat_map(|partition| partition.compiled.policies())
            .collect()
    }

    /// Where its policies came from: [`Provenance::Validated`], always.
    pub fn provenance(&self) -> Provenance {
        Provenance::Validated
    }

    /// Answers one question. Every language's policies answer it, and the answers are combined as
    /// every Permguard decision point combines them: any deny is a deny, else any failure is
    /// indeterminate, else any permit is a permit, else it is denied by default.
    ///
    /// It reads the compiled policies and the request, and nothing else: no file, no socket, no
    /// clock, no log. Asked twice, it answers the same.
    pub fn evaluate(&self, request: &Request) -> Result<Decision, Refused> {
        // The input against each compiled schema, before any policy is consulted: a request that
        // is malformed is refused, never denied.
        for partition in &self.partitions {
            partition
                .compiled
                .check_input(&request.input)
                .map_err(Refused::Input)?;
        }
        let work = self
            .partitions
            .iter()
            .map(|partition| {
                (
                    Arc::clone(&partition.compiled),
                    Query {
                        subject: request.principal.clone(),
                        resource: request.resource.clone(),
                        action: request.action.clone(),
                        context: request.context.clone(),
                        deadline: None,
                        input: request.input.clone(),
                    },
                )
            })
            .collect();
        let verdicts = crate::evaluate::evaluate_all(work)
            .into_iter()
            .map(|answered| answered.verdict);
        Ok(Decision {
            outcome: resolve(verdicts),
            provenance: Provenance::Validated,
        })
    }
}
