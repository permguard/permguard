// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The answer of a decision's record, from an evaluator's: the explicit conversion between what
//! a decision point concluded and what the record says it concluded.
//!
//! An evaluator knows the answer and nothing a record needs beside it: not who asked, under
//! which name they are recorded, which policy state answered or how long it took. The record's
//! writer supplies those; this fixes the members both must agree about.
//!
//! | Record member | From the evaluator's answer                                         |
//! | ------------- | ------------------------------------------------------------------- |
//! | `decision`    | `true` for a permit, and for nothing else                           |
//! | `outcome`     | which of the four results it was                                    |
//! | `causes`      | the codes behind an indeterminate result, sorted and distinct       |
//! | `policies`    | what permitted it, or what refused it; nothing for the other two    |
//! | `reason.code` | `200`, `403`, or `evaluation_indeterminate`: never `403` a failure  |
//!
//! It is the mapping the Data Plane records a stateless decision with, so an application that
//! embeds the evaluator and keeps its own records writes what a Plane would have written.

use permguard_evaluator::{Decision, Outcome as Evaluated, Resolution};

use crate::record::{DecisionBody, Outcome, Reason};

/// The record's spelling of a resolution.
impl From<Resolution> for Outcome {
    fn from(resolution: Resolution) -> Self {
        match resolution {
            Resolution::Permit => Self::Permit,
            Resolution::Deny => Self::Deny,
            Resolution::DenyByDefault => Self::DenyByDefault,
            Resolution::Indeterminate => Self::Indeterminate,
        }
    }
}

/// The record's `reason.code` for a stateless decision: the codes the record has always carried
/// for a permit and a deny, and the native contract's for an indeterminate result, so a failure
/// never reads as a policy deny.
pub fn reason_code(resolution: Resolution) -> String {
    match resolution {
        Resolution::Permit => "200".to_owned(),
        Resolution::Deny | Resolution::DenyByDefault => "403".to_owned(),
        Resolution::Indeterminate => {
            permguard_core::codes::pdp_native::EVALUATION_INDETERMINATE.to_owned()
        }
    }
}

/// What a decision's record says the decision point concluded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Answer {
    /// The answer: `true` for a permit alone.
    pub decision: bool,
    /// Which of the four results it was.
    pub outcome: Outcome,
    /// The `evaluation_*` codes behind an indeterminate result, sorted and distinct; empty for
    /// the other three.
    pub causes: Vec<String>,
    /// The policies the decision cites.
    pub policies: Vec<String>,
    /// The class of the outcome.
    pub reason: Reason,
}

impl Answer {
    /// The answer `evaluated` is recorded as.
    pub fn of(evaluated: &Evaluated) -> Self {
        Self {
            decision: evaluated.permitted(),
            outcome: evaluated.resolution.into(),
            causes: evaluated.causes().into_iter().map(str::to_owned).collect(),
            policies: evaluated.determining().to_vec(),
            reason: Reason {
                code: reason_code(evaluated.resolution),
            },
        }
    }

    /// Writes the answer into `body`, replacing the five members it fixes and no other.
    pub fn write(self, body: &mut DecisionBody) {
        body.decision = self.decision;
        body.outcome = Some(self.outcome);
        body.causes = (!self.causes.is_empty()).then_some(self.causes);
        body.policies = self.policies;
        body.reason = self.reason;
    }
}

/// The answer an evaluator's decision is recorded as.
impl From<&Decision> for Answer {
    fn from(decision: &Decision) -> Self {
        Self::of(decision.outcome())
    }
}

#[cfg(test)]
mod tests {
    use permguard_evaluator::EvaluationError;

    use super::*;

    fn evaluated(resolution: Resolution) -> Evaluated {
        Evaluated {
            resolution,
            permits: vec!["allow-read".to_owned()],
            denials: vec!["forbid-export".to_owned()],
            errors: vec![
                EvaluationError {
                    code: permguard_core::codes::pdp_native::EVALUATION_INPUT_REJECTED,
                    message: "an engine's own sentence".to_owned(),
                },
                EvaluationError {
                    code: permguard_core::codes::pdp_native::EVALUATION_INPUT_REJECTED,
                    message: "again".to_owned(),
                },
            ],
        }
    }

    #[test]
    fn a_permit_cites_what_permitted_and_is_the_only_true() {
        let answer = Answer::of(&evaluated(Resolution::Permit));
        assert!(answer.decision);
        assert_eq!(answer.outcome, Outcome::Permit);
        assert_eq!(answer.policies, ["allow-read"]);
        assert!(answer.causes.is_empty());
        assert_eq!(answer.reason.code, "200");
    }

    #[test]
    fn a_deny_cites_what_refused() {
        let answer = Answer::of(&evaluated(Resolution::Deny));
        assert!(!answer.decision);
        assert_eq!(answer.outcome, Outcome::Deny);
        assert_eq!(answer.policies, ["forbid-export"]);
        assert!(answer.causes.is_empty());
        assert_eq!(answer.reason.code, "403");
    }

    #[test]
    fn a_default_deny_cites_nothing() {
        let answer = Answer::of(&evaluated(Resolution::DenyByDefault));
        assert!(!answer.decision);
        assert_eq!(answer.outcome, Outcome::DenyByDefault);
        assert!(answer.policies.is_empty());
        assert_eq!(answer.reason.code, "403");
    }

    #[test]
    fn a_failure_is_never_recorded_as_a_policy_deny() {
        let answer = Answer::of(&evaluated(Resolution::Indeterminate));
        assert!(!answer.decision);
        assert_eq!(answer.outcome, Outcome::Indeterminate);
        assert!(answer.policies.is_empty());
        // Codes only, once each: never the engine's text.
        assert_eq!(
            answer.causes,
            [permguard_core::codes::pdp_native::EVALUATION_INPUT_REJECTED]
        );
        assert_eq!(
            answer.reason.code,
            permguard_core::codes::pdp_native::EVALUATION_INDETERMINATE
        );
    }
}
