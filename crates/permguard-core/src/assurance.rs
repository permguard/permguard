// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The assurance profiles: `development` ⊂ `production` ⊂ `regulated`.
//!
//! A deployment states one word and every control of that profile is in force; a control names the
//! lowest profile that requires it, and a check asks whether the running profile is at least that
//! one. The order is the type's: `Development < Production < Regulated`.
//!
//! The profile is stated by `assurance.profile` (default `production`, owner decision of
//! 2026-10-06) and checked at Bootstrap by `Config::validate` (WP-2.8). [`Control`] is the typed
//! registry of every control of the profile table, each with the lowest profile that requires it
//! and where it is enforced; [`Relaxation`] names every relaxation a profile may permit;
//! [`Assurance`] is the profile in force with the higher controls a deployment switched on.

use std::collections::BTreeSet;
use std::fmt;
use std::str::FromStr;

use serde::Serialize;

use crate::domains::assurance as names;

/// One of the three assurance profiles, ordered from the least to the most demanding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum AssuranceProfile {
    /// Somebody's laptop or a test environment: the controls that cost nothing still hold.
    Development,
    /// The floor for any Host that serves real decisions.
    Production,
    /// What a regulated industry or a security audit requires on top of `production`.
    Regulated,
}

impl AssuranceProfile {
    /// The word a deployment writes for this profile.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Development => "development",
            Self::Production => "production",
            Self::Regulated => "regulated",
        }
    }

    /// Whether this profile includes every control of `floor`.
    pub fn at_least(self, floor: Self) -> bool {
        self >= floor
    }
}

impl fmt::Display for AssuranceProfile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for AssuranceProfile {
    type Err = String;

    /// Reads one of the three words, and nothing else: the retired spellings (`strict`,
    /// `high-assurance`, `security-critical`) are refused rather than mapped.
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.trim() {
            "development" => Ok(Self::Development),
            "production" => Ok(Self::Production),
            "regulated" => Ok(Self::Regulated),
            other => Err(format!(
                "`{other}` is not an assurance profile: expected development, production or \
                 regulated"
            )),
        }
    }
}

/// How a profile is enforced: by this Host, never attested by it (`enforcement: local`).
pub const ENFORCEMENT_LOCAL: &str = "local";

/// One control of the profile table (`7-architecture-security.md#assurance-profiles`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Control {
    EvidenceRequired,
    SchemaPartition,
    SchemaWarningsAsErrors,
    SchemaRegoInput,
    InterfacesExplicit,
    EngineBounded,
    RuntimeExperimentalGated,
    RuntimeExperimentalForbidden,
    ProviderSupervised,
    GrpcLosslessSubset,
    GrpcStrictDecoder,
    CustodyEncrypted,
    CustodyHsm,
    AuditExternalCheckpoints,
    IdentityWitness,
    OperationsDualControl,
    Tls13Only,
}

impl Control {
    /// Every control, in the order of the profile table.
    pub const ALL: [Self; 17] = [
        Self::EvidenceRequired,
        Self::SchemaPartition,
        Self::SchemaWarningsAsErrors,
        Self::SchemaRegoInput,
        Self::InterfacesExplicit,
        Self::EngineBounded,
        Self::RuntimeExperimentalGated,
        Self::RuntimeExperimentalForbidden,
        Self::ProviderSupervised,
        Self::GrpcLosslessSubset,
        Self::GrpcStrictDecoder,
        Self::CustodyEncrypted,
        Self::CustodyHsm,
        Self::AuditExternalCheckpoints,
        Self::IdentityWitness,
        Self::OperationsDualControl,
        Self::Tls13Only,
    ];

    /// The stable name discovery publishes.
    pub fn name(self) -> &'static str {
        match self {
            Self::EvidenceRequired => names::EVIDENCE_REQUIRED,
            Self::SchemaPartition => names::SCHEMA_PARTITION,
            Self::SchemaWarningsAsErrors => names::SCHEMA_WARNINGS_AS_ERRORS,
            Self::SchemaRegoInput => names::SCHEMA_REGO_INPUT,
            Self::InterfacesExplicit => names::INTERFACES_EXPLICIT,
            Self::EngineBounded => names::ENGINE_BOUNDED,
            Self::RuntimeExperimentalGated => names::RUNTIME_EXPERIMENTAL_GATED,
            Self::RuntimeExperimentalForbidden => names::RUNTIME_EXPERIMENTAL_FORBIDDEN,
            Self::ProviderSupervised => names::PROVIDER_SUPERVISED,
            Self::GrpcLosslessSubset => names::GRPC_LOSSLESS_SUBSET,
            Self::GrpcStrictDecoder => names::GRPC_STRICT_DECODER,
            Self::CustodyEncrypted => names::CUSTODY_ENCRYPTED,
            Self::CustodyHsm => names::CUSTODY_HSM,
            Self::AuditExternalCheckpoints => names::AUDIT_EXTERNAL_CHECKPOINTS,
            Self::IdentityWitness => names::IDENTITY_WITNESS,
            Self::OperationsDualControl => names::OPERATIONS_DUAL_CONTROL,
            Self::Tls13Only => names::TLS_1_3_ONLY,
        }
    }

    /// The lowest profile that requires the control.
    pub fn floor(self) -> AssuranceProfile {
        match self {
            Self::SchemaWarningsAsErrors
            | Self::SchemaRegoInput
            | Self::RuntimeExperimentalForbidden
            | Self::GrpcStrictDecoder
            | Self::CustodyHsm
            | Self::OperationsDualControl
            | Self::Tls13Only => AssuranceProfile::Regulated,
            _ => AssuranceProfile::Production,
        }
    }

    /// Whether this build enforces the control when a deployment adds it above its profile: the
    /// controls checked at Bootstrap do. The others are enforced at their own floor only, by
    /// points that take the profile; adding one is refused rather than published unenforced
    /// (nothing is listed as in force that is not).
    pub fn enforceable_when_added(self) -> bool {
        matches!(
            self,
            Self::Tls13Only
                | Self::RuntimeExperimentalForbidden
                | Self::CustodyEncrypted
                | Self::IdentityWitness
        )
    }

    /// Where the control is enforced, and by which package when that package is still to come.
    pub fn enforced_at(self) -> &'static str {
        match self {
            Self::EvidenceRequired => {
                "the Data Plane decision log; the evidence modes arrive with the evidence packages"
            }
            Self::SchemaPartition | Self::SchemaWarningsAsErrors | Self::SchemaRegoInput => {
                "the ledger load gate (`permguard_languages::registry::check_schema_floor`)"
            }
            Self::InterfacesExplicit => "the ledger load gate (manifest `interfaces`)",
            Self::EngineBounded | Self::ProviderSupervised => {
                "the evaluator choice (`permguard_languages::registry::isolation_required`)"
            }
            Self::RuntimeExperimentalGated | Self::RuntimeExperimentalForbidden => {
                "Bootstrap (`Config::validate`) and the language gate"
            }
            Self::GrpcLosslessSubset | Self::GrpcStrictDecoder => {
                "the evaluation interfaces' gRPC decoders (interface packages)"
            }
            Self::CustodyEncrypted | Self::CustodyHsm => {
                "Bootstrap (`Config::validate`); the custody providers arrive with WP-3.2"
            }
            Self::AuditExternalCheckpoints => "the audit trail (WP-3.5)",
            Self::IdentityWitness => "the Host identity (WP-2.2)",
            Self::OperationsDualControl => "the plan receipts of the Host API (WP-3.9)",
            Self::Tls13Only => "Bootstrap (`Config::validate`) over every listener's TLS settings",
        }
    }
}

impl fmt::Display for Control {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

impl FromStr for Control {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let value = value.trim();
        Self::ALL
            .into_iter()
            .find(|control| control.name() == value)
            .ok_or_else(|| {
                format!(
                    "`{value}` is not an assurance control; the controls are {}",
                    Self::ALL.map(Self::name).join(", ")
                )
            })
    }
}

/// The evidence a coordinator accepts for one control of a member (WP-4.2): an ordered threshold,
/// the appraisal policy naming the least sufficient class (owner decision of 2026-10-10).
///
/// A declaration proves only which Host made the claim; an operator approval is an accountable
/// risk decision; an attestation is a configured verifier's fresh result.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum EvidenceClass {
    Declared,
    OperatorApproved,
    Attested,
}

impl EvidenceClass {
    /// Every class, weakest first.
    pub const ALL: [Self; 3] = [Self::Declared, Self::OperatorApproved, Self::Attested];

    /// The stable name an appraisal policy and a binding carry.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Declared => "declared",
            Self::OperatorApproved => "operator-approved",
            Self::Attested => "attested",
        }
    }
}

impl fmt::Display for EvidenceClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for EvidenceClass {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let value = value.trim();
        Self::ALL
            .into_iter()
            .find(|class| class.as_str() == value)
            .ok_or_else(|| {
                format!(
                    "`{value}` is not an evidence class; the classes are {}",
                    Self::ALL.map(Self::as_str).join(", ")
                )
            })
    }
}

/// One relaxation a profile may permit: always a named value, published when in force.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Relaxation {
    EvidenceBestEffort,
    SchemaRegoInputAbsent,
    GrpcTransportParityPartial,
    Tls12Compat,
    CustodyPlaintext,
}

impl Relaxation {
    /// Every relaxation.
    pub const ALL: [Self; 5] = [
        Self::EvidenceBestEffort,
        Self::SchemaRegoInputAbsent,
        Self::GrpcTransportParityPartial,
        Self::Tls12Compat,
        Self::CustodyPlaintext,
    ];

    /// The stable name discovery publishes.
    pub fn name(self) -> &'static str {
        match self {
            Self::EvidenceBestEffort => names::RELAX_EVIDENCE_BEST_EFFORT,
            Self::SchemaRegoInputAbsent => names::RELAX_SCHEMA_REGO_INPUT_ABSENT,
            Self::GrpcTransportParityPartial => names::RELAX_GRPC_TRANSPORT_PARITY_PARTIAL,
            Self::Tls12Compat => names::RELAX_TLS_1_2_COMPAT,
            Self::CustodyPlaintext => names::RELAX_CUSTODY_PLAINTEXT,
        }
    }

    /// The control whose being in force forbids this relaxation.
    pub fn forbidden_by(self) -> Control {
        match self {
            Self::EvidenceBestEffort => Control::EvidenceRequired,
            Self::SchemaRegoInputAbsent => Control::SchemaRegoInput,
            Self::GrpcTransportParityPartial => Control::GrpcStrictDecoder,
            Self::Tls12Compat => Control::Tls13Only,
            Self::CustodyPlaintext => Control::CustodyEncrypted,
        }
    }

    /// Whether the relaxation is permitted *despite* its forbidding control being in force at the
    /// profile's own floor: `production` keeps `evidence.required` by default and still permits
    /// `best-effort` per ledger with a recorded risk acceptance.
    fn excepted_at(self, profile: AssuranceProfile) -> bool {
        matches!(
            (self, profile),
            (Self::EvidenceBestEffort, AssuranceProfile::Production)
        )
    }
}

impl fmt::Display for Relaxation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// The profile in force and the higher controls a deployment switched on (the ratchet: a
/// control can be added, never removed).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Assurance {
    profile: AssuranceProfile,
    added: BTreeSet<Control>,
}

impl Assurance {
    /// `profile`, plus `added` controls of a higher profile; a control the profile already
    /// requires is in force anyway and is not listed as added.
    pub fn new(profile: AssuranceProfile, added: impl IntoIterator<Item = Control>) -> Self {
        Self {
            profile,
            added: added
                .into_iter()
                .filter(|control| !profile.at_least(control.floor()))
                .collect(),
        }
    }

    /// The profile in force.
    pub fn profile(&self) -> AssuranceProfile {
        self.profile
    }

    /// Whether `control` is in force: required by the profile or added.
    pub fn requires(&self, control: Control) -> bool {
        self.profile.at_least(control.floor()) || self.added.contains(&control)
    }

    /// Whether `relaxation` is permitted.
    pub fn permits(&self, relaxation: Relaxation) -> bool {
        let forbidding = relaxation.forbidden_by();
        if !self.requires(forbidding) {
            return true;
        }
        // An exception holds only at the profile's floor, never when the control was added.
        !self.added.contains(&forbidding) && relaxation.excepted_at(self.profile)
    }

    /// Refuses the first relaxation in force the profile does not permit.
    pub fn check(&self, in_force: &[Relaxation]) -> Result<(), String> {
        match in_force
            .iter()
            .find(|relaxation| !self.permits(**relaxation))
        {
            None => Ok(()),
            Some(refused) => Err(format!(
                "the configuration relaxes `{refused}`, which the `{}` assurance profile does not \
                 permit: `{}` is in force (enforced at {}); a developer's machine states \
                 `assurance.profile: development`, the profile is `production` when none is stated",
                self.profile,
                refused.forbidden_by(),
                refused.forbidden_by().enforced_at()
            )),
        }
    }

    /// What discovery and `host status` publish.
    pub fn report(&self, in_force: &[Relaxation]) -> AssuranceReport {
        let mut relaxations: Vec<&'static str> = in_force.iter().map(|r| r.name()).collect();
        relaxations.sort_unstable();
        relaxations.dedup();
        AssuranceReport {
            profile: self.profile.as_str(),
            enforcement: ENFORCEMENT_LOCAL,
            added_controls: self.added.iter().map(|control| control.name()).collect(),
            relaxations,
        }
    }
}

/// The published assurance block: `{profile, enforcement: local, added_controls[], relaxations[]}`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AssuranceReport {
    pub profile: &'static str,
    pub enforcement: &'static str,
    pub added_controls: Vec<&'static str>,
    pub relaxations: Vec<&'static str>,
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;

    #[test]
    fn test_the_profiles_are_ordered_and_read_back_by_their_words() {
        assert!(AssuranceProfile::Development < AssuranceProfile::Production);
        assert!(AssuranceProfile::Production < AssuranceProfile::Regulated);
        assert!(AssuranceProfile::Regulated.at_least(AssuranceProfile::Production));
        assert!(!AssuranceProfile::Development.at_least(AssuranceProfile::Production));
        for profile in [
            AssuranceProfile::Development,
            AssuranceProfile::Production,
            AssuranceProfile::Regulated,
        ] {
            assert_eq!(profile.to_string().parse::<AssuranceProfile>(), Ok(profile));
        }
        for refused in ["strict", "high-assurance", "Production", ""] {
            assert!(refused.parse::<AssuranceProfile>().is_err(), "{refused:?}");
        }
    }

    #[test]
    fn every_control_has_a_name_a_floor_and_an_enforcement_point_and_reads_back() {
        for control in Control::ALL {
            assert_eq!(control.name().parse::<Control>(), Ok(control));
            assert!(!control.enforced_at().is_empty());
            assert!(control.floor().at_least(AssuranceProfile::Production));
        }
        assert!("tls.1_2".parse::<Control>().is_err());
    }

    /// Each row of the profile table: the control is in force at its floor and above, and not
    /// below it.
    #[test]
    fn each_control_is_in_force_from_its_floor_upward_and_never_below() {
        for control in Control::ALL {
            for profile in [
                AssuranceProfile::Development,
                AssuranceProfile::Production,
                AssuranceProfile::Regulated,
            ] {
                assert_eq!(
                    Assurance::new(profile, []).requires(control),
                    profile.at_least(control.floor()),
                    "{control} under {profile}"
                );
            }
        }
    }

    #[test]
    fn a_higher_control_can_be_added_and_an_own_one_is_not_listed_as_added() {
        let assurance = Assurance::new(
            AssuranceProfile::Production,
            [Control::Tls13Only, Control::SchemaPartition],
        );
        assert!(assurance.requires(Control::Tls13Only));
        assert!(!assurance.requires(Control::CustodyHsm));
        assert_eq!(
            assurance.report(&[]).added_controls,
            vec!["tls.1_3_only"],
            "schema.partition is the profile's own"
        );
    }

    #[test]
    fn each_relaxation_is_permitted_exactly_where_the_table_says() {
        use AssuranceProfile::{Development, Production, Regulated};
        let expected = [
            (Relaxation::EvidenceBestEffort, [true, true, false]),
            (Relaxation::SchemaRegoInputAbsent, [true, true, false]),
            (Relaxation::GrpcTransportParityPartial, [true, true, false]),
            (Relaxation::Tls12Compat, [true, true, false]),
            (Relaxation::CustodyPlaintext, [true, false, false]),
        ];
        for (relaxation, permitted) in expected {
            for (profile, permitted) in [Development, Production, Regulated]
                .into_iter()
                .zip(permitted)
            {
                assert_eq!(
                    Assurance::new(profile, []).permits(relaxation),
                    permitted,
                    "{relaxation} under {profile}"
                );
            }
        }
        // An added control takes its relaxation away.
        let ratcheted = Assurance::new(Production, [Control::Tls13Only]);
        assert!(!ratcheted.permits(Relaxation::Tls12Compat));
        assert!(ratcheted.check(&[Relaxation::Tls12Compat]).is_err());
        let refused = Assurance::new(Production, [])
            .check(&[Relaxation::CustodyPlaintext])
            .expect_err("plaintext custody under production");
        assert!(refused.contains("custody.plaintext"), "{refused}");
        assert!(refused.contains("custody.encrypted"), "{refused}");
    }

    #[test]
    fn the_report_is_the_published_block() {
        let report = Assurance::new(AssuranceProfile::Development, [Control::Tls13Only])
            .report(&[Relaxation::CustodyPlaintext, Relaxation::CustodyPlaintext]);
        assert_eq!(report.profile, "development");
        assert_eq!(report.enforcement, "local");
        assert_eq!(report.added_controls, vec!["tls.1_3_only"]);
        assert_eq!(report.relaxations, vec!["custody.plaintext"]);
    }
}
