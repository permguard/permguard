// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The service objectives a deployment declares rather than assumes (TS-5,
//! `8-architecture-storage-operations.md` service objectives): the top-level `objectives` section.
//!
//! | Key                                   | Value    | Bounds            | Cross-validated against, from `production`                            |
//! | ------------------------------------- | -------- | ----------------- | --------------------------------------------------------------------- |
//! | `objectives.data_loss`                | duration | 0s to 1d          | —                                                                     |
//! | `objectives.recovery_time`            | duration | 1s to 30d         | —                                                                     |
//! | `objectives.max_volume_size`          | size     | 1M to 1P          | `storage.quotas.host.bytes`, declared and at most this                |
//! | `objectives.membership_offline_grace` | duration | 1s to 365d        | — (declared and published; the coordinator's lease policy grants it) |
//! | `objectives.mirror_staleness`         | duration | 1s to 365d        | `dataPlane.mirrors.stale_after`, declared and within the margin       |
//! | `objectives.evidence_shipping_lag`    | duration | 1s to 365d        | the decision spool's `age`, within the margin                         |
//! | `objectives.spool_headroom`           | percent  | 1% to 90%         | —                                                                     |
//! | `objectives.checkpoint_export_lag`    | duration | 1s to 365d        | `operations.audit.checkpoints.max_lag`, within the margin             |
//! | `objectives.backup_interval`          | duration | 1m to 365d        | `operations.backup.retention`, longer than it                         |
//! | `objectives.restore_test_interval`    | duration | 1h to 365d        | `operations.backup.retention`, at most it                             |
//! | `objectives.key_recovery_owner`       | label    | 1 to 128 bytes    | —                                                                     |
//!
//! Every value is bounded whatever the profile; from `production` every one is required, and an
//! inconsistent one stops Bootstrap. The margin is a fifth of the objective: a subsystem bound that
//! alarms, or a readiness monitor that holds, does so by four fifths of the objective, so readiness
//! falls before the objective is violated, never after.

use std::time::Duration;

use anyhow::{Context as _, Result, bail};
use serde::Serialize;

/// The fraction of an objective a bound or a monitor may reach before it acts.
pub const MARGIN_NUMERATOR: u32 = 4;
pub const MARGIN_DENOMINATOR: u32 = 5;

/// `objective` less its margin: where a bound must sit, and where a monitor holds readiness.
pub fn within_margin(objective: Duration) -> Duration {
    objective * MARGIN_NUMERATOR / MARGIN_DENOMINATOR
}

/// The objectives as declared, each `None` when left out.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Objectives {
    pub data_loss: Option<Duration>,
    pub recovery_time: Option<Duration>,
    pub max_volume_size: Option<u64>,
    pub membership_offline_grace: Option<Duration>,
    pub mirror_staleness: Option<Duration>,
    pub evidence_shipping_lag: Option<Duration>,
    /// The share of the decision spool kept free, in percent.
    pub spool_headroom: Option<u8>,
    pub checkpoint_export_lag: Option<Duration>,
    pub backup_interval: Option<Duration>,
    pub restore_test_interval: Option<Duration>,
    pub key_recovery_owner: Option<String>,
}

/// The `objectives` section, as the file writes it: every value text, read by the server's rules.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObjectivesSection {
    #[serde(default)]
    pub data_loss: Option<String>,
    #[serde(default)]
    pub recovery_time: Option<String>,
    #[serde(default)]
    pub max_volume_size: Option<String>,
    #[serde(default)]
    pub membership_offline_grace: Option<String>,
    #[serde(default)]
    pub mirror_staleness: Option<String>,
    #[serde(default)]
    pub evidence_shipping_lag: Option<String>,
    #[serde(default)]
    pub spool_headroom: Option<String>,
    #[serde(default)]
    pub checkpoint_export_lag: Option<String>,
    #[serde(default)]
    pub backup_interval: Option<String>,
    #[serde(default)]
    pub restore_test_interval: Option<String>,
    #[serde(default)]
    pub key_recovery_owner: Option<String>,
}

const DAY: u64 = 86_400;

fn bounded(
    key: &str,
    value: &Option<String>,
    low: Duration,
    high: Duration,
) -> Result<Option<Duration>> {
    let Some(value) = value else {
        return Ok(None);
    };
    let read = if value.trim() == "0" || value.trim() == "0s" {
        Duration::ZERO
    } else {
        crate::config::parse_duration(value).with_context(|| format!("reading objectives.{key}"))?
    };
    if read < low || read > high {
        bail!(
            "objectives.{key}: `{value}` is outside {}s to {}s",
            low.as_secs(),
            high.as_secs()
        );
    }
    Ok(Some(read))
}

impl ObjectivesSection {
    /// The objectives, every value read and bounded.
    pub fn read(&self) -> Result<Objectives> {
        let seconds = Duration::from_secs;
        let max_volume_size = match &self.max_volume_size {
            None => None,
            Some(value) => {
                let bytes = crate::config::parse_bytes(value)
                    .context("reading objectives.max_volume_size")?;
                if !(1 << 20..=1 << 50).contains(&bytes) {
                    bail!("objectives.max_volume_size: `{value}` is outside 1M to 1P");
                }
                Some(bytes)
            }
        };
        let spool_headroom = match &self.spool_headroom {
            None => None,
            Some(value) => {
                let percent = value
                    .trim()
                    .trim_end_matches('%')
                    .trim()
                    .parse::<u8>()
                    .ok()
                    .filter(|percent| (1..=90).contains(percent));
                Some(percent.ok_or_else(|| {
                    anyhow::anyhow!(
                        "objectives.spool_headroom: `{value}` is not a percentage from 1% to 90%"
                    )
                })?)
            }
        };
        let key_recovery_owner = match &self.key_recovery_owner {
            None => None,
            Some(value) => {
                let value = value.trim();
                if value.is_empty() || value.len() > 128 || value.chars().any(char::is_control) {
                    bail!("objectives.key_recovery_owner is a label of 1 to 128 printable bytes");
                }
                Some(value.to_owned())
            }
        };
        Ok(Objectives {
            data_loss: bounded("data_loss", &self.data_loss, Duration::ZERO, seconds(DAY))?,
            recovery_time: bounded(
                "recovery_time",
                &self.recovery_time,
                seconds(1),
                seconds(30 * DAY),
            )?,
            max_volume_size,
            membership_offline_grace: bounded(
                "membership_offline_grace",
                &self.membership_offline_grace,
                seconds(1),
                seconds(365 * DAY),
            )?,
            mirror_staleness: bounded(
                "mirror_staleness",
                &self.mirror_staleness,
                seconds(1),
                seconds(365 * DAY),
            )?,
            evidence_shipping_lag: bounded(
                "evidence_shipping_lag",
                &self.evidence_shipping_lag,
                seconds(1),
                seconds(365 * DAY),
            )?,
            spool_headroom,
            checkpoint_export_lag: bounded(
                "checkpoint_export_lag",
                &self.checkpoint_export_lag,
                seconds(1),
                seconds(365 * DAY),
            )?,
            backup_interval: bounded(
                "backup_interval",
                &self.backup_interval,
                seconds(60),
                seconds(365 * DAY),
            )?,
            restore_test_interval: bounded(
                "restore_test_interval",
                &self.restore_test_interval,
                seconds(3_600),
                seconds(365 * DAY),
            )?,
            key_recovery_owner,
        })
    }
}

/// What the objectives are cross-validated against: the subsystem bounds in force. A bound of a
/// subsystem this process does not run is `None` in the outer option.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Limits {
    /// `Some` when this process mirrors: its `stale_after`, itself optional.
    pub mirrors_stale_after: Option<Option<Duration>>,
    /// `Some` when this process spools decisions: the spool's `age`.
    pub decision_spool_age: Option<Duration>,
    pub audit_checkpoints_max_lag: Duration,
    pub backup_retention: Option<Duration>,
    pub host_quota_bytes: Option<u64>,
}

impl Objectives {
    /// The keys left out, in the table's order.
    pub fn missing(&self) -> Vec<&'static str> {
        [
            ("data_loss", self.data_loss.is_none()),
            ("recovery_time", self.recovery_time.is_none()),
            ("max_volume_size", self.max_volume_size.is_none()),
            (
                "membership_offline_grace",
                self.membership_offline_grace.is_none(),
            ),
            ("mirror_staleness", self.mirror_staleness.is_none()),
            (
                "evidence_shipping_lag",
                self.evidence_shipping_lag.is_none(),
            ),
            ("spool_headroom", self.spool_headroom.is_none()),
            (
                "checkpoint_export_lag",
                self.checkpoint_export_lag.is_none(),
            ),
            ("backup_interval", self.backup_interval.is_none()),
            (
                "restore_test_interval",
                self.restore_test_interval.is_none(),
            ),
            ("key_recovery_owner", self.key_recovery_owner.is_none()),
        ]
        .into_iter()
        .filter_map(|(key, missing)| missing.then_some(key))
        .collect()
    }

    /// Every declared objective a subsystem bound contradicts, as a sentence naming both.
    pub fn inconsistencies(&self, limits: &Limits) -> Vec<String> {
        let mut found = Vec::new();
        let secs = |duration: Duration| duration.as_secs();
        if let (Some(objective), Some(stale_after)) =
            (self.mirror_staleness, limits.mirrors_stale_after)
        {
            match stale_after {
                None => found.push(
                    "objectives.mirror_staleness needs dataPlane.mirrors.stale_after declared: \
                     nothing alarms on a stale mirror otherwise"
                        .to_owned(),
                ),
                Some(bound) if bound > within_margin(objective) => found.push(format!(
                    "dataPlane.mirrors.stale_after ({}s) alarms past the margin of \
                     objectives.mirror_staleness ({}s): at most {}s",
                    secs(bound),
                    secs(objective),
                    secs(within_margin(objective))
                )),
                Some(_) => {}
            }
        }
        if let (Some(objective), Some(age)) =
            (self.evidence_shipping_lag, limits.decision_spool_age)
            && age > within_margin(objective)
        {
            found.push(format!(
                "the decision spool's age ({}s) passes the margin of \
                 objectives.evidence_shipping_lag ({}s): at most {}s",
                secs(age),
                secs(objective),
                secs(within_margin(objective))
            ));
        }
        if let Some(objective) = self.checkpoint_export_lag
            && limits.audit_checkpoints_max_lag > within_margin(objective)
        {
            found.push(format!(
                "operations.audit.checkpoints.max_lag ({}s) passes the margin of \
                 objectives.checkpoint_export_lag ({}s): at most {}s",
                secs(limits.audit_checkpoints_max_lag),
                secs(objective),
                secs(within_margin(objective))
            ));
        }
        if let (Some(interval), Some(retention)) = (self.backup_interval, limits.backup_retention)
            && interval >= retention
        {
            found.push(format!(
                "objectives.backup_interval ({}s) is not shorter than \
                 operations.backup.retention ({}s): a backup would be destroyed before the next",
                secs(interval),
                secs(retention)
            ));
        }
        if let (Some(interval), Some(retention)) =
            (self.restore_test_interval, limits.backup_retention)
            && interval > retention
        {
            found.push(format!(
                "objectives.restore_test_interval ({}s) is longer than \
                 operations.backup.retention ({}s): a drill could find no backup kept to test",
                secs(interval),
                secs(retention)
            ));
        }
        if let Some(size) = self.max_volume_size {
            match limits.host_quota_bytes {
                None => found.push(
                    "objectives.max_volume_size needs storage.quotas.host.bytes declared: nothing \
                     keeps the volume within the size its recovery time was sized for otherwise"
                        .to_owned(),
                ),
                Some(quota) if quota > size => found.push(format!(
                    "storage.quotas.host.bytes ({quota}) is above objectives.max_volume_size \
                     ({size})"
                )),
                Some(_) => {}
            }
        }
        found
    }

    /// What discovery and health publish: every declared value, in seconds, bytes or percent,
    /// and the validation state; the owner is a label, never a secret.
    pub fn report(&self, validation: &'static str) -> ObjectivesReport {
        let secs = |value: Option<Duration>| value.map(|duration| duration.as_secs());
        ObjectivesReport {
            validation: validation.to_owned(),
            data_loss_seconds: secs(self.data_loss),
            recovery_time_seconds: secs(self.recovery_time),
            max_volume_bytes: self.max_volume_size,
            membership_offline_grace_seconds: secs(self.membership_offline_grace),
            mirror_staleness_seconds: secs(self.mirror_staleness),
            evidence_shipping_lag_seconds: secs(self.evidence_shipping_lag),
            spool_headroom_percent: self.spool_headroom,
            checkpoint_export_lag_seconds: secs(self.checkpoint_export_lag),
            backup_interval_seconds: secs(self.backup_interval),
            restore_test_interval_seconds: secs(self.restore_test_interval),
            key_recovery_owner: self.key_recovery_owner.clone(),
        }
    }
}

/// The objectives as discovery and health publish them (TS-5).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, serde::Deserialize)]
pub struct ObjectivesReport {
    /// `validated`, every objective declared and consistent; `incomplete`, accepted below
    /// `production` with some left out.
    pub validation: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data_loss_seconds: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recovery_time_seconds: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_volume_bytes: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub membership_offline_grace_seconds: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mirror_staleness_seconds: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub evidence_shipping_lag_seconds: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub spool_headroom_percent: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub checkpoint_export_lag_seconds: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub backup_interval_seconds: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub restore_test_interval_seconds: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_recovery_owner: Option<String>,
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;

    fn complete() -> ObjectivesSection {
        let text = |value: &str| Some(value.to_owned());
        ObjectivesSection {
            data_loss: text("0s"),
            recovery_time: text("1h"),
            max_volume_size: text("100G"),
            membership_offline_grace: text("24h"),
            mirror_staleness: text("5m"),
            evidence_shipping_lag: text("15m"),
            spool_headroom: text("20%"),
            checkpoint_export_lag: text("1h"),
            backup_interval: text("24h"),
            restore_test_interval: text("30d"),
            key_recovery_owner: text("security-team"),
        }
    }

    fn limits() -> Limits {
        Limits {
            mirrors_stale_after: Some(Some(Duration::from_secs(240))),
            decision_spool_age: Some(Duration::from_secs(600)),
            audit_checkpoints_max_lag: Duration::from_secs(1800),
            backup_retention: Some(Duration::from_secs(90 * DAY)),
            host_quota_bytes: Some(80 << 30),
        }
    }

    #[test]
    fn complete_objectives_read_and_agree_with_their_subsystems() {
        let objectives = complete().read().expect("reads");
        assert!(objectives.missing().is_empty());
        assert_eq!(objectives.inconsistencies(&limits()), Vec::<String>::new());
        assert_eq!(objectives.spool_headroom, Some(20));
        assert_eq!(objectives.max_volume_size, Some(100 << 30));
        let report = objectives.report("validated");
        assert_eq!(report.mirror_staleness_seconds, Some(300));
        assert_eq!(report.key_recovery_owner.as_deref(), Some("security-team"));
    }

    #[test]
    fn every_value_is_bounded() {
        for (set, value) in [
            ("data_loss", "2d"),
            ("recovery_time", "0s"),
            ("max_volume_size", "1k"),
            ("spool_headroom", "95%"),
            ("spool_headroom", "lots"),
            ("backup_interval", "10s"),
            ("restore_test_interval", "400d"),
            ("key_recovery_owner", ""),
        ] {
            let mut section = complete();
            let slot = match set {
                "data_loss" => &mut section.data_loss,
                "recovery_time" => &mut section.recovery_time,
                "max_volume_size" => &mut section.max_volume_size,
                "spool_headroom" => &mut section.spool_headroom,
                "backup_interval" => &mut section.backup_interval,
                "restore_test_interval" => &mut section.restore_test_interval,
                _ => &mut section.key_recovery_owner,
            };
            *slot = Some(value.to_owned());
            let refused = section.read().expect_err("out of bounds").to_string();
            assert!(refused.contains(set), "{set}={value}: {refused}");
        }
    }

    #[test]
    fn missing_objectives_are_named_in_order() {
        let section = ObjectivesSection {
            mirror_staleness: Some("5m".to_owned()),
            ..complete()
        };
        let partial = ObjectivesSection {
            data_loss: None,
            key_recovery_owner: None,
            ..section
        };
        assert_eq!(
            partial.read().expect("reads").missing(),
            ["data_loss", "key_recovery_owner"]
        );
        assert_eq!(
            ObjectivesSection::default()
                .read()
                .expect("reads")
                .missing()
                .len(),
            11
        );
    }

    /// Each contradiction with a subsystem bound is found and named; a subsystem this process
    /// does not run is not judged.
    #[test]
    fn a_subsystem_bound_past_the_margin_is_an_inconsistency() {
        let objectives = complete().read().expect("reads");
        let cases: [(Limits, &str); 7] = [
            (
                Limits {
                    mirrors_stale_after: Some(None),
                    ..limits()
                },
                "stale_after declared",
            ),
            (
                Limits {
                    mirrors_stale_after: Some(Some(Duration::from_secs(241))),
                    ..limits()
                },
                "dataPlane.mirrors.stale_after (241s)",
            ),
            (
                Limits {
                    decision_spool_age: Some(Duration::from_secs(721)),
                    ..limits()
                },
                "decision spool's age (721s)",
            ),
            (
                Limits {
                    audit_checkpoints_max_lag: Duration::from_secs(2881),
                    ..limits()
                },
                "max_lag (2881s)",
            ),
            (
                Limits {
                    backup_retention: Some(Duration::from_secs(DAY)),
                    ..limits()
                },
                "backup_interval",
            ),
            (
                Limits {
                    host_quota_bytes: None,
                    ..limits()
                },
                "quotas.host.bytes declared",
            ),
            (
                Limits {
                    host_quota_bytes: Some(200 << 30),
                    ..limits()
                },
                "is above",
            ),
        ];
        for (limits, said) in cases {
            let found = objectives.inconsistencies(&limits);
            // A day of retention is not longer than the backup interval, nor than the
            // restore-test interval: two findings, the first the backup interval's.
            let expected = if said == "backup_interval" { 2 } else { 1 };
            assert_eq!(found.len(), expected, "{said}: {found:?}");
            assert!(found[0].contains(said), "{said}: {found:?}");
        }
        let short_retention = Limits {
            backup_retention: Some(Duration::from_secs(10 * DAY)),
            ..limits()
        };
        assert!(
            objectives
                .inconsistencies(&short_retention)
                .iter()
                .any(|found| found.contains("restore_test_interval")),
        );
        let alone = Limits {
            mirrors_stale_after: None,
            decision_spool_age: None,
            ..limits()
        };
        assert!(objectives.inconsistencies(&alone).is_empty(), "not judged");
        assert_eq!(
            within_margin(Duration::from_secs(300)),
            Duration::from_secs(240)
        );
    }
}
