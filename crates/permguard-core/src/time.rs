// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! Turning a Unix timestamp into a date, and back.
//!
//! Two things in Permguard need a calendar: an audit trail, which wants a file name that groups
//! records by day and a timestamp inside each record a human can read, and any report that has to
//! say when it looked. Both are calendar arithmetic on UTC, which is a closed-form problem with a
//! published solution — Howard Hinnant's `civil_from_days`, exact for every date the type can hold
//! and with no table to get wrong.
//!
//! It lives here, with the contracts, because a timestamp is part of what those records and reports
//! *are*, and because two implementations of a calendar is one too many: the leap-century rule is
//! the classic bug, and it should be got right once. Nothing here allocates a dependency — it is
//! integer arithmetic — so it costs the contracts crate nothing.
//!
//! Everything here is UTC. An audit trail whose day boundary moves twice a year is an audit trail
//! with two hours that appear twice and one that never happened.

/// How many seconds there are in a day.
const DAY: i64 = 86_400;

/// The day number of the Unix epoch in the algorithm's shifted era.
const EPOCH_SHIFT: i64 = 719_468;

/// A date, with no time and no zone.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Date {
    /// The year.
    pub year: i64,
    /// The month, from 1.
    pub month: u32,
    /// The day, from 1.
    pub day: u32,
}

impl Date {
    /// Returns the date as `YYYY-MM-DD`.
    pub fn to_iso(self) -> String {
        format!("{:04}-{:02}-{:02}", self.year, self.month, self.day)
    }

    /// Reads a date written as `YYYY-MM-DD`, or nothing when it is not one.
    pub fn from_iso(text: &str) -> Option<Self> {
        let mut parts = text.split('-');
        let year = parts.next()?.parse().ok()?;
        let month = parts.next()?.parse().ok()?;
        let day = parts.next()?.parse().ok()?;

        if parts.next().is_some() || !(1..=12).contains(&month) || !(1..=31).contains(&day) {
            return None;
        }

        Some(Self { year, month, day })
    }
}

/// Returns which day a timestamp falls on, counting from the Unix epoch.
///
/// Floor division, so timestamps before the epoch land on the day they belong to rather than the one
/// after it.
pub fn day_of(seconds: i64) -> i64 {
    seconds.div_euclid(DAY)
}

/// Returns the date of a day number.
pub fn date_of(days: i64) -> Date {
    // Howard Hinnant, "chrono-Compatible Low-Level Date Algorithms". The era is a 400-year cycle,
    // which is the period after which the Gregorian calendar repeats exactly.
    let shifted = days + EPOCH_SHIFT;
    let era = if shifted >= 0 {
        shifted
    } else {
        shifted - 146_096
    } / 146_097;
    let day_of_era = shifted - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    // March-based months, which is what makes the leap day the last day of the year and the whole
    // thing branchless.
    let shifted_month = (5 * day_of_year + 2) / 153;
    let day = (day_of_year - (153 * shifted_month + 2) / 5 + 1) as u32;
    let month = if shifted_month < 10 {
        shifted_month + 3
    } else {
        shifted_month - 9
    } as u32;

    Date {
        year: if month <= 2 { year + 1 } else { year },
        month,
        day,
    }
}

/// Returns the day number of a date.
pub fn days_of(date: Date) -> i64 {
    let year = if date.month <= 2 {
        date.year - 1
    } else {
        date.year
    };
    let era = if year >= 0 { year } else { year - 399 } / 400;
    let year_of_era = year - era * 400;
    let shifted_month = if date.month > 2 {
        i64::from(date.month) - 3
    } else {
        i64::from(date.month) + 9
    };
    let day_of_year = (153 * shifted_month + 2) / 5 + i64::from(date.day) - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;

    era * 146_097 + day_of_era - EPOCH_SHIFT
}

/// Returns a timestamp as RFC 3339 in UTC, which is what a record carries.
pub fn to_rfc3339(seconds: i64) -> String {
    let date = date_of(day_of(seconds));
    let time = seconds.rem_euclid(DAY);

    format!(
        "{}T{:02}:{:02}:{:02}Z",
        date.to_iso(),
        time / 3600,
        (time % 3600) / 60,
        time % 60
    )
}

/// Reads a timestamp written as RFC 3339, to the second — or nothing when it is not one.
///
/// `2026-08-01T00:00:00Z`, a lowercase `t` or `z`, a fraction of a second (dropped) and a numeric
/// offset (`+02:00`, applied) are all accepted. A bare date, a bare number and a clock with no zone
/// are refused. It exists so a filter typed at a terminal can be checked before it is compared:
/// two timestamps compare correctly as text only when both are in this module's canonical form,
/// and an input that is not a timestamp at all has to be a refusal — not a filter that quietly
/// matches everything, or nothing.
pub fn from_rfc3339(text: &str) -> Option<i64> {
    let text = text.trim();
    let (date, rest) = text.split_at_checked(10)?;
    let date = Date::from_iso(date)?;
    // `from_iso` checks the ranges a month cannot exceed; the round trip checks the one it can.
    if date_of(days_of(date)) != date {
        return None;
    }
    let rest = rest.strip_prefix(['T', 't'])?;

    let (clock, rest) = rest.split_at_checked(8)?;
    let mut parts = clock.split(':');
    let hour: i64 = parts.next()?.parse().ok()?;
    let minute: i64 = parts.next()?.parse().ok()?;
    let second: i64 = parts.next()?.parse().ok()?;
    if parts.next().is_some() || hour > 23 || minute > 59 || second > 60 {
        return None;
    }

    // A fraction is allowed and dropped: records carry whole seconds.
    let rest = match rest.strip_prefix('.') {
        Some(fraction) => {
            let digits = fraction
                .find(|character: char| !character.is_ascii_digit())
                .unwrap_or(fraction.len());
            if digits == 0 {
                return None;
            }
            &fraction[digits..]
        }
        None => rest,
    };

    let offset = match rest {
        "Z" | "z" => 0,
        signed => {
            let sign = match signed.chars().next()? {
                '+' => 1,
                '-' => -1,
                _ => return None,
            };
            let (hours, minutes) = signed.get(1..)?.split_once(':')?;
            if hours.len() != 2 || minutes.len() != 2 {
                return None;
            }
            let hours: i64 = hours.parse().ok()?;
            let minutes: i64 = minutes.parse().ok()?;
            if hours > 23 || minutes > 59 {
                return None;
            }

            sign * (hours * 3600 + minutes * 60)
        }
    };

    Some(days_of(date) * DAY + hour * 3600 + minute * 60 + second - offset)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_the_epoch_is_the_day_it_is_named_after() {
        assert_eq!(date_of(0).to_iso(), "1970-01-01");
        assert_eq!(to_rfc3339(0), "1970-01-01T00:00:00Z");
    }

    #[test]
    fn test_the_dates_everybody_checks_a_calendar_against() {
        for (seconds, expected) in [
            // A leap day in a year divisible by four.
            (951_782_400, "2000-02-29T00:00:00Z"),
            // The last second of a year.
            (1_609_459_199, "2020-12-31T23:59:59Z"),
            // The first second of the next one.
            (1_609_459_200, "2021-01-01T00:00:00Z"),
            // A leap day in a year divisible by four but not a century.
            (1_709_164_800, "2024-02-29T00:00:00Z"),
            // The day this was written.
            (1_754_697_600, "2025-08-09T00:00:00Z"),
        ] {
            assert_eq!(to_rfc3339(seconds), expected, "for {seconds}");
        }
    }

    #[test]
    fn test_a_century_that_is_not_a_leap_year_is_not_treated_as_one() {
        // 1900 was not a leap year; 2000 was. Getting this wrong is the classic calendar bug.
        assert_eq!(
            days_of(Date {
                year: 1900,
                month: 3,
                day: 1
            }) - days_of(Date {
                year: 1900,
                month: 2,
                day: 28
            }),
            1
        );
        assert_eq!(
            days_of(Date {
                year: 2000,
                month: 3,
                day: 1
            }) - days_of(Date {
                year: 2000,
                month: 2,
                day: 28
            }),
            2
        );
    }

    #[test]
    fn test_a_date_round_trips_through_its_day_number_and_its_text() {
        // Every day for a decade around now, which covers every month length and every leap rule
        // that can fire in the range a deployment will ever hold records for.
        for day in 18_000..21_650 {
            let date = date_of(day);

            assert_eq!(days_of(date), day, "day number of {}", date.to_iso());
            assert_eq!(Date::from_iso(&date.to_iso()), Some(date));
        }
    }

    #[test]
    fn test_something_that_is_not_a_date_is_refused() {
        for written in [
            "",
            "2026",
            "2026-08",
            "2026-13-01",
            "2026-08-32",
            "2026-08-09-1",
            "x-y-z",
        ] {
            assert!(Date::from_iso(written).is_none(), "reading {written:?}");
        }
    }

    #[test]
    fn test_a_timestamp_before_the_epoch_lands_on_the_day_it_belongs_to() {
        assert_eq!(to_rfc3339(-1), "1969-12-31T23:59:59Z");
    }

    #[test]
    fn test_a_timestamp_reads_back_to_the_seconds_it_was_written_from() {
        for seconds in [0, 951_782_400, 1_609_459_199, 1_754_697_600, 1_789_997_319] {
            assert_eq!(from_rfc3339(&to_rfc3339(seconds)), Some(seconds));
        }
    }

    #[test]
    fn test_the_forms_rfc3339_allows_are_all_read_as_the_same_instant() {
        let canonical = from_rfc3339("2026-08-01T00:00:00Z");
        assert!(canonical.is_some());
        for written in [
            "2026-08-01t00:00:00z",
            "2026-08-01T00:00:00.250Z",
            "2026-08-01T02:00:00+02:00",
            "2026-07-31T22:30:00-01:30",
            " 2026-08-01T00:00:00Z ",
        ] {
            assert_eq!(from_rfc3339(written), canonical, "reading {written:?}");
        }
    }

    #[test]
    fn test_something_that_is_not_a_timestamp_is_refused() {
        for written in [
            "",
            "1789981824",
            "not-a-date",
            "2026-08-01",
            "2026-08-01T00:00:00",
            "2026-08-01T24:00:00Z",
            "2026-02-30T00:00:00Z",
            "2026-08-01T00:00:00.Z",
            "2026-08-01T00:00:00+2:00",
            "2026-08-01 00:00:00Z",
        ] {
            assert!(from_rfc3339(written).is_none(), "reading {written:?}");
        }
    }
}
