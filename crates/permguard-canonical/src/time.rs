// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The instant of the temporal protocol: a canonical RFC 3339 UTC instant at whole-second
//! precision, read as epoch seconds and rendered back, each the exact inverse of the other.

/// A canonical RFC 3339 UTC instant at whole-second precision, as epoch seconds.
///
/// Deliberately strict. Dogwood's windows are closed intervals over signed epoch seconds, so a
/// fractional second or a non-UTC offset has no exact representation and would land on one side or
/// the other of a boundary depending on how it was rounded. Refused rather than rounded.
pub fn epoch_seconds(instant: &str) -> Option<i64> {
    // `YYYY-MM-DDTHH:MM:SSZ`, and nothing else.
    let bytes = instant.as_bytes();
    if bytes.len() != 20 || bytes[10] != b'T' || bytes[19] != b'Z' {
        return None;
    }
    let number = |from: usize, to: usize| instant.get(from..to)?.parse::<i64>().ok();
    let year = number(0, 4)?;
    let month = number(5, 7)?;
    let day = number(8, 10)?;
    let hour = number(11, 13)?;
    let minute = number(14, 16)?;
    let second = number(17, 19)?;
    if !(1..=12).contains(&month)
        || !(1..=31).contains(&day)
        || hour > 23
        || minute > 59
        // Leap seconds have no epoch-second of their own, so `:60` is refused rather than
        // silently folded onto the following second.
        || second > 59
    {
        return None;
    }

    // Days from the civil epoch — Howard Hinnant's algorithm, which is exact for the whole range
    // and needs no calendar table.
    let year = if month <= 2 { year - 1 } else { year };
    let era = if year >= 0 { year } else { year - 399 } / 400;
    let year_of_era = year - era * 400;
    let month_adjusted = if month > 2 { month - 3 } else { month + 9 };
    let day_of_year = (153 * month_adjusted + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    let days = era * 146_097 + day_of_era - 719_468;

    let seconds = days * 86_400 + hour * 3_600 + minute * 60 + second;

    // The round trip is what "canonical" means here, so it is what is checked.
    //
    // Every field above is in range on its own, and that is not enough: `1..=31` admits a day the
    // month does not have, and the civil-days arithmetic has no notion of a date that does not
    // exist — it converts `2025-02-29` into the instant three lines of algebra say it is, which is
    // `2025-03-01`. Accepting that puts two spellings on one instant, and leaves a record holding a
    // date the calendar never had while the index and the engine use a different one. A February
    // 29th in a year that has none is an ordinary client bug, not an exotic input.
    //
    // Rendering the result and requiring it back is exact, and needs no second table of month
    // lengths and no second leap rule to disagree with this one: the only strings that survive are
    // the ones this system also writes.
    (render_epoch_seconds(seconds)? == instant).then_some(seconds)
}

/// The canonical instant of an epoch second — the exact inverse of [`epoch_seconds`].
///
/// One spelling of an instant, produced here and parsed there, so a record read back is the record
/// that was written. `None` for a second whose civil date does not fit the four-digit year form
/// the canonical spelling has: a range no clock in this system reaches, refused rather than
/// rendered as something [`epoch_seconds`] would then read as a different time.
pub fn render_epoch_seconds(seconds: i64) -> Option<String> {
    let days = seconds.div_euclid(86_400);
    let rest = seconds.rem_euclid(86_400);

    // Hinnant's civil-from-days, the inverse of the days computation in `epoch_seconds`.
    let days = days + 719_468;
    let era = if days >= 0 { days } else { days - 146_096 } / 146_097;
    let day_of_era = days - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_adjusted = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_adjusted + 2) / 5 + 1;
    let month = if month_adjusted < 10 {
        month_adjusted + 3
    } else {
        month_adjusted - 9
    };
    let year = if month <= 2 { year + 1 } else { year };
    if !(0..=9999).contains(&year) {
        return None;
    }

    Some(format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        rest / 3_600,
        (rest % 3_600) / 60,
        rest % 60
    ))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;

    /// A date the calendar does not have is refused, not moved to one that exists.
    ///
    /// # Why this needs a test of its own
    ///
    /// Each field passes on its own: `02` is a month and `29` is inside `1..=31`. What fails is the
    /// combination, and the civil-days arithmetic has no opinion about it — it converts
    /// `2025-02-29` into the instant the algebra says, which is `2025-03-01`. That put two
    /// spellings on one instant: the audit record kept the date the caller sent while the index and
    /// the engine used another, three days apart at the extreme. A leap year off by one is an
    /// ordinary client bug, so this is an input that really arrives.
    #[test]
    fn a_date_the_calendar_does_not_have_is_refused_rather_than_moved() {
        for absent in [
            // February, in years that have no twenty-ninth.
            "2025-02-29T00:00:00Z",
            "2026-02-29T00:00:00Z",
            "2100-02-29T00:00:00Z",
            // February never has these at all.
            "2024-02-30T00:00:00Z",
            "2026-02-31T00:00:00Z",
            // The thirty-day months have no thirty-first.
            "2026-04-31T00:00:00Z",
            "2026-06-31T00:00:00Z",
            "2026-09-31T00:00:00Z",
            "2026-11-31T00:00:00Z",
        ] {
            assert_eq!(
                epoch_seconds(absent),
                None,
                "`{absent}` is not a date, and accepting it would record an instant days from the \
                 one it spells"
            );
        }
    }

    /// The dates that do exist still convert, including the awkward ones.
    #[test]
    fn the_calendar_dates_that_do_exist_are_accepted() {
        for present in [
            // Leap days, by each of the rules that decide them.
            "2024-02-29T00:00:00Z",
            "2000-02-29T00:00:00Z",
            // The last day of each length of month.
            "2026-01-31T00:00:00Z",
            "2026-02-28T00:00:00Z",
            "2026-04-30T00:00:00Z",
            // Either side of a year boundary.
            "2026-12-31T23:59:59Z",
            "2027-01-01T00:00:00Z",
        ] {
            assert!(
                epoch_seconds(present).is_some(),
                "`{present}` is a date this system must keep accepting"
            );
        }
    }

    /// Parsing and rendering are inverse, which is what makes the spelling one.
    #[test]
    fn an_instant_survives_a_round_trip() {
        let mut at = 0i64;
        // Steps of a second, a minute, an hour, a day, a year and a leap cycle: the walk crosses
        // month ends, leap days and the epoch without enumerating a century.
        for step in [1i64, 59, 3_600, 86_400, 86_400 * 365, 86_400 * 1_461] {
            for _ in 0..64 {
                let text = render_epoch_seconds(at).expect("the instant renders");
                assert_eq!(
                    epoch_seconds(&text),
                    Some(at),
                    "`{text}` must read back as the second it was written from"
                );
                at = at.saturating_add(step);
            }
        }
    }

    #[test]
    fn a_canonical_instant_converts_exactly_and_anything_else_is_refused() {
        assert_eq!(epoch_seconds("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(epoch_seconds("2026-08-28T10:15:30Z"), Some(1_787_912_130));

        for refused in [
            "2026-08-28T10:15:30.500Z",  // a fraction has no exact epoch second
            "2026-08-28T10:15:30+02:00", // a non-UTC offset is not canonical here
            "2026-08-28T10:15:60Z",      // a leap second has no epoch second of its own
            "2026-08-28 10:15:30Z",      // not RFC 3339
            "2026-13-01T00:00:00Z",      // not a month
            "",
        ] {
            assert_eq!(epoch_seconds(refused), None, "{refused}");
        }
    }
}
