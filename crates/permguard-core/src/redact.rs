// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! Rendering a value unreadable when it has to appear at all.
//!
//! This is the second line. The first is [`Secret`](crate::secrets::Secret), which has no `Display`
//! and no `Debug` and therefore cannot reach a log by accident. Masking exists for everything that is
//! *not* secret material but still must not be read: a bearer token pasted into a configuration
//! value, an identifier in a diagnostic, a field an operator needs to recognise without seeing.
//!
//! The mask is **fixed width**. A mask as long as the value tells a reader how long the value was,
//! and length is information: it separates a 32-character API key from a 64-character one, narrows a
//! brute force, and identifies which kind of credential was in the field. Every masked value here
//! renders as the same eight characters no matter what it was.

use std::fmt;

/// What every masked value renders as, whatever it was.
pub const MASK: &str = "********";

/// The number of trailing characters [`Masked::tail`] leaves readable at most.
const MAX_TAIL: usize = 4;

/// A value rendered unreadable.
///
/// Both `Display` and `Debug` render the mask, so a value wrapped here stays masked whether it is
/// formatted with `{}`, `{:?}`, or a structured log field.
#[derive(Clone, Copy)]
pub struct Masked<'a> {
    value: &'a str,
    tail: usize,
}

impl<'a> Masked<'a> {
    /// Masks `value` completely.
    pub fn full(value: &'a str) -> Self {
        Self { value, tail: 0 }
    }

    /// Masks `value` but leaves its last `keep` characters readable, at most four.
    ///
    /// This is for the cases where a human has to recognise which value it is — the tail of an
    /// account identifier, say — and never for credentials. The prefix stays fixed width, so the tail
    /// is the only thing a reader learns.
    ///
    /// A value with no more characters than the tail would ask for is masked completely: revealing
    /// the tail of a four-character value reveals the value.
    pub fn tail(value: &'a str, keep: usize) -> Self {
        let keep = keep.min(MAX_TAIL);
        let characters = value.chars().count();

        Self {
            value,
            tail: if characters > keep { keep } else { 0 },
        }
    }

    /// Renders the mask, with whatever tail this value was allowed to keep.
    fn render(&self) -> String {
        if self.tail == 0 {
            return MASK.to_owned();
        }

        let tail: String = self
            .value
            .chars()
            .skip(self.value.chars().count() - self.tail)
            .collect();

        format!("{MASK}{tail}")
    }
}

impl fmt::Display for Masked<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.render())
    }
}

impl fmt::Debug for Masked<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.render())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_a_masked_value_renders_the_same_whatever_it_was() {
        let short = Masked::full("a");
        let long = Masked::full("a-very-long-api-key-nobody-should-read");

        assert_eq!(short.to_string(), MASK);
        assert_eq!(long.to_string(), MASK);
        assert_eq!(short.to_string(), long.to_string());
    }

    #[test]
    fn test_the_mask_hides_the_length_as_well_as_the_value() {
        let lengths: Vec<usize> = ["a", "ab", "abcdefghijklmnopqrstuvwxyz"]
            .into_iter()
            .map(|value| Masked::full(value).to_string().chars().count())
            .collect();

        assert_eq!(lengths, vec![MASK.chars().count(); 3]);
    }

    #[test]
    fn test_debug_masks_exactly_as_display_does() {
        let masked = Masked::full("secret-value");

        assert_eq!(format!("{masked:?}"), format!("{masked}"));
        assert!(!format!("{masked:?}").contains("secret"));
    }

    #[test]
    fn test_a_tail_reveals_only_the_characters_it_was_allowed() {
        let masked = Masked::tail("account-1234567890", 4);

        assert_eq!(masked.to_string(), format!("{MASK}7890"));
    }

    #[test]
    fn test_a_tail_longer_than_the_maximum_is_cut_down_to_it() {
        let masked = Masked::tail("account-1234567890", 12);

        assert_eq!(masked.to_string(), format!("{MASK}7890"));
    }

    #[test]
    fn test_a_value_no_longer_than_its_tail_is_masked_completely() {
        assert_eq!(Masked::tail("1234", 4).to_string(), MASK);
        assert_eq!(Masked::tail("12", 4).to_string(), MASK);
        assert_eq!(Masked::tail("", 4).to_string(), MASK);
    }

    #[test]
    fn test_a_tail_of_zero_masks_completely() {
        assert_eq!(Masked::tail("account-1234567890", 0).to_string(), MASK);
    }

    #[test]
    fn test_multibyte_values_are_masked_by_character_not_by_byte() {
        let masked = Masked::tail("segreto-àèìòù", 3);

        assert_eq!(masked.to_string(), format!("{MASK}ìòù"));
    }
}
