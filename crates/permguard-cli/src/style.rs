// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! Terminal styling — the change dialect every workspace command
//! speak: `+` green, `~` yellow, `-` red, identifiers cyan, chrome dim.
//!
//! Color is a property of *where the output lands*, never of the data:
//! enabled only when stdout is a terminal, `NO_COLOR` is unset and `TERM`
//! is not `dumb` — piped output stays byte-clean without asking. *How much*
//! color is the same question asked once more: 24-bit where the terminal
//! announces it, the 256-color cube where it does not, plain magenta on the
//! terminals that have neither. The brand gradient degrades, it never breaks.

use std::io::IsTerminal as _;
use std::sync::OnceLock;

fn enabled() -> bool {
    static ENABLED: OnceLock<bool> = OnceLock::new();
    *ENABLED.get_or_init(|| {
        std::io::stdout().is_terminal()
            && std::env::var_os("NO_COLOR").is_none()
            && std::env::var("TERM")
                .map(|term| term != "dumb")
                .unwrap_or(true)
    })
}

/// The two stops of the Permguard gradient: the pink the mark starts at and
/// the purple it ends on — the very pair the website paints its logo with.
const BRAND_FROM: [u8; 3] = [0xF0, 0x5C, 0x80];
const BRAND_TO: [u8; 3] = [0xCC, 0x34, 0xDF];

const RESET: &str = "\x1b[0m";

/// How many colors this terminal can actually be asked for.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Depth {
    /// None at all — piped, `NO_COLOR`, or a dumb terminal.
    None,
    /// The sixteen ANSI colors, and nothing more.
    Basic,
    /// The 256-color cube.
    Ansi256,
    /// 24-bit color, which is the only tier the gradient renders faithfully.
    True,
}

fn depth() -> Depth {
    static DEPTH: OnceLock<Depth> = OnceLock::new();
    *DEPTH.get_or_init(|| {
        if !enabled() {
            return Depth::None;
        }

        let colorterm = std::env::var("COLORTERM").unwrap_or_default();
        if colorterm == "truecolor" || colorterm == "24bit" {
            return Depth::True;
        }

        if std::env::var("TERM")
            .map(|term| term.contains("256color"))
            .unwrap_or(false)
        {
            return Depth::Ansi256;
        }

        Depth::Basic
    })
}

/// The gradient sampled at `t`, from the pink stop at `0.0` to the purple at `1.0`.
fn ramp(t: f32) -> [u8; 3] {
    let t = t.clamp(0.0, 1.0);

    let mut rgb = [0u8; 3];
    for channel in 0..3 {
        let from = f32::from(BRAND_FROM[channel]);
        let to = f32::from(BRAND_TO[channel]);
        rgb[channel] = (from + (to - from) * t).round() as u8;
    }

    rgb
}

/// The escape that sets `rgb` as the foreground, at the best fidelity available.
fn foreground(rgb: [u8; 3]) -> String {
    match depth() {
        Depth::True => format!("\x1b[38;2;{};{};{}m", rgb[0], rgb[1], rgb[2]),
        // The 6×6×6 cube: each channel snapped to the nearest of its six levels.
        Depth::Ansi256 => {
            let level = |c: u8| u16::from((f32::from(c) / 255.0 * 5.0).round() as u8);
            let index = 16 + 36 * level(rgb[0]) + 6 * level(rgb[1]) + level(rgb[2]);
            format!("\x1b[38;5;{index}m")
        }
        // Bright magenta is the closest the sixteen colors get to the brand.
        _ => "\x1b[95m".to_owned(),
    }
}

fn paint(code: &str, text: &str) -> String {
    if enabled() {
        format!("\x1b[{code}m{text}\x1b[0m")
    } else {
        text.to_owned()
    }
}

/// Something being created.
pub fn create(text: &str) -> String {
    paint("32", text)
}

/// Something being changed in place.
pub fn modify(text: &str) -> String {
    paint("33", text)
}

/// Something being removed.
pub fn delete(text: &str) -> String {
    paint("31", text)
}

/// Paints a block of art with the brand gradient, running diagonally from the
/// pink in the top-left to the purple in the bottom-right.
///
/// Spaces are left uncolored — there is no background to paint, so an escape
/// around them would only be bytes — and an escape is emitted only where the
/// color actually changes, which is what keeps six lines of art under a few
/// hundred bytes instead of one sequence per character.
pub fn brand_gradient(block: &str) -> String {
    if depth() == Depth::None {
        return block.to_owned();
    }

    let lines: Vec<&str> = block.lines().collect();
    let last_row = lines.len().saturating_sub(1).max(1);
    let last_column = lines
        .iter()
        .map(|line| line.chars().count())
        .max()
        .unwrap_or(1)
        .saturating_sub(1)
        .max(1);

    let mut out = String::new();
    for (row, line) in lines.iter().enumerate() {
        let mut current: Option<String> = None;

        for (column, glyph) in line.chars().enumerate() {
            if glyph == ' ' {
                if current.take().is_some() {
                    out.push_str(RESET);
                }
                out.push(glyph);
                continue;
            }

            let across = column as f32 / last_column as f32;
            let down = row as f32 / last_row as f32;
            let code = foreground(ramp((across + down) / 2.0));

            if current.as_deref() != Some(code.as_str()) {
                out.push_str(&code);
                current = Some(code);
            }
            out.push(glyph);
        }

        if current.is_some() {
            out.push_str(RESET);
        }
        if row < lines.len().saturating_sub(1) {
            out.push('\n');
        }
    }

    out
}

/// An identifier — a digest, a GUID — set apart from the prose.
pub fn id(text: &str) -> String {
    paint("36", text)
}

/// Chrome: labels, timestamps, the quiet parts.
pub fn dim(text: &str) -> String {
    paint("90", text)
}

/// The line that states the outcome.
pub fn bold(text: &str) -> String {
    paint("1", text)
}

/// A verified fact — the good kind.
pub fn ok(text: &str) -> String {
    paint("32", text)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_the_ramp_runs_from_the_pink_stop_to_the_purple_one() {
        assert_eq!(ramp(0.0), BRAND_FROM);
        assert_eq!(ramp(1.0), BRAND_TO);

        let middle = ramp(0.5);
        for channel in 0..3 {
            let (low, high) = (
                BRAND_FROM[channel].min(BRAND_TO[channel]),
                BRAND_FROM[channel].max(BRAND_TO[channel]),
            );
            assert!(middle[channel] >= low && middle[channel] <= high);
        }
    }

    #[test]
    fn test_the_ramp_is_clamped_outside_its_ends() {
        assert_eq!(ramp(-1.0), BRAND_FROM);
        assert_eq!(ramp(2.0), BRAND_TO);
    }

    #[test]
    fn test_the_gradient_leaves_the_art_untouched_when_there_is_no_color() {
        // Under a test harness stdout is not a terminal, so the depth is None.
        let art = " __ \n|__|";

        assert_eq!(brand_gradient(art), art);
    }
}
