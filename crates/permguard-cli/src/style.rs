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

/// The two stops of the Permguard gradient: the pink the mark starts at and
/// the purple it ends on — the very pair the website paints its logo with.
const BRAND_FROM: [u8; 3] = [0xF0, 0x5C, 0x80];
const BRAND_TO: [u8; 3] = [0xCC, 0x34, 0xDF];

const RESET: &str = "\x1b[0m";

/// How many colors this terminal can actually be asked for.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Depth {
    /// None at all — piped, `NO_COLOR`, or a dumb terminal.
    None,
    /// The sixteen ANSI colors, and nothing more.
    Basic,
    /// The 256-color cube.
    Ansi256,
    /// 24-bit color, which is the only tier the gradient renders faithfully.
    True,
}

/// The colour decision, from stated conditions rather than from the process.
///
/// # Why this is separate from [`depth`]
///
/// Whether to colour is a question about *where the output lands*, and the only
/// honest way to answer it at runtime is to ask the process: is stdout a
/// terminal, what does the environment say. That answer is ambient, and a test
/// that reads it is a test about the machine it happens to run on — green when
/// the suite is piped into a file, red in the terminal a developer actually
/// runs `task test` in, for reasons that have nothing to do with the code.
///
/// So the policy is a function of its inputs and nothing else, and the ambient
/// reading happens once, in [`depth`]. Rendering asks the policy; tests state
/// the conditions.
pub(crate) fn depth_from(
    is_terminal: bool,
    no_color: bool,
    term: Option<&str>,
    colorterm: Option<&str>,
) -> Depth {
    if !is_terminal || no_color || term == Some("dumb") {
        return Depth::None;
    }
    if matches!(colorterm, Some("truecolor" | "24bit")) {
        return Depth::True;
    }
    if term.is_some_and(|term| term.contains("256color")) {
        return Depth::Ansi256;
    }

    Depth::Basic
}

/// The colour decision for this process, read once.
pub(crate) fn depth() -> Depth {
    static DEPTH: OnceLock<Depth> = OnceLock::new();
    *DEPTH.get_or_init(|| {
        depth_from(
            std::io::stdout().is_terminal(),
            std::env::var_os("NO_COLOR").is_some(),
            std::env::var("TERM").ok().as_deref(),
            std::env::var("COLORTERM").ok().as_deref(),
        )
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
fn foreground(depth: Depth, rgb: [u8; 3]) -> String {
    match depth {
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

fn paint_with(depth: Depth, code: &str, text: &str) -> String {
    if depth == Depth::None {
        return text.to_owned();
    }

    format!("\x1b[{code}m{text}\x1b[0m")
}

fn paint(code: &str, text: &str) -> String {
    paint_with(depth(), code, text)
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
pub(crate) fn brand_gradient(depth: Depth, block: &str) -> String {
    if depth == Depth::None {
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
            let code = foreground(depth, ramp((across + down) / 2.0));

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
    dim_with(depth(), text)
}

/// [`dim`], against a stated colour depth rather than the process's.
pub(crate) fn dim_with(depth: Depth, text: &str) -> String {
    paint_with(depth, "90", text)
}

/// The line that states the outcome.
pub fn bold(text: &str) -> String {
    bold_with(depth(), text)
}

/// [`bold`], against a stated colour depth rather than the process's.
pub(crate) fn bold_with(depth: Depth, text: &str) -> String {
    paint_with(depth, "1", text)
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
        let art = " __ \n|__|";

        assert_eq!(brand_gradient(Depth::None, art), art);
    }

    /// The colour decision, stated rather than inherited.
    ///
    /// Every branch is a condition the contract names — not a terminal,
    /// `NO_COLOR`, `TERM=dumb` — and each is checked here against inputs, so the
    /// suite answers the same way whether it runs piped or in a terminal.
    #[test]
    fn test_the_colour_depth_follows_the_stated_conditions() {
        assert_eq!(
            depth_from(false, false, Some("xterm-256color"), Some("truecolor")),
            Depth::None,
            "output that is not a terminal is never coloured"
        );
        assert_eq!(
            depth_from(true, true, Some("xterm-256color"), Some("truecolor")),
            Depth::None,
            "NO_COLOR wins over everything the terminal announces"
        );
        assert_eq!(
            depth_from(true, false, Some("dumb"), Some("truecolor")),
            Depth::None,
            "a dumb terminal is taken at its word"
        );
        assert_eq!(
            depth_from(true, false, Some("xterm"), Some("truecolor")),
            Depth::True,
            "24-bit where the terminal announces it"
        );
        assert_eq!(
            depth_from(true, false, Some("xterm-256color"), None),
            Depth::Ansi256,
            "the cube where truecolor is not announced"
        );
        assert_eq!(
            depth_from(true, false, None, None),
            Depth::Basic,
            "a terminal that announces nothing still gets the sixteen"
        );
    }
}
