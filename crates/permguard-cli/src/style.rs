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

/// The six values a channel of the 6×6×6 cube can actually take.
///
/// They are not evenly spaced, and treating them as though they were is the mistake this constant
/// exists to prevent: `round(c / 255 * 5)` picks the right *index* for an even ramp and the wrong
/// *colour* for this one. `0x8a` lands on index 3, which is `175` — a colour thirty-seven points
/// lighter than the one asked for, and on a light terminal that is the difference between chrome
/// and something nobody can read.
const CUBE: [u8; 6] = [0, 95, 135, 175, 215, 255];

/// The first index of the 24-step grey ramp, whose entries are `8 + 10 * step`.
const GREY_RAMP: u8 = 232;

/// The palette entry nearest `rgb`, by squared distance.
///
/// Both halves of the palette are considered, because for a grey they disagree: the cube can only
/// offer six evenly-named-but-unevenly-spaced greys, while the ramp offers twenty-four ten apart —
/// so a grey that the cube would miss by tens the ramp usually hits exactly.
fn nearest(rgb: [u8; 3]) -> u8 {
    let distance = |from: [u8; 3]| -> i32 {
        (0..3)
            .map(|channel| {
                let apart = i32::from(from[channel]) - i32::from(rgb[channel]);
                apart * apart
            })
            .sum()
    };

    let level = |c: u8| {
        CUBE.iter()
            .position(|value| *value == nearest_of(&CUBE, c))
            .unwrap_or(0)
    };
    let (red, green, blue) = (level(rgb[0]), level(rgb[1]), level(rgb[2]));
    let cube = [CUBE[red], CUBE[green], CUBE[blue]];
    let cube_index = 16 + 36 * red + 6 * green + blue;

    let average = (i32::from(rgb[0]) + i32::from(rgb[1]) + i32::from(rgb[2])) / 3;
    let step = ((average - 8) as f32 / 10.0).round().clamp(0.0, 23.0) as i32;
    let grey = u8::try_from(8 + 10 * step).unwrap_or(u8::MAX);

    match distance([grey; 3]) < distance(cube) {
        true => GREY_RAMP.saturating_add(u8::try_from(step).unwrap_or(0)),
        false => u8::try_from(cube_index).unwrap_or(u8::MAX),
    }
}

/// The value of `levels` closest to `c`.
fn nearest_of(levels: &[u8], c: u8) -> u8 {
    levels
        .iter()
        .copied()
        .min_by_key(|level| (i32::from(*level) - i32::from(c)).abs())
        .unwrap_or(0)
}

/// The escape that sets `rgb` as the foreground, at the best fidelity available.
fn foreground(depth: Depth, rgb: [u8; 3]) -> String {
    match depth {
        Depth::True => format!("\x1b[38;2;{};{};{}m", rgb[0], rgb[1], rgb[2]),
        Depth::Ansi256 => format!("\x1b[38;5;{}m", nearest(rgb)),
        // Bright magenta is the closest the sixteen colors get to the brand.
        _ => "\x1b[95m".to_owned(),
    }
}

/// The colour a terminal actually shows for a 256-palette index.
///
/// The inverse of [`nearest`], and it exists for the tests: asserting the colour that was *asked*
/// for says nothing about what a reader sees, which is exactly how the uneven cube went unnoticed.
#[cfg(test)]
fn rendered(index: u8) -> [u8; 3] {
    if index >= GREY_RAMP {
        let value = 8 + 10 * u16::from(index - GREY_RAMP);

        return [u8::try_from(value).unwrap_or(u8::MAX); 3];
    }

    let index = usize::from(index.saturating_sub(16));

    [
        CUBE[(index / 36) % 6],
        CUBE[(index / 6) % 6],
        CUBE[index % 6],
    ]
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

/// The grey the quiet parts are set in.
///
/// # Why a stated grey rather than `bright black`
///
/// Chrome used to be SGR 90, and SGR 90 is not a grey — it is the theme's *black*, brightened by
/// whatever factor the theme chose. On a dark background that lands a step above the background it
/// is printed on, which is why a commit digest or a timestamp could be on screen and still be
/// unreadable; on a light theme the same code goes the other way and nearly disappears into white.
/// The terminal decides, the text is chrome either way, and neither outcome is one this CLI picked.
///
/// So the grey is stated. At 5:1 against a dark background and 3.4:1 against white it is quieter
/// than the prose beside it without dropping under it, and it is the same grey on every theme. The
/// balance leans toward dark backgrounds deliberately: that is where `bright black` failed worst,
/// and it is what most terminals running this are set to.
const CHROME: [u8; 3] = [0x8a, 0x8a, 0x8a];

/// Chrome: labels, timestamps, the quiet parts.
pub fn dim(text: &str) -> String {
    dim_with(depth(), text)
}

/// [`dim`], against a stated colour depth rather than the process's.
pub(crate) fn dim_with(depth: Depth, text: &str) -> String {
    match depth {
        Depth::None => text.to_owned(),
        // Sixteen colours have no grey to state: 90 is the least bad of them, and the tier is rare
        // enough that carrying its compromise is better than making chrome as loud as the prose.
        Depth::Basic => paint_with(depth, "90", text),
        Depth::Ansi256 | Depth::True => {
            format!("{}{text}{RESET}", foreground(depth, CHROME))
        }
    }
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
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    /// The relative luminance of an sRGB colour, per WCAG.
    fn luminance(rgb: [u8; 3]) -> f32 {
        let channel = |c: u8| {
            let c = f32::from(c) / 255.0;
            match c <= 0.04045 {
                true => c / 12.92,
                false => ((c + 0.055) / 1.055).powf(2.4),
            }
        };

        0.2126 * channel(rgb[0]) + 0.7152 * channel(rgb[1]) + 0.0722 * channel(rgb[2])
    }

    fn contrast(one: [u8; 3], other: [u8; 3]) -> f32 {
        let (a, b) = (luminance(one), luminance(other));
        (a.max(b) + 0.05) / (a.min(b) + 0.05)
    }

    const NEAR_BLACK: [u8; 3] = [0x0f, 0x1b, 0x2d];
    const WHITE: [u8; 3] = [0xff, 0xff, 0xff];

    /// The colour an escape actually paints, read back out of the escape itself.
    fn painted(escape: &str) -> [u8; 3] {
        if let Some(rest) = escape.strip_prefix("\x1b[38;2;") {
            let mut channels = rest.trim_end_matches('m').split(';');
            let mut next = || {
                channels
                    .next()
                    .and_then(|held| held.parse::<u8>().ok())
                    .expect("a 24-bit escape names three channels")
            };

            return [next(), next(), next()];
        }
        let index = escape
            .strip_prefix("\x1b[38;5;")
            .and_then(|rest| rest.trim_end_matches('m').parse::<u8>().ok())
            .expect("the escape is one of the two forms this module emits");

        rendered(index)
    }

    /// Chrome stays readable on a dark terminal and on a light one — *as rendered*.
    ///
    /// # Why the rendered colour and not the requested one
    ///
    /// Asserting `CHROME` itself is what let the palette bug through. The constant was legible; the
    /// escape the 256-colour tier emitted for it was not, because the cube's six levels are
    /// `0, 95, 135, 175, 215, 255` and the conversion treated them as evenly spaced. `0x8a` was
    /// sent as `175`, which is 2.19:1 on white — worse than the `bright black` the constant
    /// replaced. The test passed the whole time, because it was checking a number nobody sees.
    ///
    /// So the assertion goes through the escape: whatever the tier does to the colour, what is
    /// measured is what a reader gets.
    #[test]
    fn chrome_is_legible_at_every_tier_that_can_paint_it() {
        for depth in [Depth::True, Depth::Ansi256] {
            let shown = painted(&foreground(depth, CHROME));
            assert!(
                contrast(shown, NEAR_BLACK) >= 4.5,
                "{depth:?} paints chrome as {shown:?}, which is {:.2}:1 on a dark terminal",
                contrast(shown, NEAR_BLACK)
            );
            assert!(
                contrast(shown, WHITE) >= 3.0,
                "{depth:?} paints chrome as {shown:?}, which is {:.2}:1 on a light terminal",
                contrast(shown, WHITE)
            );
        }
    }

    /// The 256-colour tier snaps to entries the palette has, not to an even ramp it does not.
    #[test]
    fn the_palette_snaps_to_colours_the_terminal_really_has() {
        // Chrome is a grey, and the 24-step ramp holds it exactly — the cube could only have
        // offered 175.
        assert_eq!(
            painted(&foreground(Depth::Ansi256, CHROME)),
            CHROME,
            "a grey on the ramp is painted exactly, not snapped to a cube level tens away"
        );

        // A chromatic colour lands on real cube levels rather than on interpolated ones.
        for asked in [[0xff, 0x00, 0x80], [0x40, 0xa0, 0xc0], [0x12, 0x34, 0x56]] {
            let shown = painted(&foreground(Depth::Ansi256, asked));
            for channel in shown {
                assert!(
                    CUBE.contains(&channel) || shown[0] == shown[1] && shown[1] == shown[2],
                    "{asked:?} was painted {shown:?}, which is not a colour this palette holds"
                );
            }
        }
    }

    /// The gradient degrades through the tiers without emitting an escape a terminal cannot read.
    #[test]
    fn the_gradient_degrades_across_every_tier() {
        const BLOCK: &str = "██\n██";

        assert_eq!(
            brand_gradient(Depth::None, BLOCK),
            BLOCK,
            "with no colour there is nothing to paint"
        );
        for (depth, expected) in [
            (Depth::True, "\x1b[38;2;"),
            (Depth::Ansi256, "\x1b[38;5;"),
            (Depth::Basic, "\x1b[95m"),
        ] {
            let painted = brand_gradient(depth, BLOCK);
            assert!(
                painted.contains(expected),
                "{depth:?} must paint the gradient with {expected:?}: {painted:?}"
            );
            assert!(painted.contains(RESET), "{depth:?} closes what it opens");
        }
    }

    /// Chrome is quieter than the prose beside it — it must not become plain text.
    #[test]
    fn chrome_is_still_quieter_than_the_text_it_sits_beside() {
        const NEAR_BLACK: [u8; 3] = [0x0f, 0x1b, 0x2d];
        const FOREGROUND: [u8; 3] = [0xe6, 0xe6, 0xe6];

        assert!(
            contrast(CHROME, NEAR_BLACK) < contrast(FOREGROUND, NEAR_BLACK),
            "chrome that reads as loudly as the prose is not chrome"
        );
    }

    /// Every tier that can state a grey states one; only the sixteen colours fall back.
    #[test]
    fn only_the_sixteen_colour_tier_falls_back_to_bright_black() {
        assert_eq!(dim_with(Depth::None, "x"), "x", "piped output stays clean");
        assert!(
            dim_with(Depth::Basic, "x").contains("\x1b[90m"),
            "sixteen colours have nothing better"
        );
        for depth in [Depth::Ansi256, Depth::True] {
            let painted = dim_with(depth, "x");
            assert!(
                !painted.contains("\x1b[90m"),
                "{depth:?} can state a grey and must not defer to the theme's black"
            );
            assert!(painted.ends_with(RESET), "{depth:?} closes what it opened");
        }
        assert!(
            dim_with(Depth::True, "x").contains("38;2;138;138;138"),
            "24-bit states the grey exactly"
        );
    }

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
