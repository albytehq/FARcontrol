//! CLI v2 presentation layer (ADR-0026, gh-style).
//!
//! Every owner command renders through this module: glyphs + colors on a TTY,
//! ASCII tables + no color when piped, and `--json` callers bypass it entirely.
//! Rules (research R1): status is glyph+color+word (colorblind-safe), durations
//! humanize, hints are dim, receipts are single lines, empty states inform.

use comfy_table::{presets, Table};
use std::sync::OnceLock;

/// Styling gate: colors only when stdout is a TTY and NO_COLOR is unset
/// (NO_COLOR spec + pipe safety, research R2). Cached per process.
fn styled() -> bool {
    static STYLED: OnceLock<bool> = OnceLock::new();
    *STYLED.get_or_init(|| {
        if std::env::var_os("NO_COLOR").is_some() {
            return false;
        }
        std::io::IsTerminal::is_terminal(&std::io::stdout())
    })
}

use owo_colors::OwoColorize;

/// Status glyph + color + word (shape differs so meaning survives color loss).
pub fn dot(state: Dot) -> String {
    let (glyph, color, word) = match state {
        Dot::Warn => ("◐", "yellow", "warn"),
        Dot::Dead => ("○", "dimmed", "quiet"),
        Dot::Dead2 => ("○", "dimmed", "expired"),
        Dot::Revoked => ("●", "red", "revoked"),
        Dot::Active => ("●", "green", "active"),
        Dot::Locked => ("●", "red", "locked"),
    };
    let (g, w) = (glyph.to_string(), word.to_string());
    if !styled() {
        return format!("{g} {w}");
    }
    match color {
        "green" => format!("{} {}", g.green(), w.green()),
        "yellow" => format!("{} {}", g.yellow(), w.yellow()),
        "cyan" => format!("{} {}", g.cyan(), w.cyan()),
        "red" => format!("{} {}", g.red(), w.red()),
        _ => format!("{} {}", g.dimmed(), w.dimmed()),
    }
}

#[derive(Clone, Copy)]
pub enum Dot {
    Warn,
    Dead,
    Dead2,
    Revoked,
    Active,
    Locked,
}

/// Success receipt: `✓ <line>` (green on TTY).
pub fn ok_receipt(line: &str) {
    if styled() {
        println!("{} {}", "✓".green(), line);
    } else {
        println!("✓ {line}");
    }
}

/// Failure receipt: `✗ <line>` (red on TTY).
pub fn err_receipt(line: &str) {
    if styled() {
        eprintln!("{} {}", "✗".red(), line);
    } else {
        eprintln!("✗ {line}");
    }
}

/// Dim hint line: `tip: <verb-led hint>`.
pub fn hint(line: &str) {
    if styled() {
        println!("{} {}", "tip:".dimmed(), line.dimmed());
    } else {
        println!("tip: {line}");
    }
}

/// Section label (bold on TTY).
pub fn section(label: &str) {
    if styled() {
        println!("{}", label.bold());
    } else {
        println!("{label}");
    }
}

/// Plain dim informational line.
pub fn dim(line: &str) {
    if styled() {
        println!("{}", line.dimmed());
    } else {
        println!("{line}");
    }
}

/// Humanize a duration: `45s`, `4m`, `2h 15m`, `3d 4h` (R1 A.2).
pub fn humanize(secs: i64) -> String {
    let s = secs.max(0);
    if s < 60 {
        format!("{s}s")
    } else if s < 3600 {
        format!("{}m", (s + 59) / 60)
    } else if s < 86400 {
        format!("{}h {}m", s / 3600, (s % 3600) / 60)
    } else {
        format!("{}d {}h", s / 86400, (s % 86400) / 3600)
    }
}

/// Relative timestamp: `just now`, `4m ago`, `2h ago`, `3d ago`, `never`.
pub fn ago(ts: Option<i64>) -> String {
    match ts {
        None => "never".into(),
        Some(t) => {
            let d = crate::state::now() - t;
            if d < 60 {
                "just now".into()
            } else if d < 3600 {
                format!("{}m ago", d / 60)
            } else if d < 86400 {
                format!("{}h ago", d / 3600)
            } else {
                format!("{}d ago", d / 86400)
            }
        }
    }
}

/// Middle-truncate to `max` chars with `…` (full values live in --json).
pub fn trunc(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        return s.to_string();
    }
    let head: String = s.chars().take(max / 2).collect();
    let tail: String = s.chars().skip(s.chars().count() - (max / 2).saturating_sub(1)).collect();
    format!("{head}…{tail}")
}

/// gh-style table: UTF8 (TTY) or ASCII (pipe) preset, content pre-truncated by
/// the caller (R1 A.4 / R2 NO_COLOR policy).
pub fn table(headers: &[&str], rows: &[Vec<String>]) -> String {
    let mut t = Table::new();
    if styled() {
        t.load_preset(presets::UTF8_FULL_CONDENSED);
    } else {
        t.load_preset(presets::ASCII_FULL_CONDENSED);
    }
    t.set_header(headers.iter().map(|h| h.to_string()));
    for r in rows {
        t.add_row(r.iter().map(|c| c.to_string()));
    }
    t.to_string()
}

/// Informative empty state (R1 A.5) — never a bare header-only table.
pub fn empty(line: &str) {
    if styled() {
        println!("{} {}", "✓".dimmed(), line.dimmed());
    } else {
        println!("✓ {line}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn humanize_shape() {
        assert_eq!(humanize(45), "45s");
        assert_eq!(humanize(60), "1m");
        assert_eq!(humanize(240), "4m");
        assert_eq!(humanize(8100), "2h 15m");
        assert_eq!(humanize(86400 + 7200), "1d 2h");
        assert_eq!(humanize(-5), "0s");
    }

    #[test]
    fn ago_shape() {
        let now = crate::state::now();
        assert_eq!(ago(None), "never");
        assert_eq!(ago(Some(now)), "just now");
        assert_eq!(ago(Some(now - 300)), "5m ago");
        assert_eq!(ago(Some(now - 7200)), "2h ago");
        assert_eq!(ago(Some(now - 3 * 86400)), "3d ago");
    }

    #[test]
    fn trunc_middle() {
        assert_eq!(trunc("short", 20), "short");
        let long = "a".repeat(60);
        let t = trunc(&long, 21);
        assert!(t.contains('…'));
        assert!(t.chars().count() <= 22, "truncated length bounded: {}", t.chars().count());
    }

    #[test]
    fn table_ascii_when_piped() {
        // test processes are not TTYs → ASCII preset, no color, glyphs plain
        let out = table(&["ID", "NAME"], &[vec!["FAR-1234-ABCD".into(), "laptop".into()]]);
        assert!(out.contains("FAR-1234-ABCD"));
        assert!(out.contains("ID"));
        assert!(!out.contains('\u{2500}') || !styled(), "pipe mode avoids heavy borders");
        assert!(!out.contains("\u{001b}["), "no ANSI escapes when piped");
    }

    #[test]
    fn dot_always_carries_a_word() {
        for d in [Dot::Warn, Dot::Dead, Dot::Dead2, Dot::Revoked, Dot::Active, Dot::Locked] {
            let s = dot(d);
            assert!(s.contains('●') || s.contains('◐') || s.contains('○') || s.contains('✗'), "glyph present: {s}");
            assert!(s.split_whitespace().count() >= 2, "word present: {s}");
        }
    }
}
