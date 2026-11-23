//! Screen text, as `derm_terminal_read` serves it (lane PD's;
//! `contracts/project-tools.md` section 3). Shared by `derm run`, which
//! renders the harness's output and cleans it before `screen.put`, and the
//! daemon, which cleans it again before a reply leaves (section 3.4).
//!
//! What `clean` removes (section 3.3): every character of Unicode general
//! category Cc but `\n` and `\t` (`char::is_control` is exactly Cc), every
//! character of category Cf as Unicode 18.0.0 lists it ([`FORMAT`]), and
//! U+FFFD. Unicode 18.0.0 is the version unicode-width 0.2.3 (the reader's
//! width tables, through vt100 0.18.1) is built from. Its Cf list is the
//! same 170 code points as 17.0.0's (both `DerivedGeneralCategory.txt`
//! files read and compared, lane PD's status doc, Research).

/// Most UTF-8 bytes one `screen.put` text or one `derm_terminal_read` reply
/// carries: under the socket's 1 MiB line cap (`derm-daemon`'s
/// `socket::MAX_LINE_BYTES`; case 185). Cut from the top.
pub const MAX_TEXT_BYTES: usize = 512 * 1024;

/// Most scrollback lines a reader keeps per chat.
pub const MAX_SCROLLBACK_LINES: usize = 10_000;

/// Most lines one `derm_terminal_read` asks for.
pub const MAX_READ_LINES: u32 = 2_000;

/// The Unicode version [`FORMAT`] is taken from.
pub const UNICODE_VERSION: (u8, u8, u8) = (18, 0, 0);

/// General category Cf (Format), Unicode 18.0.0, as inclusive ranges, from
/// `DerivedGeneralCategory-18.0.0.txt` (dated 2026-06-29, sha256
/// `d6b151d2d40ee9b1876d26f417980f45ffae47b6055ccf7203cb31f07a030f94`,
/// unicode-org/unicodetools `unicodetools/data/ucd/18.0.0/extracted/`),
/// section `General_Category=Format`, "Total code points: 170". Sorted and
/// disjoint (tested).
pub const FORMAT: &[(u32, u32)] = &[
    (0x00AD, 0x00AD),   // SOFT HYPHEN
    (0x0600, 0x0605),   // ARABIC NUMBER SIGN..ARABIC NUMBER MARK ABOVE
    (0x061C, 0x061C),   // ARABIC LETTER MARK
    (0x06DD, 0x06DD),   // ARABIC END OF AYAH
    (0x070F, 0x070F),   // SYRIAC ABBREVIATION MARK
    (0x0890, 0x0891),   // ARABIC POUND MARK ABOVE..ARABIC PIASTRE MARK ABOVE
    (0x08E2, 0x08E2),   // ARABIC DISPUTED END OF AYAH
    (0x180E, 0x180E),   // MONGOLIAN VOWEL SEPARATOR
    (0x200B, 0x200F),   // ZERO WIDTH SPACE..RIGHT-TO-LEFT MARK
    (0x202A, 0x202E),   // LEFT-TO-RIGHT EMBEDDING..RIGHT-TO-LEFT OVERRIDE
    (0x2060, 0x2064),   // WORD JOINER..INVISIBLE PLUS
    (0x2066, 0x206F),   // LEFT-TO-RIGHT ISOLATE..NOMINAL DIGIT SHAPES
    (0xFEFF, 0xFEFF),   // ZERO WIDTH NO-BREAK SPACE
    (0xFFF9, 0xFFFB),   // INTERLINEAR ANNOTATION ANCHOR..TERMINATOR
    (0x110BD, 0x110BD), // KAITHI NUMBER SIGN
    (0x110CD, 0x110CD), // KAITHI NUMBER SIGN ABOVE
    (0x13430, 0x1343F), // EGYPTIAN HIEROGLYPH VERTICAL JOINER..END WALLED ENCLOSURE
    (0x1BCA0, 0x1BCA3), // SHORTHAND FORMAT LETTER OVERLAP..UP STEP
    (0x1D173, 0x1D17A), // MUSICAL SYMBOL BEGIN BEAM..END PHRASE
    (0xE0001, 0xE0001), // LANGUAGE TAG
    (0xE0020, 0xE007F), // TAG SPACE..CANCEL TAG
];

/// What `clean` kept and what it removed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Clean {
    pub text: String,
    /// Characters removed (Cc other than `\n` and `\t`, every Cf, U+FFFD).
    pub removed: usize,
    /// The text was cut from the top to fit `MAX_TEXT_BYTES`.
    pub truncated: bool,
}

/// Whether `c` is of category Cf (Unicode 18.0.0).
pub fn is_format(c: char) -> bool {
    let c = c as u32;
    FORMAT
        .binary_search_by(|&(lo, hi)| {
            if hi < c {
                std::cmp::Ordering::Less
            } else if lo > c {
                std::cmp::Ordering::Greater
            } else {
                std::cmp::Ordering::Equal
            }
        })
        .is_ok()
}

/// Whether `clean` removes `c`.
pub fn removes(c: char) -> bool {
    (c.is_control() && c != '\n' && c != '\t') || is_format(c) || c == '\u{fffd}'
}

/// Removes every character of Unicode category Cc other than `\n` and
/// `\t`, every Cf character, and U+FFFD; trims trailing spaces on each
/// line; cuts from the top to `MAX_TEXT_BYTES` on a character boundary
/// (contracts/project-tools.md section 3.3). Removal comes first, so a
/// space left before a removed `\r` is trimmed too.
pub fn clean(text: &str) -> Clean {
    clean_to(text, MAX_TEXT_BYTES)
}

/// [`clean`] with another byte budget (tests, and a caller that keeps room
/// for its own fields).
pub fn clean_to(text: &str, max_bytes: usize) -> Clean {
    let mut out = String::with_capacity(text.len().min(max_bytes.saturating_add(4)));
    let mut removed = 0usize;
    let mut line_start = 0usize;
    let trim = |out: &mut String, line_start: usize| {
        while out.len() > line_start && out.ends_with(' ') {
            out.pop();
        }
    };
    for c in text.chars() {
        if c == '\n' {
            trim(&mut out, line_start);
            out.push('\n');
            line_start = out.len();
        } else if removes(c) {
            removed += 1;
        } else {
            out.push(c);
        }
    }
    trim(&mut out, line_start);
    let mut truncated = false;
    if out.len() > max_bytes {
        let mut start = out.len() - max_bytes;
        while !out.is_char_boundary(start) {
            start += 1;
        }
        out.drain(..start);
        truncated = true;
    }
    Clean {
        text: out,
        removed,
        truncated,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_format_table_is_sorted_disjoint_and_holds_the_ucds_170_code_points() {
        let mut total = 0u32;
        for w in FORMAT.windows(2) {
            assert!(w[0].1 < w[1].0, "{:X?} then {:X?}", w[0], w[1]);
        }
        for &(lo, hi) in FORMAT {
            assert!(lo <= hi);
            total += hi - lo + 1;
        }
        assert_eq!(total, 170);
    }

    #[test]
    fn every_cf_edge_is_removed_and_its_neighbours_kept() {
        for &(lo, hi) in FORMAT {
            for c in [lo, hi] {
                let c = char::from_u32(c).unwrap();
                assert!(is_format(c), "U+{:04X}", c as u32);
            }
            if let Some(b) = lo.checked_sub(1).and_then(char::from_u32) {
                // A range's neighbours are never Cf: the UCD lists each run
                // of Cf as one range, so two ranges never touch.
                assert!(!is_format(b), "U+{:04X}", b as u32);
            }
            if let Some(a) = char::from_u32(hi + 1) {
                assert!(!is_format(a), "U+{:04X}", a as u32);
            }
        }
        // The three the contract's own list left out (in Cf since before 17.0).
        for c in ['\u{890}', '\u{891}', '\u{8e2}'] {
            assert_eq!(clean(&format!("a{c}b")).text, "ab");
        }
    }

    #[test]
    fn cc_but_newline_and_tab_is_removed_and_counted() {
        let all: String = (0u32..0x20)
            .chain(0x7f..0xa0)
            .filter_map(char::from_u32)
            .collect();
        let c = clean(&format!("x{all}y"));
        assert_eq!(c.text, "x\t\ny");
        assert_eq!(c.removed, 0x20 + 0x21 - 2);
    }

    #[test]
    fn trailing_spaces_go_on_every_line_and_inner_spaces_stay() {
        let c = clean("a b   \n  c  \r\n\n   ");
        assert_eq!(c.text, "a b\n  c\n\n");
        assert_eq!(c.removed, 1);
        assert!(!c.truncated);
    }

    #[test]
    fn a_cut_keeps_the_bottom_on_a_character_boundary() {
        let text = format!("{}\nend", "é".repeat(10));
        let c = clean_to(&text, 8);
        assert!(c.truncated);
        assert!(c.text.len() <= 8, "{c:?}");
        assert!(c.text.ends_with("\nend"), "{c:?}");
        // 'é' is two bytes; an odd start is moved to the next boundary.
        let c = clean_to("éé", 3);
        assert_eq!(c.text, "é");
        let c = clean_to("short", 8);
        assert!(!c.truncated);
        assert_eq!(c.text, "short");
    }

    #[test]
    fn clean_twice_is_clean_once() {
        let once = clean("a\u{202e}b \u{1b}[0m\u{85}\u{fffd}\r\n\u{e0041}z");
        let twice = clean(&once.text);
        assert_eq!(once.text, twice.text);
        assert_eq!(twice.removed, 0);
    }
}
