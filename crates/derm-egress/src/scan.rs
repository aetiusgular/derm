//! What a request is searched for, and in which forms (`contracts/policy.md`
//! section 8.3; case 217).
//!
//! A placeholder is `dermsecret_<id>_<16 lowercase hex>` (section 8.2): it is
//! looked for case-blind, as sent and after percent-decoding, and in a host
//! name also with its dots removed (a placeholder split over labels). A
//! secret's value is looked for in the same forms, plus its lowercase hex and
//! its base64 at each of the three byte alignments a value can sit at inside a
//! longer base64 run, in both alphabets (standard and URL-safe). A value shorter
//! than [`MIN_VALUE_LEN`] is refused when it is loaded, since its forms would
//! match ordinary text.
//!
//! Prior art: srt 0.0.82's body scan is a raw byte scan for an exact
//! `[a-z0-9_-]` sentinel (`dist/sandbox/body-substitution.js:1-15`); Codex
//! 0.167.2 scans bytes for an opaque ASCII marker (`secret_substitution.rs`).
//! Neither looks for the real value; derm does, because a value that reached
//! the agent is the leak the block exists for.

use base64::engine::general_purpose::{STANDARD_NO_PAD, URL_SAFE_NO_PAD};
use base64::Engine;
use memchr::memmem;

/// Shorter values are refused at load: their encoded forms are too short to
/// tell from ordinary text.
pub const MIN_VALUE_LEN: usize = 8;
/// Percent-decoding rounds tried on a haystack (`%2564` is `%64` is `d`).
const DECODE_ROUNDS: usize = 2;

/// The forms of one needle the scan looks for.
#[derive(Clone)]
pub(crate) struct Needles {
    /// Compared against the lowercased haystack.
    folded: Vec<Vec<u8>>,
    /// Compared against the haystack as sent (base64 is case-sensitive).
    exact: Vec<Vec<u8>>,
}

impl Needles {
    /// A placeholder: its own text, case-blind.
    pub(crate) fn placeholder(p: &str) -> Needles {
        Needles {
            folded: vec![p.to_ascii_lowercase().into_bytes()],
            exact: Vec::new(),
        }
    }

    /// A secret's value: case-blind text and hex, and base64 at three
    /// alignments in two alphabets. Empty for a value too short to guard.
    pub(crate) fn value(v: &str) -> Needles {
        let b = v.as_bytes();
        if b.len() < MIN_VALUE_LEN {
            return Needles {
                folded: Vec::new(),
                exact: Vec::new(),
            };
        }
        let mut folded = vec![v.to_ascii_lowercase().into_bytes()];
        let hex: String = b.iter().map(|x| format!("{x:02x}")).collect();
        folded.push(hex.into_bytes());
        let mut exact = Vec::new();
        for core in base64_cores(b) {
            if core.len() >= MIN_VALUE_LEN && !exact.contains(&core) {
                exact.push(core);
            }
        }
        Needles { folded, exact }
    }

    fn is_empty(&self) -> bool {
        self.folded.is_empty() && self.exact.is_empty()
    }
}

/// The base64 characters that depend only on `v`'s bytes, for `v` starting
/// at each byte offset modulo 3 inside a longer encoded run, in the standard
/// and the URL-safe alphabet, unpadded.
fn base64_cores(v: &[u8]) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    let n = v.len();
    for shift in 0..3usize {
        let mut buf = vec![0u8; shift];
        buf.extend_from_slice(v);
        let start = (8 * shift).div_ceil(6);
        let end = (8 * shift + 8 * n) / 6;
        for engine in [&STANDARD_NO_PAD, &URL_SAFE_NO_PAD] {
            let enc = engine.encode(&buf).into_bytes();
            if end > start && end <= enc.len() {
                out.push(enc[start..end].to_vec());
            }
        }
    }
    out
}

/// Whether `hay` holds any form of `n`, as sent or after percent-decoding.
pub(crate) fn holds(hay: &[u8], n: &Needles) -> bool {
    if n.is_empty() || hay.is_empty() {
        return false;
    }
    if holds_plain(hay, n) {
        return true;
    }
    let mut cur: Vec<u8> = hay.to_vec();
    for _ in 0..DECODE_ROUNDS {
        if !cur.contains(&b'%') && !cur.contains(&b'\\') {
            break;
        }
        let next = unescape(&cur);
        if next == cur {
            break;
        }
        if holds_plain(&next, n) {
            return true;
        }
        cur = next;
    }
    false
}

/// Whether a host name holds any form of `n`: as written, and with its dots
/// removed (a needle split over labels).
pub(crate) fn host_holds(host: &str, n: &Needles) -> bool {
    if holds(host.as_bytes(), n) {
        return true;
    }
    let joined: String = host.chars().filter(|c| *c != '.').collect();
    holds(joined.as_bytes(), n)
}

fn holds_plain(hay: &[u8], n: &Needles) -> bool {
    if !n.exact.is_empty() && n.exact.iter().any(|x| memmem::find(hay, x).is_some()) {
        return true;
    }
    if n.folded.is_empty() {
        return false;
    }
    let low = hay.to_ascii_lowercase();
    n.folded.iter().any(|x| memmem::find(&low, x).is_some())
}

/// One round of `%XX` decoding (and `+` left as is), and a JSON `\/` taken as
/// `/`. Bytes that are not a valid escape are kept.
fn unescape(s: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(s.len());
    let mut i = 0;
    while i < s.len() {
        match s[i] {
            b'%' if i + 2 < s.len() => match (hexval(s[i + 1]), hexval(s[i + 2])) {
                (Some(a), Some(b)) => {
                    out.push(a << 4 | b);
                    i += 3;
                }
                _ => {
                    out.push(b'%');
                    i += 1;
                }
            },
            b'\\' if i + 1 < s.len() && s[i + 1] == b'/' => {
                out.push(b'/');
                i += 2;
            }
            c => {
                out.push(c);
                i += 1;
            }
        }
    }
    out
}

fn hexval(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

/// Replace every `from` with `to` in one left-to-right pass, never scanning
/// what was put in (srt's rule: \"the substituted real value is never
/// rescanned\", `body-substitution.js:70-75`). Returns `None` when nothing
/// matched. Placeholders never overlap (section 8.2's form), so the order of
/// `pairs` does not change the result.
pub(crate) fn swap(hay: &[u8], pairs: &[(&[u8], &[u8])]) -> Option<Vec<u8>> {
    if pairs.is_empty() {
        return None;
    }
    let mut out = Vec::with_capacity(hay.len());
    let mut i = 0;
    let mut any = false;
    'outer: while i < hay.len() {
        for (from, to) in pairs {
            if !from.is_empty() && hay[i..].starts_with(from) {
                out.extend_from_slice(to);
                i += from.len();
                any = true;
                continue 'outer;
            }
        }
        out.push(hay[i]);
        i += 1;
    }
    any.then_some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    const V: &str = "fake-secret-value-not-a-token-0000";

    #[test]
    fn a_value_is_found_as_text_hex_and_base64_at_every_alignment() {
        let n = Needles::value(V);
        assert!(holds(format!("x={V}").as_bytes(), &n));
        assert!(holds(V.to_uppercase().as_bytes(), &n), "case-blind");
        let hex: String = V.bytes().map(|b| format!("{b:02x}")).collect();
        assert!(holds(hex.as_bytes(), &n));
        for pre in ["", "a", "ab", "abc", "abcd"] {
            for engine in [&STANDARD_NO_PAD, &URL_SAFE_NO_PAD] {
                let enc = engine.encode(format!("{pre}{V}tail"));
                assert!(holds(enc.as_bytes(), &n), "base64 after {pre:?}");
            }
        }
    }

    #[test]
    fn a_value_is_found_after_percent_decoding_twice_and_a_json_slash_escape() {
        let n = Needles::value("abc/def+ghi123");
        assert!(holds(b"q=abc%2Fdef%2Bghi123", &n));
        assert!(holds(b"q=abc%252Fdef%252Bghi123", &n));
        assert!(holds(br#"{"t":"abc\/def+ghi123"}"#, &n));
    }

    #[test]
    fn a_short_value_is_never_searched_for() {
        let n = Needles::value("short");
        assert!(!holds(b"short short", &n));
    }

    #[test]
    fn a_placeholder_split_over_host_labels_is_found() {
        let n = Needles::placeholder("dermsecret_github_0123456789abcdef");
        assert!(host_holds(
            "dermsecret_github_0123.456789abcdef.evil.test",
            &n
        ));
        assert!(host_holds(
            "DERMSECRET_GITHUB_0123456789ABCDEF.evil.test",
            &n
        ));
        assert!(!host_holds("api.github.com", &n));
    }

    #[test]
    fn ordinary_text_is_not_a_hit() {
        let n = Needles::value(V);
        assert!(!holds(b"the quick brown fox jumps over the lazy dog", &n));
        let p = Needles::placeholder("dermsecret_github_0123456789abcdef");
        assert!(
            !holds(b"dermsecret_github_0123456789abcde", &p),
            "one short"
        );
    }

    #[test]
    fn swap_is_one_pass_and_never_rescans_what_it_put_in() {
        let a: &[u8] = b"PH_A";
        let b: &[u8] = b"PH_B";
        // A's value holds B's placeholder: it must not be swapped again.
        let out = swap(b"x PH_A y PH_B", &[(a, b"val PH_B"), (b, b"vb")]).unwrap();
        assert_eq!(out, b"x val PH_B y vb");
        assert!(swap(b"nothing", &[(a, b"v")]).is_none());
    }

    #[test]
    fn percent_at_the_end_is_kept() {
        assert_eq!(unescape(b"a%"), b"a%");
        assert_eq!(unescape(b"a%4"), b"a%4");
        assert_eq!(unescape(b"a%41"), b"aA");
    }
}
