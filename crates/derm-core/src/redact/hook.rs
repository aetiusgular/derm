//! The hook core's redactor, ported from
//! `packages/derm-claude-plugin/src/core/redact.ts` at `e29ce27` by the wave
//! 5b base. Best effort: it finds values whose key looks like a secret, a few
//! well-known token shapes and PEM private keys; it cannot find an arbitrary
//! secret in text and is never presented as doing so.
//!
//! The TypeScript works on UTF-16 code units and JavaScript's regular
//! expressions; this works on `char`s. Every pattern is ASCII, JavaScript's
//! `\w` and `\b` are ASCII-only, and `\s` is read as JavaScript's
//! [`js_space`], so the two give the same output on the same text (tests:
//! `random_strings_match_the_typescript_output`, recorded from the
//! TypeScript in `contracts/fixtures/redact/`).

use serde_json::{Map, Value};

/// The marker the hook core writes (`REDACTED` in `redact.ts`).
pub const REDACTED: &str = "[redacted by derm]";

/// The fork's property-name pattern (`SECRET_LIKE`, `dockerArgs.ts:38` at
/// `159ef3e`), case-insensitive.
pub fn secret_like_key(key: &str) -> bool {
    let k = key.to_ascii_lowercase();
    KEY_WORDS.iter().any(|w| k.contains(w))
}

const KEY_WORDS: [&str; 7] = [
    "token",
    "secret",
    "password",
    "passwd",
    "apikey",
    "api_key",
    "private_key",
];

/// One redaction: the text and how many values it replaced.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Redaction {
    pub text: String,
    pub count: usize,
}

/// JavaScript's `\s` (ECMA-262 WhiteSpace and LineTerminator).
pub fn js_space(c: char) -> bool {
    matches!(
        c,
        '\t' | '\n' | '\u{0B}' | '\u{0C}' | '\r' | ' ' | '\u{A0}' | '\u{1680}' | '\u{2000}'
            ..='\u{200A}'
                | '\u{2028}'
                | '\u{2029}'
                | '\u{202F}'
                | '\u{205F}'
                | '\u{3000}'
                | '\u{FEFF}'
    )
}

fn word(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_'
}

fn run_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-')
}

fn quote(c: Option<&char>) -> bool {
    matches!(c, Some('"') | Some('\''))
}

fn has_key_word(run: &[char]) -> bool {
    let s: String = run.iter().collect();
    secret_like_key(&s)
}

/// End of `\s*<sep>\s*` at `at`, where `sep` is one of `seps`.
fn sep_end(c: &[char], at: usize, seps: &[char]) -> Option<usize> {
    let mut i = at;
    while i < c.len() && js_space(c[i]) {
        i += 1;
    }
    if i < c.len() && seps.contains(&c[i]) {
        i += 1;
        while i < c.len() && js_space(c[i]) {
            i += 1;
        }
        Some(i)
    } else {
        None
    }
}

/// The maximal runs of `[A-Za-z0-9_.-]` from `from`, in order.
fn next_run(c: &[char], from: usize) -> Option<(usize, usize)> {
    let mut s = from;
    while s < c.len() && !run_char(c[s]) {
        s += 1;
    }
    if s >= c.len() {
        return None;
    }
    let mut e = s;
    while e < c.len() && run_char(c[e]) {
        e += 1;
    }
    Some((s, e))
}

/// `"key": "value"` pairs: the value replaced, the rest kept.
fn redact_quoted(c: &[char]) -> (Vec<char>, usize) {
    let red: Vec<char> = REDACTED.chars().collect();
    let mut out = Vec::with_capacity(c.len());
    let mut count = 0;
    let mut copied = 0;
    let mut pos = 0;
    let mut from = 0;
    while let Some((s, e)) = next_run(c, from) {
        from = e;
        if s < pos + 1 || !quote(c.get(s - 1)) || !quote(c.get(e)) || !has_key_word(&c[s..e]) {
            continue;
        }
        let Some(sep) = sep_end(c, e + 1, &[':']) else {
            continue;
        };
        let Some(&q) = c.get(sep).filter(|q| **q == '"' || **q == '\'') else {
            continue;
        };
        let mut i = sep + 1;
        let mut closed = None;
        while i < c.len() {
            if c[i] == '\\' {
                match c.get(i + 1) {
                    None | Some('\n') | Some('\r') | Some('\u{2028}') | Some('\u{2029}') => break,
                    _ => {
                        i += 2;
                        continue;
                    }
                }
            }
            if c[i] == q {
                closed = Some(i);
                break;
            }
            i += 1;
        }
        let Some(closed) = closed else {
            continue;
        };
        let value = &c[sep + 1..closed];
        if !value.is_empty() && value != red.as_slice() {
            out.extend_from_slice(&c[copied..sep + 1]);
            out.extend_from_slice(&red);
            copied = closed;
            count += 1;
        }
        pos = closed + 1;
        from = pos;
    }
    out.extend_from_slice(&c[copied..]);
    (out, count)
}

/// `key=value` and `key: value` pairs: the value replaced, the rest kept.
fn redact_bare(c: &[char]) -> (Vec<char>, usize) {
    let red: Vec<char> = REDACTED.chars().collect();
    let mut out = Vec::with_capacity(c.len());
    let mut count = 0;
    let mut copied = 0;
    let mut from = 0;
    while let Some((s, e)) = next_run(c, from) {
        from = e;
        if !c[s..e].iter().any(|ch| word(*ch)) || !has_key_word(&c[s..e]) {
            continue;
        }
        let Some(sep) = sep_end(c, e, &['=', ':']) else {
            continue;
        };
        let peek: String = c[sep..(sep + 9).min(c.len())].iter().collect();
        if peek.to_lowercase() == "[redacted" {
            continue;
        }
        let mut v = sep;
        while v < c.len() && !js_space(c[v]) && !matches!(c[v], '&' | ';' | '"' | '\'' | ',' | '}')
        {
            v += 1;
        }
        if v == sep {
            continue;
        }
        if !c[sep..v].iter().all(|ch| ch.is_ascii_digit()) {
            out.extend_from_slice(&c[copied..sep]);
            out.extend_from_slice(&red);
            copied = v;
            count += 1;
        }
        from = v;
    }
    out.extend_from_slice(&c[copied..]);
    (out, count)
}

/// A token shape: a literal head (one of `heads`), then a body of `body`
/// characters, `min` long or more (`max` at most), and JavaScript's `\b`
/// before the head and, when `end_boundary`, after the body.
struct Shape {
    heads: &'static [&'static str],
    body: fn(char) -> bool,
    min: usize,
    max: usize,
    end_boundary: bool,
}

fn alnum(c: char) -> bool {
    c.is_ascii_alphanumeric()
}
fn upper_digit(c: char) -> bool {
    c.is_ascii_uppercase() || c.is_ascii_digit()
}
fn word_dash(c: char) -> bool {
    word(c) || c == '-'
}
fn alnum_dash(c: char) -> bool {
    alnum(c) || c == '-'
}

/// `TOKEN_SHAPES` in `redact.ts`, in its order (sources in
/// `plans/parallel/tk_lane_F.md`, Research, and integration w5's continue).
const SHAPES: [Shape; 6] = [
    // \bgh[pousr]_[A-Za-z0-9]{36,255}\b: GitHub classic and app tokens.
    Shape {
        heads: &["ghp_", "gho_", "ghu_", "ghs_", "ghr_"],
        body: alnum,
        min: 36,
        max: 255,
        end_boundary: true,
    },
    // \bgithub_pat_[A-Za-z0-9_]{22,255}\b
    Shape {
        heads: &["github_pat_"],
        body: word,
        min: 22,
        max: 255,
        end_boundary: true,
    },
    // \b(?:AKIA|ASIA)[A-Z0-9]{16}\b
    Shape {
        heads: &["AKIA", "ASIA"],
        body: upper_digit,
        min: 16,
        max: 16,
        end_boundary: true,
    },
    // \bsk-ant-[A-Za-z0-9_-]{20,}\b
    Shape {
        heads: &["sk-ant-"],
        body: word_dash,
        min: 20,
        max: usize::MAX,
        end_boundary: true,
    },
    // \bxox[abposr]-[A-Za-z0-9-]{10,}\b
    Shape {
        heads: &["xoxa-", "xoxb-", "xoxp-", "xoxo-", "xoxs-", "xoxr-"],
        body: alnum_dash,
        min: 10,
        max: usize::MAX,
        end_boundary: true,
    },
    // \bsk-(?:proj|svcacct|admin)-[A-Za-z0-9_-]{40,}
    Shape {
        heads: &["sk-proj-", "sk-svcacct-", "sk-admin-"],
        body: word_dash,
        min: 40,
        max: usize::MAX,
        end_boundary: false,
    },
];

fn starts_with(c: &[char], at: usize, head: &str) -> bool {
    let n = head.chars().count();
    at + n <= c.len() && c[at..at + n].iter().copied().eq(head.chars())
}

/// `\b` between `c[at - 1]` and `c[at]` (JavaScript's, ASCII words).
fn boundary(c: &[char], at: usize) -> bool {
    let before = at > 0 && word(c[at - 1]);
    let after = at < c.len() && word(c[at]);
    before != after
}

/// Where a match of `shape` that starts at `at` ends, as JavaScript's
/// backtracking finds it: the longest body allowed that meets the end.
fn shape_end(shape: &Shape, c: &[char], at: usize) -> Option<usize> {
    if !boundary(c, at) {
        return None;
    }
    for head in shape.heads {
        if !starts_with(c, at, head) {
            continue;
        }
        let b = at + head.chars().count();
        let mut run = 0;
        while b + run < c.len() && run < shape.max && (shape.body)(c[b + run]) {
            run += 1;
        }
        if run < shape.min {
            continue;
        }
        if !shape.end_boundary {
            return Some(b + run);
        }
        let mut k = run;
        while k >= shape.min {
            if boundary(c, b + k) {
                return Some(b + k);
            }
            k -= 1;
        }
    }
    None
}

fn replace_shape(shape: &Shape, c: Vec<char>, count: &mut usize) -> Vec<char> {
    let red: Vec<char> = REDACTED.chars().collect();
    let mut out = Vec::with_capacity(c.len());
    let mut i = 0;
    while i < c.len() {
        if let Some(end) = shape_end(shape, &c, i) {
            out.extend_from_slice(&red);
            *count += 1;
            // JavaScript's `replace` with an empty match would step one on;
            // no shape here matches empty.
            i = end;
        } else {
            out.push(c[i]);
            i += 1;
        }
    }
    out
}

/// End of a PEM label (`-----BEGIN ` or `-----END ` at `at`) followed by a
/// maximal run of `[A-Z0-9 ]` that ends in `PRIVATE KEY` and then five
/// dashes; `None` when it is not one.
fn pem_label_end(c: &[char], at: usize, label: &str) -> Option<usize> {
    let start = at + label.chars().count();
    let mut run_end = start;
    while run_end < c.len()
        && (c[run_end].is_ascii_uppercase() || c[run_end].is_ascii_digit() || c[run_end] == ' ')
    {
        run_end += 1;
    }
    let tail = "PRIVATE KEY";
    let tl = tail.chars().count();
    if run_end - start < tl || !starts_with(c, run_end - tl, tail) {
        return None;
    }
    starts_with(c, run_end, "-----").then_some(run_end + 5)
}

fn find(c: &[char], from: usize, needle: &str) -> Option<usize> {
    (from..c.len()).find(|&i| starts_with(c, i, needle))
}

fn redact_pem(c: Vec<char>) -> (Vec<char>, usize) {
    const BEGIN: &str = "-----BEGIN ";
    const END: &str = "-----END ";
    let red: Vec<char> = REDACTED.chars().collect();
    let mut out = Vec::new();
    let mut count = 0;
    let mut from = 0;
    let mut b = find(&c, 0, BEGIN);
    while let Some(at) = b {
        if at < from {
            b = find(&c, at + 1, BEGIN);
            continue;
        }
        let Some(header_end) = pem_label_end(&c, at, BEGIN) else {
            b = find(&c, at + 1, BEGIN);
            continue;
        };
        let mut footer_end = None;
        let mut e = find(&c, header_end, END);
        while let Some(eat) = e {
            footer_end = pem_label_end(&c, eat, END);
            if footer_end.is_some() {
                break;
            }
            e = find(&c, eat + 1, END);
        }
        out.extend_from_slice(&c[from..at]);
        out.extend_from_slice(&red);
        count += 1;
        match footer_end {
            None => {
                // No END line: a key cut short is still a key (W4-R6).
                from = c.len();
                break;
            }
            Some(fe) => {
                from = fe;
                b = find(&c, fe, BEGIN);
            }
        }
    }
    if count == 0 {
        return (c, 0);
    }
    out.extend_from_slice(&c[from..]);
    (out, count)
}

/// Redacts secret-like values in one string, in time linear in its length
/// (`redactText`).
pub fn redact_text(text: &str) -> Redaction {
    let c: Vec<char> = text.chars().collect();
    let (q, qn) = redact_quoted(&c);
    let (b, bn) = redact_bare(&q);
    let mut count = qn + bn;
    let mut out = b;
    for shape in &SHAPES {
        out = replace_shape(shape, out, &mut count);
    }
    let (p, pn) = redact_pem(out);
    Redaction {
        text: p.into_iter().collect(),
        count: count + pn,
    }
}

/// Whether any token shape occurs in `text` (`TOKEN_SHAPES.some`).
pub fn has_token_shape(text: &str) -> bool {
    let c: Vec<char> = text.chars().collect();
    SHAPES
        .iter()
        .any(|s| (0..c.len()).any(|i| shape_end(s, &c, i).is_some()))
}

/// Redacts every string inside a JSON value; a string under a secret-like key
/// is replaced whole (`redactValue`). Returns the new value and the count.
pub fn redact_value(value: &Value) -> (Value, usize) {
    fn walk(v: &Value, key_secret: bool, count: &mut usize) -> Value {
        match v {
            Value::String(s) => {
                if key_secret && !s.is_empty() && s != REDACTED {
                    *count += 1;
                    return Value::String(REDACTED.into());
                }
                let r = redact_text(s);
                *count += r.count;
                Value::String(r.text)
            }
            Value::Array(a) => Value::Array(a.iter().map(|x| walk(x, key_secret, count)).collect()),
            Value::Object(o) => {
                let mut m = Map::new();
                for (k, x) in o {
                    m.insert(k.clone(), walk(x, secret_like_key(k), count));
                }
                Value::Object(m)
            }
            other => other.clone(),
        }
    }
    let mut count = 0;
    let out = walk(value, false, &mut count);
    (out, count)
}

#[cfg(test)]
#[path = "hook_tests.rs"]
mod tests;
