//! Where a secret's value may go beside the headers, and how it is written
//! there (review W6C-S8, note BD; Tony's call of 13 Nov).
//!
//! A placement names its field: `query:<param>` or `body:<path>`. A value is
//! swapped only into that field, and written for its place: percent-encoded
//! in a query or a form body (RFC 3986's unreserved characters as they are),
//! JSON-escaped inside a JSON string. A body is read only as JSON
//! (`application/json`, `+json`) or a form (`application/x-www-form-
//! urlencoded`), the parser chosen by its `Content-Type` (varlock's rule).
//! When any copy of the placeholder sits anywhere but the named field, or in
//! a spelling the parser decodes (`\u` in JSON, `%` in a form), nothing of
//! that secret is swapped: the placeholder stays the useless fake, and
//! nothing leaks.

use serde_json::Value;

/// One place a secret's value may go.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Spot {
    /// A dotted path into a JSON body (`auth.token`, `items[0].key`), or one
    /// field of a form body.
    Body(String),
    /// One query parameter.
    Query(String),
}

/// A placement item: `body:<path>` or `query:<param>`; `None` for anything
/// else, bare `body` and `query` included.
pub fn spot(item: &str) -> Option<Spot> {
    if let Some(p) = item.strip_prefix("body:") {
        return path(p).map(|_| Spot::Body(p.to_string()));
    }
    let p = item.strip_prefix("query:")?;
    let ok = !p.is_empty()
        && p.len() <= 64
        && p.bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"-._~".contains(&c));
    ok.then(|| Spot::Query(p.to_string()))
}

/// One step of a body path.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Step {
    Key(String),
    Index(usize),
}

/// A body path's steps: names of 1 to 64 of `A-Z a-z 0-9 _ -`, joined by
/// `.`, each followed by any number of `[n]`; at most 16 names.
fn path(p: &str) -> Option<Vec<Step>> {
    let mut steps = Vec::new();
    let names: Vec<&str> = p.split('.').collect();
    if names.len() > 16 {
        return None;
    }
    for part in names {
        let (name, mut rest) = part.split_at(part.find('[').unwrap_or(part.len()));
        if name.is_empty()
            || name.len() > 64
            || !name
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || c == b'_' || c == b'-')
        {
            return None;
        }
        steps.push(Step::Key(name.to_string()));
        while !rest.is_empty() {
            let inner = rest.strip_prefix('[')?;
            let end = inner.find(']')?;
            let n = &inner[..end];
            if n.is_empty() || n.len() > 6 || !n.bytes().all(|c| c.is_ascii_digit()) {
                return None;
            }
            steps.push(Step::Index(n.parse().ok()?));
            rest = &inner[end + 1..];
        }
    }
    Some(steps)
}

/// Percent-encoding with RFC 3986's unreserved characters left as they are.
pub fn pct_encode(v: &str) -> String {
    let mut out = String::with_capacity(v.len());
    for b in v.bytes() {
        if b.is_ascii_alphanumeric() || b"-._~".contains(&b) {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// A query or form name or value as it reads, `+` as a space; `None` for a
/// malformed escape.
fn pct_decode(v: &str) -> Option<Vec<u8>> {
    let b = v.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'%' => {
                let hex = std::str::from_utf8(b.get(i + 1..i + 3)?).ok()?;
                out.push(u8::from_str_radix(hex, 16).ok()?);
                i += 3;
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            c => {
                out.push(c);
                i += 1;
            }
        }
    }
    Some(out)
}

/// A value as the inside of a JSON string (RFC 8259 section 7).
pub fn json_escape(v: &str) -> String {
    let mut out = String::with_capacity(v.len() + 2);
    for c in v.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

#[derive(Clone, Copy)]
/// One secret to swap: its placeholder, its value, and the field it may go
/// into.
pub struct Want<'a> {
    pub placeholder: &'a str,
    pub value: &'a str,
    pub field: &'a str,
}

fn count(hay: &[u8], needle: &[u8]) -> usize {
    memchr::memmem::find_iter(hay, needle).count()
}

/// The `&`-joined pairs of a query or form body with each wanted secret's
/// value written into its named field, percent-encoded. A secret is swapped
/// only when every copy of its placeholder in `text` is the whole value of
/// its named field; the returned indices name the swapped wants.
pub fn swap_pairs(text: &str, wants: &[Want<'_>]) -> (Option<String>, Vec<usize>) {
    let pairs: Vec<&str> = text.split('&').collect();
    let mut done = Vec::new();
    let mut fields: Vec<Option<String>> = vec![None; pairs.len()];
    for (w, want) in wants.iter().enumerate() {
        let total = count(text.as_bytes(), want.placeholder.as_bytes());
        if total == 0 {
            continue;
        }
        let hits: Vec<usize> = pairs
            .iter()
            .enumerate()
            .filter(|(_, p)| {
                let (k, v) = p.split_once('=').unwrap_or((p, ""));
                pct_decode(k).as_deref() == Some(want.field.as_bytes()) && v == want.placeholder
            })
            .map(|(i, _)| i)
            .collect();
        if hits.len() != total {
            continue;
        }
        for i in hits {
            let k = pairs[i].split_once('=').map_or(pairs[i], |(k, _)| k);
            fields[i] = Some(format!("{k}={}", pct_encode(want.value)));
        }
        done.push(w);
    }
    if done.is_empty() {
        return (None, done);
    }
    let out: Vec<String> = pairs
        .iter()
        .zip(fields)
        .map(|(p, f)| f.unwrap_or_else(|| p.to_string()))
        .collect();
    (Some(out.join("&")), done)
}

/// Every place a JSON string holds `needle`: the count in string values at
/// `steps` (`at`), and in any string or key anywhere (`all`).
fn json_counts(v: &Value, steps: Option<&[Step]>, needle: &str, at: &mut usize, all: &mut usize) {
    let here = steps.is_some_and(|s| s.is_empty());
    match v {
        Value::String(s) => {
            let n = s.matches(needle).count();
            *all += n;
            if here {
                *at += n;
            }
        }
        Value::Array(items) => {
            for (i, item) in items.iter().enumerate() {
                let next = match steps {
                    Some([Step::Index(j), rest @ ..]) if *j == i => Some(rest),
                    _ => None,
                };
                json_counts(item, next, needle, at, all);
            }
        }
        Value::Object(map) => {
            for (k, item) in map {
                *all += k.matches(needle).count();
                let next = match steps {
                    Some([Step::Key(name), rest @ ..]) if name == k => Some(rest),
                    _ => None,
                };
                json_counts(item, next, needle, at, all);
            }
        }
        _ => {}
    }
}

/// A JSON body with each wanted secret's value written, JSON-escaped, into
/// the string at its path. A secret is swapped only when every copy of its
/// placeholder in the raw body is a literal copy inside the string at its
/// path (none escaped, none in a key or another field); the returned indices
/// name the swapped wants. `None` for a body that is not JSON.
pub fn swap_json(body: &[u8], wants: &[Want<'_>]) -> Option<(Vec<u8>, Vec<usize>)> {
    let parsed: Value = serde_json::from_slice(body).ok()?;
    let mut pairs: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
    let mut done = Vec::new();
    for (w, want) in wants.iter().enumerate() {
        let raw = count(body, want.placeholder.as_bytes());
        let Some(steps) = path(want.field) else {
            continue;
        };
        let (mut at, mut all) = (0, 0);
        json_counts(&parsed, Some(&steps), want.placeholder, &mut at, &mut all);
        if raw == 0 || raw != all || at != all {
            continue;
        }
        pairs.push((
            want.placeholder.as_bytes().to_vec(),
            json_escape(want.value).into_bytes(),
        ));
        done.push(w);
    }
    if done.is_empty() {
        return Some((body.to_vec(), done));
    }
    let refs: Vec<(&[u8], &[u8])> = pairs
        .iter()
        .map(|(a, b)| (a.as_slice(), b.as_slice()))
        .collect();
    let out = crate::scan::swap(body, &refs)?;
    serde_json::from_slice::<Value>(&out).ok()?;
    Some((out, done))
}

/// How a body is read for a swap, by its `Content-Type`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BodyKind {
    Json,
    Form,
    Other,
}

pub fn body_kind(headers: &[(String, String)]) -> BodyKind {
    let ct = headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("content-type"))
        .map(|(_, v)| {
            v.split(';')
                .next()
                .unwrap_or("")
                .trim()
                .to_ascii_lowercase()
        });
    match ct.as_deref() {
        Some("application/json") => BodyKind::Json,
        Some(t) if t.starts_with("application/") && t.ends_with("+json") => BodyKind::Json,
        Some("application/x-www-form-urlencoded") => BodyKind::Form,
        _ => BodyKind::Other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_placement_names_its_field() {
        assert_eq!(spot("query:key"), Some(Spot::Query("key".into())));
        assert_eq!(
            spot("body:items[0].auth.token"),
            Some(Spot::Body("items[0].auth.token".into()))
        );
        for bad in [
            "body",
            "query",
            "body:",
            "query:",
            "body:a..b",
            "body:a[]",
            "body:a[x]",
            "body:a b",
            "query:a&b",
            "query:a=b",
            "header:x",
            "url",
        ] {
            assert_eq!(spot(bad), None, "{bad}");
        }
    }

    #[test]
    fn encodings_are_the_rfcs() {
        assert_eq!(pct_encode("a&b=c d~-._/"), "a%26b%3Dc%20d~-._%2F");
        assert_eq!(json_escape("a\"b\\c\nd\u{1}"), "a\\\"b\\\\c\\nd\\u0001");
    }
}
