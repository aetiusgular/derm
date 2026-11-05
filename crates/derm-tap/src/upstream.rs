//! Where the tap forwards: a fixed table, never a host taken from a request.
//!
//! The second path segment after the route names an upstream by key
//! (`/r/<route>/anthropic/v1/messages`); the tap joins the rest of the path
//! to that key's base. A key the table does not hold is refused, so the tap
//! is never an open proxy (universal plan lane S: "The tap refuses any
//! upstream it was not configured for"). Extra upstreams, such as the box's
//! local llama-swap, come only from the tap's `Config`, which the daemon
//! builds from what the user confirmed (case 113); none is read from a
//! request, a harness's settings or a project file.

use std::collections::BTreeMap;

/// One upstream: its base URL (scheme, host, optional port and path prefix,
/// no trailing slash) and whether it is the user's own local server, where
/// case 94's fold applies.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Upstream {
    pub base: String,
    pub local: bool,
}

impl Upstream {
    pub fn remote(base: &str) -> Self {
        Upstream {
            base: base.trim_end_matches('/').to_string(),
            local: false,
        }
    }

    /// The host (and port, when not the scheme's) for records: never the
    /// path, never a query.
    pub fn host(&self) -> String {
        let rest = self
            .base
            .split_once("://")
            .map(|(_, r)| r)
            .unwrap_or(&self.base);
        rest.split('/').next().unwrap_or("").to_string()
    }
}

/// The keys every tap knows. `openai-auto` is Codex's: the ChatGPT backend
/// when the request carries a ChatGPT login, else the API (Codex 0.163.0's
/// own rule, `model-provider-info/src/lib.rs:427-445`).
pub const ANTHROPIC: &str = "anthropic";
pub const OPENAI: &str = "openai";
pub const CHATGPT: &str = "chatgpt";
pub const OPENAI_AUTO: &str = "openai-auto";
pub const GEMINI: &str = "gemini";

/// The built-in table.
pub fn builtin() -> BTreeMap<String, Upstream> {
    let mut t = BTreeMap::new();
    t.insert(
        ANTHROPIC.into(),
        Upstream::remote("https://api.anthropic.com"),
    );
    t.insert(OPENAI.into(), Upstream::remote("https://api.openai.com/v1"));
    t.insert(
        CHATGPT.into(),
        Upstream::remote("https://chatgpt.com/backend-api/codex"),
    );
    t.insert(
        GEMINI.into(),
        Upstream::remote("https://generativelanguage.googleapis.com"),
    );
    t
}

/// A key as written: lowercase letters, digits and `-`, at most 32.
pub fn key_well_formed(key: &str) -> bool {
    !key.is_empty()
        && key.len() <= 32
        && key
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// `/<key>/<rest>` split into the key and `/<rest>` (the query kept).
pub fn split_key(path: &str) -> Option<(&str, &str)> {
    let rest = path.strip_prefix('/')?;
    let (key, tail) = match rest.find(['/', '?']) {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, ""),
    };
    key_well_formed(key).then_some((key, tail))
}

/// The rest of a path, checked before it is joined to a base: it must start
/// with `/` or `?` (or be empty), hold no `..` segment, no `//`, no `@`, no
/// `\`, no `#`, no control or non-ASCII byte, so the joined URL can only name
/// the base's host.
pub fn tail_is_safe(tail: &str) -> bool {
    if tail.is_empty() {
        return true;
    }
    if !(tail.starts_with('/') || tail.starts_with('?')) {
        return false;
    }
    let (path, _query) = tail.split_once('?').unwrap_or((tail, ""));
    if path.contains("//") || path.split('/').any(|seg| seg == ".." || seg == ".") {
        return false;
    }
    let lower = path.to_ascii_lowercase();
    if lower.contains("%2e") || lower.contains("%2f") || lower.contains("%5c") {
        return false;
    }
    tail.bytes()
        .all(|b| b.is_ascii_graphic() && !matches!(b, b'@' | b'\\' | b'#'))
}

/// Which of `openai` or `chatgpt` an `openai-auto` request goes to, from its
/// credential only: a `chatgpt-account-id` header, or a bearer that is a JWT
/// (three dot-separated base64url parts), means a ChatGPT login. The
/// credential is read here and nowhere else, and never kept.
pub fn openai_auto_key(has_account_header: bool, authorization: Option<&str>) -> &'static str {
    if has_account_header {
        return CHATGPT;
    }
    let bearer = authorization
        .and_then(|v| {
            let v = v.trim();
            v.get(..7)
                .filter(|p| p.eq_ignore_ascii_case("bearer "))
                .map(|_| v[7..].trim())
        })
        .unwrap_or("");
    let parts: Vec<&str> = bearer.split('.').collect();
    let jwt = parts.len() == 3
        && parts.iter().all(|p| {
            !p.is_empty()
                && p.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        });
    if jwt {
        CHATGPT
    } else {
        OPENAI
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_and_tails_cannot_reach_another_host() {
        assert_eq!(
            split_key("/anthropic/v1/messages?beta=true"),
            Some(("anthropic", "/v1/messages?beta=true"))
        );
        assert_eq!(
            split_key("/openai-auto/responses"),
            Some(("openai-auto", "/responses"))
        );
        assert_eq!(split_key("/anthropic"), Some(("anthropic", "")));
        assert_eq!(split_key("/Anthropic/v1"), None);
        assert_eq!(split_key("/evil.com/v1"), None);
        assert_eq!(split_key("//evil.com/v1"), None);
        for good in [
            "",
            "/v1/messages",
            "/v1/messages?beta=true",
            "/v1beta/models/g:streamGenerateContent?alt=sse",
        ] {
            assert!(tail_is_safe(good), "{good}");
        }
        for bad in [
            "/v1/../../etc",
            "/v1//x",
            "@evil.com/v1",
            "/v1@evil.com",
            "/v1/%2e%2e/x",
            "/a%2Fb",
            "/v1\\x",
            "/v1#frag",
            "/v1/ x",
            "v1/messages",
            "/v1/./x",
            "/caf\u{e9}",
        ] {
            assert!(!tail_is_safe(bad), "{bad}");
        }
    }

    #[test]
    fn the_builtin_table_names_only_the_providers_hosts() {
        let t = builtin();
        let hosts: Vec<String> = t.values().map(Upstream::host).collect();
        assert_eq!(
            hosts,
            vec![
                "api.anthropic.com",
                "chatgpt.com",
                "generativelanguage.googleapis.com",
                "api.openai.com"
            ]
        );
        assert!(t
            .values()
            .all(|u| u.base.starts_with("https://") && !u.local));
        assert!(
            !t.contains_key(OPENAI_AUTO),
            "openai-auto is a choice between two, not a host"
        );
    }

    #[test]
    fn openai_auto_reads_the_credential_shape_only() {
        assert_eq!(openai_auto_key(true, None), CHATGPT);
        assert_eq!(
            openai_auto_key(false, Some("Bearer eyJhbGciOi.eyJzdWIiOi.c2lnbmF0dXJl")),
            CHATGPT
        );
        assert_eq!(openai_auto_key(false, Some("bearer aaa.bbb.ccc")), CHATGPT);
        assert_eq!(
            openai_auto_key(false, Some("Bearer sk-proj-abc123")),
            OPENAI
        );
        assert_eq!(openai_auto_key(false, Some("Bearer a.b")), OPENAI);
        assert_eq!(openai_auto_key(false, Some("Bearer a..c")), OPENAI);
        assert_eq!(openai_auto_key(false, None), OPENAI);
    }
}
