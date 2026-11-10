//! Which chat a request belongs to.
//!
//! Every chat `derm run` starts gets a route: 32 hex characters derived from
//! its chat token, carried to the tap either as the first path segment after
//! `/r/` in the harness's base URL (`ANTHROPIC_BASE_URL`, which sits in the
//! launch environment only) or in the `x-derm-tap-route` header (Codex's
//! `env_http_headers`, Pi's provider headers), so it never sits in an argv
//! a run record keeps or `ps` shows.
//!
//! The route is derived from the token's hash, which the daemon keeps across
//! a restart (`chats.json`, BX8), so a restarted daemon still knows every
//! running chat's route with no new state. Knowing a route does not open the
//! socket (that needs the token itself); it lets a request be recorded under
//! that chat and forwarded to that chat's fixed upstreams, which is why it
//! stays out of argv and logs like the token.

use sha2::{Digest, Sha256};

/// The header form of the route. Read and removed by the tap; never
/// forwarded upstream, never recorded.
pub const HEADER: &str = "x-derm-tap-route";

/// A route's length in hex characters (128 bits).
pub const LEN: usize = 32;

const DOMAIN: &[u8] = b"derm-tap-route-v1\0";

/// The route of a chat, from its token's hash as `derm_core::token::hash`
/// writes it (lowercase hex).
pub fn of_token_hash(token_hash_hex: &str) -> String {
    let mut h = Sha256::new();
    h.update(DOMAIN);
    h.update(token_hash_hex.trim().to_ascii_lowercase().as_bytes());
    hex(&h.finalize())[..LEN].to_string()
}

/// The route of a chat, from its token (what `derm run` holds).
pub fn of_token(token: &str) -> String {
    of_token_hash(&derm_core::token::hash(token))
}

/// A route as written: exactly `LEN` lowercase hex characters.
pub fn well_formed(route: &str) -> bool {
    route.len() == LEN
        && route
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// `/r/<route>/<rest>` split into the route and `/<rest>`; `None` when the
/// path does not start that way or the route is not well formed.
pub fn split_path(path: &str) -> Option<(&str, &str)> {
    let rest = path.strip_prefix("/r/")?;
    let (route, tail) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, ""),
    };
    well_formed(route).then_some((route, tail))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_route_comes_from_the_token_hash_and_never_shows_it() {
        let token = "a".repeat(64);
        let hash = derm_core::token::hash(&token);
        let r = of_token(&token);
        assert_eq!(r, of_token_hash(&hash));
        assert!(well_formed(&r));
        assert!(!hash.contains(&r), "the route is not a slice of the hash");
        assert_ne!(of_token(&"b".repeat(64)), r);
    }

    #[test]
    fn the_path_form_needs_a_whole_route() {
        let r = of_token(&"c".repeat(64));
        let p = format!("/r/{r}/anthropic/v1/messages?beta=true");
        assert_eq!(
            split_path(&p),
            Some((r.as_str(), "/anthropic/v1/messages?beta=true"))
        );
        assert_eq!(split_path(&format!("/r/{r}")), Some((r.as_str(), "")));
        assert_eq!(split_path("/r/abc/anthropic"), None);
        assert_eq!(split_path(&format!("/r/{}/x", r.to_uppercase())), None);
        assert_eq!(split_path("/anthropic/v1/messages"), None);
    }
}
