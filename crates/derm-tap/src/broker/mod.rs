//! Provider API keys through the tap (wave 6, lane 6C;
//! `plans/toolkit_wave6_plan.md` section 2.2 and call 3; note AZ row S4).
//! The wave 6 base cut this seam: the tap passes every request header it
//! forwards through [`outbound_header`]. The stub returns each value as it
//! came, so the tap forwards exactly what it did before.
//!
//! What lane 6C may build here: a placeholder the agent holds for a
//! provider key swapped for the key on the plain-HTTP side of the tap, for
//! the provider's own host only (I in note AZ: the tap forwards the client's
//! own headers to a fixed provider table, so no TLS termination is needed).
//! Never under sbx, whose proxy owns provider credentials (case 207, AZ row
//! C6). No header name or value is logged, recorded or echoed (case 114).

use std::borrow::Cow;

/// The header value the tap forwards upstream for `chat`. The base's stub
/// returns `value` unchanged.
pub fn outbound_header<'a>(_chat: &str, _name: &str, value: &'a str) -> Cow<'a, str> {
    Cow::Borrowed(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_stub_forwards_every_value_as_it_came() {
        for (n, v) in [
            ("authorization", "Bearer x"),
            ("x-api-key", "derm-secret:anthropic"),
        ] {
            assert!(matches!(outbound_header("c", n, v), Cow::Borrowed(s) if s == v));
        }
    }
}
