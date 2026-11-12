//! derm-egress (wave 6, lane 6C; `plans/toolkit_wave6_plan.md` section 2.2;
//! `contracts/policy.md` section 8; `contracts/events.md` section 6.3). The
//! wave 6 base's stub: the types the contract names and a [`decide`] that
//! forwards every request unchanged, so the red test in `tests/contract.rs`
//! builds and fails until the lane is done. Nothing starts this crate yet.
//!
//! What lane 6C builds (note AZ rows C1 to C8, AZ-4, AZ-9, AZ-11): an egress
//! proxy that checks the TLS SNI against the CONNECT host, records one
//! `egress.connect` per connection, swaps a placeholder for its secret only
//! in a request bound for a host the secret names, and blocks and records a
//! placeholder or a secret's value bound for any other host, in a header,
//! the body, the URL or a DNS name (case 217). Under sbx it brokers no
//! provider credential (case 218, C6). The chain to it per tier: Claude
//! Code's `network.httpProxyPort` (derm-egress then filters alone, C1) or its
//! `HTTPS_PROXY`; srt's `network.parentProxy` (C2); Codex's own proxy
//! resolves a host before chaining (AZ-11).

/// A secret the person added with `derm secret add` (`contracts/policy.md`
/// section 8). `value` never reaches a record, a log or the agent.
#[derive(Clone, Debug)]
pub struct Secret {
    pub id: String,
    pub value: String,
    /// Hosts the secret may be sent to, exact names, lowercase, no port.
    pub hosts: Vec<String>,
    /// The placeholder the agent holds instead of the value (section 8.2).
    pub placeholder: String,
}

/// One request the proxy is about to forward.
#[derive(Clone, Debug)]
pub struct Outbound<'a> {
    /// The host the client named in CONNECT (or the URL's, plain HTTP).
    pub connect_host: &'a str,
    /// The TLS ClientHello's server name, where the request came over TLS.
    pub sni: Option<&'a str>,
    /// The request target as the client sent it (path and query, or a
    /// whole URL for plain HTTP through a proxy).
    pub target: &'a str,
    pub headers: &'a [(String, String)],
    pub body: &'a [u8],
}

/// What the proxy does with one request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// Forward, with these headers and this body (a placeholder swapped for
    /// its value where the host may have it).
    Forward {
        headers: Vec<(String, String)>,
        body: Vec<u8>,
    },
    /// Refuse, and record `reason` (never the value).
    Block { reason: String },
}

/// The decision for one request. The base's stub forwards it unchanged.
pub fn decide(o: &Outbound<'_>, _secrets: &[Secret]) -> Verdict {
    Verdict::Forward {
        headers: o.headers.to_vec(),
        body: o.body.to_vec(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_stub_forwards_unchanged() {
        let h = vec![("accept".to_string(), "*/*".to_string())];
        let o = Outbound {
            connect_host: "example.com",
            sni: Some("example.com"),
            target: "/",
            headers: &h,
            body: b"",
        };
        assert_eq!(
            decide(&o, &[]),
            Verdict::Forward {
                headers: h.clone(),
                body: Vec::new()
            }
        );
    }
}
