//! derm-egress (wave 6, lane 6C; `plans/toolkit_wave6_plan.md` section 2.2;
//! `contracts/policy.md` section 8; `contracts/events.md` section 6.3).
//!
//! An egress proxy for one chat under the Standard tier or srt, and the
//! secrets broker inside it (note AZ rows C1 to C8, AZ-4, AZ-9, AZ-11):
//! - [`decide`]: the rule for one request (case 217): a placeholder is
//!   swapped for its value only in a request whose CONNECT host is one of
//!   that secret's hosts and whose TLS server name is that host; the
//!   placeholder or the value bound for any other host, in a header, the
//!   body, the URL or the host name itself, blocks the request; an SNI that
//!   is not the CONNECT host blocks it;
//! - [`secrets`]: `~/.derm/secrets.json` (`contracts/secrets.schema.json`),
//!   where each value is read from at chat start, and the per-chat
//!   placeholders;
//! - [`ca`]: the local CA the person creates from a terminal, and the leaves
//!   it signs per host;
//! - [`http`]: the HTTP/1.1 the proxy reads and writes;
//! - [`proxy`]: the server, one per chat, with its records.
//!
//! Under sbx it brokers nothing (case 218, C6): sbx's own proxy owns provider
//! credentials there. Subscription sign-ins are out of scope (cases 181, 186,
//! 190). The chain to it per tier is `derm-cli`'s (`secret/chain.rs`).

pub mod ca;
pub mod http;
pub mod proxy;
mod scan;
pub mod secrets;

pub use proxy::{Config, Egress, Sink};
pub use scan::MIN_VALUE_LEN;

/// A secret the person added with `derm secret add` (`contracts/policy.md`
/// section 8). `value` never reaches a record, a log or the agent.
#[derive(Clone)]
pub struct Secret {
    pub id: String,
    pub value: String,
    /// Hosts the secret may be sent to, exact names, lowercase, no port.
    pub hosts: Vec<String>,
    /// The placeholder the agent holds instead of the value (section 8.2).
    pub placeholder: String,
}

impl std::fmt::Debug for Secret {
    /// The value is never printed, even in a panic or a test failure.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Secret")
            .field("id", &self.id)
            .field("hosts", &self.hosts)
            .field("placeholder", &self.placeholder)
            .finish_non_exhaustive()
    }
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

/// Where a placeholder or a value sat (`events.md` 6.3, `secret.block`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Place {
    Header,
    Body,
    Url,
    Dns,
}

impl Place {
    pub fn as_str(self) -> &'static str {
        match self {
            Place::Header => "header",
            Place::Body => "body",
            Place::Url => "url",
            Place::Dns => "dns",
        }
    }
}

/// Why a request was blocked, for its record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Blocked {
    /// A secret's placeholder or value bound for a host it does not name
    /// (`secret.block`). `value` says which of the two it was.
    Secret {
        id: String,
        place: Place,
        value: bool,
    },
    /// The TLS server name is not the CONNECT host.
    SniMismatch,
    /// A body this proxy cannot read (a `Content-Encoding` other than
    /// identity) bound for a host some secret does not name.
    EncodedBody,
    /// The host is not on the chat's allow list.
    NotAllowed,
    /// The `Host` header or an absolute-form target names another host than
    /// the CONNECT host (domain fronting would route an injected secret to
    /// another backend behind the same front).
    HostMismatch,
}

impl Blocked {
    /// The reason a record and the client's error page carry. Never a value.
    pub fn reason(&self) -> String {
        match self {
            Blocked::Secret { id, place, value } => format!(
                "the {} of secret {id} in the {} of a request to a host it does not name",
                if *value { "value" } else { "placeholder" },
                place.as_str()
            ),
            Blocked::SniMismatch => "the TLS server name is not the CONNECT host".into(),
            Blocked::EncodedBody => {
                "an encoded request body derm cannot read, bound for a host a secret does not name"
                    .into()
            }
            Blocked::NotAllowed => "the host is not on this chat's allow list".into(),
            Blocked::HostMismatch => {
                "the Host header or the URL names another host than the connection".into()
            }
        }
    }
}

/// The chat's egress rules beside its secrets.
#[derive(Clone, Debug, Default)]
pub struct Policy {
    /// With `Some`, only these hosts are reached (\"default deny optional\",
    /// the wave 6 plan's card; needed with Claude Code's `httpProxyPort`,
    /// where Claude Code applies no allow list of its own, C1).
    pub allow: Option<Vec<String>>,
    /// Hosts where a placeholder alone is forwarded unchanged and not
    /// blocked: the model providers a chat's transcript goes to, which can
    /// hold a placeholder the agent printed. The value still blocks there.
    /// Empty by default; the chain sets it (Decisions in the lane doc).
    pub model_hosts: Vec<String>,
    /// Secrets whose value is also swapped into a request's body toward
    /// their own host (`secrets.json`'s `placement: ["body"]`). By default a
    /// value goes into headers only (decision 2, item 2, Tony's call of 12
    /// Nov: OpenShell and Google's agent credentials do the same).
    pub swap_body: Vec<String>,
    /// Secrets whose value is also swapped into a request's query (after
    /// `?`) toward their own host (`placement: ["query"]`).
    pub swap_query: Vec<String>,
}

/// The whole outcome of [`decide_with`]: the verdict, the secrets swapped in,
/// and why a block happened.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Decision {
    pub verdict: Verdict,
    /// Ids of the secrets whose placeholder was swapped (`secret.inject`).
    pub injected: Vec<String>,
    pub blocked: Option<Blocked>,
    /// A placeholder was forwarded unchanged to a model host.
    pub placeholder_to_model: bool,
    /// The request target with a value swapped into its query, when one was
    /// (`Policy::swap_query`); `None` leaves the target as sent.
    pub target: Option<String>,
}

/// The decision for one request with no allow list and no model hosts.
pub fn decide(o: &Outbound<'_>, secrets: &[Secret]) -> Verdict {
    decide_with(o, secrets, &Policy::default()).verdict
}

/// Lowercase, no trailing dot, no IPv6 brackets.
pub fn normal_host(h: &str) -> String {
    let h = h.trim().trim_end_matches('.');
    let h = h
        .strip_prefix('[')
        .and_then(|x| x.strip_suffix(']'))
        .unwrap_or(h);
    h.to_ascii_lowercase()
}

/// The decision for one request (`contracts/policy.md` section 8.3).
pub fn decide_with(o: &Outbound<'_>, secrets: &[Secret], policy: &Policy) -> Decision {
    let block = |b: Blocked| Decision {
        verdict: Verdict::Block { reason: b.reason() },
        injected: Vec::new(),
        blocked: Some(b),
        placeholder_to_model: false,
        target: None,
    };
    let host = normal_host(o.connect_host);
    if let Some(sni) = o.sni {
        if normal_host(sni) != host {
            return block(Blocked::SniMismatch);
        }
    }
    let named = o
        .headers
        .iter()
        .filter(|(k, _)| k.eq_ignore_ascii_case("host"))
        .map(|(_, v)| authority_host(v))
        .chain(target_host(o.target));
    for n in named {
        if n != host {
            return block(Blocked::HostMismatch);
        }
    }
    // A placeholder or a value in the host name itself, for every secret: no
    // secret names a host that holds one (hosts are exact names).
    for s in secrets {
        for (n, value) in needles(s) {
            if scan::host_holds(&host, &n) {
                return block(Blocked::Secret {
                    id: s.id.clone(),
                    place: Place::Dns,
                    value,
                });
            }
        }
    }
    if let Some(allow) = &policy.allow {
        if !allow.iter().any(|a| normal_host(a) == host) {
            return block(Blocked::NotAllowed);
        }
    }
    let own: Vec<&Secret> = secrets.iter().filter(|s| names(s, &host)).collect();
    let others: Vec<&Secret> = secrets.iter().filter(|s| !names(s, &host)).collect();
    let model = policy.model_hosts.iter().any(|m| normal_host(m) == host);
    let encoded = !identity_encoded(o.headers);
    let mut placeholder_to_model = false;
    if !others.is_empty() {
        if encoded && !o.body.is_empty() {
            return block(Blocked::EncodedBody);
        }
        for s in &others {
            for (n, value) in needles(s) {
                let hit =
                    if scan::holds(o.target.as_bytes(), &n) {
                        Some(Place::Url)
                    } else if o.headers.iter().any(|(k, v)| {
                        scan::holds(k.as_bytes(), &n) || scan::holds(v.as_bytes(), &n)
                    }) {
                        Some(Place::Header)
                    } else if scan::holds(o.body, &n) {
                        Some(Place::Body)
                    } else {
                        None
                    };
                if let Some(place) = hit {
                    // Decision 2 as Tony settled it (12 Nov 23:58 PST): a
                    // model host takes a foreign placeholder in the body, the
                    // conversation, only; in the URL or a header it blocks.
                    if model && !value && place == Place::Body {
                        placeholder_to_model = true;
                        continue;
                    }
                    return block(Blocked::Secret {
                        id: s.id.clone(),
                        place,
                        value,
                    });
                }
            }
        }
    }
    // Swap for this host's own secrets: every header value; the body only for
    // a secret whose placement names it, when the proxy can read the body and
    // nothing signs it (both vendors skip an encoded body or one with a
    // digest; srt `body-substitution.js:44-56`, Codex
    // `secret_substitution.rs:37-60`); the query only for a secret whose
    // placement names it (decision 2, item 2: NVIDIA OpenShell swaps
    // `Authorization` only by default and Google's agent credentials only at
    // the declared `injection_location`). A placeholder left in place is the
    // useless fake: authentication fails and nothing leaks.
    let pairs_of = |only: Option<&[String]>| -> Vec<(&[u8], &[u8])> {
        own.iter()
            .filter(|s| only.is_none_or(|ids| ids.contains(&s.id)))
            .map(|s| (s.placeholder.as_bytes(), s.value.as_bytes()))
            .collect()
    };
    let pairs = pairs_of(None);
    let body_pairs = pairs_of(Some(&policy.swap_body));
    let query_pairs = pairs_of(Some(&policy.swap_query));
    let mut injected: Vec<String> = Vec::new();
    let note = |s: &[u8], ids: Option<&[String]>, list: &mut Vec<String>| {
        for x in &own {
            if ids.is_none_or(|ids| ids.contains(&x.id))
                && memchr::memmem::find(s, x.placeholder.as_bytes()).is_some()
                && !list.contains(&x.id)
            {
                list.push(x.id.clone());
            }
        }
    };
    let mut headers: Vec<(String, String)> = Vec::with_capacity(o.headers.len());
    for (k, v) in o.headers {
        match scan::swap(v.as_bytes(), &pairs) {
            Some(new) => {
                note(v.as_bytes(), None, &mut injected);
                // The value came from a str and the placeholder is ASCII, so
                // the result is UTF-8; a value with a line break would split
                // the header, so such a value is refused at load.
                headers.push((k.clone(), String::from_utf8(new).unwrap_or_default()));
            }
            None => headers.push((k.clone(), v.clone())),
        }
    }
    let mut body = o.body.to_vec();
    if !encoded && !signed(o.headers) && !body_pairs.is_empty() {
        if let Some(new) = scan::swap(o.body, &body_pairs) {
            note(o.body, Some(&policy.swap_body), &mut injected);
            body = new;
            for (k, v) in headers.iter_mut() {
                if k.eq_ignore_ascii_case("content-length") {
                    *v = body.len().to_string();
                }
            }
        }
    }
    // The query: only after the first `?`, so a placeholder in the path stays.
    let mut target = None;
    if let Some(q) = o.target.find('?').filter(|_| !query_pairs.is_empty()) {
        let query = &o.target.as_bytes()[q + 1..];
        if let Some(new) = scan::swap(query, &query_pairs) {
            note(query, Some(&policy.swap_query), &mut injected);
            let mut t = o.target.as_bytes()[..=q].to_vec();
            t.extend_from_slice(&new);
            target = String::from_utf8(t).ok();
        }
    }
    Decision {
        verdict: Verdict::Forward { headers, body },
        injected,
        blocked: None,
        placeholder_to_model,
        target,
    }
}

/// The host of an authority (`host`, `host:port`, `[v6]:port`), normalized.
pub fn authority_host(a: &str) -> String {
    let a = a.trim();
    let a = a.rsplit_once('@').map_or(a, |(_, h)| h);
    if let Some(rest) = a.strip_prefix('[') {
        return normal_host(rest.split(']').next().unwrap_or(rest));
    }
    match a.rsplit_once(':') {
        Some((h, p)) if !h.contains(':') && p.bytes().all(|c| c.is_ascii_digit()) => normal_host(h),
        _ => normal_host(a),
    }
}

/// The host of an absolute-form target (`http://h/...`), if it is one.
pub fn target_host(t: &str) -> Option<String> {
    let lower = t.get(..8).unwrap_or(t).to_ascii_lowercase();
    let rest = if lower.starts_with("http://") {
        &t[7..]
    } else if lower.starts_with("https://") {
        &t[8..]
    } else {
        return None;
    };
    let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    Some(authority_host(&rest[..end]))
}

fn names(s: &Secret, host: &str) -> bool {
    s.hosts.iter().any(|h| normal_host(h) == host)
}

fn needles(s: &Secret) -> [(scan::Needles, bool); 2] {
    [
        (scan::Needles::placeholder(&s.placeholder), false),
        (scan::Needles::value(&s.value), true),
    ]
}

/// Whether every `Content-Encoding` coding is `identity` (or there is none).
fn identity_encoded(headers: &[(String, String)]) -> bool {
    headers
        .iter()
        .filter(|(k, _)| k.eq_ignore_ascii_case("content-encoding"))
        .all(|(_, v)| {
            v.split(',')
                .all(|c| c.trim().is_empty() || c.trim().eq_ignore_ascii_case("identity"))
        })
}

/// Headers that sign or checksum the body, so a swap would break the request
/// (Codex's list, `secret_substitution.rs:46-58`).
fn signed(headers: &[(String, String)]) -> bool {
    headers.iter().any(|(k, _)| {
        let k = k.to_ascii_lowercase();
        matches!(
            k.as_str(),
            "content-md5" | "digest" | "content-digest" | "repr-digest" | "x-amz-content-sha256"
        ) || k.starts_with("x-amz-checksum-")
            || k == "trailer"
            || k == "x-amz-trailer"
    })
}

#[cfg(test)]
mod tests;
