//! The chain to derm-egress per tier (`contracts/policy.md` section 8.1;
//! note AZ C1 to C6, AZ-4, AZ-11; `plans/parallel/tk_lane_6C.md`): what a
//! chat's start adds so the harness's traffic reaches the chat's egress proxy
//! and trusts derm's CA, and what it says on the start line. Pure: it computes
//! the plan; `run/` (integration's) applies it (the lane's request).
//!
//! - **Standard tier** (no srt): the harness's own `HTTPS_PROXY` and
//!   `HTTP_PROXY` name derm-egress. Claude Code 2.1.322's sandbox then applies
//!   its own `allowedDomains` first (403 for a host off the list) and chains
//!   only what it allowed (C1, run on the Mac); `httpProxyPort` is not used,
//!   since with it Claude Code applies no list and derm-egress would filter
//!   alone. Codex 0.167.2 takes the same variables with its own network proxy
//!   off (its `network_proxy` feature is experimental and off,
//!   `features/src/lib.rs:1559-1566`; with it on it would resolve each host
//!   itself first, AZ-11). Loopback stays direct (`NO_PROXY`), so the tap's
//!   and the OTLP receiver's ports never pass through derm-egress (AZ-4).
//! - **srt**: srt 0.0.82's `network.parentProxy` names derm-egress (C2, run
//!   on the Mac); srt sets the harness's proxy variables to its own proxy and
//!   chains what its allow list admits. srt's `tlsTerminate` and `credentials`
//!   stay off: its terminated leg ignores `parentProxy`
//!   (`dist/sandbox/tls-terminate-proxy.js:987`), so the two cannot stack.
//! - **sbx**: nothing (case 218, C6). sbx's host proxy terminates TLS with its
//!   own CA and owns credentials; `sbx secret set` and `sbx secret
//!   set-custom` are the path there, and the start line names them.
//! - **Any other chat** (the whole tier with no srt): no broker, so the
//!   variables of env-sourced secrets are taken out of the harness's
//!   environment rather than passed on with their real values.
//!
//! Trust (C4): `NODE_EXTRA_CA_CERTS` (Node, Claude Code), `SSL_CERT_FILE`
//! (Codex, OpenSSL, Python, Go 1.27 modules; a bundle of the system's roots
//! plus derm's CA, since it replaces the roots), `CODEX_CA_CERTIFICATE`,
//! `REQUESTS_CA_BUNDLE`, `CURL_CA_BUNDLE`, `GIT_SSL_CAINFO`, and
//! `NODE_USE_ENV_PROXY=1` (Node 22 reads proxy variables only with it). The
//! trust files must sit where the harness's sandbox lets it read: the
//! Standard tier's blocks and srt both deny `~/.derm`.

use std::path::Path;

use derm_egress::secrets::{self, Entry, From};
use serde_json::{json, Value};

/// One chat's facts the chain depends on.
pub struct Input<'a> {
    pub harness: &'a str,
    /// `run.start`'s `tier` (`standard` or `whole`).
    pub tier: &'a str,
    /// `sbx`, `srt` or `none`.
    pub boundary: &'a str,
    /// The chat's secrets with the placeholder each was given.
    pub secrets: &'a [(Entry, String)],
    /// The chat's egress proxy (`http://127.0.0.1:<port>`), once started.
    pub egress_url: Option<&'a str>,
    /// derm's CA certificate and the root bundle with it, readable from the
    /// harness's sandbox.
    pub ca_file: &'a str,
    pub bundle_file: &'a str,
    /// The CA's SHA-256, for the start line.
    pub fingerprint: &'a str,
}

/// What a chat's start adds.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Plan {
    /// Whether derm-egress runs for this chat.
    pub brokered: bool,
    /// Variables set for the harness, in order.
    pub env: Vec<(String, String)>,
    /// Variables taken out of the harness's environment.
    pub remove: Vec<String>,
    /// srt's `network` keys to add (`parentProxy`), under srt only.
    pub srt_network: Option<Value>,
    /// derm-egress's model hosts (`Policy::model_hosts`): the tap's table.
    pub model_hosts: Vec<String>,
    /// The start line, or `None` when the chat has no secrets.
    pub line: Option<String>,
}

/// Whether a chat with this tier and boundary is brokered (section 8.1).
pub fn brokered(tier: &str, boundary: &str) -> bool {
    boundary != "sbx" && (tier == "standard" || boundary == "srt")
}

pub fn plan(i: &Input<'_>) -> Result<Plan, String> {
    let mut p = Plan::default();
    if i.secrets.is_empty() {
        return Ok(p);
    }
    let ids: Vec<&str> = i.secrets.iter().map(|(e, _)| e.id.as_str()).collect();
    let env_vars: Vec<String> = i
        .secrets
        .iter()
        .filter_map(|(e, _)| match &e.from {
            From::Env(v) => Some(v.clone()),
            _ => None,
        })
        .collect();
    if i.boundary == "sbx" {
        p.remove = env_vars;
        p.line = Some(format!(
            "secrets {}: not brokered under sbx (sbx's own proxy owns credentials there; store them with `sbx secret set` or `sbx secret set-custom`)",
            ids.join(", ")
        ));
        return Ok(p);
    }
    if !brokered(i.tier, i.boundary) {
        p.remove = env_vars;
        p.line = Some(format!(
            "secrets {}: not brokered in this chat (only under --tier standard or --boundary srt); their variables are left out",
            ids.join(", ")
        ));
        return Ok(p);
    }
    let url = i
        .egress_url
        .ok_or("the chat's egress proxy has not started")?;
    p.brokered = true;
    for (e, ph) in i.secrets {
        p.env.push((secrets::variable(e), ph.clone()));
    }
    if i.boundary == "srt" {
        // `noProxy` empty, not left out: srt 0.0.82 falls back to its own
        // `NO_PROXY`, which a person's shell may set, and hosts there would
        // skip derm-egress (`dist/sandbox/parent-proxy.js:54`; review
        // W6C-S6). Loopback never goes to a parent (`:137-142`, AZ-4).
        p.srt_network = Some(json!({"parentProxy": {"http": url, "https": url, "noProxy": ""}}));
    } else {
        for k in ["HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy"] {
            p.env.push((k.into(), url.into()));
        }
        for k in ["NO_PROXY", "no_proxy"] {
            p.env.push((k.into(), "localhost,127.0.0.1,::1".into()));
        }
    }
    let trust = [
        ("NODE_EXTRA_CA_CERTS", i.ca_file),
        ("CODEX_CA_CERTIFICATE", i.ca_file),
        ("SSL_CERT_FILE", i.bundle_file),
        ("REQUESTS_CA_BUNDLE", i.bundle_file),
        ("CURL_CA_BUNDLE", i.bundle_file),
        ("GIT_SSL_CAINFO", i.bundle_file),
        ("NODE_USE_ENV_PROXY", "1"),
    ];
    p.env
        .extend(trust.iter().map(|(k, v)| (k.to_string(), v.to_string())));
    p.model_hosts = derm_tap::upstream::builtin()
        .values()
        .map(|u| u.host())
        .collect();
    let vars: Vec<String> = i
        .secrets
        .iter()
        .map(|(e, _)| secrets::variable(e))
        .collect();
    p.line = Some(format!(
        "secrets {} brokered by derm-egress at {url} ({}); placeholders in {}; this chat trusts derm's CA sha256 {} through {}",
        ids.join(", "),
        if i.boundary == "srt" { "srt's parentProxy" } else { "the harness's HTTPS_PROXY" },
        vars.join(", "),
        i.fingerprint.get(..16).unwrap_or(i.fingerprint),
        trust.iter().take(6).map(|(k, _)| *k).collect::<Vec<_>>().join(", "),
    ));
    let _ = i.harness;
    Ok(p)
}

/// A vendor sandbox block derm-egress can chain through: no TLS terminating
/// proxy of the vendor's own and no credential masks (srt's terminated leg
/// ignores the parent proxy; Claude Code embeds srt's code, note AZ C7).
// Only the guard test runs it today, against lane 6A's real block: derm
// writes that block itself, with no TLS proxy or credential masks.
#[cfg_attr(not(test), allow(dead_code))]
pub fn vendor_block_ok(block: &Value) -> Result<(), String> {
    let s = block.get("sandbox").unwrap_or(block);
    let net = s.get("network");
    if net.and_then(|n| n.get("tlsTerminate")).is_some() {
        return Err(
            "the sandbox block turns on the vendor's TLS termination, which bypasses derm-egress"
                .into(),
        );
    }
    if s.get("credentials").is_some() || block.get("credentials").is_some() {
        return Err(
            "the sandbox block masks credentials itself, which cannot chain to derm-egress".into(),
        );
    }
    if net.and_then(|n| n.get("httpProxyPort")).is_some() {
        return Err("httpProxyPort makes Claude Code skip its own allow list (C1); derm chains through HTTPS_PROXY".into());
    }
    Ok(())
}

/// The system's root bundle, first found of the usual places, with derm's CA
/// added (`SSL_CERT_FILE` replaces the roots, C4).
pub fn bundle(ca_pem: &str) -> Result<String, String> {
    const PLACES: [&str; 5] = [
        "/etc/ssl/certs/ca-certificates.crt",
        "/etc/pki/tls/certs/ca-bundle.crt",
        "/etc/ssl/ca-bundle.pem",
        "/etc/ssl/cert.pem",
        "/usr/local/etc/openssl/cert.pem",
    ];
    for p in PLACES {
        if let Ok(roots) = std::fs::read_to_string(p) {
            if roots.contains("BEGIN CERTIFICATE") {
                let mut out = roots;
                if !out.ends_with('\n') {
                    out.push('\n');
                }
                out.push_str(ca_pem);
                return Ok(out);
            }
        }
    }
    Err("no system root bundle found".into())
}

/// Write `ca.pem` and `bundle.pem` into `dir` (public certificates, 0644) and
/// return their paths.
pub fn write_trust(dir: &Path, ca_pem: &str) -> Result<(String, String), String> {
    std::fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    let ca = dir.join("derm-ca.pem");
    let b = dir.join("derm-bundle.pem");
    std::fs::write(&ca, ca_pem).map_err(|e| format!("{}: {e}", ca.display()))?;
    std::fs::write(&b, bundle(ca_pem)?).map_err(|e| format!("{}: {e}", b.display()))?;
    Ok((
        ca.to_string_lossy().into_owned(),
        b.to_string_lossy().into_owned(),
    ))
}
