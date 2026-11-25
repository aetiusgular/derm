//! The secrets broker for one chat (integration w6's close: lane 6C's
//! request R1, hosted as Tony chose for R2 on 12 Nov, 23:53 PST: "option 2",
//! one broker per chat inside `derm run`, not in the daemon).
//!
//! For a chat with entries in `~/.derm/secrets.json`: read every value now
//! (`secrets::for_chat`; one unreadable value refuses the start), load derm's
//! CA (missing or expiring within a day refuses the start, naming `derm
//! secret ca create`), write the CA and a root bundle into a folder of this
//! chat's that the harness's sandbox can read (never under `~/.derm`, which
//! the Standard tier's blocks and srt deny), start derm-egress on loopback,
//! and apply `secret::chain::plan`: the placeholders and proxy and trust
//! variables for the harness, srt's `network.parentProxy`, the variables of
//! env-sourced secrets taken out where the chat is not brokered, and the
//! start line. The values stay in this process and die with it: no value
//! crosses a socket. derm-egress's records reach the daemon through `derm
//! run`'s own daemon-scope connection as source `run`, which no chat token
//! may post (`contracts/daemon-protocol.md` rule 2).
//!
//! A dry run reads no value and starts nothing: it names what the chat would
//! get. Under sbx and in a chat with neither the Standard tier nor srt the
//! plan brokers nothing (case 218; `chain::brokered`).

use std::path::{Path, PathBuf};
use std::sync::Arc;

use derm_egress::ca::{self, Ca};
use derm_egress::secrets::{self, Entry};
use derm_egress::{Config, Egress, Policy, Sink};
use serde_json::{json, Value};

use super::plan::Plan;
use crate::secret::chain;

/// What a chat's start set up.
pub struct Broker {
    /// The running proxy; dropping it stops it.
    pub egress: Option<Egress>,
    /// `run.start`'s `broker`: the ids, whether brokered, the port and the
    /// CA's SHA-256 (`contracts/events.md` section 6.3).
    pub record: Option<Value>,
    /// The trust folder this run made, removed when the run ends.
    pub trust_dir: Option<PathBuf>,
}

impl Broker {
    fn none() -> Broker {
        Broker {
            egress: None,
            record: None,
            trust_dir: None,
        }
    }
}

/// The chat's facts the broker reads.
pub struct Chat<'a> {
    pub chat: &'a str,
    pub harness: &'a str,
    /// `run.start`'s `tier` (`standard`, else `whole`).
    pub tier: &'a str,
    /// `sbx`, `srt` or `none`.
    pub boundary: &'a str,
    pub home: &'a Path,
    pub dry_run: bool,
    /// Where the trust folder goes (the system's temporary folder; `/tmp`
    /// for an agent account's chat, which its Landlock domain reads).
    pub temp: &'a Path,
    /// The agent account the chat runs as (`derm-<slug>`), when it is one
    /// (the accounts build, lane L4's request R4).
    pub account: Option<&'a str>,
    /// The chat's project id, `""` in no project (step P, I-4): a chat gets
    /// only the secrets bound to its project, or the unbound ones.
    pub project: &'a str,
}

/// Sets up the chat's broker and applies the chain to `p`. `env` reads `derm
/// run`'s own environment (env-sourced values); `sink` takes derm-egress's
/// records (`None` with `--no-daemon`, when they are dropped).
pub fn wire(
    c: &Chat<'_>,
    p: &mut Plan,
    env: &dyn Fn(&str) -> Option<String>,
    sink: Option<Sink>,
) -> Result<Broker, String> {
    let path = secrets::path_for(c.home);
    let file = secrets::load(&path).map_err(|e| {
        format!("{e}; fix it with `derm secret`, or move it away to run with no secrets")
    })?;
    // Request PB-1 (lane PB's request 1; I-4): the bindings are read as
    // `secrets.json` is, and a refused file stops the start the same way.
    // Values and placeholders are made from the kept file only, so they pair.
    let bindings = derm_egress::bind::load(&derm_egress::bind::path_for(c.home)).map_err(|e| {
        format!("{e}; fix it with `derm secret bind` or `derm secret unbind`, or move it away")
    })?;
    let (file, left) = derm_egress::bind::for_project(&file, &bindings, c.project);
    if let Some(line) = chain::left_out_line(&bindings, &left, c.project) {
        p.notes.push(format!("derm run: {line}"));
    }
    if file.secrets.is_empty() {
        return Ok(Broker::none());
    }
    let ids: Vec<String> = file.secrets.iter().map(|e| e.id.clone()).collect();
    let brokered = chain::brokered_for(c.tier, c.boundary, c.account);
    let ca_dir = ca::dir_for(c.home);
    if !brokered || c.dry_run {
        // No value is read: the plan needs only the entries and a placeholder.
        let mut with_ph: Vec<(Entry, String)> = Vec::new();
        for e in &file.secrets {
            with_ph.push((e.clone(), secrets::mint_placeholder(&e.id)?));
        }
        let fingerprint = Ca::load(&ca_dir)
            .ok()
            .flatten()
            .map(|ca| ca.fingerprint())
            .unwrap_or_else(|| "(none yet: derm secret ca create)".into());
        let trust = c.temp.join(format!("derm-trust-{}-<random>", c.chat));
        let ca_file = trust.join("derm-ca.pem").to_string_lossy().into_owned();
        let bundle_file = trust.join("derm-bundle.pem").to_string_lossy().into_owned();
        let url = "http://127.0.0.1:<port at the start>";
        let plan = chain::plan_for(
            &chain::Input {
                harness: c.harness,
                tier: c.tier,
                boundary: c.boundary,
                secrets: &with_ph,
                egress_url: brokered.then_some(url),
                ca_file: &ca_file,
                bundle_file: &bundle_file,
                fingerprint: &fingerprint,
            },
            c.account,
        )?;
        apply(p, &plan)?;
        return Ok(Broker {
            egress: None,
            record: (!brokered).then(|| json!({"ids": ids, "brokered": false})),
            trust_dir: None,
        });
    }
    let ca = Ca::load(&ca_dir)?.ok_or_else(|| {
        format!(
            "this chat has secrets ({}) but derm has no CA; run `derm secret ca create` from a terminal",
            ids.join(", ")
        )
    })?;
    if !ca.valid_for(1) {
        return Err(
            "derm's CA expires within a day; run `derm secret ca create --replace` from a terminal"
                .into(),
        );
    }
    // A Claude subscription token in an agent account's chat is refused
    // before any value is read (note CB 4.1; `chain::plan_for` says so too).
    if let Some(why) = chain::subscription_refusal(&file.secrets, c.boundary, c.account) {
        return Err(why);
    }
    let values = secrets::for_chat(&file, env)?;
    // A name no one can make first (review W6C-S9), removed again on any
    // error below, since `make_trust_dir` refuses a folder already there.
    let trust = c.temp.join(format!(
        "derm-trust-{}-{}",
        c.chat,
        uuid::Uuid::new_v4().simple()
    ));
    make_trust_dir(&trust)?;
    let mut guard = RemoveOnError(Some(trust.clone()));
    let (ca_file, bundle_file) = chain::write_trust(&trust, &ca.cert_pem()).inspect_err(|_| {
        let _ = std::fs::remove_dir_all(&trust);
    })?;
    let fingerprint = ca.fingerprint();
    let with_ph: Vec<(Entry, String)> = file
        .secrets
        .iter()
        .zip(&values)
        .map(|(e, s)| (e.clone(), s.placeholder.clone()))
        .collect();
    let mut config = Config::new(
        c.chat,
        c.harness,
        values,
        Arc::new(ca),
        sink.unwrap_or_else(|| Arc::new(|_| {})),
    )?;
    config.policy = policy_for(&file.secrets);
    // Every brokered chat (case 283; Tony's call 2a): its harness's sign-in
    // host passes through unread; an agent account's chat also has
    // claude.ai's connector proxy closed (Tony's 22 Nov call). A secret's own
    // host is never passed through, so its value is still swapped there.
    let (pass, deny) = account_egress(c.harness, c.account);
    config.pass_through = pass
        .into_iter()
        .filter(|(h, _)| !file.secrets.iter().any(|e| e.hosts.iter().any(|x| x == h)))
        .collect();
    config.policy.deny = deny.clone();
    let passed: Vec<String> = config
        .pass_through
        .iter()
        .map(|(h, p)| format!("{h}:{p}"))
        .collect();
    if c.account.is_some() || !passed.is_empty() {
        p.notes.push(format!(
            "derm run: derm-egress passes {} through unread for {}'s own sign-in renewal (it checks the TLS server name, never the bytes){}",
            if passed.is_empty() { "no host".to_string() } else { passed.join(", ") },
            c.harness,
            if deny.is_empty() {
                String::new()
            } else {
                format!(", and closes {}", deny.join(", "))
            }
        ));
    }
    let egress = Egress::start(config)?;
    let url = egress.url();
    let plan = chain::plan_for(
        &chain::Input {
            harness: c.harness,
            tier: c.tier,
            boundary: c.boundary,
            secrets: &with_ph,
            egress_url: Some(&url),
            ca_file: &ca_file,
            bundle_file: &bundle_file,
            fingerprint: &fingerprint,
        },
        c.account,
    )?;
    apply(p, &plan)?;
    guard.0 = None;
    Ok(Broker {
        record: Some(json!({
            "ids": ids,
            "brokered": true,
            "port": egress.port(),
            "caSha256": fingerprint,
            "passThrough": passed,
            "closed": deny,
        })),
        egress: Some(egress),
        trust_dir: Some(trust),
    })
}

/// What derm-egress relays unread and what it closes, for a brokered chat:
/// the harness's own sign-in host relayed unread for every brokered chat
/// (case 283 for an account's; Tony's call 2a, 24 Nov 2026, for the
/// person's own, whose renewal before this went through derm-egress's TLS
/// termination, `acctP_fix.md` Look out for 9), and claude.ai's connector
/// proxy closed for an agent account's chat only (Tony's 22 Nov call): a
/// person's own chat keeps its claude.ai connectors.
pub fn account_egress(harness: &str, account: Option<&str>) -> (Vec<(String, u16)>, Vec<String>) {
    let pass = super::harness::sign_in_hosts(harness)
        .iter()
        .filter_map(|hp| {
            let (h, p) = hp.rsplit_once(':')?;
            Some((h.to_string(), p.parse().ok()?))
        })
        .collect();
    let deny = if account.is_some() {
        vec![MCP_PROXY.to_string()]
    } else {
        Vec::new()
    };
    (pass, deny)
}

/// claude.ai's connector proxy (Claude Code 2.1.322's `MCP_PROXY_URL`),
/// closed to agent accounts' chats (Tony, 22 Nov 2026).
pub const MCP_PROXY: &str = "mcp-proxy.anthropic.com";

/// derm-egress's rules for the chat: the tap's model hosts (decision 2's
/// body-only pass) and each secret's placement (decision 2, item 2).
pub fn policy_for(entries: &[Entry]) -> Policy {
    use derm_egress::place::Spot;
    let mut swap_body = Vec::new();
    let mut swap_query = Vec::new();
    for e in entries {
        for s in e.spots() {
            match s {
                Spot::Body(p) => swap_body.push((e.id.clone(), p)),
                Spot::Query(q) => swap_query.push((e.id.clone(), q)),
            }
        }
    }
    Policy {
        allow: None,
        model_hosts: derm_tap::upstream::builtin()
            .values()
            .map(|u| u.host())
            .collect(),
        swap_body,
        swap_query,
        deny: Vec::new(),
    }
}

/// The plan's variables into the harness's environment (a variable it sets
/// replaces one set before), the removals, srt's `parentProxy`, and its
/// start line as a note.
fn apply(p: &mut Plan, plan: &chain::Plan) -> Result<(), String> {
    for (k, v) in &plan.env {
        p.env_set.retain(|(n, _)| n != k);
        p.env_set.push((k.clone(), v.clone()));
    }
    for k in &plan.remove {
        if !p.env_remove.contains(k) {
            p.env_remove.push(k.clone());
        }
        p.env_set.retain(|(n, _)| n != k);
    }
    if let Some(net) = &plan.srt_network {
        let text = p
            .srt_settings
            .as_deref()
            .ok_or("srt's settings are missing for the broker's parentProxy")?;
        let mut v: Value = serde_json::from_str(text).map_err(|e| e.to_string())?;
        for (k, x) in net.as_object().into_iter().flatten() {
            v["network"][k] = x.clone();
        }
        if let Some(list) = v
            .pointer_mut("/network/allowedDomains")
            .and_then(Value::as_array_mut)
        {
            for h in &plan.srt_allow {
                if !list.iter().any(|x| x.as_str() == Some(h.as_str())) {
                    list.push(json!(h));
                }
            }
        }
        p.srt_settings = Some(serde_json::to_string_pretty(&v).map_err(|e| e.to_string())?);
    }
    if let Some(line) = &plan.line {
        p.notes.push(format!("derm run: {line}"));
    }
    Ok(())
}

/// Removes a folder when dropped, unless taken back first.
struct RemoveOnError(Option<PathBuf>);

impl Drop for RemoveOnError {
    fn drop(&mut self) {
        if let Some(p) = self.0.take() {
            let _ = std::fs::remove_dir_all(p);
        }
    }
}

/// A new folder for the chat's public trust files: made fresh (never one
/// already there), readable by the harness, writable by no one else.
fn make_trust_dir(dir: &Path) -> Result<(), String> {
    std::fs::create_dir(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o755))
            .map_err(|e| format!("{}: {e}", dir.display()))?;
    }
    Ok(())
}

#[cfg(all(test, unix))]
mod tests;
