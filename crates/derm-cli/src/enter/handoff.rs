//! The handoff file (`contracts/srt-windows.md` section 3), read and judged
//! the same on every OS, so `derm enter --check` holds on Linux and macOS
//! too. Anything off its shape is refused and nothing starts.

use std::collections::BTreeMap;

use serde_json::{Map, Value};

/// The most a handoff may hold (contract section 2, item 3).
pub(crate) const MAX_BYTES: u64 = 64 * 1024;

/// Every key, in the contract's order. No other key is read or allowed.
pub(crate) const KEYS: [&str; 11] = [
    "version",
    "chat",
    "harness",
    "argv",
    "cwd",
    "variables",
    "token",
    "daemon",
    "policy",
    "policyProblem",
    "expires",
];

/// A handoff that passed every check.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct Handoff {
    pub chat: String,
    pub harness: String,
    pub argv: Vec<String>,
    pub cwd: String,
    pub variables: BTreeMap<String, String>,
    pub token: String,
    pub daemon_http: String,
    pub policy: Value,
    pub policy_problem: Option<String>,
    pub expires: u64,
}

/// Variables srt sets inside its sandbox account on Windows, or that belong
/// to that account's own profile: a handoff may not set them. srt 0.0.82:
/// the overlay is `PATH`, `PATHEXT`, `NODE_USE_ENV_PROXY`, the proxy set of
/// `generateProxyEnvVars` and the `GIT_CONFIG_*` set
/// (`src/sandbox/windows-sandbox-utils.ts:4457-4466`,
/// `src/sandbox/sandbox-utils.ts:753-930`); the rest is the account's
/// profile environment (README, "Security model").
const RESERVED: &[&str] = &[
    "PATH",
    "PATHEXT",
    "COMSPEC",
    "SYSTEMROOT",
    "WINDIR",
    "USERPROFILE",
    "USERNAME",
    "USERDOMAIN",
    "HOMEDRIVE",
    "HOMEPATH",
    "APPDATA",
    "LOCALAPPDATA",
    "TEMP",
    "TMP",
    "TMPDIR",
    "NODE_USE_ENV_PROXY",
    "SANDBOX_RUNTIME",
    "GIT_SSH_COMMAND",
    // srt's CA trust variables (`CA_TRUST_VARS`, sandbox-utils.ts:753-765).
    "NODE_EXTRA_CA_CERTS",
    "SSL_CERT_FILE",
    "CURL_CA_BUNDLE",
    "REQUESTS_CA_BUNDLE",
    "PIP_CERT",
    "GIT_SSL_CAINFO",
    "AWS_CA_BUNDLE",
    "CARGO_HTTP_CAINFO",
    "DENO_CERT",
    "CLOUDSDK_CORE_CUSTOM_CA_CERTS_FILE",
    // What `derm enter` itself sets from the handoff's own fields.
    "DERM_CHAT_TOKEN",
    "DERM_CHAT_TOKEN_FILE",
    "DERM_CHAT_FILE",
];

/// Whether a handoff may not set this variable.
pub(crate) fn reserved(name: &str) -> bool {
    let up = name.to_ascii_uppercase();
    RESERVED.contains(&up.as_str())
        || up.ends_with("_PROXY")
        || up.starts_with("CLOUDSDK_PROXY_")
        || up.starts_with("GIT_CONFIG_")
        || up.starts_with("SRT_")
}

/// `^[A-Z][A-Z0-9_]{0,63}$` (contract section 3).
pub(crate) fn variable_name(name: &str) -> bool {
    let b = name.as_bytes();
    !b.is_empty()
        && b.len() <= 64
        && b[0].is_ascii_uppercase()
        && b.iter()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || *c == b'_')
}

/// A drive-absolute Windows path (`C:\...`), read the same way on every OS:
/// no `..` part, no `/`, no control character, no NUL, not a UNC or device
/// path (srt-win refuses a mapped or UNC working folder, `mapped_drive_cwd`).
pub(crate) fn win_absolute(p: &str) -> bool {
    let b = p.as_bytes();
    b.len() >= 3
        && b[0].is_ascii_alphabetic()
        && b[1] == b':'
        && b[2] == b'\\'
        && !p.contains('/')
        && !p.chars().any(char::is_control)
        && !p.split('\\').any(|part| part == ".." || part == ".")
}

/// The harness program: drive-absolute and an `.exe` (never a batch file,
/// case 138).
pub(crate) fn exe_path(p: &str) -> bool {
    win_absolute(p) && p.to_ascii_lowercase().ends_with(".exe") && !p.ends_with('\\')
}

/// An `http://` URL to a loopback address of this machine, with a port and
/// no path, user or query: the daemon's port, reached through srt's proxy
/// (contract section 2, item 4).
pub(crate) fn loopback_http(url: &str) -> bool {
    let Some(rest) = url.strip_prefix("http://") else {
        return false;
    };
    let rest = rest.strip_suffix('/').unwrap_or(rest);
    let (host, port) = match rest.rsplit_once(':') {
        Some(hp) => hp,
        None => return false,
    };
    let host_ok = matches!(
        host,
        "127.0.0.1" | "localhost" | "[::1]" | "[::ffff:127.0.0.1]"
    );
    let port_ok = !port.is_empty()
        && port.len() <= 5
        && port.bytes().all(|c| c.is_ascii_digit())
        && !port.starts_with('0')
        && port.parse::<u32>().is_ok_and(|n| (1..=65_535).contains(&n));
    host_ok && port_ok
}

fn lower_hex64(t: &str) -> bool {
    t.len() == 64
        && t.bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}

/// Reads a handoff from its bytes. `now_ms` is the clock's time; a handoff
/// past its `expires` is refused.
pub(crate) fn parse(bytes: &[u8], now_ms: u64) -> Result<Handoff, String> {
    if bytes.len() as u64 > MAX_BYTES {
        return Err(format!("handoff: over {MAX_BYTES} bytes"));
    }
    let v: Value = serde_json::from_slice(bytes).map_err(|e| format!("handoff: not JSON ({e})"))?;
    let Value::Object(o) = v else {
        return Err("handoff: not a JSON object".into());
    };
    if let Some(k) = o.keys().find(|k| !KEYS.contains(&k.as_str())) {
        return Err(format!("handoff: extra key {k:?}; nothing is started"));
    }
    if let Some(k) = KEYS.iter().find(|k| !o.contains_key(**k)) {
        return Err(format!("handoff: missing key {k:?}"));
    }
    if o["version"] != 1 {
        return Err("handoff: version is not 1".into());
    }
    let s = |k: &str| -> Result<String, String> {
        o[k].as_str()
            .map(str::to_string)
            .ok_or_else(|| format!("handoff: {k} is not a string"))
    };
    let chat = s("chat")?;
    if !crate::run::args::valid_chat(&chat) {
        return Err("handoff: chat is not a chat id".into());
    }
    let harness = s("harness")?;
    if harness != "other"
        && !crate::run::harness::HARNESSES
            .iter()
            .any(|h| h.id == harness)
    {
        return Err(format!("handoff: no harness named {harness:?}"));
    }
    let argv: Vec<String> = match &o["argv"] {
        Value::Array(a) if !a.is_empty() => a
            .iter()
            .map(|w| w.as_str().map(str::to_string))
            .collect::<Option<_>>()
            .ok_or("handoff: argv holds a word that is not a string")?,
        _ => return Err("handoff: argv is not a list of words".into()),
    };
    if !exe_path(&argv[0]) {
        return Err("handoff: argv[0] is not an absolute path to an .exe".into());
    }
    if argv.iter().any(|w| w.contains('\0')) {
        return Err("handoff: argv holds a NUL".into());
    }
    let cwd = s("cwd")?;
    if !win_absolute(&cwd) {
        return Err("handoff: cwd is not an absolute path".into());
    }
    let variables = variables(&o["variables"])?;
    let token = s("token")?;
    if !lower_hex64(&token) {
        return Err("handoff: token is not 64 lower-case hex".into());
    }
    let daemon_http = match &o["daemon"] {
        Value::Object(d) if d.len() == 1 => d
            .get("http")
            .and_then(Value::as_str)
            .filter(|u| loopback_http(u))
            .map(str::to_string)
            .ok_or("handoff: daemon.http is not a loopback http URL")?,
        _ => return Err("handoff: daemon is not {\"http\": URL}".into()),
    };
    let policy = o["policy"].clone();
    serde_json::from_value::<derm_core::policy::PolicyFile>(policy.clone())
        .map_err(|e| format!("handoff: policy is not a policy ({e})"))?;
    let policy_problem = match &o["policyProblem"] {
        Value::Null => None,
        Value::String(p) => Some(p.clone()),
        _ => return Err("handoff: policyProblem is not null or a string".into()),
    };
    let expires = o["expires"]
        .as_u64()
        .ok_or("handoff: expires is not a whole number of milliseconds")?;
    if expires <= now_ms {
        return Err("handoff: expired; nothing is started".into());
    }
    Ok(Handoff {
        chat,
        harness,
        argv,
        cwd,
        variables,
        token,
        daemon_http,
        policy,
        policy_problem,
        expires,
    })
}

fn variables(v: &Value) -> Result<BTreeMap<String, String>, String> {
    let Value::Object(m) = v else {
        return Err("handoff: variables is not an object".into());
    };
    let mut out = BTreeMap::new();
    for (k, val) in m {
        if !variable_name(k) {
            return Err(format!("handoff: variable name {k:?} is not A-Z 0-9 _"));
        }
        if reserved(k) {
            return Err(format!(
                "handoff: variable {k} is srt's or derm enter's own"
            ));
        }
        let val = val
            .as_str()
            .ok_or_else(|| format!("handoff: variable {k} is not a string"))?;
        if val.contains('\0') {
            return Err(format!("handoff: variable {k} holds a NUL"));
        }
        out.insert(k.clone(), val.to_string());
    }
    Ok(out)
}

/// The handoff as `derm run` writes it (the inverse of [`parse`]).
pub(crate) fn to_json(h: &Handoff) -> Value {
    let mut o = Map::new();
    o.insert("version".into(), Value::from(1));
    o.insert("chat".into(), Value::from(h.chat.clone()));
    o.insert("harness".into(), Value::from(h.harness.clone()));
    o.insert("argv".into(), Value::from(h.argv.clone()));
    o.insert("cwd".into(), Value::from(h.cwd.clone()));
    o.insert(
        "variables".into(),
        Value::Object(
            h.variables
                .iter()
                .map(|(k, v)| (k.clone(), Value::from(v.clone())))
                .collect(),
        ),
    );
    o.insert("token".into(), Value::from(h.token.clone()));
    o.insert(
        "daemon".into(),
        serde_json::json!({"http": h.daemon_http.clone()}),
    );
    o.insert("policy".into(), h.policy.clone());
    o.insert(
        "policyProblem".into(),
        h.policy_problem.clone().map_or(Value::Null, Value::from),
    );
    o.insert("expires".into(), Value::from(h.expires));
    Value::Object(o)
}

/// The per-chat file the gate inside reads (`DERM_CHAT_FILE`): the policy
/// `derm run` judged on the host and the daemon's route, so the gate never
/// takes either from a variable a project can set. It sits beside the
/// handoff, readable by the sandbox account and writable by no one else.
#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) fn chat_file_json(h: &Handoff) -> Value {
    serde_json::json!({
        "version": 1,
        "chat": h.chat,
        "policy": h.policy,
        "policyProblem": h.policy_problem,
        "daemon": {"http": h.daemon_http},
    })
}
