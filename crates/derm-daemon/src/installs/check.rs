//! The pre-install check (wave 5 lane X; rules cases 130 and 134; universal
//! plan lane X item 2). Off until the user turns it on
//! (`~/.derm/settings.json`, `installs.check`; Tony's call 10). When on, for
//! each new package the gate asked about it asks the package's registry
//! whether the name exists and when the version was published, and OSV
//! whether a record names it. It answers:
//! - a name the registry does not hold: `deny`, "not in the registry"
//!   (the made-up-name case, case 130); Go is the exception, below;
//! - an OSV `MAL-` record: `deny`, naming the record;
//! - a version younger than `installs.minAgeHours` (48 by default) or with
//!   another OSV record: `ask`, with the reason;
//! - anything else, or a registry or OSV that did not answer: nothing to
//!   add, so the gate's own `ask` for a new package stands.
//!
//! It never turns an `ask` into an `allow`.
//!
//! The calls (rules section 5 item 8: the daemon's first outbound calls
//! besides the tap's): `registry.npmjs.org`, `pypi.org`, `index.crates.io`,
//! `proxy.golang.org` and `api.osv.dev`, with the package name and version
//! only. A project or user config that names another registry skips the
//! check for that ecosystem (`registry_override`): its packages may be
//! private, and their names would go to the public registry.
//!
//! Routes and shapes, read 4 Nov 2026 (`plans/parallel/tk_lane_X.md`,
//! Research): npm's packument (`time`, `dist-tags`; 404 for a missing name,
//! run); PyPI's JSON API (`/pypi/<name>/json`, `releases` with
//! `upload_time_iso_8601`; 404, run); crates.io's sparse index (one JSON
//! line per version, `pubtime` optional; "404 Not Found, 410 Gone or 451",
//! the Cargo book); Go's proxy (`@v/<version>.info` with `Version` and
//! `Time`, Go 1.24.7's `RevInfo`); OSV's `/v1/querybatch` (the osv.dev page;
//! not reachable from the workspace, so tested against hand-made replies in
//! that shape).

use std::collections::HashMap;
use std::path::Path;
use std::sync::Mutex;
use std::time::Duration;

use serde_json::{json, Value};

/// What `installs` in the settings file says.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CheckSettings {
    pub on: bool,
    pub min_age_hours: u32,
}

impl Default for CheckSettings {
    fn default() -> Self {
        CheckSettings {
            on: false,
            min_age_hours: 48,
        }
    }
}

const MAX_SETTINGS: u64 = 64 * 1024;

/// The `installs` key of `~/.derm/settings.json`, read under the same rules
/// as lane S's reader (`derm_tap::settings::load`): a regular file of this
/// user's, no link, no group or other write bit, one link, under 64 KiB;
/// anything else gives the defaults (check off) and a warning.
pub fn load_settings(path: &Path) -> (CheckSettings, Option<String>) {
    let Ok(meta) = std::fs::symlink_metadata(path) else {
        return (CheckSettings::default(), None);
    };
    let warn = |why: &str| {
        (
            CheckSettings::default(),
            Some(format!(
                "{} {why}; the pre-install check stays off",
                path.display()
            )),
        )
    };
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        // SAFETY: getuid takes no arguments and cannot fail.
        let uid = unsafe { libc::getuid() };
        if !meta.file_type().is_file()
            || meta.uid() != uid
            || meta.mode() & 0o022 != 0
            || meta.nlink() != 1
        {
            return warn("is not a regular file of yours that only you can write");
        }
    }
    #[cfg(not(unix))]
    if !meta.file_type().is_file() {
        return warn("is not a regular file");
    }
    if meta.len() > MAX_SETTINGS {
        return warn("is too large");
    }
    let Ok(text) = std::fs::read_to_string(path) else {
        return warn("cannot be read");
    };
    match parse_settings(&text) {
        Ok(s) => (s, None),
        Err(why) => warn(&why),
    }
}

/// `contracts/settings.schema.json`'s rules for the file's shape and the
/// `installs` key.
pub fn parse_settings(text: &str) -> Result<CheckSettings, String> {
    let v: Value = serde_json::from_str(text).map_err(|_| "is not JSON".to_string())?;
    let obj = v.as_object().ok_or("is not a JSON object")?;
    if obj.get("version").and_then(Value::as_i64) != Some(1) {
        return Err("has no \"version\": 1".into());
    }
    for k in obj.keys() {
        if !matches!(
            k.as_str(),
            "version" | "boundary" | "tap" | "content" | "installs" | "computerUse"
        ) {
            return Err(format!("has a key the schema does not name ({k})"));
        }
    }
    let mut s = CheckSettings::default();
    if let Some(installs) = obj.get("installs") {
        let o = installs
            .as_object()
            .ok_or("has an installs that is not an object")?;
        for (k, v) in o {
            match (k.as_str(), v) {
                ("check", Value::Bool(b)) => s.on = *b,
                ("minAgeHours", Value::Number(n)) => {
                    let h = n
                        .as_u64()
                        .filter(|h| *h <= 8760)
                        .ok_or("has installs.minAgeHours out of 0 to 8760")?;
                    s.min_age_hours = h as u32;
                }
                _ => return Err(format!("has installs.{k} the schema does not allow")),
            }
        }
    }
    Ok(s)
}

// --- Fetching -------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Response {
    pub status: u16,
    pub body: Vec<u8>,
}

/// The network, so tests can stand in for it.
pub trait Fetch: Send + Sync {
    fn get(&self, url: &str) -> Result<Response, String>;
    fn post_json(&self, url: &str, body: &[u8]) -> Result<Response, String>;
}

/// The largest registry document read (npm's packument for a package with
/// thousands of versions runs to tens of MiB: `@types/node`'s was 11 MiB on
/// 4 Nov 2026). Past it the age is unknown.
pub const MAX_BODY: u64 = 32 * 1024 * 1024;

/// The real network: ureq 3.5.1 (lane S's pin), the OS trust store, no
/// redirect followed, 5 s to connect, 20 s in all.
pub struct UreqFetch {
    agent: ureq::Agent,
}

impl Default for UreqFetch {
    fn default() -> Self {
        let tls = ureq::tls::TlsConfig::builder()
            .root_certs(ureq::tls::RootCerts::PlatformVerifier)
            .build();
        let config = ureq::Agent::config_builder()
            .http_status_as_error(false)
            .max_redirects(0)
            .tls_config(tls)
            .user_agent("derm pre-install check")
            .timeout_connect(Some(Duration::from_secs(5)))
            .timeout_global(Some(Duration::from_secs(20)))
            .build();
        UreqFetch {
            agent: ureq::Agent::new_with_config(config),
        }
    }
}

impl Fetch for UreqFetch {
    fn get(&self, url: &str) -> Result<Response, String> {
        let mut r = self
            .agent
            .get(url)
            .header("accept", "application/json")
            .call()
            .map_err(|e| e.to_string())?;
        let status = r.status().as_u16();
        let body = r
            .body_mut()
            .with_config()
            .limit(MAX_BODY)
            .read_to_vec()
            .map_err(|e| e.to_string())?;
        Ok(Response { status, body })
    }
    fn post_json(&self, url: &str, body: &[u8]) -> Result<Response, String> {
        let mut r = self
            .agent
            .post(url)
            .header("content-type", "application/json")
            .send(body)
            .map_err(|e| e.to_string())?;
        let status = r.status().as_u16();
        let body = r
            .body_mut()
            .with_config()
            .limit(MAX_BODY)
            .read_to_vec()
            .map_err(|e| e.to_string())?;
        Ok(Response { status, body })
    }
}

// --- The check --------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Query {
    /// `npm`, `PyPI`, `crates.io` or `Go` (OSV's names).
    pub ecosystem: String,
    pub name: String,
    pub version: Option<String>,
}

/// One package's findings, the `install.call` record's `check.results` item.
#[derive(Clone, Debug, PartialEq)]
pub struct Finding {
    pub name: String,
    /// The version checked: the one named, else the registry's latest.
    pub version: Option<String>,
    /// `None` when the registry did not answer.
    pub exists: Option<bool>,
    pub age_hours: Option<f64>,
    pub osv: Vec<String>,
    /// Why this package denies or asks; empty when it adds nothing.
    pub deny: Vec<String>,
    pub ask: Vec<String>,
}

impl Finding {
    pub fn to_json(&self) -> Value {
        json!({
            "name": self.name,
            "version": self.version,
            "exists": self.exists,
            "ageHours": self.age_hours.map(|h| (h * 10.0).round() / 10.0),
            "osv": self.osv.iter().take(16).map(|id| id.chars().take(64).collect::<String>()).collect::<Vec<_>>(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Verdict {
    Deny(String),
    Ask(String),
    /// Nothing to add: the gate's own answer stands.
    Nothing,
}

const NPM: &str = "https://registry.npmjs.org/";
const PYPI: &str = "https://pypi.org/pypi/";
const CRATES: &str = "https://index.crates.io/";
const GOPROXY: &str = "https://proxy.golang.org/";
const OSV: &str = "https://api.osv.dev/v1/querybatch";

/// Packages in one request.
pub const MAX_QUERIES: usize = 64;
const CACHE_MS: i64 = 60 * 60 * 1000;
const MAX_CACHE: usize = 4096;

/// Ecosystem, name, version.
type CacheKey = (String, String, Option<String>);

/// The check with a cache of registry answers (one hour; a name the
/// registry does not hold is asked again after it).
pub struct PreInstall {
    fetch: Box<dyn Fetch>,
    cache: Mutex<HashMap<CacheKey, (i64, Lookup)>>,
}

#[derive(Clone, Debug, PartialEq)]
struct Lookup {
    exists: Option<bool>,
    /// The one version the command means: the latest, a tag's, or the
    /// exact version named. `None` for a range, which names no one version.
    resolved: Option<String>,
    /// The name exists and the exact version named does not.
    missing_version: bool,
    published_ms: Option<i64>,
    why_unknown: Option<String>,
}

impl Lookup {
    fn unknown(why: impl Into<String>) -> Lookup {
        Lookup {
            exists: None,
            resolved: None,
            missing_version: false,
            published_ms: None,
            why_unknown: Some(why.into()),
        }
    }
    fn absent() -> Lookup {
        Lookup {
            exists: Some(false),
            resolved: None,
            missing_version: false,
            published_ms: None,
            why_unknown: None,
        }
    }
}

/// A version written out in full (`1.3.0`, `2.0.0rc1`, `1.0.0-beta.1`), not
/// a range, a tag or a wildcard.
fn is_exact(v: &str) -> bool {
    v.chars().next().is_some_and(|c| c.is_ascii_digit())
        && v.chars()
            .all(|c| c.is_ascii_alphanumeric() || ".-+!".contains(c))
}

impl PreInstall {
    pub fn new(fetch: Box<dyn Fetch>) -> Self {
        PreInstall {
            fetch,
            cache: Mutex::new(HashMap::new()),
        }
    }

    /// Runs the check over `queries` (at most [`MAX_QUERIES`]), skipping an
    /// ecosystem `skip` names (a registry override). `now_ms` is the wall clock.
    pub fn run(
        &self,
        queries: &[Query],
        settings: CheckSettings,
        skip: &[&str],
        now_ms: i64,
    ) -> (bool, Vec<Finding>, Verdict) {
        if !settings.on || queries.is_empty() {
            return (false, Vec::new(), Verdict::Nothing);
        }
        let mut findings: Vec<Finding> = Vec::new();
        for q in queries.iter().take(MAX_QUERIES) {
            let mut f = Finding {
                name: q.name.clone(),
                version: q.version.clone(),
                exists: None,
                age_hours: None,
                osv: Vec::new(),
                deny: Vec::new(),
                ask: Vec::new(),
            };
            if skip.contains(&q.ecosystem.as_str()) {
                f.ask.push(format!(
                    "{}: the project names its own registry, so the check did not run",
                    q.name
                ));
                findings.push(f);
                continue;
            }
            let Some(url) = registry_url(q) else {
                f.ask
                    .push(format!("{}: a name the check cannot look up", q.name));
                findings.push(f);
                continue;
            };
            let l = self.lookup(q, &url, now_ms);
            f.exists = l.exists;
            f.version = l.resolved.clone();
            match l.exists {
                Some(false) if q.ecosystem == "Go" => f.ask.push(format!(
                    "{}: not on proxy.golang.org (a private module, or a path that does not exist)",
                    q.name
                )),
                Some(false) => f.deny.push(format!("{}: not in the registry", q.name)),
                Some(true) if l.missing_version => f.ask.push(format!(
                    "{} {}: that version is not in the registry",
                    q.name,
                    q.version.as_deref().unwrap_or("")
                )),
                None => f.ask.push(format!(
                    "{}: {}",
                    q.name,
                    l.why_unknown
                        .clone()
                        .unwrap_or_else(|| "the registry did not answer".into())
                )),
                _ => {}
            }
            if let Some(p) = l.published_ms {
                let hours = ((now_ms - p) as f64 / 3_600_000.0).max(0.0);
                f.age_hours = Some(hours);
                if hours < settings.min_age_hours as f64 {
                    f.ask.push(format!(
                        "{} {}: published {:.0} hours ago, under the {}-hour minimum",
                        q.name,
                        f.version.as_deref().unwrap_or(""),
                        hours.floor(),
                        settings.min_age_hours
                    ));
                }
            }
            findings.push(f);
        }
        self.osv(queries, &mut findings);
        let deny: Vec<String> = findings.iter().flat_map(|f| f.deny.clone()).collect();
        let ask: Vec<String> = findings.iter().flat_map(|f| f.ask.clone()).collect();
        // A deny also carries what would have asked: the card shows it all.
        let verdict = if !deny.is_empty() {
            Verdict::Deny(cap(format!(
                "pre-install check: {}",
                [deny, ask].concat().join("; ")
            )))
        } else if !ask.is_empty() {
            Verdict::Ask(cap(format!("pre-install check: {}", ask.join("; "))))
        } else {
            Verdict::Nothing
        };
        (true, findings, verdict)
    }

    fn lookup(&self, q: &Query, url: &str, now_ms: i64) -> Lookup {
        let key = (q.ecosystem.clone(), q.name.clone(), q.version.clone());
        if let Ok(cache) = self.cache.lock() {
            if let Some((at, l)) = cache.get(&key) {
                if now_ms - at < CACHE_MS && l.exists.is_some() {
                    return l.clone();
                }
            }
        }
        let l = match self.fetch.get(url) {
            Err(_) => Lookup::unknown("the registry did not answer"),
            Ok(r) if matches!(r.status, 404 | 410 | 451) => Lookup::absent(),
            Ok(r) if r.status != 200 => {
                Lookup::unknown(format!("the registry answered {}", r.status))
            }
            Ok(r) => read_registry(q, &r.body),
        };
        if l.exists.is_some() {
            if let Ok(mut cache) = self.cache.lock() {
                if cache.len() >= MAX_CACHE {
                    cache.retain(|_, (at, _)| now_ms - *at < CACHE_MS);
                    if cache.len() >= MAX_CACHE {
                        cache.clear();
                    }
                }
                cache.insert(key, (now_ms, l.clone()));
            }
        }
        l
    }

    /// One OSV batch for every finding with a version; an id starting `MAL-`
    /// denies, any other asks. A batch that fails adds a note and nothing else.
    fn osv(&self, queries: &[Query], findings: &mut [Finding]) {
        let osv_version = |eco: &str, v: &str| -> String {
            if eco == "Go" {
                v.trim_start_matches('v').to_string()
            } else {
                v.to_string()
            }
        };
        let idx: Vec<usize> = findings
            .iter()
            .enumerate()
            .filter(|(i, f)| {
                f.exists == Some(true)
                    && f.version
                        .as_deref()
                        .is_some_and(|v| is_exact(&osv_version(&queries[*i].ecosystem, v)))
            })
            .map(|(i, _)| i)
            .collect();
        if idx.is_empty() {
            return;
        }
        let body = json!({
            "queries": idx.iter().map(|&i| json!({
                "package": {"name": findings[i].name, "ecosystem": queries[i].ecosystem},
                "version": findings[i].version.as_deref().map(|v| osv_version(&queries[i].ecosystem, v)),
            })).collect::<Vec<_>>()
        });
        let Ok(bytes) = serde_json::to_vec(&body) else {
            return;
        };
        let parsed = match self.fetch.post_json(OSV, &bytes) {
            Ok(r) if r.status == 200 => serde_json::from_slice::<Value>(&r.body).ok(),
            _ => None,
        };
        let Some(results) = parsed
            .as_ref()
            .and_then(|v| v.get("results"))
            .and_then(Value::as_array)
            .filter(|r| r.len() == idx.len())
        else {
            if let Some(&first) = idx.first() {
                findings[first]
                    .ask
                    .push("OSV did not answer, so no advisory was checked".into());
            }
            return;
        };
        for (k, &i) in idx.iter().enumerate() {
            let ids: Vec<String> = results[k]
                .get("vulns")
                .and_then(Value::as_array)
                .map(|v| {
                    v.iter()
                        .filter_map(|x| x.get("id").and_then(Value::as_str))
                        .map(str::to_string)
                        .collect()
                })
                .unwrap_or_default();
            let f = &mut findings[i];
            let label = format!("{} {}", f.name, f.version.as_deref().unwrap_or(""));
            let malicious: Vec<&String> = ids.iter().filter(|id| id.starts_with("MAL-")).collect();
            if !malicious.is_empty() {
                f.deny.push(format!(
                    "{label}: known malicious ({})",
                    join_ids(&malicious)
                ));
            }
            let other: Vec<&String> = ids.iter().filter(|id| !id.starts_with("MAL-")).collect();
            if !other.is_empty() {
                f.ask
                    .push(format!("{label}: known advisories ({})", join_ids(&other)));
            }
            f.osv = ids;
        }
    }
}

fn join_ids(ids: &[&String]) -> String {
    let mut out: Vec<String> = ids
        .iter()
        .take(5)
        .map(|s| s.chars().take(64).collect())
        .collect();
    if ids.len() > 5 {
        out.push(format!("and {} more", ids.len() - 5));
    }
    out.join(", ")
}

fn cap(s: String) -> String {
    if s.chars().count() > 600 {
        let cut: String = s.chars().take(597).collect();
        format!("{cut}...")
    } else {
        s
    }
}

fn ok_chars(s: &str, extra: &str) -> bool {
    !s.is_empty()
        && s.chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || extra.contains(c))
}

/// The registry URL for one package, or `None` for a name outside the
/// registry's grammar (nothing from the input reaches a URL unchecked).
pub fn registry_url(q: &Query) -> Option<String> {
    match q.ecosystem.as_str() {
        "npm" => {
            let (scope, name) = match q.name.strip_prefix('@') {
                Some(r) => {
                    let (s, n) = r.split_once('/')?;
                    (Some(s), n)
                }
                None => (None, q.name.as_str()),
            };
            if scope.is_some_and(|s| !ok_chars(s, "._~-"))
                || !ok_chars(name, "._~-")
                || q.name.len() > 214
            {
                return None;
            }
            Some(match scope {
                Some(s) => format!("{NPM}@{s}%2f{name}"),
                None => format!("{NPM}{name}"),
            })
        }
        "PyPI" => ok_chars(&q.name, "._-").then(|| format!("{PYPI}{}/json", q.name)),
        "crates.io" => {
            let n = q.name.as_str();
            if !ok_chars(n, "_-") || n.len() > 64 {
                return None;
            }
            let path = match n.len() {
                1 => format!("1/{n}"),
                2 => format!("2/{n}"),
                3 => format!("3/{}/{n}", &n[..1]),
                _ => format!("{}/{}/{n}", &n[..2], &n[2..4]),
            };
            Some(format!("{CRATES}{path}"))
        }
        "Go" => {
            let p = q.name.as_str();
            if !p.split('/').all(|part| ok_chars(part, "._~+-"))
                || !p.split('/').next()?.contains('.')
            {
                return None;
            }
            let escaped = go_escape(p);
            let v = match q.version.as_deref() {
                None | Some("latest") => "@latest".to_string(),
                Some(v) if ok_chars(v, ".+-") => format!("@v/{}.info", go_escape(v)),
                Some(_) => return None,
            };
            Some(format!("{GOPROXY}{escaped}/{v}"))
        }
        _ => None,
    }
}

/// Go's module path escaping: an upper-case letter is `!` and its lower case
/// (`golang.org/x/mod/module.EscapePath`, Go 1.24.7's vendored copy).
fn go_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if c.is_ascii_uppercase() {
            out.push('!');
            out.push(c.to_ascii_lowercase());
        } else {
            out.push(c);
        }
    }
    out
}

fn parse_time_ms(s: &str) -> Option<i64> {
    // RFC 3339, as the registries write it: `2024-12-04T17:35:26.475Z`,
    // `2026-03-20T00:12:37Z`, `2024-12-04T17:35:26.475123Z`, `+00:00`.
    let b = s.as_bytes();
    if b.len() < 20
        || b[4] != b'-'
        || b[7] != b'-'
        || (b[10] != b'T' && b[10] != b't')
        || b[13] != b':'
        || b[16] != b':'
    {
        return None;
    }
    let num = |r: std::ops::Range<usize>| s.get(r)?.parse::<i64>().ok();
    let (y, mo, d, h, mi, se) = (
        num(0..4)?,
        num(5..7)?,
        num(8..10)?,
        num(11..13)?,
        num(14..16)?,
        num(17..19)?,
    );
    let mut i = 19;
    let mut ms = 0i64;
    if b.get(i) == Some(&b'.') {
        i += 1;
        let start = i;
        while i < b.len() && b[i].is_ascii_digit() {
            i += 1;
        }
        let frac = s.get(start..i)?;
        let first3: String = frac.chars().chain("000".chars()).take(3).collect();
        ms = first3.parse().ok()?;
    }
    let offset_min = match s.get(i..)? {
        "Z" | "z" => 0,
        tz if tz.len() == 6 && (tz.starts_with('+') || tz.starts_with('-')) => {
            let sign = if tz.starts_with('-') { -1 } else { 1 };
            sign * (tz[1..3].parse::<i64>().ok()? * 60 + tz[4..6].parse::<i64>().ok()?)
        }
        _ => return None,
    };
    if !(1..=12).contains(&mo) || !(1..=31).contains(&d) || h > 23 || mi > 59 || se > 60 {
        return None;
    }
    // Days from the civil date (Howard Hinnant's algorithm).
    let y2 = if mo <= 2 { y - 1 } else { y };
    let era = y2.div_euclid(400);
    let yoe = y2 - era * 400;
    let mp = (mo + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    Some(((days * 86_400 + h * 3600 + mi * 60 + se) - offset_min * 60) * 1000 + ms)
}

fn read_registry(q: &Query, body: &[u8]) -> Lookup {
    // The version the command means: none named is the latest; an exact one
    // is itself; anything else (a range) names no one version.
    let wanted = |latest: Option<String>| -> Option<String> {
        match q.version.as_deref() {
            None => latest,
            Some(v) if is_exact(v) => Some(v.to_string()),
            Some(_) => None,
        }
    };
    let found =
        |wanted: Option<String>, published: &dyn Fn(&str) -> Option<Option<i64>>| -> Lookup {
            match wanted {
                None => Lookup {
                    exists: Some(true),
                    resolved: None,
                    missing_version: false,
                    published_ms: None,
                    why_unknown: None,
                },
                Some(w) => match published(&w) {
                    Some(p) => Lookup {
                        exists: Some(true),
                        resolved: Some(w),
                        missing_version: false,
                        published_ms: p,
                        why_unknown: None,
                    },
                    None => Lookup {
                        exists: Some(true),
                        resolved: None,
                        missing_version: true,
                        published_ms: None,
                        why_unknown: None,
                    },
                },
            }
        };
    match q.ecosystem.as_str() {
        "npm" => {
            let Ok(v) = serde_json::from_slice::<Value>(body) else {
                return Lookup::unknown("the registry's answer was not JSON");
            };
            let tags = v.get("dist-tags").and_then(Value::as_object);
            let times = v.get("time").and_then(Value::as_object);
            let tag = |t: &str| {
                tags.and_then(|m| m.get(t))
                    .and_then(Value::as_str)
                    .map(str::to_string)
            };
            // A dist-tag (`latest`, `next`) names the version it points at.
            let w = match q.version.as_deref() {
                Some(t) if !is_exact(t) && tag(t).is_some() => tag(t),
                _ => wanted(tag("latest")),
            };
            found(w, &|ver| {
                times
                    .and_then(|t| t.get(ver))
                    .map(|x| x.as_str().and_then(parse_time_ms))
            })
        }
        "PyPI" => {
            let Ok(v) = serde_json::from_slice::<Value>(body) else {
                return Lookup::unknown("the registry's answer was not JSON");
            };
            let releases = v.get("releases").and_then(Value::as_object);
            let latest = v
                .get("info")
                .and_then(|i| i.get("version"))
                .and_then(Value::as_str)
                .map(str::to_string);
            found(wanted(latest), &|ver| {
                let files = releases?.get(ver)?.as_array()?;
                Some(
                    files
                        .iter()
                        .filter_map(|f| {
                            f.get("upload_time_iso_8601")?
                                .as_str()
                                .and_then(parse_time_ms)
                        })
                        .min(),
                )
            })
        }
        "crates.io" => {
            let text = String::from_utf8_lossy(body);
            let rows: Vec<Value> = text
                .lines()
                .filter_map(|l| serde_json::from_str(l).ok())
                .collect();
            if rows.is_empty() {
                return Lookup::unknown("the index's answer held no version");
            }
            let latest = rows
                .iter()
                .rev()
                .find(|r| r.get("yanked") != Some(&Value::Bool(true)))
                .and_then(|r| r.get("vers")?.as_str().map(str::to_string));
            found(wanted(latest), &|ver| {
                let row = rows
                    .iter()
                    .find(|r| r.get("vers").and_then(Value::as_str) == Some(ver))?;
                Some(
                    row.get("pubtime")
                        .and_then(Value::as_str)
                        .and_then(parse_time_ms),
                )
            })
        }
        "Go" => {
            let Ok(v) = serde_json::from_slice::<Value>(body) else {
                return Lookup::unknown("the proxy's answer was not JSON");
            };
            Lookup {
                exists: Some(true),
                resolved: v.get("Version").and_then(Value::as_str).map(str::to_string),
                missing_version: false,
                published_ms: v
                    .get("Time")
                    .and_then(Value::as_str)
                    .and_then(parse_time_ms),
                why_unknown: None,
            }
        }
        _ => Lookup::unknown("an ecosystem the check does not know"),
    }
}

/// Whether the project or the user names a registry other than the default
/// for `ecosystem`, in the files a manager reads for it: `.npmrc` (the
/// project's folders up to the root, and `~/.npmrc`) with `registry=` or a
/// scope's `:registry=`; `pip.conf`, `uv.toml`, or a `pyproject.toml` with
/// a `tool.uv.index`, `tool.poetry.source` or `tool.pdm.source` table;
/// `.cargo/config.toml` with `[registries` or `replace-with`. Go's
/// `GOPROXY` lives in the agent's environment, which the daemon does not
/// see; a private module is asked about, never denied (above).
pub fn registry_override(ecosystem: &str, project: &Path, home: Option<&Path>) -> bool {
    let read = |p: &Path| {
        std::fs::read_to_string(p)
            .ok()
            .filter(|t| t.len() < 1 << 20)
    };
    let mut dirs: Vec<std::path::PathBuf> = project
        .ancestors()
        .take(32)
        .map(Path::to_path_buf)
        .collect();
    if let Some(h) = home {
        dirs.push(h.to_path_buf());
    }
    match ecosystem {
        "npm" => dirs.iter().any(|d| {
            read(&d.join(".npmrc")).is_some_and(|t| {
                t.lines().map(str::trim).any(|l| {
                    let key = l.split('=').next().unwrap_or("").trim();
                    !l.starts_with('#')
                        && !l.starts_with(';')
                        && (key == "registry" || key.ends_with(":registry"))
                })
            })
        }),
        "PyPI" => {
            let mut files: Vec<std::path::PathBuf> = Vec::new();
            for d in &dirs {
                files.push(d.join("pyproject.toml"));
                files.push(d.join("uv.toml"));
            }
            if let Some(h) = home {
                files.push(h.join(".config/pip/pip.conf"));
                files.push(h.join(".pip/pip.conf"));
                files.push(h.join(".config/uv/uv.toml"));
            }
            files.push("/etc/pip.conf".into());
            files.iter().any(|f| {
                read(f).is_some_and(|t| {
                    t.lines().map(str::trim).any(|l| {
                        l.starts_with("[[tool.uv.index]]")
                            || l.starts_with("[[tool.poetry.source]]")
                            || l.starts_with("[[tool.pdm.source]]")
                            || l.starts_with("[[index]]")
                            || l.starts_with("index-url")
                            || l.starts_with("extra-index-url")
                            || l.starts_with("index_url")
                    })
                })
            })
        }
        "crates.io" => dirs.iter().any(|d| {
            [d.join(".cargo/config.toml"), d.join(".cargo/config")]
                .iter()
                .any(|f| {
                    read(f).is_some_and(|t| t.contains("[registries") || t.contains("replace-with"))
                })
        }),
        _ => false,
    }
}

#[cfg(test)]
mod tests;
