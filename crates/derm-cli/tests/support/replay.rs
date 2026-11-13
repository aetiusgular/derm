//! Replays a recorded TypeScript hook case against `derm hook <agent>
//! <event>` (the wave 5b base's red tests). Each call of the case is set up
//! as the recorder saw it: the temp folders and the files in them, the
//! environment, stdin, the fake daemon's answer mode; then `derm` runs with
//! exactly that environment and the reply is held to the TypeScript's under
//! `contracts/hook-dialects.md` section 9.3.

use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use serde_json::Value;

/// The keys whose string is a reason meant for people: only its first two
/// words are compared (section 9.3, rule 2).
const REASON_KEYS: [&str; 9] = [
    "reason",
    "permissionDecisionReason",
    "systemMessage",
    "stopReason",
    "user_message",
    "agent_message",
    "message",
    "additionalContext",
    "followup_message",
];

fn repo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join("..")
}

/// "derm: rule bash deny; x" -> "derm: rule bash"; "no rule (x)" -> "no rule".
pub fn reason_head(s: &str) -> String {
    let t = s.trim();
    let (prefix, rest) = match t.strip_prefix("derm: ") {
        Some(r) => ("derm: ", r),
        None => match t.strip_prefix("derm asks: ") {
            Some(r) => ("derm asks: ", r),
            None => ("", t),
        },
    };
    let words: Vec<String> = rest
        .split(|c: char| c.is_whitespace() || c == ';' || c == '(')
        .filter(|w| !w.is_empty())
        .take(2)
        .map(str::to_string)
        .collect();
    format!("{prefix}{}", words.join(" "))
}

fn norm_json(v: &Value, key: Option<&str>) -> Value {
    match v {
        Value::String(s) if key.is_some_and(|k| REASON_KEYS.contains(&k)) => {
            Value::String(reason_head(s))
        }
        Value::Object(o) => Value::Object(
            o.iter()
                .map(|(k, x)| (k.clone(), norm_json(x, Some(k))))
                .collect(),
        ),
        Value::Array(a) => Value::Array(a.iter().map(|x| norm_json(x, key)).collect()),
        other => other.clone(),
    }
}

/// Stdout as compared: empty, each JSON line normalized, or the text's head.
pub fn norm_stdout(s: &str) -> Vec<Value> {
    s.lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| match serde_json::from_str::<Value>(l) {
            Ok(v) => norm_json(&v, None),
            Err(_) => Value::String(reason_head(l)),
        })
        .collect()
}

pub fn norm_stderr(s: &str) -> String {
    s.lines()
        .find(|l| !l.trim().is_empty())
        .map(reason_head)
        .unwrap_or_default()
}

fn subst(s: &str, map: &BTreeMap<String, String>) -> String {
    let mut out = s.to_string();
    for (k, v) in map {
        out = out.replace(k, v);
    }
    out
}

struct Scratch(PathBuf);
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn scratch() -> Scratch {
    use std::sync::atomic::{AtomicU32, Ordering};
    static N: AtomicU32 = AtomicU32::new(0);
    // Short: a Unix socket path holds about 104 bytes.
    let p = std::env::temp_dir().join(format!(
        "dr{}-{}",
        std::process::id(),
        N.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = std::fs::remove_dir_all(&p);
    std::fs::create_dir_all(&p).unwrap();
    Scratch(p)
}

#[cfg(unix)]
fn set_mode(p: &Path, m: u64) {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(p, std::fs::Permissions::from_mode(m as u32));
}
#[cfg(not(unix))]
fn set_mode(_p: &Path, _m: u64) {}

/// Runs one recorded case: every call in order, each held to its recording.
pub fn case(cases: &str, id: &str) {
    let doc: Value = serde_json::from_str(cases).expect("case file");
    let case = doc["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["id"] == id)
        .unwrap_or_else(|| panic!("no case {id}"));
    let mut failures = Vec::new();
    for (i, call) in case["calls"].as_array().unwrap().iter().enumerate() {
        // A call the test made with its own dependencies: listed in
        // manual-calls.json for the lane to port by hand (section 9.4).
        if call.get("manual").is_some() {
            continue;
        }
        if let Err(why) = one(call) {
            failures.push(format!(
                "call {i} ({} {}): {why}",
                call["agent"], call["event"]
            ));
        }
    }
    assert!(
        failures.is_empty(),
        "{}\n{}",
        case["test"],
        failures.join("\n")
    );
}

fn one(call: &Value) -> Result<(), String> {
    let root = scratch();
    let mut map = BTreeMap::new();
    map.insert(
        "{REPO}".to_string(),
        repo().canonicalize().unwrap().display().to_string(),
    );
    // The fake daemon, when the case had one.
    #[cfg(unix)]
    let daemon = call["daemon"].as_str().map(|mode| {
        let d = super::fake_daemon::FakeDaemon::start(
            super::fake_daemon::Approve::parse(mode),
            Some(&root.0),
        );
        map.insert("{D}".into(), d.dir.display().to_string());
        d
    });
    #[cfg(not(unix))]
    if call["daemon"].is_string() {
        return Err("the fake daemon is Unix only".into());
    }
    // Temp folders: {T0} and on, each a fresh folder under the scratch root.
    for f in call["files"].as_array().unwrap() {
        let p = f["path"].as_str().unwrap();
        if let Some(rest) = p.strip_prefix("{T") {
            let n: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
            let key = format!("{{T{n}}}");
            map.entry(key)
                .or_insert_with(|| root.0.join(format!("t{n}")).display().to_string());
        }
    }
    for f in call["files"].as_array().unwrap() {
        let p = PathBuf::from(subst(f["path"].as_str().unwrap(), &map));
        match f["kind"].as_str() {
            Some("dir") => {
                std::fs::create_dir_all(&p).map_err(|e| format!("{}: {e}", p.display()))?;
                if let Some(m) = f["mode"].as_u64() {
                    set_mode(&p, m);
                }
            }
            Some("file") => {
                if let Some(parent) = p.parent() {
                    std::fs::create_dir_all(parent).ok();
                }
                std::fs::write(&p, subst(f["text"].as_str().unwrap_or(""), &map))
                    .map_err(|e| format!("{}: {e}", p.display()))?;
                if let Some(m) = f["mode"].as_u64() {
                    set_mode(&p, m);
                }
            }
            #[cfg(unix)]
            Some("link") => {
                let _ = std::os::unix::fs::symlink(subst(f["target"].as_str().unwrap(), &map), &p);
            }
            #[cfg(unix)]
            Some("fifo") => {
                let c = std::ffi::CString::new(p.display().to_string()).unwrap();
                // SAFETY: a NUL-terminated path.
                unsafe { libc::mkfifo(c.as_ptr(), 0o600) };
            }
            _ => {}
        }
    }
    // Folders a file is under are set to their mode last (a 0500 folder
    // would refuse the files written into it).
    for f in call["files"].as_array().unwrap() {
        if f["kind"] == "dir" {
            if let Some(m) = f["mode"].as_u64() {
                set_mode(&PathBuf::from(subst(f["path"].as_str().unwrap(), &map)), m);
            }
        }
    }
    let home = root.0.join("home");
    std::fs::create_dir_all(&home).unwrap();
    let agent = call["agent"].as_str().unwrap();
    let event = call["event"].as_str().unwrap();
    let mut cmd = match std::env::var("DERM_REPLAY_ORACLE").ok().as_deref() {
        // The harness's own check: the TypeScript hook replayed against its
        // own recording must pass, or the harness, not derm, is wrong.
        Some("ts") => oracle(agent, event),
        _ => {
            let mut c = Command::new(env!("CARGO_BIN_EXE_derm"));
            c.args(["hook", agent, event]);
            c
        }
    };
    cmd.env_clear();
    // The TypeScript hook read os.homedir() when the case set no HOME; an
    // empty home of its own stands for it here.
    cmd.env("HOME", &home);
    for (k, v) in call["env"].as_object().unwrap() {
        cmd.env(k, subst(v.as_str().unwrap_or(""), &map));
    }
    cmd.current_dir(subst(call["cwd"].as_str().unwrap(), &map));
    cmd.stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = cmd.spawn().map_err(|e| format!("spawn derm: {e}"))?;
    let stdin = subst(call["stdin"].as_str().unwrap(), &map);
    if let Some(mut s) = child.stdin.take() {
        let _ = s.write_all(stdin.as_bytes());
    }
    let limit =
        Duration::from_millis(call["ms"].as_u64().unwrap_or(0) * 3).max(Duration::from_secs(20));
    let t0 = Instant::now();
    loop {
        if child.try_wait().map_err(|e| e.to_string())?.is_some() {
            break;
        }
        if t0.elapsed() > limit {
            let _ = child.kill();
            return Err(format!("derm hook ran past {limit:?}"));
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    let out = child.wait_with_output().map_err(|e| e.to_string())?;
    let want = &call["want"];
    let mut why = Vec::new();
    let got_exit = out.status.code().unwrap_or(-1);
    if i64::from(got_exit) != want["exit"].as_i64().unwrap() {
        why.push(format!("exit {got_exit}, want {}", want["exit"]));
    }
    let got_out = String::from_utf8_lossy(&out.stdout);
    let want_out = subst(want["stdout"].as_str().unwrap(), &map);
    if norm_stdout(&got_out) != norm_stdout(&want_out) {
        why.push(format!(
            "stdout {:?}, want {:?}",
            got_out.trim(),
            want_out.trim()
        ));
    }
    let got_err = String::from_utf8_lossy(&out.stderr);
    let want_err = subst(want["stderr"].as_str().unwrap(), &map);
    if norm_stderr(&got_err) != norm_stderr(&want_err) {
        why.push(format!(
            "stderr {:?}, want {:?}",
            got_err.trim(),
            want_err.trim()
        ));
    }
    // What a call's own text was must never reach a reply it did not have
    // in the TypeScript either (case 77): checked through rule 4.
    #[cfg(unix)]
    if let Some(d) = &daemon {
        let got: Vec<Value> = d
            .lines()
            .into_iter()
            .map(|(_, l)| l)
            .filter(|l| l["op"] != "hello")
            // Taint (wave 6, lane 6D) came after these recordings: the
            // TypeScript hooks had none, so its op and its records are left
            // out of the comparison, and `gate::taint`'s tests hold them
            // (integration w6, phase 2, request 6D-1). Its verdict still
            // reaches the reply, which is compared whole above.
            .filter(|l| {
                l["op"] != "taint"
                    && !(l["op"] == "event"
                        && l["event"]["kind"]
                            .as_str()
                            .is_some_and(|k| k.starts_with("taint.")))
            })
            .map(|l| match l["op"].as_str() {
                Some("event") => serde_json::json!({"op": "event", "kind": l["event"]["kind"], "harness": l["event"]["harness"], "decision": l["event"]["detail"]["decision"], "tool": l["event"]["detail"]["tool"]}),
                Some("approve") => serde_json::json!({"op": "approve", "harness": l["request"]["harness"], "tool": l["request"]["tool"]}),
                other => serde_json::json!({"op": other}),
            })
            .collect();
        if Value::Array(got.clone()) != call["sent"] {
            why.push(format!("daemon lines {got:?}, want {}", call["sent"]));
        }
    }
    if why.is_empty() {
        Ok(())
    } else {
        Err(why.join("; "))
    }
}

/// The TypeScript hook for `agent` (`DERM_REPLAY_ORACLE=ts`), run with the
/// `node` found on this test's PATH.
fn oracle(agent: &str, event: &str) -> Command {
    let node = std::env::var_os("PATH")
        .and_then(|p| {
            std::env::split_paths(&p)
                .map(|d| d.join("node"))
                .find(|n| n.is_file())
        })
        .expect("node on PATH for DERM_REPLAY_ORACLE=ts");
    let pkg = |p: &str| repo().join("packages").join(p).join("bin");
    let mut c = Command::new(node);
    c.arg("--no-warnings");
    match agent {
        "claude-code" => c
            .arg(pkg("derm-claude-plugin").join("derm-hook.mjs"))
            .arg(event),
        "codex" => c
            .arg(pkg("derm-codex-plugin").join("derm-hook.mjs"))
            .arg(event),
        "gemini" => c
            .arg(pkg("derm-gemini-extension").join("derm-hook.mjs"))
            .arg(event),
        "hermes" => c.arg(pkg("derm-hermes-plugin").join("derm-decide.mjs")),
        "cursor" | "antigravity" | "goose" | "mistral-vibe" | "crush" | "kiro" => c
            .arg(pkg("derm-hooks-native").join("derm-hook.mjs"))
            .arg(agent),
        _ => c
            .arg(pkg("derm-hooks-claude-compat").join("derm-hook.mjs"))
            .args([agent, event]),
    };
    c
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_reason_is_compared_by_its_first_two_words() {
        assert_eq!(reason_head("derm: rule bash deny; x"), "derm: rule bash");
        assert_eq!(reason_head("derm: rule bash"), "derm: rule bash");
        assert_eq!(reason_head("no rule (no policy file)"), "no rule");
    }
}
