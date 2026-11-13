//! One red test per wave 5b contract (the wave 5b base), at the process
//! boundary so they build on the base and fail there: `contracts/
//! gate-serve.md` (lane 5bC), `srt-windows.md` (5bD), `hook-dialects.md`
//! section 9 (5bA's marks rule, 5bF's registration line). The Sysmon
//! service's is `crates/derm-sysmon/tests/contract.rs` (5bE). They pass
//! since the close and always build: `cargo test -p derm-cli --test
//! contracts_w5b`.

mod support;

use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

use serde_json::Value;

fn repo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join("..")
}

fn scratch(name: &str) -> PathBuf {
    let p = std::env::temp_dir().join(format!("dc-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&p);
    std::fs::create_dir_all(&p).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    p
}

fn derm() -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_derm"));
    c.env_clear();
    c
}

/// Lane 5bC: `derm gate serve` answers `contracts/fixtures/gate-serve/
/// exchange.jsonl` line for line (the replies are what `gate::core` answers,
/// held so by `gate::core::tests::the_gate_serve_fixture_is_what_the_core_answers`).
#[test]
fn gate_serve_answers_the_fixture_exchange() {
    let dir = scratch("serve");
    let policy = dir.join("policy.json");
    std::fs::copy(
        repo().join("contracts/fixtures/gate-serve/policy.json"),
        &policy,
    )
    .unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&policy, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    let lines: Vec<Value> =
        std::fs::read_to_string(repo().join("contracts/fixtures/gate-serve/exchange.jsonl"))
            .unwrap()
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
    // The chat's folder is a sibling of the policy: a `DERM_POLICY` inside
    // the folder the gate runs in is refused (case 226, `gate/policy.rs`),
    // which the base's first form of this test ran into (lane 5bC's request 3).
    let work = dir.join("work");
    std::fs::create_dir_all(&work).unwrap();
    let mut child = derm()
        .args(["gate", "serve", "--agent", "pi"])
        .env("HOME", &dir)
        // The light tier's home on Windows (`gate::locallog`): with no home
        // folder its record is lost, and since the wave 6 phase 1 merge a
        // lost decision record denies in a hook with no chat token.
        .env("USERPROFILE", &dir)
        .env("DERM_POLICY", &policy)
        .current_dir(&work)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let mut out = BufReader::new(child.stdout.take().unwrap());
    for l in &lines {
        let line = &l["line"];
        if l["dir"] == "in" {
            writeln!(stdin, "{line}").unwrap();
            continue;
        }
        let mut got = String::new();
        let n = out.read_line(&mut got).unwrap_or(0);
        assert!(n > 0, "derm gate serve answered nothing for {line}");
        let got: Value = serde_json::from_str(&got).unwrap_or(Value::Null);
        // `hello`'s policy object and an error's wording are the lane's; the
        // rest of each reply is the fixture's.
        if line.get("error").is_some() {
            assert_eq!(got["ok"], false, "{got}");
        } else if line.get("protocol").is_some() {
            assert_eq!(got["ok"], true, "{got}");
            assert_eq!(got["protocol"], 1, "{got}");
        } else {
            assert_eq!(&got, line);
        }
    }
    drop(stdin);
    let _ = child.wait_timeout_or_kill(Duration::from_secs(5));
    let _ = std::fs::remove_dir_all(&dir);
}

trait WaitTimeout {
    fn wait_timeout_or_kill(&mut self, d: Duration) -> Option<std::process::ExitStatus>;
}
impl WaitTimeout for std::process::Child {
    fn wait_timeout_or_kill(&mut self, d: Duration) -> Option<std::process::ExitStatus> {
        let t0 = std::time::Instant::now();
        while t0.elapsed() < d {
            if let Ok(Some(s)) = self.try_wait() {
                return Some(s);
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        let _ = self.kill();
        None
    }
}

/// Lane 5bD: `derm enter --check <handoff>` reads `contracts/fixtures/
/// srt-windows/handoff.json`, starts nothing, and says what it would do.
#[test]
fn enter_check_reads_the_fixture_handoff() {
    let out = derm()
        .args(["enter", "--check"])
        .arg(repo().join("contracts/fixtures/srt-windows/handoff.json"))
        .output()
        .unwrap();
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let v: Value =
        serde_json::from_slice(out.stdout.split(|b| *b == b'\n').next().unwrap()).unwrap();
    assert_eq!(v["ok"], true);
    assert_eq!(v["chat"], "derm-0123456789ab");
    assert!(v["variables"]
        .as_array()
        .unwrap()
        .iter()
        .any(|n| n == "DERM_CHAT_ID"));
    // The token's value is never printed.
    assert!(!String::from_utf8_lossy(&out.stdout).contains(&"2".repeat(64)));
}

/// Lane 5bD: a handoff with an extra key, or one past `expires`, is refused.
#[test]
fn enter_check_refuses_a_handoff_off_its_shape() {
    let dir = scratch("enter");
    let mut v: Value = serde_json::from_str(
        &std::fs::read_to_string(repo().join("contracts/fixtures/srt-windows/handoff.json"))
            .unwrap(),
    )
    .unwrap();
    v["extra"] = Value::from(1);
    let f = dir.join("h.json");
    std::fs::write(&f, v.to_string()).unwrap();
    let out = derm().args(["enter", "--check"]).arg(&f).output().unwrap();
    assert_ne!(out.status.code(), Some(0));
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("extra"),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// Lane 5bA (BCR-7, case 109): input with Cursor's marks reaching
/// `derm hook claude-code pre`, with derm's own Cursor gate not registered,
/// is blocked and the reason names Cursor and the fix, never answered as
/// Claude Code's.
#[test]
fn another_agents_input_is_not_answered_in_this_dialect() {
    let home = scratch("marks");
    let input = serde_json::json!({
        "conversation_id": "c", "generation_id": "g", "cursor_version": "2026.11.10",
        "hook_event_name": "preToolUse", "tool_name": "Shell", "tool_input": {"command": "ls"}, "tool_use_id": "t"
    });
    let mut child = derm()
        .args(["hook", "claude-code", "pre"])
        .env("HOME", &home)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let _ = child
        .stdin
        .take()
        .unwrap()
        .write_all(input.to_string().as_bytes());
    let out = child.wait_with_output().unwrap();
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(2));
    assert!(
        err.contains("Cursor") && err.contains("derm connect cursor --gate"),
        "{err}"
    );
    let _ = std::fs::remove_dir_all(&home);
}

/// Lane 5bF (case 227): `derm connect cursor --gate` prints a registration
/// that runs `derm hook cursor pre` by derm's absolute path, with no
/// `--hook` folder and no `node`. Unix only: it sets `HOME`, which derm
/// reads as `USERPROFILE` on Windows, and the launcher route there is lane
/// 5bF's Windows half ("Come back to", the wave 5b close).
#[cfg(unix)]
#[test]
fn connect_gate_registers_derm_hook_by_its_absolute_path() {
    let home = scratch("connect");
    let out = derm()
        .args(["connect", "cursor", "--gate"])
        .env("HOME", &home)
        .output()
        .unwrap();
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(out.status.code(), Some(0), "{text}");
    let exe = std::fs::canonicalize(env!("CARGO_BIN_EXE_derm")).unwrap();
    assert!(
        text.contains(&format!("{} hook cursor pre", exe.display()))
            || text.contains(&format!("\"{}\" hook cursor pre", exe.display())),
        "{text}"
    );
    assert!(!text.contains("node --no-warnings"), "{text}");
    let _ = std::fs::remove_dir_all(&home);
}
