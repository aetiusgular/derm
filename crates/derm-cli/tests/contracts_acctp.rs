//! Step P's process-level red test in derm-cli (the base, 20 Nov 2026;
//! `plans/parallel_build_accounts.md` section 8.3, item 7): lane PF's AI-7.
//! The in-crate red tests are `src/contracts_acctp.rs`. No lane edits this
//! file; P integration drops the `ignore` once lane PF is green.

#![cfg(unix)]

use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use serde_json::{json, Value};

fn repo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join("..")
}

fn scratch(name: &str) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let p = std::env::temp_dir().join(format!("dacctp-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&p);
    std::fs::create_dir_all(p.join("work")).unwrap();
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o700)).unwrap();
    p
}

/// Review AI-7 (accounts integration, low; note CC section 6; case 287):
/// on `approve`, `derm gate serve` must record the permission of the
/// decision it made, never one read back from the reason the plugin returns,
/// since a plugin the agent can change could name another. Here the decide
/// reply names no permission (`rule write ask` in the fixture policy), the
/// plugin hands back a reason that starts with `secrets, ` (the core's form,
/// `Permission::prefix`; a hook dialect adds `derm: ` in front), and the
/// light tier's record of the outcome (no daemon, `"record": false`,
/// `contracts/gate-serve.md` 2.1) must carry no `permission`. Red on the
/// base: serve reads the name back from the reason (`serve/mod.rs`
/// `answer_of`, `Permission::of_reason`).
#[test]
#[ignore = "lane PF: red until AI-7; gate serve records the plugin's permission"]
fn pf_gate_serve_records_its_own_decisions_permission_on_approve() {
    use std::os::unix::fs::PermissionsExt;
    let dir = scratch("ai7");
    let policy = dir.join("policy.json");
    std::fs::copy(
        repo().join("contracts/fixtures/gate-serve/policy.json"),
        &policy,
    )
    .unwrap();
    std::fs::set_permissions(&policy, std::fs::Permissions::from_mode(0o600)).unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_derm"))
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("HOME", &dir)
        .env("DERM_POLICY", &policy)
        .args(["gate", "serve", "--agent", "pi"])
        .current_dir(dir.join("work"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let mut out = BufReader::new(child.stdout.take().unwrap());
    let mut ask = |line: Value| -> Value {
        writeln!(stdin, "{line}").unwrap();
        let mut got = String::new();
        out.read_line(&mut got).unwrap();
        serde_json::from_str(&got).unwrap_or(Value::Null)
    };
    assert_eq!(
        ask(json!({"id": 0, "op": "hello", "agent": "pi", "protocol": 1}))["ok"],
        true
    );
    let call = json!({"tool": "write", "input": {"path": "a"}, "chat": "c-ai7", "toolUseId": "t1"});
    let decided = ask(json!({"id": 1, "op": "decide", "call": call, "record": false}));
    assert_eq!(decided["action"], "ask", "{decided}");
    assert_eq!(decided["permission"], Value::Null, "{decided}");
    let mut forged = decided.clone();
    forged["reason"] = json!(format!("secrets, {}", decided["reason"].as_str().unwrap()));
    let approved = ask(json!({
        "id": 2, "op": "approve", "call": call, "answer": forged,
        "canAsk": false, "record": false,
    }));
    assert_eq!(approved["ok"], true, "{approved}");
    drop(stdin);
    let _ = child.wait();
    let log = dir.join(".derm/local/c-ai7.jsonl");
    let text = std::fs::read_to_string(&log).unwrap_or_default();
    let records: Vec<Value> = text
        .lines()
        .filter_map(|l| serde_json::from_str(l).ok())
        .collect();
    assert!(
        !records.is_empty(),
        "no light-tier record in {}",
        log.display()
    );
    for r in &records {
        // A light-tier line: `{hash, kind, prev, record}` (contracts/events.md 6.4).
        let detail = r.get("record").and_then(|e| e.get("detail"));
        assert!(detail.is_some(), "a light-tier line with no record: {r}");
        assert!(
            detail.and_then(|d| d.get("permission")).is_none(),
            "the record names a permission the decision did not: {r}"
        );
    }
    let _ = std::fs::remove_dir_all(&dir);
}
