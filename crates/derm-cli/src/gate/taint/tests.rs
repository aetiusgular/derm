//! The gate's taint, end to end through [`super::adjust_in`] with a home of
//! its own and no daemon (the light tier), and the rules against states
//! built by hand. The real hook's path is `crates/derm-cli/tests/contracts_w6.rs`
//! (the base's red tests) and `tests/cli-contract/checks/6D/`.

use std::path::{Path, PathBuf};

use derm_core::policy::Action;
use serde_json::{json, Value};

use super::state::{self, Mark, State};
use super::*;
use crate::gate::core::GateAnswer;

struct Home(PathBuf);

impl Home {
    fn new(name: &str) -> Home {
        let d = std::env::temp_dir().join(format!("dtaint-g-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(d.join("work")).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        Home(d)
    }
    fn env(&self) -> Env {
        #[cfg(windows)]
        let k = "USERPROFILE";
        #[cfg(not(windows))]
        let k = "HOME";
        // No daemon: a socket that cannot exist, no chat token.
        Env::of(&[
            (k, self.0.to_str().unwrap()),
            ("DERM_DAEMON_SOCKET", "/nonexistent/derm-test.sock"),
        ])
    }
    fn work(&self) -> PathBuf {
        self.0.join("work")
    }
    fn settings(&self, verdict: &str) {
        let d = self.0.join(".derm");
        std::fs::create_dir_all(&d).unwrap();
        let f = d.join("settings.json");
        std::fs::write(
            &f,
            format!(r#"{{"version":1,"taint":{{"verdict":"{verdict}"}}}}"#),
        )
        .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o700)).unwrap();
            std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
    }
    fn log(&self, chat: &str) -> Vec<Value> {
        let p = self
            .0
            .join(".derm/local")
            .join(crate::gate::locallog::file_name(chat));
        std::fs::read_to_string(p)
            .unwrap_or_default()
            .lines()
            .filter_map(|l| derm_core::audit_chain::parse(l).ok())
            .map(|l| l.record)
            .collect()
    }
}

impl Drop for Home {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn allow(tool: &str) -> GateAnswer {
    GateAnswer {
        action: Action::Allow,
        normalized_tool: tool.into(),
        reason: "rule allow".into(),
        updated_input: None,
        redacted: 0,
        ask_timeout_seconds: 60,
    }
}

fn call(tool: &str, input: Value, n: usize) -> GateCall {
    GateCall {
        harness: "claude-code".into(),
        tool: tool.into(),
        tool_input: input,
        chat: Some("c-1".into()),
        tool_use_id: Some(format!("toolu_{n}")),
        full_access: None,
    }
}

fn step(h: &Home, tool: &str, input: Value, n: usize, policy: Action) -> GateAnswer {
    let mut a = allow(tool);
    a.action = policy;
    adjust_in(a, &call(tool, input, n), &h.env(), "c-1", &h.work())
}

#[test]
fn a_file_the_chat_wrote_is_asked_about_when_it_runs() {
    let h = Home::new("own");
    let w = step(
        &h,
        "write",
        json!({"file_path": h.work().join("diag.py"), "content": "x"}),
        0,
        Action::Allow,
    );
    assert_eq!(w.action, Action::Allow);
    let r = step(
        &h,
        "bash",
        json!({"command": "python3 diag.py"}),
        1,
        Action::Allow,
    );
    assert_eq!(r.action, Action::Ask, "{}", r.reason);
    assert!(
        r.reason.contains("runs code this chat wrote"),
        "{}",
        r.reason
    );
    // A script the chat did not write keeps its answer.
    let o = step(
        &h,
        "bash",
        json!({"command": "python3 other.py"}),
        2,
        Action::Allow,
    );
    assert_eq!(o.action, Action::Allow);
}

#[test]
fn a_write_and_a_run_in_one_call_is_asked_about() {
    let h = Home::new("same");
    let r = step(
        &h,
        "bash",
        json!({"command": "cat > x.sh <<'EOF'\necho hi\nEOF\nsh x.sh"}),
        0,
        Action::Allow,
    );
    assert_eq!(r.action, Action::Ask, "{}", r.reason);
}

#[test]
fn an_untainted_chat_gets_no_coarse_review() {
    let h = Home::new("clean");
    for (n, cmd) in [
        "git push origin main",
        "npm install left-pad",
        "curl https://new.test/",
    ]
    .iter()
    .enumerate()
    {
        let a = step(&h, "bash", json!({"command": cmd}), n, Action::Allow);
        assert_eq!(a.action, Action::Allow, "{cmd}: {}", a.reason);
    }
    let a = step(
        &h,
        "write",
        json!({"file_path": h.work().join(".github/workflows/ci.yml"), "content": "x"}),
        9,
        Action::Allow,
    );
    assert_eq!(a.action, Action::Allow);
}

#[test]
fn after_a_fetch_a_protected_write_an_install_a_push_and_a_new_host_are_asked_about() {
    let h = Home::new("after");
    // A host reached before the taint is not new afterwards.
    assert_eq!(
        step(
            &h,
            "bash",
            json!({"command": "curl -s https://known.test/x"}),
            0,
            Action::Allow
        )
        .action,
        Action::Allow
    );
    let f = step(
        &h,
        "webfetch",
        json!({"url": "https://docs.example.test/page"}),
        1,
        Action::Allow,
    );
    assert_eq!(
        f.action,
        Action::Allow,
        "the fetch itself is the source: {}",
        f.reason
    );
    for (n, tool, input, rule) in [
        (
            2,
            "write",
            json!({"file_path": h.work().join(".husky/pre-commit"), "content": "x"}),
            "protected-write",
        ),
        (
            3,
            "bash",
            json!({"command": "npm install left-pad"}),
            "install",
        ),
        (
            4,
            "bash",
            json!({"command": "git push origin main"}),
            "push",
        ),
        (
            5,
            "bash",
            json!({"command": "curl -s https://new.test/x"}),
            "new-host",
        ),
    ] {
        let a = step(&h, tool, input, n, Action::Allow);
        assert_eq!(a.action, Action::Ask, "{rule}: {}", a.reason);
        assert!(a.reason.starts_with("taint: "), "{rule}: {}", a.reason);
    }
    let ok = step(
        &h,
        "bash",
        json!({"command": "curl -s https://known.test/y"}),
        6,
        Action::Allow,
    );
    assert_eq!(ok.action, Action::Allow, "{}", ok.reason);
    let ok = step(
        &h,
        "write",
        json!({"file_path": h.work().join("src/main.rs"), "content": "x"}),
        7,
        Action::Allow,
    );
    assert_eq!(ok.action, Action::Allow, "{}", ok.reason);
    // The marks and reviews are in the chat's log.
    let log = h.log("c-1");
    let kinds: Vec<&str> = log.iter().filter_map(|r| r["kind"].as_str()).collect();
    assert_eq!(
        kinds.iter().filter(|k| **k == "taint.mark").count(),
        1,
        "{kinds:?}"
    );
    assert_eq!(
        kinds.iter().filter(|k| **k == "taint.review").count(),
        4,
        "{kinds:?}"
    );
    let mark = log.iter().find(|r| r["kind"] == "taint.mark").unwrap();
    assert_eq!(mark["id"], "claude-code-toolu_1-taint");
    assert_eq!(mark["detail"]["reason"], "untrusted-content");
    let rules: Vec<&str> = log
        .iter()
        .filter(|r| r["kind"] == "taint.review")
        .filter_map(|r| r["detail"]["rule"].as_str())
        .collect();
    assert_eq!(
        rules,
        vec!["protected-write", "install", "push", "new-host"]
    );
    let review = log.iter().find(|r| r["kind"] == "taint.review").unwrap();
    assert_eq!(
        review["detail"]["marks"],
        json!(["claude-code-toolu_1-taint"])
    );
    assert_eq!(review["detail"]["verdict"], "ask");
    assert_eq!(review["detail"]["gave"], "ask");
}

#[test]
fn a_secret_read_taints_the_chat() {
    let h = Home::new("secret");
    step(
        &h,
        "read",
        json!({"file_path": h.0.join(".aws/credentials")}),
        0,
        Action::Allow,
    );
    let a = step(&h, "bash", json!({"command": "git push"}), 1, Action::Allow);
    assert_eq!(a.action, Action::Ask, "{}", a.reason);
    assert!(a.reason.contains("after a secret read"), "{}", a.reason);
}

#[test]
fn taint_only_raises() {
    let h = Home::new("raise");
    step(
        &h,
        "webfetch",
        json!({"url": "https://a.test/"}),
        0,
        Action::Allow,
    );
    // A deny stays a deny, with no record.
    let d = step(&h, "bash", json!({"command": "git push"}), 1, Action::Deny);
    assert_eq!(d.action, Action::Deny);
    assert_eq!(d.reason, "rule allow");
    // Under `ask`, an ask the policy gave stays the policy's: no review.
    let a = step(&h, "bash", json!({"command": "git push"}), 2, Action::Ask);
    assert_eq!(a.action, Action::Ask);
    assert_eq!(a.reason, "rule allow");
    let reviews = h
        .log("c-1")
        .iter()
        .filter(|r| r["kind"] == "taint.review")
        .count();
    assert_eq!(reviews, 0);
}

#[test]
fn the_setting_decides_the_verdict_in_the_light_tier() {
    let h = Home::new("deny");
    h.settings("deny");
    step(
        &h,
        "webfetch",
        json!({"url": "https://a.test/"}),
        0,
        Action::Allow,
    );
    let d = step(&h, "bash", json!({"command": "git push"}), 1, Action::Allow);
    assert_eq!(d.action, Action::Deny, "{}", d.reason);
    // Under `deny` an ask is raised too.
    let d = step(&h, "bash", json!({"command": "npm i x"}), 2, Action::Ask);
    assert_eq!(d.action, Action::Deny, "{}", d.reason);

    let h = Home::new("record");
    h.settings("record");
    step(
        &h,
        "webfetch",
        json!({"url": "https://a.test/"}),
        0,
        Action::Allow,
    );
    let r = step(&h, "bash", json!({"command": "git push"}), 1, Action::Allow);
    assert_eq!(r.action, Action::Allow);
    let log = h.log("c-1");
    let rev = log.iter().find(|r| r["kind"] == "taint.review").unwrap();
    assert_eq!(rev["detail"]["verdict"], "record");
    assert_eq!(rev["detail"]["wouldBe"], "ask");
    assert_eq!(rev["detail"]["gave"], "allow");
    assert_eq!(rev["detail"]["rule"], "push");
}

#[test]
fn a_setting_others_can_write_is_not_read() {
    let h = Home::new("loose");
    h.settings("record");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let f = h.0.join(".derm/settings.json");
        std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o622)).unwrap();
        step(
            &h,
            "webfetch",
            json!({"url": "https://a.test/"}),
            0,
            Action::Allow,
        );
        let a = step(&h, "bash", json!({"command": "git push"}), 1, Action::Allow);
        assert_eq!(
            a.action,
            Action::Ask,
            "record from a loose file must not lower ask"
        );
    }
}

#[test]
fn a_chat_with_no_id_is_left_alone() {
    let h = Home::new("noid");
    let mut c = call("webfetch", json!({"url": "https://a.test/"}), 0);
    c.chat = None;
    let a = adjust(allow("webfetch"), &c, &h.env());
    assert_eq!(a, allow("webfetch"));
    assert!(!h.0.join(".derm").exists());
}

#[cfg(unix)]
#[test]
fn a_state_that_cannot_be_kept_denies_what_it_should_have_kept() {
    let h = Home::new("broken");
    // `~/.derm/local` is a plain file: neither the state nor the log can be
    // written.
    std::fs::create_dir_all(h.0.join(".derm")).unwrap();
    std::fs::write(h.0.join(".derm/local"), "").unwrap();
    let w = step(
        &h,
        "write",
        json!({"file_path": h.work().join("a.sh"), "content": "x"}),
        0,
        Action::Allow,
    );
    assert_eq!(w.action, Action::Deny, "{}", w.reason);
    // A read of an ordinary file needs nothing kept.
    let r = step(
        &h,
        "read",
        json!({"file_path": h.work().join("readme.md")}),
        1,
        Action::Allow,
    );
    assert_eq!(r.action, Action::Allow);
}

#[test]
fn a_denied_call_adds_nothing() {
    let h = Home::new("denied");
    step(
        &h,
        "webfetch",
        json!({"url": "https://a.test/"}),
        0,
        Action::Deny,
    );
    step(
        &h,
        "write",
        json!({"file_path": h.work().join("x.sh"), "content": "x"}),
        1,
        Action::Deny,
    );
    let st = state::load(&state::file_path(&h.0, "c-1")).unwrap();
    assert!(!st.tainted() && st.written.is_empty(), "{st:?}");
}

#[test]
fn the_rules_read_a_state() {
    let f = facts::of(
        "bash",
        &json!({"command": "bash run.sh"}),
        Path::new("/w"),
        None,
    );
    let mut st = State::default();
    assert!(rules(&f, &st, &[]).is_empty());
    st.written.push("/w/run.sh".into());
    assert_eq!(rules(&f, &st, &[])[0].rule, "session-written-code");
    let f2 = facts::of(
        "bash",
        &json!({"command": "curl https://seen.test/"}),
        Path::new("/w"),
        None,
    );
    st.marks.push(Mark {
        id: "m".into(),
        reason: "untrusted-content".into(),
        kind: "web".into(),
        tool: "webfetch".into(),
        tool_use_id: None,
    });
    let hits = rules(&f2, &st, &["seen.test".to_string()]);
    let names: Vec<&str> = hits.iter().map(|h| h.rule).collect();
    assert_eq!(names, vec!["named-in-result", "new-host"]);
    st.hosts.push(derm_tap::results::fingerprint("seen.test"));
    let names: Vec<&str> = rules(&f2, &st, &[]).iter().map(|h| h.rule).collect();
    assert!(names.is_empty(), "{names:?}");
    // An unreadable state: tainted, and every run is the chat's own.
    let bad = State {
        unreadable: true,
        ..State::default()
    };
    let names: Vec<&str> = rules(&f, &bad, &[]).iter().map(|h| h.rule).collect();
    assert_eq!(names, vec!["session-written-code"]);
}
