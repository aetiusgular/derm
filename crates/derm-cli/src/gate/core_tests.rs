//! `gate.test.ts`'s cases (the hook core at `e29ce27`), ported with the
//! module: the text a shell call is checked on (S7), full access (case 83,
//! W4-S3), and the install records (cases 132, 133; W5C-S9, W5R-4, W5R2-1).

use super::*;
use serde_json::json;

fn policy(v: Value) -> LoadedPolicy {
    LoadedPolicy {
        policy: derm_core::policy::parse(&v.to_string()).expect("policy"),
        problem: None,
    }
}

fn allow_bash() -> LoadedPolicy {
    policy(json!({"version": 1, "rules": [{"tool": "bash", "action": "allow"}]}))
}

fn call(harness: &str, tool: &str, input: Value) -> GateCall {
    GateCall {
        harness: harness.into(),
        tool: tool.into(),
        tool_input: input,
        ..GateCall::default()
    }
}

fn no_env() -> Env {
    Env::default()
}

#[test]
fn a_workdir_beside_the_command_is_checked() {
    let a = decide_call(
        &allow_bash(),
        &call(
            "opencode",
            "bash",
            json!({"command": "sed -i s/a/b/ settings.json", "workdir": "/home/u/.claude"}),
        ),
        &no_env(),
    );
    assert_eq!(a.action, Action::Ask);
    let b = decide_call(
        &allow_bash(),
        &call(
            "opencode",
            "bash",
            json!({"command": "cat policy.json", "workdir": "/home/u/.derm/"}),
        ),
        &no_env(),
    );
    assert_eq!(b.action, Action::Ask);
    assert!(b.reason.contains("control file"), "{}", b.reason);
}

#[test]
fn the_description_is_left_out() {
    let a = decide_call(
        &allow_bash(),
        &call(
            "claude-code",
            "Bash",
            json!({"command": "ls -la", "description": "List the files in ~ (all of them!)", "timeout": 5000}),
        ),
        &no_env(),
    );
    assert_eq!(a.action, Action::Allow);
    assert_eq!(
        input_text_for(
            "bash",
            &json!({"command": "ls", "description": "x ~", "timeout": 5})
        )
        .unwrap(),
        "ls\n5"
    );
    assert_eq!(
        input_text_for("bash", &json!({"command": "ls -la"})).unwrap(),
        "ls -la"
    );
}

fn ask_bash() -> LoadedPolicy {
    policy(
        json!({"version": 1, "rules": [{"tool": "bash", "action": "ask"}, {"tool": "read", "action": "allow"}]}),
    )
}

#[test]
fn full_access_turns_an_ask_into_a_deny() {
    let c = call("copilot-cli", "bash", json!({"command": "ls"}));
    assert_eq!(decide_call(&ask_bash(), &c, &no_env()).action, Action::Ask);
    let full = GateCall {
        full_access: Some(true),
        ..c.clone()
    };
    let a = decide_call(&ask_bash(), &full, &no_env());
    assert_eq!(a.action, Action::Deny);
    // derm_core's reason names the rule's action (`rule bash ask`), where
    // the TypeScript's said `rule bash`; the full-access note follows it.
    assert!(a.reason.starts_with("rule bash"), "{}", a.reason);
    assert!(
        a.reason.contains("; the chat runs in full access"),
        "{}",
        a.reason
    );
    let env = Env::of(&[("DERM_FULL_ACCESS", "1")]);
    assert_eq!(decide_call(&ask_bash(), &c, &env).action, Action::Deny);
    let not = GateCall {
        full_access: Some(false),
        ..c.clone()
    };
    assert_eq!(decide_call(&ask_bash(), &not, &env).action, Action::Ask);
    assert_eq!(
        decide_call(
            &ask_bash(),
            &call("copilot-cli", "read", json!({"path": "a"})),
            &env
        )
        .action,
        Action::Allow
    );
    let secret = call("copilot-cli", "bash", json!({"command": "TOKEN=abc ls"}));
    assert_eq!(
        decide_call(&allow_bash(), &secret, &env).action,
        Action::Deny
    );
}

#[test]
fn full_access_denies_an_ask_that_reaches_resolve_ask_without_asking() {
    let c = call("grok", "bash", json!({"command": "ls"}));
    let answer = decide_call(&ask_bash(), &c, &no_env());
    assert_eq!(answer.action, Action::Ask);
    let asked = std::cell::Cell::new(0);
    let none = |_: &ApproveRequest| {
        asked.set(asked.get() + 1);
        ApproveOutcome::Answer {
            yes: false,
            by: By::None,
        }
    };
    assert!(matches!(
        resolve_ask(&answer, &c, true, &no_env(), &none),
        AskResolution::Harness(_)
    ));
    asked.set(0);
    let full = GateCall {
        full_access: Some(true),
        ..c.clone()
    };
    let r = resolve_ask(&answer, &full, true, &no_env(), &none);
    assert!(
        matches!(&r, AskResolution::Deny(why) if why.contains("full access")),
        "{r:?}"
    );
    assert_eq!(asked.get(), 0);
    let yes = |_: &ApproveRequest| {
        asked.set(asked.get() + 1);
        ApproveOutcome::Answer {
            yes: true,
            by: By::Approver,
        }
    };
    let env = Env::of(&[("DERM_FULL_ACCESS", "1")]);
    assert!(matches!(
        resolve_ask(&answer, &c, true, &env, &yes),
        AskResolution::Deny(_)
    ));
    assert_eq!(asked.get(), 0);
}

#[test]
fn an_ask_resolves_by_the_approvers_answer() {
    let c = call("codex", "bash", json!({"command": "ls"}));
    let answer = decide_call(&ask_bash(), &c, &no_env());
    let by = |o: ApproveOutcome| move |_: &ApproveRequest| o.clone();
    let r = resolve_ask(
        &answer,
        &c,
        false,
        &no_env(),
        &by(ApproveOutcome::Answer {
            yes: true,
            by: By::Approver,
        }),
    );
    assert_eq!(
        r,
        AskResolution::Allow("rule bash ask; approved in derm".into())
    );
    let r = resolve_ask(
        &answer,
        &c,
        false,
        &no_env(),
        &by(ApproveOutcome::Answer {
            yes: false,
            by: By::None,
        }),
    );
    assert_eq!(
        r,
        AskResolution::Deny("rule bash ask; ask needs an approver and none is connected".into())
    );
    let r = resolve_ask(
        &answer,
        &c,
        false,
        &no_env(),
        &by(ApproveOutcome::Answer {
            yes: false,
            by: By::Timeout,
        }),
    );
    assert_eq!(
        r,
        AskResolution::Deny("rule bash ask; ask timed out".into())
    );
    let r = resolve_ask(
        &answer,
        &c,
        false,
        &no_env(),
        &by(ApproveOutcome::Answer {
            yes: false,
            by: By::Approver,
        }),
    );
    assert_eq!(
        r,
        AskResolution::Deny("rule bash ask; declined in derm".into())
    );
    let r = resolve_ask(
        &answer,
        &c,
        false,
        &no_env(),
        &by(ApproveOutcome::Unreachable("x".into())),
    );
    assert_eq!(
        r,
        AskResolution::Deny(
            "rule bash ask; ask needs an approver and the derm daemon is not reachable (x)".into()
        )
    );
    let r = resolve_ask(
        &answer,
        &c,
        true,
        &no_env(),
        &by(ApproveOutcome::Unreachable("x".into())),
    );
    assert_eq!(
        r,
        AskResolution::Harness("rule bash ask (derm daemon: x)".into())
    );
}

fn install_call(command: &str, tool_use_id: Option<&str>) -> GateCall {
    GateCall {
        tool_use_id: tool_use_id.map(str::to_string),
        ..call("claude-code", "Bash", json!({ "command": command }))
    }
}

#[test]
fn one_install_record_per_install_whatever_the_policy_said() {
    let c = install_call(
        "npm install left-pad@1.3.0 && pip install six",
        Some("toolu_01"),
    );
    let ask_only = policy(json!({"version": 1, "rules": [{"tool": "bash", "action": "ask"}]}));
    for p in [allow_bash(), ask_only] {
        let answer = decide_call(&p, &c, &no_env());
        let events = install_events(&c, &answer, answer.action, "chat-1");
        assert_eq!(
            events.iter().map(|e| e.kind.as_str()).collect::<Vec<_>>(),
            ["install.call", "install.call"]
        );
        assert_eq!(
            events
                .iter()
                .map(|e| e.detail["manager"].clone())
                .collect::<Vec<_>>(),
            [json!("npm"), json!("pip")]
        );
        assert_eq!(
            events[0].detail["packages"],
            json!([{"name": "left-pad", "version": "1.3.0", "ecosystem": "npm", "inLockfile": null}])
        );
        assert_eq!(events[0].detail["toolUseId"], json!("toolu_01"));
        let want = match answer.action {
            Action::Allow => "allow",
            Action::Ask => "ask",
            Action::Deny => "deny",
        };
        assert_eq!(events[0].detail["decision"], json!(want));
        assert_eq!(events[0].chat_id, "chat-1");
        assert_eq!(events[0].harness, "claude-code");
    }
}

#[test]
fn a_package_the_redactor_flags_is_left_out_and_counted() {
    let token = ["sk", "proj", "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGH"].join("-");
    let ant = ["sk", "ant", "api03", "abcdefghijklmnopqrstuvwxyz"].join("-");
    for cmd in [
        format!("pip install {token}"),
        format!("npm i left-pad {ant}"),
        format!("npm i left-pad@{token}"),
    ] {
        let c = install_call(&cmd, Some("t9"));
        let events = install_events(
            &c,
            &decide_call(&allow_bash(), &c, &no_env()),
            Action::Ask,
            "c",
        );
        assert_eq!(events.len(), 1, "{cmd}");
        let text = format!("{events:?}");
        assert!(!text.contains(&token) && !text.contains(&ant), "{cmd}");
        let want = if cmd.contains("left-pad ") { 2 } else { 1 };
        assert_eq!(events[0].detail["redacted"], json!(want), "{cmd}");
    }
    let kept = install_events(
        &install_call(&format!("npm i left-pad {ant}"), Some("t9")),
        &decide_call(&allow_bash(), &install_call("npm i x", None), &no_env()),
        Action::Ask,
        "c",
    );
    assert_eq!(kept[0].detail["packages"], json!([]));
    assert_eq!(kept[0].summary, "npm add  ask");
    let gh = ["ghp", "Zx9Zx9Zx9Zx9Zx9Zx9Zx9Zx9Zx9Zx9Zx9Zx9Zx9Z"].join("_");
    for cmd in [
        format!("pip install {gh}"),
        format!("uv add {gh}"),
        format!("npm i left-pad {gh}"),
    ] {
        let c = install_call(&cmd, Some("t10"));
        let events = install_events(
            &c,
            &decide_call(&allow_bash(), &c, &no_env()),
            Action::Ask,
            "c",
        );
        let text = format!("{events:?}").to_lowercase();
        assert!(!text.contains("zx9zx9zx9"), "{cmd}");
        assert!(
            events
                .iter()
                .all(|e| e.detail["packages"].as_array().is_some_and(Vec::is_empty)),
            "{cmd}"
        );
        let total: u64 = events
            .iter()
            .map(|e| e.detail["redacted"].as_u64().unwrap_or(0))
            .sum();
        assert!(total > 0, "{cmd}");
    }
    let wide: String = gh
        .chars()
        .map(|c| char::from_u32(c as u32 + 0xfee0).unwrap())
        .collect();
    for cmd in [
        format!("pip install {}''{}", &gh[..2], &gh[2..]),
        format!("pip install \"{}\"{}", &gh[..4], &gh[4..]),
        format!("pip install {wide}"),
    ] {
        let c = install_call(&cmd, Some("t11"));
        let events = install_events(
            &c,
            &decide_call(&allow_bash(), &c, &no_env()),
            Action::Ask,
            "c",
        );
        assert!(
            !format!("{events:?}").to_lowercase().contains("zx9zx9zx9"),
            "{cmd}"
        );
    }
    let plain = install_events(
        &install_call("npm i left-pad", Some("t9")),
        &decide_call(&allow_bash(), &install_call("npm i x", None), &no_env()),
        Action::Ask,
        "c",
    );
    assert!(plain[0].detail.get("redacted").is_none());
}

#[test]
fn no_record_for_a_call_that_is_not_an_install_or_a_tool_that_is_not_a_shell() {
    let plain = install_call("npm test", None);
    assert!(install_events(
        &plain,
        &decide_call(&allow_bash(), &plain, &no_env()),
        Action::Allow,
        "c"
    )
    .is_empty());
    let write = call(
        "claude-code",
        "Write",
        json!({"file_path": "a.txt", "content": "npm install left-pad"}),
    );
    assert!(install_events(
        &write,
        &decide_call(&allow_bash(), &write, &no_env()),
        Action::Ask,
        "c"
    )
    .is_empty());
}

#[test]
fn the_record_names_the_decision_the_harness_got() {
    let c = install_call("npx cowsay hi", Some("t2"));
    let answer = decide_call(&allow_bash(), &c, &no_env());
    assert_eq!(answer.action, Action::Ask);
    assert_eq!(
        install_events(&c, &answer, Action::Deny, "c")[0].detail["decision"],
        json!("deny")
    );
}

#[test]
fn each_record_has_an_id_the_agent_cannot_work_out_first() {
    let c = install_call("npm i a b", Some("t3"));
    let a = install_events(
        &c,
        &decide_call(&allow_bash(), &c, &no_env()),
        Action::Ask,
        "c",
    );
    let b = install_events(
        &c,
        &decide_call(&allow_bash(), &c, &no_env()),
        Action::Ask,
        "c",
    );
    let id = &a[0].id;
    let nonce = id.strip_prefix("claude-code-t3-install-0-").expect(id);
    assert!(
        nonce.len() == 32
            && nonce
                .bytes()
                .all(|x| x.is_ascii_hexdigit() && !x.is_ascii_uppercase())
    );
    assert_ne!(a[0].id, b[0].id);
}

#[test]
fn look_alike_letters_do_not_hide_an_install() {
    let c = install_call("ｎｐｍ install left-pad", None);
    let events = install_events(
        &c,
        &decide_call(&allow_bash(), &c, &no_env()),
        Action::Ask,
        "c",
    );
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].detail["toolUseId"], Value::Null);
}

#[test]
fn at_most_eight_records_for_one_call() {
    let cmd = (0..12)
        .map(|i| format!("npm i p{i}"))
        .collect::<Vec<_>>()
        .join(" && ");
    let c = install_call(&cmd, None);
    assert_eq!(
        install_events(
            &c,
            &decide_call(&allow_bash(), &c, &no_env()),
            Action::Ask,
            "c"
        )
        .len(),
        MAX_INSTALL_RECORDS
    );
}

#[test]
fn a_redacted_input_is_rewritten_for_a_tool_that_sends_it_out_and_asks_for_one_that_runs_it() {
    let p = policy(
        json!({"version": 1, "servers": ["exa"], "rules": [{"tool": "*", "action": "allow"}]}),
    );
    let mcp = call(
        "claude-code",
        "mcp__exa__search",
        json!({"q": "x", "api_key": "abc"}),
    );
    let a = decide_call(&p, &mcp, &no_env());
    assert_eq!(a.action, Action::Allow);
    assert_eq!(
        a.updated_input,
        Some(json!({"q": "x", "api_key": derm_core::redact::hook::REDACTED}))
    );
    assert!(
        a.reason.ends_with("; 1 secret-like value redacted"),
        "{}",
        a.reason
    );
    let write = call(
        "claude-code",
        "Write",
        json!({"file_path": "a", "content": "password=x"}),
    );
    let a = decide_call(&p, &write, &no_env());
    assert_eq!(a.action, Action::Ask);
    assert_eq!(a.reason, "secret-like value in input");
}

#[test]
fn the_load_problem_is_named_when_no_rule_matched() {
    let empty = LoadedPolicy {
        policy: Default::default(),
        problem: Some("no policy file".into()),
    };
    let a = decide_call(
        &empty,
        &call("codex", "Bash", json!({"command": "ls"})),
        &no_env(),
    );
    assert_eq!(a.action, Action::Ask);
    assert!(
        a.reason.starts_with("no rule (no policy file)"),
        "{}",
        a.reason
    );
}

#[test]
fn the_approval_summary_is_redacted_and_cut_at_160() {
    let a = GateAnswer {
        action: Action::Ask,
        normalized_tool: "bash".into(),
        reason: String::new(),
        updated_input: None,
        redacted: 0,
        ask_timeout_seconds: 1,
    };
    let s = approval_summary(&a, &json!({"command": "curl --password=hunter2   x"}));
    assert_eq!(
        s,
        format!(
            "bash: curl --password={}  x",
            derm_core::redact::hook::REDACTED
        )
        .replace("  x", " x")
    );
    let long = approval_summary(&a, &json!({"command": "x".repeat(400)}));
    assert_eq!(long.encode_utf16().count(), 160);
    assert!(long.ends_with('…'));
}
