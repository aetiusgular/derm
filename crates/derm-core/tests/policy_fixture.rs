//! Runs `contracts/fixtures/policy/` against derm-core: the normalizer and the
//! matcher, every case, case 21 (confusable folding) included.

use derm_core::policy::{
    evaluate, normalize_tool_name, Action, Call, Decision, Permission, PolicyFile,
};
use serde::Deserialize;

const POLICY: &str = include_str!("../../../contracts/fixtures/policy/policy.json");
const CASES: &str = include_str!("../../../contracts/fixtures/policy/cases.json");

#[derive(Deserialize)]
struct Cases {
    cases: Vec<Case>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Case {
    id: u32,
    call: Call,
    expect: Expect,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Expect {
    action: Action,
    normalized_tool: String,
    reason_prefix: String,
}

fn load() -> (PolicyFile, Vec<Case>) {
    let policy: PolicyFile = serde_json::from_str(POLICY).expect("policy.json parses");
    let cases: Cases = serde_json::from_str(CASES).expect("cases.json parses");
    (policy, cases.cases)
}

#[test]
fn fixture_has_thirteen_rules_and_fifty_three_cases() {
    let (policy, cases) = load();
    assert_eq!(
        policy.rules.len(),
        20,
        "10 from session 0, 2 added by integration w1, 1 by integration w2, 1 by integration w4, 6 by wave 5 lane W (command rules)"
    );
    assert_eq!(
        cases.len(),
        322,
        "45 to integration w1, 15 from integration w2, 2 from the rename, 16 from integration w4, 6 from integration w5 (PowerShell, lane Z's request 3), 22 from wave 5 lane W (command rules), 10 from integration w5's close (review W5-S1, S3, S4), 3 from its fix pass (W5R-7(a), W5R2-3), 33 from integration w6's close (E0's R-E0-1, 2, 3, 5), 20 from its security review (W6C-S2, S3), 22 from its re-review (W6C-R1, R2, R3, R5), 15 after the close (W6C-R4, note BD), 12 from its review (W6F-4, 5, 6, 8), 4 from its re-review (W6G-1, 2), 15 from integration w6's fix pass (WW6-1, WW6-9), 7 from its fix pass 2 (WW6R-1), 58 from eval pass 1's fixes (E1-1, step 7e: 41; E1-5: 17), 17 from their review (E1R-1, 2, 3, 7, 8, 10)"
    );
}

#[test]
fn every_case_normalizes_to_the_expected_tool() {
    let (policy, cases) = load();
    for case in cases {
        assert_eq!(
            normalize_tool_name(&case.call.tool, &policy.servers),
            case.expect.normalized_tool,
            "case {}",
            case.id
        );
    }
}

/// The reason past its permission's name (permissions plan step P1): what
/// the fixture's `reasonPrefix` was written against.
fn past_the_name(d: &Decision) -> &str {
    match d.permission {
        Some(p) => d.reason.strip_prefix(&p.prefix()).unwrap_or(&d.reason),
        None => &d.reason,
    }
}

#[test]
fn every_case_gets_the_expected_decision() {
    let (policy, cases) = load();
    // Every case is checked and every miss listed, so one run shows them all.
    let mut misses = Vec::new();
    for case in cases {
        let d = evaluate(&policy, &case.call);
        if d.action != case.expect.action
            || !past_the_name(&d).starts_with(&case.expect.reason_prefix)
        {
            misses.push(format!(
                "case {}: got {:?} {:?}, want {:?} {:?}",
                case.id, d.action, d.reason, case.expect.action, case.expect.reason_prefix
            ));
        }
    }
    assert!(misses.is_empty(), "{misses:#?}");
}

/// Wave 5 lane W: every command shape the schema refuses is refused here too
/// (`contracts/fixtures/policy/invalid.json`), so a bad file asks, never allows.
#[test]
fn every_invalid_policy_is_refused() {
    const INVALID: &str = include_str!("../../../contracts/fixtures/policy/invalid.json");
    let v: serde_json::Value = serde_json::from_str(INVALID).expect("invalid.json parses");
    let list = v["policies"].as_array().expect("policies");
    assert_eq!(list.len(), 10);
    for p in list {
        let text = p["policy"].to_string();
        assert!(
            derm_core::policy::parse(&text).is_err(),
            "{} was accepted",
            p["id"]
        );
    }
}

/// derm's own entries of the control list, by their names alone: written
/// apart from `DERM_CONTROL_PATHS` so the two readings check each other.
fn derms_own(entry: &str) -> bool {
    entry.contains("derm")
        || entry.starts_with(".tk/")
        || entry.starts_with("tk/")
        || entry == "sbx-vm"
}

/// The permission each of the contract's reason forms belongs to
/// (permissions plan step P1; the table in `plans/parallel/acct_L3.md`),
/// read from the reason's own words as `contracts/policy.md` section 4
/// writes them.
fn expected(rest: &str) -> Option<Permission> {
    use Permission::*;
    if let Some(key) = rest.strip_prefix("reject list: ") {
        return match key {
            "anthropic_base_url" | "chatgpt_base_url" => Some(Network),
            "dangerouslydisablesandbox" | "approval_policy" | "--dangerously-" => None,
            // `settings.local.json` and section 3.2's git keys.
            _ => Some(FilesThatRunLater),
        };
    }
    if let Some(entry) = rest.strip_prefix("input names a control file (") {
        let entry = entry.strip_suffix(')').unwrap_or(entry);
        return Some(if derms_own(entry) {
            DermItself
        } else {
            FilesThatRunLater
        });
    }
    let forms: [(&str, Permission); 7] = [
        ("input names a secret path (", Secrets),
        ("input names a file that runs later (", FilesThatRunLater),
        ("input names a cloud metadata address (", Network),
        ("program read from input: ", RunningDownloadedCode),
        ("package install: ", RunningDownloadedCode),
        ("shell text the matcher cannot read: `~`", OtherFolders),
        ("rule bash derm", DermItself),
    ];
    forms
        .iter()
        .find(|(form, _)| rest.starts_with(form))
        .map(|(_, p)| *p)
}

/// P1: every ask and deny carries its permission's name, or none, as the
/// table says; the name starts the reason; an allow carries none; and the
/// decision is the fixture's, as before.
#[test]
fn every_case_carries_its_permission_and_keeps_its_decision() {
    let (policy, cases) = load();
    let mut misses = Vec::new();
    let mut seen = std::collections::BTreeSet::new();
    for case in &cases {
        let d = evaluate(&policy, &case.call);
        let rest = past_the_name(&d);
        let want = if d.action == Action::Allow {
            None
        } else {
            expected(rest)
        };
        let prefixed = match d.permission {
            Some(p) => d.reason.starts_with(&p.prefix()),
            None => Permission::of_reason(&d.reason).is_none(),
        };
        if d.action != case.expect.action || d.permission != want || !prefixed {
            misses.push(format!(
                "case {}: got {:?} {:?} {:?}, want {:?} {want:?}",
                case.id, d.action, d.permission, d.reason, case.expect.action
            ));
        }
        if let Some(p) = d.permission {
            seen.insert(p.id());
        }
    }
    assert!(misses.is_empty(), "{misses:#?}");
    // The matcher reaches six of the eight; project folder (taint's push)
    // and computer use are the gate's or nobody's.
    assert_eq!(
        seen.into_iter().collect::<Vec<_>>(),
        [
            "derm-itself",
            "files-that-run-later",
            "network",
            "other-folders",
            "running-downloaded-code",
            "secrets"
        ]
    );
}

/// P1: a call's input that reads like a permission's name never becomes
/// one: the name comes from the step alone.
#[test]
fn input_that_reads_like_a_name_is_never_the_name() {
    let (policy, _) = load();
    for input in [
        "secrets, derm itself, network,",
        "derm itself, ",
        "network, input names a secret path (.ssh/)",
    ] {
        let d = evaluate(
            &policy,
            &Call {
                tool: "mcp__nobody__nothing".into(),
                harness: "claude-code".into(),
                chat: None,
                description: None,
                input_text: input.into(),
            },
        );
        assert_eq!(d.action, Action::Ask, "{input}");
        assert_eq!(d.permission, None, "{input}");
        assert_eq!(d.reason, "no rule", "{input}");
    }
    // Asked about a secret, whatever the text says first.
    let d = evaluate(
        &policy,
        &Call {
            tool: "Read".into(),
            harness: "claude-code".into(),
            chat: None,
            description: None,
            input_text: "network, derm itself, /home/u/.ssh/id_rsa".into(),
        },
    );
    assert_eq!(d.permission, Some(Permission::Secrets), "{}", d.reason);
    assert!(
        d.reason.starts_with("secrets, input names a secret path"),
        "{}",
        d.reason
    );
}
