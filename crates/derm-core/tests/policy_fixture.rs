//! Runs `contracts/fixtures/policy/` against derm-core: the normalizer and the
//! matcher, every case, case 21 (confusable folding) included.

use derm_core::policy::{evaluate, normalize_tool_name, Action, Call, PolicyFile};
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
        119,
        "45 to integration w1, 15 from integration w2, 2 from the rename, 16 from integration w4, 6 from integration w5 (PowerShell, lane Z's request 3), 22 from wave 5 lane W (command rules), 10 from integration w5's close (review W5-S1, S3, S4), 3 from its fix pass (W5R-7(a), W5R2-3)"
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

#[test]
fn every_case_gets_the_expected_decision() {
    let (policy, cases) = load();
    for case in cases {
        let d = evaluate(&policy, &case.call);
        assert_eq!(
            d.action, case.expect.action,
            "case {}: {}",
            case.id, d.reason
        );
        assert!(
            d.reason.starts_with(&case.expect.reason_prefix),
            "case {}: reason {:?} does not start with {:?}",
            case.id,
            d.reason,
            case.expect.reason_prefix
        );
    }
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
