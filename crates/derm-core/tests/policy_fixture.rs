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
        225,
        "45 to integration w1, 15 from integration w2, 2 from the rename, 16 from integration w4, 6 from integration w5 (PowerShell, lane Z's request 3), 22 from wave 5 lane W (command rules), 10 from integration w5's close (review W5-S1, S3, S4), 3 from its fix pass (W5R-7(a), W5R2-3), 33 from integration w6's close (E0's R-E0-1, 2, 3, 5), 20 from its security review (W6C-S2, S3), 22 from its re-review (W6C-R1, R2, R3, R5), 15 after the close (W6C-R4, note BD), 12 from its review (W6F-4, 5, 6, 8), 4 from its re-review (W6G-1, 2)"
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
    // Every case is checked and every miss listed, so one run shows them all.
    let mut misses = Vec::new();
    for case in cases {
        let d = evaluate(&policy, &case.call);
        if d.action != case.expect.action || !d.reason.starts_with(&case.expect.reason_prefix) {
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
