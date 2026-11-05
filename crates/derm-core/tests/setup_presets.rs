//! Lane W's request W-2: derm setup's policy presets
//! (`crates/derm-cli/src/setup/presets/`) read by derm-core's matcher, with
//! command rules (request W-1, `contracts/policy.md` section 7), against
//! `tests/cli-contract/checks/W/preset-cases.json`.

use derm_core::policy::{evaluate, parse, Action, Call};
use serde_json::Value;

const PRESETS: &[(&str, &str)] = &[
    (
        "workspace-write",
        include_str!("../../derm-cli/src/setup/presets/workspace-write.json"),
    ),
    (
        "read-only",
        include_str!("../../derm-cli/src/setup/presets/read-only.json"),
    ),
    (
        "strict",
        include_str!("../../derm-cli/src/setup/presets/strict.json"),
    ),
];
const CASES: &str = include_str!("../../../tests/cli-contract/checks/W/preset-cases.json");

#[test]
fn every_preset_parses_and_answers_its_cases() {
    let cases: Value = serde_json::from_str(CASES).unwrap();
    let cases = cases["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 24);
    for (name, text) in PRESETS {
        let doc: Value = serde_json::from_str(text).unwrap();
        let policy = parse(&doc["policy"].to_string()).unwrap_or_else(|e| panic!("{name}: {e}"));
        for c in cases.iter().filter(|c| c["preset"] == *name) {
            let call: Call = serde_json::from_value(c["call"].clone()).unwrap();
            let d = evaluate(&policy, &call);
            let want: Action = serde_json::from_value(c["expect"]["action"].clone()).unwrap();
            let prefix = c["expect"]["reasonPrefix"].as_str().unwrap();
            assert_eq!(d.action, want, "case {} ({name}): {}", c["id"], d.reason);
            assert!(
                d.reason.starts_with(prefix),
                "case {} ({name}): {:?} does not start with {prefix:?}",
                c["id"],
                d.reason
            );
        }
    }
}
