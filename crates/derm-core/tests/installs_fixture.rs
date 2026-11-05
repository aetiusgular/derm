//! `contracts/fixtures/installs/` against derm-core's install check (wave 5
//! lane X): the base's `cases.json`, lane X's `cases-x.json` and the
//! lockfiles. The hook core and derm-pi run the same files.

use derm_core::installs::{check, parse_installs, parse_lockfile, LockKind};
use derm_core::policy::fold_text;
use serde_json::Value;

fn fixture(name: &str) -> Value {
    let path = format!(
        "{}/../../contracts/fixtures/installs/{name}",
        env!("CARGO_MANIFEST_DIR")
    );
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

fn cases(name: &str) -> Vec<Value> {
    fixture(name)["cases"].as_array().unwrap().clone()
}

#[test]
fn what_the_fixture_says_is_not_an_install_is_never_read_as_one() {
    let all = cases("cases.json");
    assert!(all.len() >= 30, "{}", all.len());
    let mut not_installs = 0;
    for c in &all {
        if c["expect"]["install"] == false {
            not_installs += 1;
            let text = fold_text(c["text"].as_str().unwrap());
            assert_eq!(check("bash", &text), None, "case {}", c["id"]);
        }
    }
    assert!(not_installs >= 5);
}

#[test]
fn the_bases_install_cases_read_and_ask_as_the_fixture_says() {
    for c in cases("cases.json") {
        let text = fold_text(c["text"].as_str().unwrap());
        let got = parse_installs(&text);
        if c["expect"]["install"] == false {
            assert!(got.is_empty(), "case {}", c["id"]);
            continue;
        }
        assert_eq!(got.len(), 1, "case {}", c["id"]);
        let g = serde_json::to_value(&got[0]).unwrap();
        assert_eq!(g["manager"], c["expect"]["manager"], "case {}", c["id"]);
        assert_eq!(g["form"], c["expect"]["form"], "case {}", c["id"]);
        assert_eq!(g["packages"], c["expect"]["packages"], "case {}", c["id"]);
        assert_eq!(g["unseen"], serde_json::json!([]), "case {}", c["id"]);
        let d = check("bash", &text).unwrap();
        assert_eq!(d.action, derm_core::policy::Action::Ask, "case {}", c["id"]);
        for p in c["expect"]["packages"].as_array().unwrap() {
            assert!(
                d.reason.contains(p["name"].as_str().unwrap()),
                "case {}: {}",
                c["id"],
                d.reason
            );
        }
    }
}

#[test]
fn lane_xs_cases_read_as_the_fixture_says() {
    let all = cases("cases-x.json");
    assert!(all.len() >= 80);
    for c in all {
        let text = fold_text(c["text"].as_str().unwrap());
        let got = serde_json::to_value(parse_installs(&text)).unwrap();
        assert_eq!(got, c["installs"], "case {}: {}", c["id"], c["text"]);
    }
}

#[test]
fn the_lockfile_readers_give_what_expected_json_says() {
    let expected = fixture("lockfiles/expected.json");
    let files = expected["files"].as_object().unwrap();
    assert_eq!(files.len(), 21);
    for (file, want) in files {
        let kind = LockKind::from_name(want["kind"].as_str().unwrap()).unwrap();
        let path = format!(
            "{}/../../contracts/fixtures/installs/lockfiles/{file}",
            env!("CARGO_MANIFEST_DIR")
        );
        let got = parse_lockfile(kind, &std::fs::read_to_string(path).unwrap());
        assert_eq!(
            serde_json::to_value(got).unwrap(),
            want["entries"],
            "{file}"
        );
    }
}
