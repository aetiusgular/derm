//! `contracts/fixtures/installs/cases.json` against derm-core's install check
//! (the wave 5 base; lane X's seam). What holds today and after lane X: a
//! case the fixture says is not an install is never read as one. Lane X adds
//! the install cases' expectations here as it builds the check.

use derm_core::installs::check;
use derm_core::policy::fold_text;
use serde_json::Value;

fn cases() -> Vec<Value> {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../contracts/fixtures/installs/cases.json"
    );
    let v: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    v["cases"].as_array().unwrap().clone()
}

#[test]
fn what_the_fixture_says_is_not_an_install_is_never_read_as_one() {
    let all = cases();
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
