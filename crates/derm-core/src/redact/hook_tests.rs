//! `redact.test.ts`'s cases, held to the TypeScript's own output recorded in
//! `contracts/fixtures/redact/hook-cases.json` (rules section 9, item 12):
//! the same generators, the same inputs, the same digest.

use super::*;
use serde_json::Value;
use sha2::{Digest, Sha256};

fn cases() -> Value {
    let text = include_str!("../../../../contracts/fixtures/redact/hook-cases.json");
    serde_json::from_str(text).expect("hook-cases.json")
}

/// `redact.test.ts`'s `rng`, ported (Math.imul is a wrapping 32-bit
/// multiply; `>>>` is a logical shift).
fn rng(seed: u32) -> impl FnMut() -> f64 {
    let mut s = seed;
    move || {
        s = s.wrapping_add(0x6d2b_79f5);
        let mut t = s;
        t = (t ^ (t >> 15)).wrapping_mul(t | 1);
        t ^= t.wrapping_add((t ^ (t >> 7)).wrapping_mul(t | 61));
        f64::from(t ^ (t >> 14)) / 4_294_967_296.0
    }
}

const PIECES: [&str; 49] = [
    "token",
    "Token",
    "TOK",
    "en",
    "secret",
    "password",
    "api_key",
    "apikey",
    "private_key",
    "passwd",
    "max_tokens",
    "x",
    "A",
    "1",
    "42",
    ".",
    "-",
    "_",
    "=",
    ":",
    ": ",
    " ",
    "  ",
    "\t",
    "\n",
    "\r",
    "\"",
    "'",
    "\\",
    "\\\"",
    "\\'",
    "\\\n",
    "&",
    ";",
    ",",
    "}",
    "{",
    "[",
    "]",
    "[redacted",
    REDACTED,
    "[REDACTED x",
    "é",
    "\u{2028}",
    "\u{2029}",
    "ghp_",
    "abcdefghijklmnopqrstuvwxyz0123456789",
    "--",
    "=v",
];

fn random_text(next: &mut impl FnMut() -> f64) -> String {
    let n = 1 + (next() * 28.0) as usize;
    let mut s = String::new();
    for _ in 0..n {
        s.push_str(PIECES[(next() * PIECES.len() as f64) as usize]);
    }
    s
}

const PEM_PARTS: [&str; 14] = [
    "-----BEGIN ",
    "-----END ",
    "PRIVATE KEY-----",
    "RSA ",
    "EC ",
    "-----",
    "-",
    " ",
    "\n",
    "MIIB",
    "x",
    "PRIVATE KEY",
    "BEGIN",
    "END",
];

fn digest(cases: &[(String, Redaction)]) -> String {
    let mut h = Sha256::new();
    for (t, r) in cases {
        h.update(format!("{t}\u{0}{}\u{0}{}\n", r.text, r.count).as_bytes());
    }
    h.finalize().iter().map(|b| format!("{b:02x}")).collect()
}

fn check_first(recorded: &Value, got: &[(String, Redaction)]) {
    for (i, case) in recorded["first"].as_array().unwrap().iter().enumerate() {
        let (t, r) = &got[i];
        assert_eq!(case["text"].as_str().unwrap(), t, "input {i}");
        assert_eq!(case["out"].as_str().unwrap(), r.text, "output {i}: {t:?}");
        assert_eq!(
            case["count"].as_u64().unwrap() as usize,
            r.count,
            "count {i}: {t:?}"
        );
    }
}

#[test]
fn random_strings_match_the_typescript_output() {
    let rec = cases();
    let got: Vec<(String, Redaction)> = (1..=30_000u32)
        .map(|seed| {
            let t = random_text(&mut rng(seed));
            let r = redact_text(&t);
            (t, r)
        })
        .collect();
    check_first(&rec["random"], &got);
    assert_eq!(rec["random"]["sha256"].as_str().unwrap(), digest(&got));
}

#[test]
fn random_pem_fragments_match_the_typescript_output() {
    let rec = cases();
    // JavaScript computes `seed * 1103515245 + 12345` in doubles, which round
    // past 2^53, then `& 0x7fffffff` takes ToInt32 of that double.
    let mut seed: f64 = 7.0;
    let mut rand = |n: usize| {
        let x = seed * 1_103_515_245.0 + 12_345.0;
        let int32 = x.rem_euclid(4_294_967_296.0) as u64;
        seed = (int32 & 0x7fff_ffff) as f64;
        (seed as usize) % n
    };
    let mut got = Vec::new();
    for _ in 0..30_000 {
        let mut t = String::new();
        let n = 1 + rand(12);
        for _ in 0..n {
            t.push_str(PEM_PARTS[rand(PEM_PARTS.len())]);
        }
        let r = redact_text(&t);
        got.push((t, r));
    }
    check_first(&rec["pem"], &got);
    assert_eq!(rec["pem"]["sha256"].as_str().unwrap(), digest(&got));
}

#[test]
fn the_documented_cases_and_token_shapes() {
    for case in cases()["named"].as_array().unwrap() {
        let t = case["text"].as_str().unwrap();
        let r = redact_text(t);
        assert_eq!(case["out"].as_str().unwrap(), r.text, "{t:?}");
        assert_eq!(case["count"].as_u64().unwrap() as usize, r.count, "{t:?}");
    }
    // A redacted value is not counted again.
    let once = redact_text("TOKEN=abc").text;
    assert_eq!(redact_text(&once).count, 0);
}

#[test]
fn json_values_match_the_typescript_output() {
    for case in cases()["values"].as_array().unwrap() {
        let (v, n) = redact_value(&case["input"]);
        assert_eq!(case["value"], v);
        assert_eq!(case["count"].as_u64().unwrap() as usize, n);
    }
}

fn under(ms: u128, f: impl FnOnce()) {
    let t0 = std::time::Instant::now();
    f();
    let took = t0.elapsed().as_millis();
    // The TypeScript pins 100 ms; a debug build is allowed ten times that.
    let cap = if cfg!(debug_assertions) { ms * 10 } else { ms };
    assert!(took < cap, "{took} ms");
}

#[test]
fn crafted_inputs_take_linear_time() {
    let crafted = [
        "token.".repeat(10_923),
        "token.".repeat(10_922) + "x=v",
        format!("\"{}", "secret-".repeat(9_362)),
        "\"token\":\"\\".repeat(6_553),
        "'token':\"".repeat(7_281),
        "password= ".repeat(6_553),
        format!("api_key{}", " ".repeat(65_000)),
    ];
    for text in crafted {
        assert!(text.len() >= 64_000);
        under(100, || {
            redact_text(&text);
        });
    }
    for unit in [
        "-----BEGIN PRIVATE KEY-----\n".to_string(),
        "-----BEGIN PRIVATE KEY-----\n-----END X-----\n".to_string(),
        "-----BEGIN RSA PRIVATE KEY".to_string(),
    ] {
        let big: String = unit
            .repeat(256_000 / unit.len() + 1)
            .chars()
            .take(256_000)
            .collect();
        under(100, || {
            redact_text(&big);
        });
    }
}

#[test]
fn a_json_value_of_crafted_text_takes_linear_time() {
    let value = serde_json::json!({
        "command": "token.".repeat(10_923),
        "env": { "API_TOKEN": "x" },
        "args": ["secret-".repeat(9_362)],
    });
    let mut got = Value::Null;
    under(100, || got = redact_value(&value).0);
    assert_eq!(got["env"]["API_TOKEN"], REDACTED);
}

#[test]
fn token_shapes_are_found_for_the_install_record() {
    assert!(has_token_shape(&format!(
        "pip install ghp_{}",
        "a".repeat(36)
    )));
    assert!(!has_token_shape("pip install requests"));
}
