use serde_json::{json, Value};

use super::handoff::{self, parse};

fn fixture() -> Value {
    serde_json::from_str(include_str!(
        "../../../../contracts/fixtures/srt-windows/handoff.json"
    ))
    .unwrap()
}

fn bytes(v: &Value) -> Vec<u8> {
    v.to_string().into_bytes()
}

const NOW: u64 = 1_762_790_400_000;

#[test]
fn the_fixture_is_a_handoff() {
    let h = parse(&bytes(&fixture()), NOW).unwrap();
    assert_eq!(h.chat, "derm-0123456789ab");
    assert_eq!(h.harness, "claude-code");
    assert_eq!(h.daemon_http, "http://127.0.0.1:60088");
    assert!(h.variables.contains_key("DERM_CHAT_ID"));
    // And writing it again gives the same object.
    assert_eq!(handoff::to_json(&h), fixture());
}

#[test]
fn every_key_is_required_and_no_other_is_read() {
    for k in handoff::KEYS {
        let mut v = fixture();
        v.as_object_mut().unwrap().remove(k);
        let e = parse(&bytes(&v), NOW).unwrap_err();
        assert!(e.contains("missing"), "{k}: {e}");
    }
    let mut v = fixture();
    v["extra"] = json!(1);
    assert!(parse(&bytes(&v), NOW).unwrap_err().contains("extra"));
}

#[test]
fn a_handoff_past_its_time_is_refused() {
    let mut v = fixture();
    v["expires"] = json!(NOW);
    assert!(parse(&bytes(&v), NOW).unwrap_err().contains("expired"));
    v["expires"] = json!(-1);
    assert!(parse(&bytes(&v), NOW).is_err());
}

#[test]
fn the_program_is_an_absolute_exe_never_a_batch_file_or_a_bare_name() {
    for bad in [
        "claude",
        "claude.exe",
        "C:\\npm\\claude.cmd",
        "C:\\npm\\claude.bat",
        "C:/npm/claude.exe",
        "\\\\server\\share\\claude.exe",
        "C:\\npm\\..\\claude.exe",
        "C:\\npm\\\u{7}claude.exe",
    ] {
        let mut v = fixture();
        v["argv"][0] = json!(bad);
        assert!(parse(&bytes(&v), NOW).is_err(), "{bad}");
    }
    let mut v = fixture();
    v["argv"] = json!([]);
    assert!(parse(&bytes(&v), NOW).is_err());
    v["argv"] = json!(["C:\\a\\b.exe", 1]);
    assert!(parse(&bytes(&v), NOW).is_err());
    v["argv"] = json!(["C:\\a\\b.exe", "a\0b"]);
    assert!(parse(&bytes(&v), NOW).is_err());
}

#[test]
fn variables_srt_or_enter_owns_are_refused_in_any_case() {
    for name in [
        "PATH",
        "Path",
        "PATHEXT",
        "COMSPEC",
        "SYSTEMROOT",
        "USERPROFILE",
        "TEMP",
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "NO_PROXY",
        "GRPC_PROXY",
        "RSYNC_PROXY",
        "CLOUDSDK_PROXY_PASSWORD",
        "NODE_USE_ENV_PROXY",
        "NODE_EXTRA_CA_CERTS",
        "SSL_CERT_FILE",
        "GIT_CONFIG_COUNT",
        "GIT_CONFIG_PARAMETERS",
        "GIT_SSH_COMMAND",
        "SRT_DEBUG",
        "DERM_CHAT_TOKEN",
        "DERM_CHAT_TOKEN_FILE",
        "DERM_CHAT_FILE",
    ] {
        let mut v = fixture();
        v["variables"][name] = json!("x");
        assert!(parse(&bytes(&v), NOW).is_err(), "{name}");
    }
    for name in ["lower", "9START", "HAS-DASH", &"A".repeat(65)] {
        let mut v = fixture();
        v["variables"][name] = json!("x");
        assert!(parse(&bytes(&v), NOW).is_err(), "{name}");
    }
    let mut v = fixture();
    v["variables"]["CODEX_HOME"] = json!(1);
    assert!(parse(&bytes(&v), NOW).is_err());
}

#[test]
fn the_daemon_is_a_loopback_http_port_and_nothing_else() {
    for good in [
        "http://127.0.0.1:60088",
        "http://127.0.0.1:41234/",
        "http://[::1]:5",
        "http://[::ffff:127.0.0.1]:65535",
        "http://localhost:80",
    ] {
        assert!(handoff::loopback_http(good), "{good}");
    }
    for bad in [
        "https://127.0.0.1:60088",
        "http://127.0.0.1",
        "http://127.0.0.1:0",
        "http://127.0.0.1:65536",
        "http://127.0.0.1:080",
        "http://10.0.0.1:60088",
        "http://evil.example:60088",
        "http://user@127.0.0.1:1",
        "http://127.0.0.1:60088/derm",
        "http://127.0.0.1:60088?x",
    ] {
        assert!(!handoff::loopback_http(bad), "{bad}");
    }
    let mut v = fixture();
    v["daemon"] = json!({"http": "http://127.0.0.1:1", "socket": "x"});
    assert!(parse(&bytes(&v), NOW).is_err());
}

#[test]
fn the_token_and_the_policy_are_checked() {
    let mut v = fixture();
    v["token"] = json!("2".repeat(63));
    assert!(parse(&bytes(&v), NOW).is_err());
    v["token"] = json!("A".repeat(64));
    assert!(parse(&bytes(&v), NOW).is_err());
    let mut v = fixture();
    v["policy"] = json!({"version": 1, "rules": [], "extra": true});
    assert!(parse(&bytes(&v), NOW).is_err());
    v["policy"] = json!({"version": 1});
    v["policyProblem"] = json!("policy file missing");
    let h = parse(&bytes(&v), NOW).unwrap();
    assert_eq!(h.policy_problem.as_deref(), Some("policy file missing"));
    v["policyProblem"] = json!(3);
    assert!(parse(&bytes(&v), NOW).is_err());
}

#[test]
fn chat_and_harness_are_names_derm_knows() {
    let mut v = fixture();
    v["chat"] = json!("..\\x");
    assert!(parse(&bytes(&v), NOW).is_err());
    let mut v = fixture();
    v["harness"] = json!("not-an-agent");
    assert!(parse(&bytes(&v), NOW).is_err());
    v["harness"] = json!("codex");
    assert!(parse(&bytes(&v), NOW).is_ok());
}

#[test]
fn a_handoff_too_big_or_not_an_object_is_refused() {
    let big = vec![b' '; handoff::MAX_BYTES as usize + 1];
    assert!(parse(&big, NOW).unwrap_err().contains("bytes"));
    assert!(parse(b"[]", NOW).is_err());
    assert!(parse(b"not json", NOW).is_err());
    let mut v = fixture();
    v["version"] = json!(2);
    assert!(parse(&bytes(&v), NOW).is_err());
}

#[test]
fn the_chat_file_holds_the_policy_and_route_only() {
    let h = parse(&bytes(&fixture()), NOW).unwrap();
    let c = handoff::chat_file_json(&h);
    assert_eq!(c["chat"], "derm-0123456789ab");
    assert_eq!(c["daemon"]["http"], "http://127.0.0.1:60088");
    assert_eq!(c["policy"], fixture()["policy"]);
    assert!(!c.to_string().contains(&"2".repeat(64)));
}

#[test]
fn enter_with_no_file_or_a_flag_prints_usage() {
    assert_eq!(super::main(&[]), 2);
    assert_eq!(super::main(&["--start".into()]), 2);
}

#[cfg(not(windows))]
#[test]
fn enter_starts_nothing_off_windows() {
    let d = std::env::temp_dir().join(format!("derm-enter-off-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&d);
    let f = d.join("h.json");
    std::fs::write(&f, bytes(&fixture())).unwrap();
    assert_eq!(super::main(&[f.to_string_lossy().into_owned()]), 2);
    // The handoff is left where it was.
    assert!(f.exists());
    let _ = std::fs::remove_dir_all(&d);
}

#[cfg(unix)]
#[test]
fn check_refuses_a_link_and_a_folder() {
    let d = std::env::temp_dir().join(format!("derm-enter-link-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    let f = d.join("h.json");
    std::fs::write(&f, bytes(&fixture())).unwrap();
    let l = d.join("l.json");
    std::os::unix::fs::symlink(&f, &l).unwrap();
    assert_eq!(super::check(&l), 2);
    assert_eq!(super::check(&d), 2);
    assert_eq!(super::check(&f), 0);
    let _ = std::fs::remove_dir_all(&d);
}
