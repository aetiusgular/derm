//! `derm secret` and the chain per tier (cases 217's setup, 218; rules 147,
//! 89). Values are made-up strings.

use super::chain::{self, Input};
use super::*;
use derm_egress::secrets::{Entry, From};

const VAL: &str = "made-up-value-for-tests-0000";

struct Home(PathBuf);
impl Drop for Home {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn home(tag: &str) -> Home {
    let d = std::env::temp_dir().join(format!("derm-secret-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    Home(d)
}

fn s(a: &[&str]) -> Vec<String> {
    a.iter().map(|x| x.to_string()).collect()
}

/// Run a verb and return (code, stdout, stderr).
fn go(h: &Path, terminal: bool, in_chat: Option<&str>, args: &[&str]) -> (u8, String, String) {
    let env = |k: &str| (k == "GH_TOKEN").then(|| VAL.to_string());
    let (mut out, mut err) = (Vec::new(), Vec::new());
    let mut ctx = Ctx {
        home: h.to_path_buf(),
        terminal,
        in_chat: in_chat.map(str::to_string),
        env: &env,
        out: &mut out,
        err: &mut err,
    };
    let code = run(&mut ctx, &s(args));
    (
        code,
        String::from_utf8(out).unwrap(),
        String::from_utf8(err).unwrap(),
    )
}

#[test]
fn add_parses_every_source_and_refuses_two() {
    let e = parse_add(&s(&[
        "gh",
        "--host",
        "api.github.com",
        "--host",
        "uploads.github.com",
        "--env",
        "GH_TOKEN",
        "--note",
        "n",
    ]))
    .unwrap();
    assert_eq!(e.hosts.len(), 2);
    assert_eq!(e.from, From::Env("GH_TOKEN".into()));
    assert!(parse_add(&s(&["gh", "--host", "a.b", "--env", "A", "--file", "/x"])).is_err());
    assert!(parse_add(&s(&["gh", "--env", "A"])).is_err(), "no host");
    assert!(
        parse_add(&s(&["gh", "--host", "a.b"])).is_err(),
        "no source"
    );
    assert!(parse_add(&s(&["--host", "a.b"])).is_err(), "no id");
    assert!(parse_add(&s(&["gh", "--host"])).is_err());
}

/// Decision 2, item 2 (integration w6's close), with review W6C-S8 (Tony's
/// call of 13 Nov): `--in body:<path>` and `--in query:<param>` name one
/// field each and set the entry's placement, once each; bare `body` and
/// `query` and anything else are refused; with no `--in` the value goes into
/// headers only and the file holds no placement.
#[test]
fn add_takes_a_placement_for_the_body_or_the_query() {
    let e = parse_add(&s(&[
        "gh",
        "--host",
        "api.github.com",
        "--file",
        "/x",
        "--in",
        "body:auth.token",
        "--in",
        "query:key",
    ]))
    .unwrap();
    assert_eq!(
        e.placement,
        Some(vec!["body:auth.token".to_string(), "query:key".to_string()])
    );
    assert_eq!(
        e.spots(),
        vec![
            derm_egress::place::Spot::Body("auth.token".into()),
            derm_egress::place::Spot::Query("key".into())
        ]
    );
    let plain = parse_add(&s(&["gh", "--host", "api.github.com", "--file", "/x"])).unwrap();
    assert_eq!(plain.placement, None);
    assert!(plain.spots().is_empty());
    assert!(!secrets::render(&secrets::File {
        version: 1,
        secrets: vec![plain]
    })
    .contains("placement"));
    for bad in [
        ["--in", "header"],
        ["--in", "url"],
        ["--in", "body"],
        ["--in", "query"],
        ["--in", "body:a b"],
    ] {
        let mut a = s(&["gh", "--host", "a.b", "--file", "/x"]);
        a.extend(s(&bad));
        assert!(parse_add(&a).is_err(), "{bad:?}");
    }
    assert!(parse_add(&s(&[
        "gh", "--host", "a.b", "--file", "/x", "--in", "body:t", "--in", "body:t"
    ]))
    .is_err());
    // The file's own check refuses what the schema refuses.
    let mut f = secrets::File::default();
    let mut e = entry("gh", From::File("/x".into()));
    e.placement = Some(vec!["header".into()]);
    f.secrets.push(e);
    assert!(f.check().is_err());
    for bad in ["body", "query", "query:a&b"] {
        let mut f = secrets::File::default();
        let mut e = entry("gh", From::File("/x".into()));
        e.placement = Some(vec![bad.into()]);
        f.secrets.push(e);
        assert!(f.check().is_err(), "{bad}");
    }
}

#[test]
fn writing_verbs_refuse_without_a_terminal_and_inside_a_chat() {
    let h = home("refuse");
    let add = ["add", "gh", "--host", "api.github.com", "--env", "GH_TOKEN"];
    let (c, _, e) = go(&h.0, false, None, &add);
    assert_eq!(c, 2);
    assert!(e.contains("only from a terminal"), "{e}");
    let (c, _, e) = go(&h.0, true, Some("DERM_CHAT_TOKEN is set"), &add);
    assert_eq!(c, 2);
    assert!(e.contains("inside a chat"), "{e}");
    for v in [&["remove", "gh"][..], &["ca", "create"], &["ca", "remove"]] {
        assert_eq!(go(&h.0, false, None, v).0, 2, "{v:?}");
        assert_eq!(go(&h.0, true, Some("x"), v).0, 2, "{v:?}");
    }
    assert!(!secrets::path_for(&h.0).exists(), "nothing written");
    // Reading verbs run anywhere.
    assert_eq!(go(&h.0, false, Some("x"), &["list"]).0, 0);
}

/// Mac test w6, MW6-5: the note that a chat already running keeps its
/// sandbox until it restarts was printed for an `--env` add only; a `--file`
/// add changes what a new chat's sandbox hides (W6C-R9) just the same.
#[test]
fn mw6_5_every_add_says_a_running_chat_keeps_its_sandbox() {
    let h = home("mw65");
    let v = h.0.join("value");
    std::fs::write(&v, "fake-not-a-token\n").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&v, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    let file = v.to_string_lossy().into_owned();
    for (id, from) in [
        ("a", ["--env", "GH_TOKEN"]),
        ("b", ["--file", file.as_str()]),
    ] {
        let mut args = vec!["add", id, "--host", "api.github.com"];
        args.extend(from);
        let (c, out, e) = go(&h.0, true, None, &args);
        assert_eq!(c, 0, "{e}");
        assert!(
            out.contains("a chat already running keeps its sandbox until it restarts"),
            "{id}: {out}"
        );
    }
}

#[test]
fn add_list_check_remove_round_trip_never_print_the_value() {
    let h = home("trip");
    let (c, out, e) = go(
        &h.0,
        true,
        None,
        &["add", "gh", "--host", "api.github.com", "--env", "GH_TOKEN"],
    );
    assert_eq!(c, 0, "{e}");
    assert!(out.contains("GH_TOKEN"));
    let (c, _, e) = go(
        &h.0,
        true,
        None,
        &["add", "gh", "--host", "api.github.com", "--env", "GH_TOKEN"],
    );
    assert_eq!(c, 2, "a second add of one id");
    assert!(e.contains("exists"));
    let (_, list, _) = go(&h.0, false, None, &["list"]);
    assert!(list.contains("gh  api.github.com"), "{list}");
    // check: the value reads, no CA yet.
    let (c, out, _) = go(&h.0, false, None, &["check"]);
    assert_eq!(c, 2);
    assert!(out.contains("gh: ok") && out.contains("CA: none"), "{out}");
    let (c, _, _) = go(&h.0, true, None, &["ca", "create"]);
    assert_eq!(c, 0);
    let (c, out, _) = go(&h.0, false, None, &["check"]);
    assert_eq!(c, 0, "{out}");
    let (c, show, _) = go(&h.0, false, None, &["ca", "show"]);
    assert_eq!(c, 0);
    assert!(show.contains("derm local CA") && show.contains("sha256"));
    assert_eq!(
        go(&h.0, true, None, &["ca", "create"]).0,
        2,
        "no silent replace"
    );
    assert_eq!(go(&h.0, true, None, &["ca", "create", "--replace"]).0, 0);
    let (c, _, _) = go(&h.0, true, None, &["remove", "gh"]);
    assert_eq!(c, 0);
    assert_eq!(go(&h.0, true, None, &["remove", "gh"]).0, 2);
    let all = std::fs::read_to_string(secrets::path_for(&h.0)).unwrap();
    assert!(!all.contains(VAL));
    let (c, out, _) = go(&h.0, true, None, &["ca", "remove"]);
    assert_eq!(c, 0);
    assert!(out.contains("3 file(s)"));
}

#[test]
fn an_unreadable_value_warns_at_add_and_fails_check_without_the_value() {
    let h = home("warn");
    let (c, _, e) = go(
        &h.0,
        true,
        None,
        &[
            "add",
            "np",
            "--host",
            "registry.npmjs.org",
            "--env",
            "NPM_TOKEN",
        ],
    );
    assert_eq!(c, 0);
    assert!(e.contains("warning"), "{e}");
    let (c, out, _) = go(&h.0, false, None, &["check"]);
    assert_eq!(c, 2);
    assert!(out.contains("np: NPM_TOKEN is not set"), "{out}");
}

fn entry(id: &str, from: From) -> Entry {
    Entry {
        placement: None,
        id: id.into(),
        hosts: vec!["api.github.com".into()],
        from,
        note: None,
    }
}

fn input<'a>(tier: &'a str, boundary: &'a str, sec: &'a [(Entry, String)]) -> Input<'a> {
    Input {
        harness: "claude-code",
        tier,
        boundary,
        secrets: sec,
        egress_url: Some("http://127.0.0.1:41000"),
        ca_file: "/run/chat/derm-ca.pem",
        bundle_file: "/run/chat/derm-bundle.pem",
        fingerprint: "0123456789abcdef0123",
    }
}

fn get<'a>(p: &'a chain::Plan, k: &str) -> Option<&'a str> {
    p.env.iter().find(|(a, _)| a == k).map(|(_, v)| v.as_str())
}

#[test]
fn under_sbx_derm_brokers_nothing_sets_no_placeholder_and_names_sbx_secret() {
    // Case 218.
    let sec = vec![(
        entry("gh", From::Env("GH_TOKEN".into())),
        "dermsecret_gh_0123456789abcdef".to_string(),
    )];
    for tier in ["standard", "whole"] {
        let p = chain::plan(&input(tier, "sbx", &sec)).unwrap();
        assert!(!p.brokered);
        assert!(p.env.is_empty(), "no placeholder, no proxy, no CA");
        assert!(p.srt_network.is_none());
        assert_eq!(p.remove, ["GH_TOKEN"]);
        assert!(p.line.unwrap().contains("sbx secret set"));
    }
}

#[test]
fn under_srt_derm_egress_is_srts_parent_proxy_and_the_harness_trusts_derms_ca() {
    let sec = vec![(
        entry("gh", From::File("/x".into())),
        "dermsecret_gh_0123456789abcdef".to_string(),
    )];
    let p = chain::plan(&input("whole", "srt", &sec)).unwrap();
    assert!(p.brokered);
    assert_eq!(
        p.srt_network.as_ref().unwrap()["parentProxy"]["https"],
        "http://127.0.0.1:41000"
    );
    // W6C-S6: an empty list, so srt does not fall back to the shell's
    // NO_PROXY and send those hosts around derm-egress.
    assert_eq!(
        p.srt_network.as_ref().unwrap()["parentProxy"]["noProxy"],
        ""
    );
    assert!(
        get(&p, "HTTPS_PROXY").is_none(),
        "srt sets the harness's proxy to its own"
    );
    assert_eq!(
        get(&p, "DERM_SECRET_GH"),
        Some("dermsecret_gh_0123456789abcdef")
    );
    assert_eq!(
        get(&p, "NODE_EXTRA_CA_CERTS"),
        Some("/run/chat/derm-ca.pem")
    );
    assert_eq!(get(&p, "SSL_CERT_FILE"), Some("/run/chat/derm-bundle.pem"));
    assert!(p.model_hosts.contains(&"api.anthropic.com".to_string()));
    let line = p.line.unwrap();
    assert!(
        line.contains("0123456789abcdef") && line.contains("parentProxy"),
        "{line}"
    );
}

#[test]
fn under_the_standard_tier_the_harness_proxy_names_derm_egress_and_loopback_stays_direct() {
    let sec = vec![(
        entry("gh", From::Env("GH_TOKEN".into())),
        "dermsecret_gh_0123456789abcdef".to_string(),
    )];
    let p = chain::plan(&input("standard", "none", &sec)).unwrap();
    assert!(p.brokered);
    assert_eq!(get(&p, "HTTPS_PROXY"), Some("http://127.0.0.1:41000"));
    assert_eq!(get(&p, "NO_PROXY"), Some("localhost,127.0.0.1,::1"));
    // The real variable's name now holds the placeholder.
    assert_eq!(get(&p, "GH_TOKEN"), Some("dermsecret_gh_0123456789abcdef"));
    assert!(p.remove.is_empty());
    assert!(chain::plan(&Input {
        egress_url: None,
        ..input("standard", "none", &sec)
    })
    .is_err());
}

#[test]
fn a_chat_outside_both_gets_no_broker_and_loses_the_env_variables() {
    let sec = vec![(
        entry("gh", From::Env("GH_TOKEN".into())),
        "dermsecret_gh_0123456789abcdef".to_string(),
    )];
    let p = chain::plan(&input("whole", "none", &sec)).unwrap();
    assert!(!p.brokered && p.env.is_empty());
    assert_eq!(p.remove, ["GH_TOKEN"]);
    assert!(chain::plan(&input("standard", "none", &[]))
        .unwrap()
        .line
        .is_none());
}

#[test]
fn lane_6as_claude_code_block_can_chain_to_derm_egress() {
    // The guard the lane's request names: 6A's Standard block carries no TLS
    // termination, no credential masks and no httpProxyPort.
    let c = crate::connect::sandbox::Context {
        home: "/home/u".into(),
        folders: vec!["/home/u/p".into()],
        ..Default::default()
    };
    chain::vendor_block_ok(&crate::connect::sandbox::claude_block(&c)).unwrap();
    for bad in [
        serde_json::json!({"sandbox": {"network": {"tlsTerminate": {}}}}),
        serde_json::json!({"sandbox": {"credentials": {"mask": []}}}),
        serde_json::json!({"sandbox": {"network": {"httpProxyPort": 8899}}}),
    ] {
        assert!(chain::vendor_block_ok(&bad).is_err(), "{bad}");
    }
}

#[test]
fn the_bundle_holds_the_system_roots_and_derms_ca() {
    let ca = derm_egress::ca::Ca::generate().unwrap();
    match chain::bundle(&ca.cert_pem()) {
        Ok(b) => {
            assert!(b.ends_with(&ca.cert_pem()));
            assert!(b.matches("BEGIN CERTIFICATE").count() > 1);
        }
        Err(e) => assert!(e.contains("no system root bundle")),
    }
}

#[test]
fn the_trust_files_are_written_where_the_chain_names_them() {
    let h = home("trust");
    let ca = derm_egress::ca::Ca::generate().unwrap();
    match chain::write_trust(&h.0.join("run"), &ca.cert_pem()) {
        Ok((c, b)) => {
            assert_eq!(std::fs::read_to_string(c).unwrap(), ca.cert_pem());
            assert!(std::fs::read_to_string(b)
                .unwrap()
                .ends_with(&ca.cert_pem()));
        }
        Err(e) => assert!(e.contains("no system root bundle")),
    }
}

/// Mac test w6, MW6-6: gh cannot start in a chat whose sandbox hides
/// `~/.config/gh`, so a GitHub secret's start line says what gh needs; and a
/// brokered Codex chat under the Standard tier says its commands have no
/// network (`:workspace`), so the secret is not usable there.
#[test]
fn mw6_6_a_github_secret_names_what_gh_needs_and_codex_standard_says_no_network() {
    let sec = vec![(
        entry("gh", From::File("/x".into())),
        "dermsecret_gh_0123456789abcdef".to_string(),
    )];
    let line = chain::plan(&input("whole", "srt", &sec))
        .unwrap()
        .line
        .unwrap();
    assert!(
        line.contains("GH_CONFIG_DIR") && line.contains("GH_TOKEN"),
        "{line}"
    );
    assert!(!line.contains("no network"), "{line}");
    let mut i = input("standard", "none", &sec);
    i.harness = "codex";
    let line = chain::plan(&i).unwrap().line.unwrap();
    assert!(
        line.contains("Codex's own commands have no network"),
        "{line}"
    );
    let mut other = entry("x", From::File("/x".into()));
    other.hosts = vec!["api.example.com".into()];
    let sec = vec![(other, "dermsecret_x_0123456789abcdef".to_string())];
    let line = chain::plan(&input("whole", "srt", &sec))
        .unwrap()
        .line
        .unwrap();
    assert!(!line.contains("GH_CONFIG_DIR"), "{line}");
}
