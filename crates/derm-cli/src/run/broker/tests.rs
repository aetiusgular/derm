//! The broker's wiring (integration w6's close, lane 6C's R1 with Tony's R2).
//! Values here are made-up strings, never a token's shape (rules section 5,
//! item 1).

use super::*;
use derm_egress::secrets::{File, From};

const VALUE: &str = "fake-secret-value-not-a-token-0000";

/// A home with a private `.derm`, a temp folder, and a value file of the
/// user's alone.
fn home(tag: &str) -> (PathBuf, PathBuf, PathBuf) {
    use std::os::unix::fs::PermissionsExt;
    let root = std::env::temp_dir().join(format!("dbroker-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let h = root.join("home");
    let t = root.join("tmp");
    std::fs::create_dir_all(h.join(".derm")).unwrap();
    std::fs::create_dir_all(&t).unwrap();
    for d in [&root, &h, &h.join(".derm"), &t] {
        std::fs::set_permissions(d, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let v = root.join("gh-value");
    std::fs::write(&v, format!("{VALUE}\n")).unwrap();
    std::fs::set_permissions(&v, std::fs::Permissions::from_mode(0o600)).unwrap();
    (h, t, v)
}

fn secrets_file(h: &Path, entries: Vec<Entry>) {
    secrets::save(
        &secrets::path_for(h),
        &File {
            version: 1,
            secrets: entries,
        },
    )
    .unwrap();
}

fn entry(id: &str, from: From) -> Entry {
    Entry {
        id: id.into(),
        hosts: vec!["api.github.com".into()],
        from,
        placement: None,
        note: None,
    }
}

fn chat<'a>(h: &'a Path, t: &'a Path, tier: &'a str, boundary: &'a str, dry: bool) -> Chat<'a> {
    Chat {
        chat: "derm-broker1",
        harness: "codex",
        tier,
        boundary,
        home: h,
        dry_run: dry,
        temp: t,
        account: None,
        project: "",
    }
}

fn no_env(_: &str) -> Option<String> {
    panic!("no value is read here")
}

fn srt_plan() -> Plan {
    Plan {
        srt_settings: Some(r#"{"network":{"allowedDomains":["api.github.com"]}}"#.into()),
        ..Plan::default()
    }
}

fn holds_value(p: &Plan, b: &Broker) -> bool {
    p.env_set.iter().any(|(_, v)| v.contains(VALUE))
        || p.notes.iter().any(|n| n.contains(VALUE))
        || p.srt_settings.as_deref().is_some_and(|s| s.contains(VALUE))
        || b.record
            .as_ref()
            .is_some_and(|r| r.to_string().contains(VALUE))
}

#[test]
fn a_chat_with_no_secrets_gets_no_broker_and_no_change() {
    let (h, t, _) = home("none");
    let mut p = srt_plan();
    let before = p.clone();
    let b = wire(&chat(&h, &t, "whole", "srt", false), &mut p, &no_env, None).unwrap();
    assert!(b.egress.is_none() && b.record.is_none() && b.trust_dir.is_none());
    assert_eq!(p, before);
}

/// Mac test w6, MW6-4 (srt's half): srt's allow list held derm's ports and
/// the sign-in host, so `gh api user` in a brokered srt chat got srt's own
/// "host is not on the allow list" until `--allow-host api.github.com:443`.
/// srt admits what its list holds and chains it to `parentProxy` (note AZ
/// C2), so each secret's host is admitted on 443, the one port derm-egress
/// swaps on (case 258); a dry run plans the same.
#[test]
fn mw6_4_under_srt_each_secrets_host_is_on_srts_allow_list() {
    let (h, t, v) = home("mw64srt");
    Ca::generate()
        .unwrap()
        .save(&ca::dir_for(&h), false)
        .unwrap();
    let mut e = entry("gh", From::File(v.to_string_lossy().into_owned()));
    e.hosts = vec!["api.github.com".into(), "uploads.github.com".into()];
    secrets_file(&h, vec![e]);
    for dry in [false, true] {
        let mut p = Plan {
            srt_settings: Some(r#"{"network":{"allowedDomains":["127.0.0.1:4318"]}}"#.into()),
            ..Plan::default()
        };
        let _b = wire(&chat(&h, &t, "whole", "srt", dry), &mut p, &no_env, None).unwrap();
        let s: Value = serde_json::from_str(p.srt_settings.as_deref().unwrap()).unwrap();
        assert_eq!(
            s["network"]["allowedDomains"],
            serde_json::json!([
                "127.0.0.1:4318",
                "api.github.com:443",
                "uploads.github.com:443"
            ]),
            "dry {dry}"
        );
    }
}

#[test]
fn under_srt_the_broker_starts_and_srt_chains_to_it_and_no_value_leaves_this_process() {
    let (h, t, v) = home("srt");
    Ca::generate()
        .unwrap()
        .save(&ca::dir_for(&h), false)
        .unwrap();
    secrets_file(
        &h,
        vec![entry("gh", From::File(v.to_string_lossy().into_owned()))],
    );
    let mut p = srt_plan();
    let b = wire(&chat(&h, &t, "whole", "srt", false), &mut p, &no_env, None).unwrap();
    let egress = b.egress.as_ref().expect("started");
    let s: Value = serde_json::from_str(p.srt_settings.as_deref().unwrap()).unwrap();
    assert_eq!(s["network"]["parentProxy"]["https"], egress.url());
    assert_eq!(s["network"]["allowedDomains"][0], "api.github.com", "kept");
    let ph = p
        .env_set
        .iter()
        .find(|(k, _)| k == "DERM_SECRET_GH")
        .map(|(_, v)| v.clone())
        .unwrap();
    assert!(ph.starts_with("dermsecret_gh_"), "{ph}");
    let ca_file = p
        .env_set
        .iter()
        .find(|(k, _)| k == "NODE_EXTRA_CA_CERTS")
        .map(|(_, v)| PathBuf::from(v))
        .unwrap();
    let trust = b.trust_dir.clone().unwrap();
    assert!(ca_file.starts_with(&trust) && ca_file.exists());
    assert!(trust.starts_with(&t), "never under ~/.derm");
    let r = b.record.clone().unwrap();
    assert_eq!(r["brokered"], true);
    assert_eq!(r["port"], egress.port());
    assert_eq!(r["ids"][0], "gh");
    assert!(p
        .notes
        .iter()
        .any(|n| n.contains("brokered by derm-egress")));
    assert!(!holds_value(&p, &b));
}

#[test]
fn a_dry_run_reads_no_value_and_starts_nothing() {
    let (h, t, v) = home("dry");
    secrets_file(
        &h,
        vec![entry("gh", From::File(v.to_string_lossy().into_owned()))],
    );
    let mut p = Plan::default();
    let b = wire(
        &chat(&h, &t, "standard", "none", true),
        &mut p,
        &no_env,
        None,
    )
    .unwrap();
    assert!(b.egress.is_none() && b.trust_dir.is_none());
    assert!(p.env_set.iter().any(|(k, _)| k == "HTTPS_PROXY"));
    assert!(p
        .notes
        .iter()
        .any(|n| n.contains("brokered by derm-egress")));
    // The trust folder's name carries a random part (W6C-S9): none is left.
    assert!(std::fs::read_dir(&t).unwrap().all(|e| !e
        .unwrap()
        .file_name()
        .to_string_lossy()
        .starts_with("derm-trust-")));
}

/// Lane L4's request R4: a chat run as an agent account with no other
/// boundary is brokered (its own network is loopback only), and a Claude
/// subscription token is refused there (note CB 4.1). A dry run, so no
/// value is read and nothing starts.
#[test]
fn an_agent_account_chat_is_brokered_and_refuses_a_subscription_token() {
    let (h, t, v) = home("acct");
    secrets_file(
        &h,
        vec![entry("gh", From::File(v.to_string_lossy().into_owned()))],
    );
    let mut c = chat(&h, &t, "whole", "none", true);
    c.account = Some("derm-max");
    let mut p = Plan::default();
    let b = wire(&c, &mut p, &no_env, None).unwrap();
    assert!(b.record.is_none(), "brokered: {:?}", b.record);
    assert!(p.env_set.iter().any(|(k, _)| k == "HTTPS_PROXY"));
    assert!(
        p.notes.iter().any(|n| n.contains("derm-max")),
        "{:?}",
        p.notes
    );
    // The same chat as the person is not brokered (case 218's rule).
    let mut q = Plan::default();
    let b = wire(&chat(&h, &t, "whole", "none", true), &mut q, &no_env, None).unwrap();
    assert_eq!(b.record.unwrap()["brokered"], false);
    // A subscription token is refused in the account's chat, and only there.
    secrets_file(
        &h,
        vec![entry("claude", From::Env("CLAUDE_CODE_OAUTH_TOKEN".into()))],
    );
    let mut p = Plan::default();
    let Err(e) = wire(&c, &mut p, &no_env, None) else {
        panic!("a subscription token was carried in an account's chat");
    };
    assert!(
        e.contains("subscription token") && e.contains("derm agents login"),
        "{e}"
    );
    let mut p = Plan::default();
    assert!(wire(&chat(&h, &t, "whole", "none", true), &mut p, &no_env, None).is_ok());
}

#[test]
fn a_chat_that_is_not_brokered_loses_its_env_sourced_variables() {
    let (h, t, _) = home("plain");
    secrets_file(&h, vec![entry("gh", From::Env("GH_TOKEN".into()))]);
    let mut p = Plan {
        env_set: vec![("GH_TOKEN".into(), "x".into())],
        ..Plan::default()
    };
    let b = wire(&chat(&h, &t, "whole", "none", false), &mut p, &no_env, None).unwrap();
    assert!(b.egress.is_none());
    assert!(p.env_remove.contains(&"GH_TOKEN".to_string()));
    assert!(!p.env_set.iter().any(|(k, _)| k == "GH_TOKEN"));
    assert_eq!(b.record.unwrap()["brokered"], false);
    // Under sbx too (case 218), and the line names sbx's own store.
    let mut q = Plan::default();
    wire(
        &chat(&h, &t, "standard", "sbx", false),
        &mut q,
        &no_env,
        None,
    )
    .unwrap();
    assert!(q.env_remove.contains(&"GH_TOKEN".to_string()));
    assert!(q.notes.iter().any(|n| n.contains("sbx secret set")));
}

#[test]
fn a_missing_ca_or_an_unreadable_value_refuses_the_start_and_leaves_nothing() {
    let (h, t, _) = home("refuse");
    secrets_file(
        &h,
        vec![entry("gh", From::File("/nonexistent/derm".into()))],
    );
    let mut p = srt_plan();
    let e = wire(&chat(&h, &t, "whole", "srt", false), &mut p, &no_env, None)
        .err()
        .unwrap();
    assert!(e.contains("derm secret ca create"), "{e}");
    Ca::generate()
        .unwrap()
        .save(&ca::dir_for(&h), false)
        .unwrap();
    let e = wire(&chat(&h, &t, "whole", "srt", false), &mut p, &no_env, None)
        .err()
        .unwrap();
    assert!(e.contains("secret gh"), "{e}");
    // The trust folder's name carries a random part (W6C-S9): none is left.
    assert!(std::fs::read_dir(&t).unwrap().all(|e| !e
        .unwrap()
        .file_name()
        .to_string_lossy()
        .starts_with("derm-trust-")));
}

#[test]
fn the_policy_carries_the_model_hosts_and_each_secrets_placement() {
    let mut a = entry("gh", From::File("/x".into()));
    a.placement = Some(vec!["query:key".into()]);
    let mut b = entry("npm", From::File("/y".into()));
    b.placement = Some(vec!["body:auth.token".into(), "query:t".into()]);
    let c = entry("plain", From::File("/z".into()));
    let pol = policy_for(&[a, b, c]);
    let pair = |a: &str, b: &str| (a.to_string(), b.to_string());
    assert_eq!(pol.swap_body, vec![pair("npm", "auth.token")]);
    assert_eq!(pol.swap_query, vec![pair("gh", "key"), pair("npm", "t")]);
    assert!(pol.model_hosts.iter().any(|h| h == "api.anthropic.com"));
    assert!(pol.allow.is_none());
}

#[test]
fn the_file_a_secret_is_read_from_is_hidden_by_every_sandbox_derm_writes() {
    // Integration w6's review, W6C-S1: `derm secret add --file` kept the
    // value out of the environment but left the file readable to a
    // sandboxed `cat`. srt's `denyRead` and the Standard tier's denies now
    // name it, as written and by its real path.
    let (h, _t, v) = home("hide");
    // The value file through a linked folder (the broker refuses a final
    // link, so a file named through one could not start a chat; W6C-R9).
    std::os::unix::fs::symlink(v.parent().unwrap(), h.join("keys")).unwrap();
    let link = h.join("keys").join(v.file_name().unwrap());
    secrets_file(
        &h,
        vec![entry("gh", From::File(link.to_string_lossy().into_owned()))],
    );
    let files = crate::secret::value_files(&h);
    let real = std::fs::canonicalize(&v).unwrap();
    assert!(
        files.contains(&link.to_string_lossy().into_owned()),
        "{files:?}"
    );
    assert!(
        files.contains(&real.to_string_lossy().into_owned()),
        "{files:?}"
    );
    let ctx = crate::connect::sandbox::Context {
        home: h.to_string_lossy().into_owned(),
        folders: vec![h.join("work").to_string_lossy().into_owned()],
        daemon_dir: None,
        data_dir: None,
        allowed_domains: Vec::new(),
        tmp_to_chat: false,
    };
    let denied = crate::connect::sandbox::denied_reads(&ctx);
    assert!(
        denied.contains(&real.to_string_lossy().into_owned()),
        "{denied:?}"
    );
    // Codex's profile carries the same denies.
    assert!(
        crate::connect::sandbox::codex_profile(&ctx).contains(&real.to_string_lossy().into_owned())
    );
}

/// Request PB-1 (lane PB's request 1; I-4): a chat gets only the secrets
/// bound to its own project, a chat in no project only the unbound ones,
/// and the start names what was left out. Shown by a dry run, which reads
/// no value: the plan holds a placeholder per secret the chat gets.
#[test]
fn pb_r1_a_chat_gets_only_the_secrets_bound_to_its_project() {
    let (h, t, v) = home("pbr1");
    let a = "aaaaaaaaaaaaaaaa";
    let b = "bbbbbbbbbbbbbbbb";
    secrets_file(
        &h,
        vec![
            entry("gh-a", From::File(v.to_string_lossy().into_owned())),
            entry("gh-b", From::File(v.to_string_lossy().into_owned())),
            entry("free", From::File(v.to_string_lossy().into_owned())),
        ],
    );
    let mut bind = derm_egress::bind::Bindings::default();
    bind.projects.insert("gh-a".into(), vec![a.into()]);
    bind.projects.insert("gh-b".into(), vec![b.into()]);
    derm_egress::bind::save(&derm_egress::bind::path_for(&h), &bind).unwrap();
    for (project, kept, left) in [
        (a, "gh-a", vec!["gh-b"]),
        (b, "gh-b", vec!["gh-a"]),
        ("", "free", vec!["gh-a", "gh-b"]),
    ] {
        let mut p = srt_plan();
        let mut c = chat(&h, &t, "whole", "srt", true);
        c.project = project;
        let _b = wire(&c, &mut p, &no_env, None).unwrap();
        let text = format!("{p:?}");
        assert!(text.contains(kept), "{project}: {text}");
        for l in &left {
            let note = p.notes.iter().find(|n| n.contains(l));
            assert!(
                note.is_some(),
                "{project}: {l} named as left out: {:?}",
                p.notes
            );
        }
    }
}

/// Case 283 and Tony's 22 Nov call, for an agent account's brokered chat,
/// whose `HTTPS_PROXY` is derm-egress: the harness's own sign-in host passes
/// through unread (a renewal's tokens stay in the harness's TLS, note CB
/// 4.1), and claude.ai's connector proxy is closed. A person's own chat gets
/// neither.
#[test]
fn case_283_an_account_chats_egress_passes_its_sign_in_host_and_closes_mcp_proxy() {
    let (pass, deny) = account_egress("claude-code", Some("derm-max"));
    assert_eq!(pass, vec![("platform.claude.com".to_string(), 443)]);
    assert_eq!(deny, vec!["mcp-proxy.anthropic.com".to_string()]);
    let (pass, deny) = account_egress("codex", Some("derm-max"));
    assert_eq!(pass, vec![("auth.openai.com".to_string(), 443)]);
    assert_eq!(deny, vec!["mcp-proxy.anthropic.com".to_string()]);
    let (pass, deny) = account_egress("pi", Some("derm-max"));
    assert!(pass.is_empty());
    assert_eq!(deny.len(), 1);
    for h in ["claude-code", "codex"] {
        assert_eq!(account_egress(h, None), (Vec::new(), Vec::new()), "{h}");
    }
}
