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
    a.placement = Some(vec!["query".into()]);
    let mut b = entry("npm", From::File("/y".into()));
    b.placement = Some(vec!["body".into(), "query".into()]);
    let c = entry("plain", From::File("/z".into()));
    let pol = policy_for(&[a, b, c]);
    assert_eq!(pol.swap_body, vec!["npm".to_string()]);
    assert_eq!(pol.swap_query, vec!["gh".to_string(), "npm".to_string()]);
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
    let link = h.join("gh-link");
    std::os::unix::fs::symlink(&v, &link).unwrap();
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
