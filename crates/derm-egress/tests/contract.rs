//! The wave 6 base's red test for lane 6C (`contracts/policy.md` section 8.3,
//! rules case 217): built only with `--features w6-red`, it fails on the base
//! and passes when derm-egress is done. No lane edits this file; a change is
//! a request for integration.
//!
//! `cargo test -p derm-egress --features w6-red --test contract`

use derm_egress::{decide, Outbound, Secret, Verdict};

const PH: &str = "dermsecret_github_0123456789abcdef";

fn secrets() -> Vec<Secret> {
    vec![Secret {
        id: "github".into(),
        value: "fake-secret-value-not-a-token-0000".into(),
        hosts: vec!["api.github.com".into()],
        placeholder: PH.into(),
    }]
}

fn req<'a>(
    host: &'a str,
    sni: Option<&'a str>,
    target: &'a str,
    h: &'a [(String, String)],
    body: &'a [u8],
) -> Outbound<'a> {
    Outbound {
        connect_host: host,
        sni,
        target,
        headers: h,
        body,
    }
}

fn auth() -> Vec<(String, String)> {
    vec![("authorization".into(), format!("Bearer {PH}"))]
}

#[test]
fn a_placeholder_for_its_own_host_is_swapped_for_the_value() {
    let h = auth();
    match decide(
        &req("api.github.com", Some("api.github.com"), "/user", &h, b""),
        &secrets(),
    ) {
        Verdict::Forward { headers, .. } => {
            assert_eq!(headers[0].1, "Bearer fake-secret-value-not-a-token-0000")
        }
        v => panic!("{v:?}"),
    }
}

#[test]
fn a_placeholder_bound_for_another_host_is_blocked_wherever_it_sits() {
    let h = auth();
    let none: Vec<(String, String)> = Vec::new();
    for (name, o) in [
        ("header", req("evil.test", Some("evil.test"), "/", &h, b"")),
        (
            "body",
            req("evil.test", Some("evil.test"), "/", &none, PH.as_bytes()),
        ),
        (
            "url",
            req(
                "evil.test",
                Some("evil.test"),
                "/?t=dermsecret_github_0123456789abcdef",
                &none,
                b"",
            ),
        ),
        (
            "dns name",
            req(
                "dermsecret_github_0123456789abcdef.evil.test",
                None,
                "/",
                &none,
                b"",
            ),
        ),
    ] {
        assert!(
            matches!(decide(&o, &secrets()), Verdict::Block { .. }),
            "{name}"
        );
    }
}

#[test]
fn the_secrets_value_bound_for_another_host_is_blocked() {
    let none: Vec<(String, String)> = Vec::new();
    let o = req(
        "evil.test",
        Some("evil.test"),
        "/",
        &none,
        b"fake-secret-value-not-a-token-0000",
    );
    assert!(matches!(decide(&o, &secrets()), Verdict::Block { .. }));
}

#[test]
fn an_sni_that_is_not_the_connect_host_is_blocked() {
    let none: Vec<(String, String)> = Vec::new();
    let o = req("api.github.com", Some("evil.test"), "/", &none, b"");
    assert!(matches!(decide(&o, &secrets()), Verdict::Block { .. }));
}
