//! `decide`'s cases beyond the base's red test (`tests/contract.rs`): case
//! 217's forms and the swap's limits. Values here are made-up strings, never a
//! token's shape (rules section 5, item 1).

use super::*;

const PH_A: &str = "dermsecret_github_0123456789abcdef";
const PH_B: &str = "dermsecret_npm_fedcba9876543210";
const VAL_A: &str = "fake-secret-value-not-a-token-0000";
const VAL_B: &str = "another-made-up-value-1111";

fn two() -> Vec<Secret> {
    vec![
        Secret {
            id: "github".into(),
            value: VAL_A.into(),
            hosts: vec!["api.github.com".into(), "uploads.github.com".into()],
            placeholder: PH_A.into(),
        },
        Secret {
            id: "npm".into(),
            value: VAL_B.into(),
            hosts: vec!["registry.npmjs.org".into()],
            placeholder: PH_B.into(),
        },
    ]
}

fn h(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
    pairs
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

fn out<'a>(
    host: &'a str,
    target: &'a str,
    hd: &'a [(String, String)],
    body: &'a [u8],
) -> Outbound<'a> {
    Outbound {
        connect_host: host,
        sni: Some(host),
        target,
        headers: hd,
        body,
    }
}

#[test]
fn with_no_secrets_a_request_is_forwarded_unchanged() {
    let hd = h(&[("accept", "*/*")]);
    assert_eq!(
        decide(&out("example.com", "/", &hd, b"x"), &[]),
        Verdict::Forward {
            headers: hd.clone(),
            body: b"x".to_vec()
        }
    );
}

#[test]
fn a_body_swap_recomputes_content_length_and_names_the_secret() {
    // A body swap needs the secret's placement to name the field (decision
    // 2, item 2; review W6C-S8); this test sets it.
    let body = format!("{{\"token\":\"{PH_A}\"}}");
    let hd = h(&[
        ("content-type", "application/json"),
        ("Content-Length", &body.len().to_string()),
    ]);
    let d = decide_with(
        &out("api.github.com", "/x", &hd, body.as_bytes()),
        &two(),
        &Policy {
            swap_body: vec![("github".into(), "token".into())],
            ..Policy::default()
        },
    );
    let want = format!("{{\"token\":\"{VAL_A}\"}}");
    match d.verdict {
        Verdict::Forward { headers, body } => {
            assert_eq!(body, want.as_bytes());
            assert_eq!(headers[1].1, want.len().to_string());
        }
        v => panic!("{v:?}"),
    }
    assert_eq!(d.injected, vec!["github".to_string()]);
}

#[test]
fn the_host_is_matched_case_blind_and_without_a_trailing_dot() {
    let hd = h(&[("authorization", &format!("token {PH_A}"))]);
    for host in ["API.GitHub.com", "api.github.com."] {
        match decide(&out(host, "/", &hd, b""), &two()) {
            Verdict::Forward { headers, .. } => assert_eq!(headers[0].1, format!("token {VAL_A}")),
            v => panic!("{host}: {v:?}"),
        }
    }
}

#[test]
fn a_subdomain_or_a_lookalike_of_the_secrets_host_is_another_host() {
    let hd = h(&[("authorization", &format!("Bearer {PH_A}"))]);
    for host in [
        "evil.api.github.com",
        "api.github.com.evil.test",
        "api-github.com",
    ] {
        assert!(
            matches!(
                decide(&out(host, "/", &hd, b""), &two()),
                Verdict::Block { .. }
            ),
            "{host}"
        );
    }
}

#[test]
fn one_secrets_placeholder_is_never_laundered_through_another_secrets_host() {
    // srt's rule (credential-sentinel.js:37-42), and derm blocks it too.
    let hd = h(&[("authorization", &format!("Bearer {PH_B}"))]);
    let d = decide_with(
        &out("api.github.com", "/", &hd, b""),
        &two(),
        &Policy::default(),
    );
    assert_eq!(
        d.blocked,
        Some(Blocked::Secret {
            id: "npm".into(),
            place: Place::Header,
            value: false
        })
    );
}

#[test]
fn the_value_is_found_encoded_on_another_host() {
    use base64::Engine;
    let b64 = base64::engine::general_purpose::STANDARD.encode(format!("user:{VAL_A}"));
    let hd = h(&[("authorization", &format!("Basic {b64}"))]);
    let d = decide_with(&out("evil.test", "/", &hd, b""), &two(), &Policy::default());
    assert!(matches!(
        d.blocked,
        Some(Blocked::Secret {
            value: true,
            place: Place::Header,
            ..
        })
    ));
    let pct = VAL_A.replace('-', "%2D");
    let d = decide_with(
        &out("evil.test", &format!("/?q={pct}"), &[], b""),
        &two(),
        &Policy::default(),
    );
    assert!(matches!(
        d.blocked,
        Some(Blocked::Secret {
            value: true,
            place: Place::Url,
            ..
        })
    ));
}

#[test]
fn a_record_reason_never_holds_the_value_or_the_placeholder() {
    let body = format!("{PH_A} {VAL_A}");
    let d = decide_with(
        &out("evil.test", "/", &[], body.as_bytes()),
        &two(),
        &Policy::default(),
    );
    let Verdict::Block { reason } = d.verdict else {
        panic!()
    };
    assert!(
        !reason.contains(VAL_A) && !reason.contains(PH_A),
        "{reason}"
    );
    assert!(reason.contains("github"));
}

#[test]
fn an_encoded_body_is_blocked_on_another_host_and_not_swapped_on_its_own() {
    let hd = h(&[("content-encoding", "gzip")]);
    let d = decide_with(
        &out("evil.test", "/", &hd, b"\x1f\x8b..."),
        &two(),
        &Policy::default(),
    );
    assert_eq!(d.blocked, Some(Blocked::EncodedBody));
    // An encoded body to its own host for every secret is not blocked, and
    // its bytes are not touched (the vendors' fail-safe direction).
    let one = vec![two().remove(0)];
    let body = format!("gz {PH_A}");
    match decide(&out("api.github.com", "/", &hd, body.as_bytes()), &one) {
        Verdict::Forward { body: b, .. } => assert_eq!(b, body.as_bytes()),
        v => panic!("{v:?}"),
    }
    // `identity`, and an empty body, are readable.
    let id = h(&[("content-encoding", "identity")]);
    assert!(decide_with(
        &out("evil.test", "/", &id, b"ok"),
        &two(),
        &Policy::default()
    )
    .blocked
    .is_none());
    assert!(
        decide_with(&out("evil.test", "/", &hd, b""), &two(), &Policy::default())
            .blocked
            .is_none()
    );
}

#[test]
fn a_signed_body_keeps_its_bytes_but_headers_are_still_swapped() {
    let body = format!("x={PH_A}");
    let hd = h(&[("x-amz-content-sha256", "abc"), ("authorization", PH_A)]);
    let one = vec![two().remove(0)];
    match decide(&out("api.github.com", "/", &hd, body.as_bytes()), &one) {
        Verdict::Forward { headers, body: b } => {
            assert_eq!(b, body.as_bytes());
            assert_eq!(headers[1].1, VAL_A);
        }
        v => panic!("{v:?}"),
    }
}

#[test]
fn the_allow_list_blocks_every_other_host() {
    let p = Policy {
        allow: Some(vec!["api.github.com".into()]),
        ..Policy::default()
    };
    assert!(
        decide_with(&out("api.github.com", "/", &[], b""), &two(), &p)
            .blocked
            .is_none()
    );
    assert_eq!(
        decide_with(&out("example.com", "/", &[], b""), &two(), &p).blocked,
        Some(Blocked::NotAllowed)
    );
}

#[test]
fn a_model_host_takes_a_placeholder_unchanged_but_never_the_value() {
    let p = Policy {
        model_hosts: vec!["api.anthropic.com".into()],
        ..Policy::default()
    };
    let body = format!("{{\"content\":\"the env holds {PH_A}\"}}");
    let d = decide_with(
        &out("api.anthropic.com", "/v1/messages", &[], body.as_bytes()),
        &two(),
        &p,
    );
    assert!(d.blocked.is_none() && d.placeholder_to_model);
    match d.verdict {
        Verdict::Forward { body: b, .. } => assert_eq!(b, body.as_bytes(), "not swapped"),
        v => panic!("{v:?}"),
    }
    let leak = format!("{{\"content\":\"{VAL_A}\"}}");
    let d = decide_with(
        &out("api.anthropic.com", "/v1/messages", &[], leak.as_bytes()),
        &two(),
        &p,
    );
    assert!(matches!(
        d.blocked,
        Some(Blocked::Secret { value: true, .. })
    ));
}

#[test]
fn placeholders_cannot_overlap_by_their_form() {
    // `dermsecret_<id>_<16 hex>`: the id holds no `_` and the hex has a fixed
    // length, so no placeholder is a substring of another (section 8.2).
    let ids = ["a", "ab", "a-b", "github", "github-2"];
    let hex = ["0123456789abcdef", "123456789abcdef0"];
    let all: Vec<String> = ids
        .iter()
        .flat_map(|i| hex.iter().map(move |x| format!("dermsecret_{i}_{x}")))
        .collect();
    for a in &all {
        for b in &all {
            if a != b {
                assert!(!a.contains(b.as_str()), "{a} holds {b}");
            }
        }
    }
}

#[test]
fn a_secret_prints_no_value_in_debug() {
    let s = format!("{:?}", two()[0]);
    assert!(!s.contains(VAL_A), "{s}");
}

#[test]
fn an_ip_literal_with_brackets_matches_its_sni_free_connect() {
    let o = Outbound {
        connect_host: "[::1]",
        sni: None,
        target: "/",
        headers: &[],
        body: b"",
    };
    assert!(decide_with(&o, &two(), &Policy::default())
        .blocked
        .is_none());
}

#[test]
fn a_host_header_or_absolute_target_naming_another_host_is_blocked() {
    let fronted = h(&[("host", "evil.test"), ("authorization", PH_A)]);
    let d = decide_with(
        &out("api.github.com", "/", &fronted, b""),
        &two(),
        &Policy::default(),
    );
    assert_eq!(d.blocked, Some(Blocked::HostMismatch));
    let d = decide_with(
        &out("api.github.com", "https://evil.test/x", &[], b""),
        &two(),
        &Policy::default(),
    );
    assert_eq!(d.blocked, Some(Blocked::HostMismatch));
    for ok in ["api.github.com", "API.github.com:443", "api.github.com."] {
        let hd = h(&[("host", ok)]);
        assert!(
            decide_with(
                &out("api.github.com", "/", &hd, b""),
                &two(),
                &Policy::default()
            )
            .blocked
            .is_none(),
            "{ok}"
        );
    }
    assert_eq!(authority_host("[::1]:8080"), "::1");
    assert_eq!(authority_host("user@a.test:1"), "a.test");
    assert_eq!(
        target_host("HTTP://A.test:80/p?q").as_deref(),
        Some("a.test")
    );
    assert_eq!(target_host("/p"), None);
}

// --- Decision 2 as Tony settled it (12 Nov 23:58 PST; integration w6's close)

/// Item 1: toward a model host a foreign placeholder passes in the body (the
/// conversation) only; in a header or the URL it is blocked.
#[test]
fn a_model_host_takes_a_foreign_placeholder_in_the_body_only() {
    let p = Policy {
        model_hosts: vec!["api.anthropic.com".into()],
        ..Policy::default()
    };
    let hd = h(&[("x-note", PH_A)]);
    let d = decide_with(
        &out("api.anthropic.com", "/v1/messages", &hd, b"{}"),
        &two(),
        &p,
    );
    assert_eq!(
        d.blocked,
        Some(Blocked::Secret {
            id: "github".into(),
            place: Place::Header,
            value: false
        })
    );
    let target = format!("/v1/messages?k={PH_A}");
    let d = decide_with(&out("api.anthropic.com", &target, &[], b"{}"), &two(), &p);
    assert_eq!(
        d.blocked,
        Some(Blocked::Secret {
            id: "github".into(),
            place: Place::Url,
            value: false
        })
    );
    // In the body it passes, recorded, and unchanged.
    let body = format!("{{\"content\":\"{PH_A}\"}}");
    let d = decide_with(
        &out("api.anthropic.com", "/v1/messages", &[], body.as_bytes()),
        &two(),
        &p,
    );
    assert!(d.blocked.is_none() && d.placeholder_to_model);
}

/// Item 2: the value goes into headers only, unless the secret's placement
/// names a body field or a query parameter (`Policy::swap_body`,
/// `swap_query`; `derm secret add --in body:<path>|query:<param>`). So a
/// placeholder that reached a body toward its own host (a model key's
/// placeholder in a transcript) leaves as the placeholder.
#[test]
fn a_secret_is_swapped_into_headers_only_unless_its_placement_names_the_body_or_the_query() {
    let one = vec![two().remove(0)];
    let auth = format!("token {PH_A}");
    let hd = h(&[
        ("authorization", &auth),
        ("content-type", "application/x-www-form-urlencoded"),
    ]);
    let body = format!("token={PH_A}");
    let d = decide_with(
        &out("api.github.com", "/x", &hd, body.as_bytes()),
        &one,
        &Policy::default(),
    );
    match &d.verdict {
        Verdict::Forward { headers, body: b } => {
            assert_eq!(headers[0].1, format!("token {VAL_A}"));
            assert_eq!(b, body.as_bytes(), "the body keeps the placeholder");
        }
        v => panic!("{v:?}"),
    }
    assert_eq!(d.injected, vec!["github".to_string()]);
    assert!(d.target.is_none());
    // With the field in its placement, the body is swapped too.
    let p = Policy {
        swap_body: vec![("github".into(), "token".into())],
        ..Policy::default()
    };
    match decide_with(&out("api.github.com", "/x", &hd, body.as_bytes()), &one, &p).verdict {
        Verdict::Forward { body: b, .. } => assert_eq!(b, format!("token={VAL_A}").as_bytes()),
        v => panic!("{v:?}"),
    }
    // The query: swapped only after `?`, and only into the parameter its
    // placement names; the path keeps a placeholder.
    let target = format!("/{PH_A}/x?t={PH_A}&a=1");
    assert!(decide_with(
        &out("api.github.com", &target, &[], b""),
        &one,
        &Policy::default()
    )
    .target
    .is_none());
    let q = Policy {
        swap_query: vec![("github".into(), "t".into())],
        ..Policy::default()
    };
    let d = decide_with(&out("api.github.com", &target, &[], b""), &one, &q);
    assert_eq!(d.target, Some(format!("/{PH_A}/x?t={VAL_A}&a=1")));
    assert_eq!(d.injected, vec!["github".to_string()]);
}

#[test]
fn a_host_with_userinfo_or_a_space_is_no_host_of_the_tunnel() {
    // Integration w6's review, W6C-S11: `Host: evil.test@api.github.com`
    // passed the host check, and the secret was swapped in.
    for bad in ["evil.test@api.github.com", "api.github.com evil.test"] {
        let hd = h(&[("host", bad)]);
        assert_eq!(
            decide_with(
                &out("api.github.com", "/", &hd, b""),
                &two(),
                &Policy::default()
            )
            .blocked,
            Some(Blocked::HostMismatch),
            "{bad}"
        );
    }
    let hd = h(&[("host", "api.github.com")]);
    assert_eq!(
        decide_with(
            &out("api.github.com", "https://u@api.github.com/x", &hd, b""),
            &two(),
            &Policy::default()
        )
        .blocked,
        Some(Blocked::HostMismatch)
    );
}

/// Review W6C-S8 (note BD): a swapped value is written for its place. Before
/// the fix the raw value went into the query and the body, and a value with
/// `&`, `=`, `"` or `\\` changed the request's structure (run first: the
/// query came out `t=a&b=c "d\\&a=1`).
#[test]
fn a_swapped_value_is_encoded_for_its_place() {
    let mut s = two().remove(0);
    s.value = "a&b=c \"d\\".into();
    let one = vec![s];
    let q = Policy {
        swap_query: vec![("github".into(), "t".into())],
        ..Policy::default()
    };
    let target = format!("/x?t={PH_A}&a=1");
    let d = decide_with(&out("api.github.com", &target, &[], b""), &one, &q);
    assert_eq!(d.target, Some("/x?t=a%26b%3Dc%20%22d%5C&a=1".to_string()));
    let b = Policy {
        swap_body: vec![("github".into(), "t".into())],
        ..Policy::default()
    };
    let hd = h(&[("content-type", "application/json; charset=utf-8")]);
    let body = format!("{{\"t\":\"{PH_A}\"}}");
    match decide_with(&out("api.github.com", "/x", &hd, body.as_bytes()), &one, &b).verdict {
        Verdict::Forward { body: got, .. } => {
            assert_eq!(
                String::from_utf8(got).unwrap(),
                "{\"t\":\"a&b=c \\\"d\\\\\"}"
            )
        }
        v => panic!("{v:?}"),
    }
    let hf = h(&[("content-type", "application/x-www-form-urlencoded")]);
    let form = format!("t={PH_A}&n=1");
    match decide_with(&out("api.github.com", "/x", &hf, form.as_bytes()), &one, &b).verdict {
        Verdict::Forward { body: got, .. } => {
            assert_eq!(got, b"t=a%26b%3Dc%20%22d%5C&n=1".to_vec())
        }
        v => panic!("{v:?}"),
    }
}

/// Review W6C-S8: the value goes only into the field its placement names. A
/// copy of the placeholder in any other field, in a key, in an escaped
/// spelling, or in a body that is not JSON or a form leaves every copy as the
/// fake: an agent cannot steer a token into a field the host publishes.
#[test]
fn a_placeholder_outside_the_named_field_is_never_swapped() {
    let one = vec![two().remove(0)];
    let b = Policy {
        swap_body: vec![("github".into(), "auth.token".into())],
        ..Policy::default()
    };
    let json = h(&[("content-type", "application/json")]);
    let kept = |hd: &[(String, String)], body: String| {
        let d = decide_with(&out("api.github.com", "/x", hd, body.as_bytes()), &one, &b);
        match d.verdict {
            Verdict::Forward { body: got, .. } => assert_eq!(got, body.as_bytes(), "{body}"),
            v => panic!("{v:?}"),
        }
        assert!(d.injected.is_empty(), "{body}");
    };
    kept(
        &json,
        format!("{{\"auth\":{{\"token\":\"{PH_A}\"}},\"issue\":\"{PH_A}\"}}"),
    );
    kept(&json, format!("{{\"issue\":\"{PH_A}\"}}"));
    kept(&json, format!("{{\"auth\":{{\"{PH_A}\":\"{PH_A}\"}}}}"));
    let escaped = PH_A.replacen('d', "\\u0064", 1);
    kept(&json, format!("{{\"auth\":{{\"token\":\"{escaped}\"}}}}"));
    kept(&json, format!("{{\"auth\":{{\"token\":\"{PH_A}\"}}"));
    kept(
        &h(&[("content-type", "text/plain")]),
        format!("auth.token={PH_A}"),
    );
    kept(&[], format!("{{\"auth\":{{\"token\":\"{PH_A}\"}}}}"));
    // The named field alone is swapped, at a nested path and an index.
    let p = Policy {
        swap_body: vec![("github".into(), "items[1].k".into())],
        ..Policy::default()
    };
    let body = format!("{{\"items\":[{{\"k\":\"x\"}},{{\"k\":\"Bearer {PH_A}\"}}]}}");
    match decide_with(
        &out("api.github.com", "/x", &json, body.as_bytes()),
        &one,
        &p,
    )
    .verdict
    {
        Verdict::Forward { body: got, .. } => assert_eq!(
            String::from_utf8(got).unwrap(),
            format!("{{\"items\":[{{\"k\":\"x\"}},{{\"k\":\"Bearer {VAL_A}\"}}]}}")
        ),
        v => panic!("{v:?}"),
    }
    // A query: another parameter, or a placeholder inside a longer value,
    // leaves it.
    let q = Policy {
        swap_query: vec![("github".into(), "key".into())],
        ..Policy::default()
    };
    for target in [
        format!("/x?key={PH_A}&note={PH_A}"),
        format!("/x?note={PH_A}"),
        format!("/x?key=pre{PH_A}"),
    ] {
        let d = decide_with(&out("api.github.com", &target, &[], b""), &one, &q);
        assert!(d.target.is_none(), "{target}");
    }
}

/// The re-review of the S8 fix (W6F-1, W6F-2, W6F-3): duplicate JSON keys
/// with an escaped copy at the path, a JSON body labelled as a form, two
/// `Content-Type` headers, a JSON string at the path holding more than the
/// placeholder, and a percent-encoded copy in another form field each left
/// the value in a field the placement does not name (the reviewer's probes,
/// run first against `726089a`).
#[test]
fn a_body_that_reads_two_ways_never_swaps() {
    let one = vec![two().remove(0)];
    let pol = |field: &str| Policy {
        swap_body: vec![("github".into(), field.into())],
        ..Policy::default()
    };
    let json = h(&[("content-type", "application/json")]);
    let form = h(&[("content-type", "application/x-www-form-urlencoded")]);
    let both = h(&[
        ("content-type", "application/x-www-form-urlencoded"),
        ("content-type", "application/json"),
    ]);
    let escaped = PH_A.replacen('d', "\\u0064", 1);
    let pct = PH_A.replacen('d', "%64", 1);
    let kept = |hd: &[(String, String)], field: &str, body: String| {
        let d = decide_with(
            &out("api.github.com", "/x", hd, body.as_bytes()),
            &one,
            &pol(field),
        );
        match d.verdict {
            Verdict::Forward { body: got, .. } => assert_eq!(got, body.as_bytes(), "{body}"),
            v => panic!("{v:?}"),
        }
        assert!(d.injected.is_empty(), "{body}");
    };
    kept(
        &json,
        "token",
        format!("{{\"public\":\"{PH_A}\",\"public\":\"x\",\"token\":\"{escaped}\"}}"),
    );
    kept(
        &json,
        "auth.token",
        format!("{{\"auth\":{{\"public\":\"{PH_A}\"}},\"auth\":{{\"token\":\"{escaped}\"}}}}"),
    );
    kept(
        &form,
        "token",
        format!("{{\"comment\":\"&token={PH_A}&\"}}"),
    );
    kept(&both, "token", format!("token={PH_A}"));
    kept(
        &json,
        "token",
        format!("{{\"token\":\"&publish={PH_A}&\"}}"),
    );
    kept(&form, "token", format!("token={PH_A}&note={pct}"));
    // The plain forms still swap.
    for (hd, field, body, want) in [
        (
            &json,
            "token",
            format!("{{\"token\":\"{PH_A}\"}}"),
            format!("{{\"token\":\"{VAL_A}\"}}"),
        ),
        (
            &json,
            "token",
            format!("{{\"token\":\"Bearer {PH_A}\"}}"),
            format!("{{\"token\":\"Bearer {VAL_A}\"}}"),
        ),
        (
            &form,
            "token",
            format!("token={PH_A}&n=1"),
            format!("token={VAL_A}&n=1"),
        ),
    ] {
        match decide_with(
            &out("api.github.com", "/x", hd, body.as_bytes()),
            &one,
            &pol(field),
        )
        .verdict
        {
            Verdict::Forward { body: got, .. } => assert_eq!(String::from_utf8(got).unwrap(), want),
            v => panic!("{v:?}"),
        }
    }
}

/// The re-review of the W6F fixes (W6G-3, W6G-4, W6G-5): a `%` escape that
/// is not two hex digits, a field name written with an escape, and a
/// `Content-Type` that names another charset or a list each left a copy of
/// the placeholder the counts did not see, or a field the host may name
/// differently.
#[test]
fn a_field_is_named_as_written_and_read_in_one_charset() {
    let one = vec![two().remove(0)];
    let body_pol = Policy {
        swap_body: vec![("github".into(), "token".into())],
        ..Policy::default()
    };
    let query_pol = Policy {
        swap_query: vec![("github".into(), "token".into())],
        ..Policy::default()
    };
    let form = h(&[("content-type", "application/x-www-form-urlencoded")]);
    let plus = PH_A.replacen('d', "%+d%65", 1).replacen("%65e", "%65", 1);
    let kept = |hd: &[(String, String)], body: String| {
        let d = decide_with(
            &out("api.github.com", "/x", hd, body.as_bytes()),
            &one,
            &body_pol,
        );
        match d.verdict {
            Verdict::Forward { body: got, .. } => assert_eq!(got, body.as_bytes(), "{body}"),
            v => panic!("{v:?}"),
        }
        assert!(d.injected.is_empty(), "{body}");
    };
    kept(&form, format!("token={PH_A}&note={plus}"));
    kept(&form, format!("%74oken={PH_A}"));
    kept(
        &h(&[("content-type", "application/json; charset=utf-16")]),
        format!("{{\"token\":\"{PH_A}\"}}"),
    );
    kept(
        &h(&[(
            "content-type",
            "application/json;, application/x-www-form-urlencoded",
        )]),
        format!("{{\"token\":\"{PH_A}\"}}"),
    );
    kept(
        &h(&[(
            "content-type",
            "application/x-www-form-urlencoded; charset=utf-7",
        )]),
        format!("token={PH_A}"),
    );
    for target in [
        format!("/x?%74oken={PH_A}"),
        format!("/x?token={PH_A}&n={plus}"),
    ] {
        let d = decide_with(&out("api.github.com", &target, &[], b""), &one, &query_pol);
        assert!(d.injected.is_empty(), "{target}");
    }
    // A utf-8 charset is still read.
    match decide_with(
        &out(
            "api.github.com",
            "/x",
            &h(&[("content-type", "application/json; charset=UTF-8")]),
            format!("{{\"token\":\"{PH_A}\"}}").as_bytes(),
        ),
        &one,
        &body_pol,
    )
    .verdict
    {
        Verdict::Forward { body, .. } => assert_eq!(
            String::from_utf8(body).unwrap(),
            format!("{{\"token\":\"{VAL_A}\"}}")
        ),
        v => panic!("{v:?}"),
    }
}
