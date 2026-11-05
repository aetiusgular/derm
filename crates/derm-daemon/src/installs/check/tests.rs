//! The pre-install check against registry replies recorded on 4 Nov 2026
//! and OSV replies in the shape osv.dev documents
//! (`contracts/fixtures/installs/registry/`).

use super::*;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

fn fixture(name: &str) -> Vec<u8> {
    let path = format!(
        "{}/../../contracts/fixtures/installs/registry/{name}",
        env!("CARGO_MANIFEST_DIR")
    );
    std::fs::read(path).unwrap()
}

/// Answers from the fixtures by URL; counts every request.
struct Fake {
    osv: Option<Vec<u8>>,
    calls: AtomicUsize,
    posted: Mutex<Vec<Value>>,
}

impl Fake {
    fn new(osv: Option<&str>) -> Fake {
        Fake {
            osv: osv.map(fixture),
            calls: AtomicUsize::new(0),
            posted: Mutex::new(Vec::new()),
        }
    }
}

impl Fetch for Fake {
    fn get(&self, url: &str) -> Result<Response, String> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let (status, file) = match url {
            "https://registry.npmjs.org/left-pad" => (200, "npm-left-pad.json"),
            "https://registry.npmjs.org/derm-made-up-name-x7q2z9" => (404, "npm-missing.json"),
            "https://pypi.org/pypi/six/json" => (200, "pypi-six.json"),
            "https://pypi.org/pypi/derm-made-up-name-x7q2z9/json" => (404, "pypi-missing.json"),
            "https://index.crates.io/it/oa/itoa" => (200, "crates-itoa.txt"),
            "https://proxy.golang.org/golang.org/x/text/@v/v0.20.0.info" => {
                (200, "go-text-v0.20.0.info")
            }
            "https://registry.npmjs.org/down" => return Err("connection refused".into()),
            "https://registry.npmjs.org/teapot" => {
                return Ok(Response {
                    status: 503,
                    body: Vec::new(),
                })
            }
            _ => {
                return Ok(Response {
                    status: 404,
                    body: b"{}".to_vec(),
                })
            }
        };
        Ok(Response {
            status,
            body: fixture(file),
        })
    }
    fn post_json(&self, url: &str, body: &[u8]) -> Result<Response, String> {
        assert_eq!(url, "https://api.osv.dev/v1/querybatch");
        self.posted
            .lock()
            .unwrap()
            .push(serde_json::from_slice(body).unwrap());
        match &self.osv {
            Some(b) => Ok(Response {
                status: 200,
                body: b.clone(),
            }),
            None => Err("connection refused".into()),
        }
    }
}

/// The same fake, kept by the test to read its counters.
impl Fetch for Arc<Fake> {
    fn get(&self, url: &str) -> Result<Response, String> {
        self.as_ref().get(url)
    }
    fn post_json(&self, url: &str, body: &[u8]) -> Result<Response, String> {
        self.as_ref().post_json(url, body)
    }
}

const ON: CheckSettings = CheckSettings {
    on: true,
    min_age_hours: 48,
};

fn q(eco: &str, name: &str, version: Option<&str>) -> Query {
    Query {
        ecosystem: eco.into(),
        name: name.into(),
        version: version.map(str::to_string),
    }
}

/// 4 Nov 2026, 20:00 UTC.
const NOW: i64 = 1_793_908_800_000;

#[test]
fn off_by_default_and_off_means_no_call() {
    assert_eq!(
        CheckSettings::default(),
        CheckSettings {
            on: false,
            min_age_hours: 48
        }
    );
    let fake = Fake::new(None);
    let check = PreInstall::new(Box::new(fake));
    let (ran, findings, verdict) = check.run(
        &[q("npm", "left-pad", None)],
        CheckSettings::default(),
        &[],
        NOW,
    );
    assert!(!ran);
    assert!(findings.is_empty());
    assert_eq!(verdict, Verdict::Nothing);
}

#[test]
fn a_made_up_name_is_denied_in_npm_and_pypi_case_130() {
    let check = PreInstall::new(Box::new(Fake::new(Some("osv-querybatch.json"))));
    for eco in ["npm", "PyPI"] {
        let (ran, findings, verdict) =
            check.run(&[q(eco, "derm-made-up-name-x7q2z9", None)], ON, &[], NOW);
        assert!(ran);
        assert_eq!(findings[0].exists, Some(false), "{eco}");
        assert_eq!(
            verdict,
            Verdict::Deny(
                "pre-install check: derm-made-up-name-x7q2z9: not in the registry".into()
            ),
            "{eco}"
        );
        assert_eq!(findings[0].to_json()["exists"], json!(false));
    }
}

#[test]
fn a_go_module_the_proxy_lacks_asks_and_is_not_denied() {
    let check = PreInstall::new(Box::new(Fake::new(Some("osv-querybatch.json"))));
    let (_, _, verdict) = check.run(
        &[q("Go", "example.com/private/thing", Some("v1.0.0"))],
        ON,
        &[],
        NOW,
    );
    match verdict {
        Verdict::Ask(r) => assert!(r.contains("not on proxy.golang.org"), "{r}"),
        v => panic!("{v:?}"),
    }
}

#[test]
fn an_old_existing_version_adds_nothing_and_reads_its_age() {
    // left-pad 1.3.0's time in the packument is 2018-04-09; six 1.17.0's upload 2024-12-04.
    let osv_clean = PreInstall::new(Box::new(Fake {
        osv: Some(br#"{"results":[{},{}]}"#.to_vec()),
        calls: AtomicUsize::new(0),
        posted: Mutex::new(Vec::new()),
    }));
    let (_, findings, verdict) = osv_clean.run(
        &[q("npm", "left-pad", Some("1.3.0")), q("PyPI", "six", None)],
        ON,
        &[],
        NOW,
    );
    assert_eq!(verdict, Verdict::Nothing);
    assert_eq!(findings[0].version.as_deref(), Some("1.3.0"));
    assert_eq!(
        findings[1].version.as_deref(),
        Some("1.17.0"),
        "no version is the latest"
    );
    assert!(findings[0].age_hours.unwrap() > 24.0 * 365.0 * 8.0);
}

#[test]
fn a_young_version_asks_case_134s_name_and_version_check() {
    let check = PreInstall::new(Box::new(Fake {
        osv: Some(br#"{"results":[{}]}"#.to_vec()),
        calls: AtomicUsize::new(0),
        posted: Mutex::new(Vec::new()),
    }));
    // six 1.17.0 was uploaded 2024-12-04T17:35:26.475808Z: ten hours later it is young.
    let now = parse_time_ms("2024-12-05T03:35:26Z").unwrap();
    let (_, findings, verdict) = check.run(&[q("PyPI", "six", Some("1.17.0"))], ON, &[], now);
    assert!((findings[0].age_hours.unwrap() - 10.0).abs() < 0.01);
    assert_eq!(
        verdict,
        Verdict::Ask(
            "pre-install check: six 1.17.0: published 9 hours ago, under the 48-hour minimum"
                .into()
        )
    );
    // With the minimum at 0 it adds nothing.
    let (_, _, v0) = check.run(
        &[q("PyPI", "six", Some("1.17.0"))],
        CheckSettings {
            on: true,
            min_age_hours: 0,
        },
        &[],
        now,
    );
    assert_eq!(v0, Verdict::Nothing);
}

#[test]
fn osv_malicious_denies_and_other_records_ask() {
    let fake = Fake::new(Some("osv-querybatch.json"));
    let check = PreInstall::new(Box::new(fake));
    let qs = [
        q("npm", "left-pad", Some("1.3.0")),
        q("PyPI", "six", Some("1.16.0")),
        q("crates.io", "itoa", Some("1.0.14")),
    ];
    let (_, findings, verdict) = check.run(&qs, ON, &[], NOW);
    assert_eq!(findings[0].osv, vec!["MAL-2026-0001".to_string()]);
    assert_eq!(findings[1].osv.len(), 2);
    assert!(findings[2].osv.is_empty());
    match verdict {
        Verdict::Deny(r) => {
            assert!(
                r.contains("left-pad 1.3.0: known malicious (MAL-2026-0001)"),
                "{r}"
            );
            assert!(
                r.contains("six 1.16.0: known advisories (GHSA-aaaa-bbbb-cccc, CVE-2026-0002)"),
                "{r}"
            );
        }
        v => panic!("{v:?}"),
    }
}

#[test]
fn osv_is_asked_once_with_name_ecosystem_and_exact_version_only() {
    let fake = Arc::new(Fake::new(Some("osv-querybatch.json")));
    let check = PreInstall::new(Box::new(fake.clone()));
    let qs = [
        q("npm", "left-pad", Some("^1.2.0")),
        q("npm", "left-pad", Some("1.3.0")),
        q("Go", "golang.org/x/text", Some("v0.20.0")),
    ];
    let _ = check.run(&qs, ON, &[], NOW);
    let posted = fake.posted.lock().unwrap().clone();
    assert_eq!(posted.len(), 1);
    assert_eq!(
        posted[0],
        json!({"queries": [
            {"package": {"name": "left-pad", "ecosystem": "npm"}, "version": "1.3.0"},
            {"package": {"name": "golang.org/x/text", "ecosystem": "Go"}, "version": "0.20.0"},
        ]})
    );
}

#[test]
fn a_range_names_no_version_and_a_missing_version_asks() {
    let check = PreInstall::new(Box::new(Fake {
        osv: Some(br#"{"results":[]}"#.to_vec()),
        calls: AtomicUsize::new(0),
        posted: Mutex::new(Vec::new()),
    }));
    let (_, f, v) = check.run(&[q("npm", "left-pad", Some("^1.2.0"))], ON, &[], NOW);
    assert_eq!(
        (f[0].exists, f[0].version.clone(), v),
        (Some(true), None, Verdict::Nothing)
    );
    let (_, _, v) = check.run(&[q("npm", "left-pad", Some("9.9.9"))], ON, &[], NOW);
    assert_eq!(
        v,
        Verdict::Ask(
            "pre-install check: left-pad 9.9.9: that version is not in the registry".into()
        )
    );
    let (_, f, _) = check.run(&[q("npm", "left-pad", Some("latest"))], ON, &[], NOW);
    assert_eq!(
        f[0].version.as_deref(),
        Some("1.3.0"),
        "a dist-tag names its version"
    );
    let (_, f, _) = check.run(&[q("crates.io", "itoa", None)], ON, &[], NOW);
    assert_eq!(f[0].version.as_deref(), Some("1.0.18"));
    assert!(f[0].age_hours.is_some(), "the index's pubtime");
}

#[test]
fn no_answer_asks_and_is_not_cached() {
    let fake = Fake::new(Some("osv-querybatch.json"));
    let check = PreInstall::new(Box::new(fake));
    for name in ["down", "teapot"] {
        let (_, f, v) = check.run(&[q("npm", name, None)], ON, &[], NOW);
        assert_eq!(f[0].exists, None);
        assert!(matches!(v, Verdict::Ask(_)), "{name}: {v:?}");
    }
}

#[test]
fn osv_down_adds_a_note_and_keeps_the_registry_findings() {
    let check = PreInstall::new(Box::new(Fake::new(None)));
    let (_, findings, verdict) = check.run(
        &[
            q("npm", "derm-made-up-name-x7q2z9", None),
            q("npm", "left-pad", Some("1.3.0")),
        ],
        ON,
        &[],
        NOW,
    );
    assert_eq!(findings[0].exists, Some(false));
    match verdict {
        Verdict::Deny(r) => assert!(
            r.contains("not in the registry") && r.contains("OSV did not answer"),
            "{r}"
        ),
        v => panic!("{v:?}"),
    }
}

#[test]
fn registry_answers_are_cached_for_an_hour() {
    let fake = Arc::new(Fake::new(Some("osv-querybatch.json")));
    let check = PreInstall::new(Box::new(fake.clone()));
    let qs = [q("PyPI", "six", Some("1.17.0"))];
    let _ = check.run(&qs, ON, &[], NOW);
    let _ = check.run(&qs, ON, &[], NOW + 59 * 60 * 1000);
    assert_eq!(fake.calls.load(Ordering::SeqCst), 1);
    let _ = check.run(&qs, ON, &[], NOW + 61 * 60 * 1000);
    assert_eq!(fake.calls.load(Ordering::SeqCst), 2);
}

#[test]
fn a_skipped_ecosystem_makes_no_call_and_says_why() {
    let fake = Arc::new(Fake::new(Some("osv-querybatch.json")));
    let check = PreInstall::new(Box::new(fake.clone()));
    let (_, _, v) = check.run(&[q("npm", "left-pad", None)], ON, &["npm"], NOW);
    assert_eq!(fake.calls.load(Ordering::SeqCst), 0);
    assert_eq!(v, Verdict::Ask("pre-install check: left-pad: the project names its own registry, so the check did not run".into()));
}

#[test]
fn urls_take_only_names_in_the_registrys_grammar() {
    assert_eq!(
        registry_url(&q("npm", "@types/node", None)).as_deref(),
        Some("https://registry.npmjs.org/@types%2fnode")
    );
    assert_eq!(
        registry_url(&q("crates.io", "a", None)).as_deref(),
        Some("https://index.crates.io/1/a")
    );
    assert_eq!(
        registry_url(&q("crates.io", "io", None)).as_deref(),
        Some("https://index.crates.io/2/io")
    );
    assert_eq!(
        registry_url(&q("crates.io", "ser", None)).as_deref(),
        Some("https://index.crates.io/3/s/ser")
    );
    assert_eq!(
        registry_url(&q("crates.io", "cargo", None)).as_deref(),
        Some("https://index.crates.io/ca/rg/cargo")
    );
    assert_eq!(
        registry_url(&q("Go", "golang.org/x/text", None)).as_deref(),
        Some("https://proxy.golang.org/golang.org/x/text/@latest")
    );
    for bad in ["../etc", "a?b", "a/b", "a b", "a#b", "", "x%2f"] {
        assert_eq!(registry_url(&q("npm", bad, None)), None, "{bad}");
        assert_eq!(registry_url(&q("PyPI", bad, None)), None, "{bad}");
    }
    assert_eq!(
        registry_url(&q("Go", "golang.org/x/text", Some("v1/../../x"))),
        None
    );
    assert_eq!(registry_url(&q("Go", "nodot/x", None)), None);
    assert_eq!(
        go_escape("github.com/BurntSushi/toml"),
        "github.com/!burnt!sushi/toml"
    );
}

#[test]
fn times_parse_as_the_registries_write_them() {
    assert_eq!(parse_time_ms("1970-01-01T00:00:00Z"), Some(0));
    assert_eq!(
        parse_time_ms("2024-12-04T17:35:26.475808Z"),
        Some(1_733_333_726_475)
    );
    assert_eq!(
        parse_time_ms("2026-03-20T00:12:37Z"),
        Some(1_773_965_557_000)
    );
    assert_eq!(
        parse_time_ms("2026-03-20T02:12:37+02:00"),
        Some(1_773_965_557_000)
    );
    for bad in [
        "",
        "2026-13-01T00:00:00Z",
        "yesterday",
        "2026-03-20 00:12:37",
        "2026-03-20T00:12:37",
    ] {
        assert_eq!(parse_time_ms(bad), None, "{bad}");
    }
}

#[test]
fn settings_follow_the_schema_and_a_bad_file_keeps_the_check_off() {
    assert_eq!(
        parse_settings(r#"{"version":1}"#),
        Ok(CheckSettings::default())
    );
    assert_eq!(
        parse_settings(r#"{"version":1,"installs":{"check":true,"minAgeHours":0}}"#),
        Ok(CheckSettings {
            on: true,
            min_age_hours: 0
        })
    );
    for bad in [
        r#"{"version":1,"installs":{"check":"yes"}}"#,
        r#"{"version":1,"installs":{"minAgeHours":9000}}"#,
        r#"{"version":1,"installs":{"other":1}}"#,
        r#"{"version":1,"other":{}}"#,
        r#"{"installs":{"check":true}}"#,
        "not json",
    ] {
        assert!(parse_settings(bad).is_err(), "{bad}");
    }
    let dir = std::env::temp_dir().join(format!("derm-x-settings-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let file = dir.join("settings.json");
    assert_eq!(
        load_settings(&file),
        (CheckSettings::default(), None),
        "no file: defaults, no warning"
    );
    std::fs::write(&file, r#"{"version":1,"installs":{"check":true}}"#).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(load_settings(&file).0.on);
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o666)).unwrap();
        let (s, warn) = load_settings(&file);
        assert!(
            !s.on && warn.is_some(),
            "a file others can write is not read"
        );
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).unwrap();
        let link = dir.join("link.json");
        std::os::unix::fs::symlink(&file, &link).unwrap();
        assert!(!load_settings(&link).0.on, "a link is not followed");
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn registry_override_reads_npmrc_python_and_cargo_config() {
    let root = std::env::temp_dir().join(format!("derm-x-reg-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let project = root.join("p/web");
    std::fs::create_dir_all(&project).unwrap();
    let home = root.join("home");
    std::fs::create_dir_all(&home).unwrap();
    assert!(!registry_override("npm", &project, Some(&home)));
    std::fs::write(
        root.join("p/.npmrc"),
        "# registry=https://x\nsave-exact=true\n",
    )
    .unwrap();
    assert!(
        !registry_override("npm", &project, Some(&home)),
        "a comment names nothing"
    );
    std::fs::write(
        home.join(".npmrc"),
        "@corp:registry=https://npm.corp.example\n",
    )
    .unwrap();
    assert!(registry_override("npm", &project, Some(&home)));
    assert!(!registry_override("PyPI", &project, Some(&home)));
    std::fs::write(
        project.join("pyproject.toml"),
        "[project]\nname='x'\n[[tool.uv.index]]\nurl='https://pypi.corp.example/simple'\n",
    )
    .unwrap();
    assert!(registry_override("PyPI", &project, Some(&home)));
    std::fs::create_dir_all(root.join("p/.cargo")).unwrap();
    std::fs::write(
        root.join("p/.cargo/config.toml"),
        "[source.crates-io]\nreplace-with = 'vendored'\n",
    )
    .unwrap();
    assert!(registry_override("crates.io", &project, Some(&home)));
    assert!(!registry_override("Go", &project, Some(&home)));
    let _ = std::fs::remove_dir_all(&root);
}
