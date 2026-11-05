//! The choice against a fake machine (cases 118 and 129).

use super::*;

fn s(v: &[&str]) -> Vec<String> {
    v.iter().map(|x| x.to_string()).collect()
}

/// A machine with what the test says is there, and a log of what was asked.
#[derive(Default)]
struct Fake {
    sbx: Option<Result<(), Reason>>,
    srt: Option<Result<(), Reason>>,
    terminal: bool,
    answer: Option<String>,
    pre: Option<PreAnswer>,
    pre_problem: Option<String>,
    asked: Vec<String>,
    said: Vec<String>,
    probed: Vec<&'static str>,
}

fn no(boundary: &'static str, why: &str, install: Option<&str>) -> Result<(), Reason> {
    Err(Reason {
        boundary,
        why: why.into(),
        install: install.map(str::to_string),
    })
}

impl Probe for Fake {
    fn sbx(&mut self, _: &harness::Harness) -> Result<(), Reason> {
        self.probed.push("sbx");
        self.sbx
            .clone()
            .expect("sbx probed but the test set no answer")
    }
    fn srt(&mut self, _: &harness::Harness, _: Option<&str>) -> Result<(), Reason> {
        self.probed.push("srt");
        self.srt
            .clone()
            .expect("srt probed but the test set no answer")
    }
    fn terminal(&self) -> bool {
        self.terminal
    }
    fn ask(&mut self, q: &str) -> Option<String> {
        self.asked.push(q.to_string());
        self.answer.clone()
    }
    fn pre_answer(&mut self) -> (Option<PreAnswer>, Option<String>) {
        (self.pre, self.pre_problem.clone())
    }
    fn say(&mut self, line: &str) {
        self.said.push(line.to_string());
    }
}

fn neither() -> Fake {
    Fake {
        sbx: Some(no(
            "sbx",
            "sbx is installed and not signed in to Docker",
            Some("sbx login"),
        )),
        srt: Some(no(
            "srt",
            "srt is not installed (no srt on PATH)",
            Some("npm install -g @anthropic-ai/sandbox-runtime"),
        )),
        ..Fake::default()
    }
}

#[test]
fn a_named_boundary_is_kept_and_nothing_is_probed() {
    for b in ["sbx", "srt"] {
        let mut f = Fake::default();
        let argv = s(&["pi", "--boundary", b, "--", "-p", "x"]);
        let c = choose_with(&argv, &mut f).unwrap();
        assert_eq!(c.argv, argv);
        assert_eq!(
            c.record.unwrap(),
            json!({"chosen": b, "named": true, "reasons": [], "answeredBy": "flag", "preAnswer": null})
        );
        assert!(f.probed.is_empty() && f.said.is_empty());
    }
}

#[test]
fn none_named_skips_the_question_and_still_warns() {
    let mut f = Fake::default();
    let argv = s(&["claude-code", "--boundary", "none"]);
    let c = choose_with(&argv, &mut f).unwrap();
    assert_eq!(c.argv, argv);
    assert_eq!(c.record.unwrap()["answeredBy"], "flag");
    assert!(f.probed.is_empty() && f.asked.is_empty());
    assert_eq!(f.said.len(), 1);
    assert!(f.said[0].contains("runs as you"), "{}", f.said[0]);
}

#[test]
fn sbx_first_when_it_can_run() {
    let mut f = Fake {
        sbx: Some(Ok(())),
        ..Fake::default()
    };
    let c = choose_with(&s(&["pi", "--", "-p", "x"]), &mut f).unwrap();
    assert_eq!(c.argv, s(&["pi", "--boundary", "sbx", "--", "-p", "x"]));
    assert_eq!(
        c.record.unwrap(),
        json!({"chosen": "sbx", "named": false, "reasons": [], "answeredBy": "default", "preAnswer": null})
    );
    assert_eq!(f.probed, vec!["sbx"], "srt is not probed when sbx will do");
}

#[test]
fn srt_when_sbx_is_signed_out_case_118() {
    let mut f = Fake {
        sbx: Some(no(
            "sbx",
            "sbx is installed and not signed in to Docker",
            Some("sbx login"),
        )),
        srt: Some(Ok(())),
        ..Fake::default()
    };
    let c = choose_with(&s(&["codex"]), &mut f).unwrap();
    assert_eq!(c.argv, s(&["codex", "--boundary", "srt"]));
    let r = c.record.unwrap();
    assert_eq!(r["chosen"], "srt");
    assert_eq!(r["answeredBy"], "default");
    assert_eq!(
        r["reasons"],
        json!([{"boundary": "sbx", "why": "sbx is installed and not signed in to Docker", "install": "sbx login"}])
    );
    assert!(
        f.said[0].contains("not signed in"),
        "the note says why not sbx"
    );
}

#[test]
fn neither_warns_names_each_reason_and_asks_a_person() {
    let mut f = Fake {
        terminal: true,
        answer: Some(" Yes \n".into()),
        ..neither()
    };
    let c = choose_with(&s(&["pi"]), &mut f).unwrap();
    assert_eq!(c.argv, s(&["pi", "--boundary", "none"]));
    let r = c.record.unwrap();
    assert_eq!(r["chosen"], "none");
    assert_eq!(r["named"], false);
    assert_eq!(r["answeredBy"], "terminal");
    assert_eq!(r["reasons"].as_array().unwrap().len(), 2);
    let said = f.said.join("\n");
    assert!(
        said.contains("sbx: sbx is installed and not signed in to Docker. To use it: sbx login")
    );
    assert!(said.contains("srt: srt is not installed"), "{said}");
    assert!(said.contains("npm install -g @anthropic-ai/sandbox-runtime"));
    assert!(said.contains("runs as you"));
    assert_eq!(f.asked.len(), 1);
}

#[test]
fn anything_but_yes_stops() {
    for answer in [Some("no"), Some(""), Some("run"), Some("yess"), None] {
        let mut f = Fake {
            terminal: true,
            answer: answer.map(str::to_string),
            // A pre-answer is for when no one is there; a person's answer
            // wins over it.
            pre: Some(PreAnswer::RunAsYou),
            ..neither()
        };
        let (code, msg) = choose_with(&s(&["pi"]), &mut f).unwrap_err();
        assert_eq!(code, STOPPED, "{answer:?}");
        assert!(msg.contains("stopped"), "{msg}");
    }
}

#[test]
fn no_one_to_answer_stops_unless_pre_answered_case_129() {
    // A script, a scheduled run, derm acp: no terminal.
    let mut f = neither();
    let (code, msg) = choose_with(&s(&["pi"]), &mut f).unwrap_err();
    assert_eq!(code, STOPPED);
    assert!(
        msg.contains("--boundary none") && msg.contains("preAnswer"),
        "{msg}"
    );
    assert!(f.asked.is_empty(), "no question with no one there");
    assert!(
        f.said.join("\n").contains("srt is not installed"),
        "the warning still names why"
    );

    let mut f = Fake {
        pre: Some(PreAnswer::RunAsYou),
        ..neither()
    };
    let c = choose_with(&s(&["pi"]), &mut f).unwrap();
    assert_eq!(c.argv, s(&["pi", "--boundary", "none"]));
    let r = c.record.unwrap();
    assert_eq!(r["answeredBy"], "pre-answer");
    assert_eq!(r["preAnswer"], "run-as-you");
    assert!(f.said.iter().any(|l| l.contains("pre-answers")));

    let mut f = Fake {
        pre: Some(PreAnswer::Stop),
        ..neither()
    };
    let (code, msg) = choose_with(&s(&["pi"]), &mut f).unwrap_err();
    assert_eq!(code, STOPPED);
    assert!(msg.contains("pre-answers \"stop\""), "{msg}");

    // A settings file derm could not use counts as unset, and says why.
    let mut f = Fake {
        pre: None,
        pre_problem: Some("~/.derm/settings.json is not a regular file of yours".into()),
        ..neither()
    };
    assert_eq!(choose_with(&s(&["pi"]), &mut f).unwrap_err().0, STOPPED);
    assert!(f.said.iter().any(|l| l.contains("counts as unset")));
}

#[test]
fn a_program_after_the_separator_gets_its_boundary_before_it() {
    let mut f = Fake {
        sbx: Some(no("sbx", "derm knows no sbx kit for this program", None)),
        srt: Some(Ok(())),
        ..Fake::default()
    };
    let c = choose_with(&s(&["--chat", "c1", "--", "aider", "--yes"]), &mut f).unwrap();
    assert_eq!(
        c.argv,
        s(&["--boundary", "srt", "--chat", "c1", "--", "aider", "--yes"])
    );
    // What follows `--` is the harness's: a `--boundary` there is its word.
    let mut f = Fake {
        sbx: Some(Ok(())),
        ..Fake::default()
    };
    let c = choose_with(&s(&["pi", "--", "--boundary", "none"]), &mut f).unwrap();
    assert_eq!(
        c.argv,
        s(&["pi", "--boundary", "sbx", "--", "--boundary", "none"])
    );
    assert_eq!(c.record.unwrap()["named"], false);
}

#[test]
fn an_argv_parse_will_refuse_goes_on_unprobed() {
    for argv in [
        s(&[]),
        s(&["no-such-agent"]),
        s(&["pi", "--boundary", "docker"]),
    ] {
        let mut f = Fake::default();
        let c = choose_with(&argv, &mut f).unwrap();
        assert_eq!(c.argv, argv);
        assert!(f.probed.is_empty(), "{argv:?}");
        if argv.len() == 3 && argv[1] == "--boundary" {
            assert_eq!(c.record, None);
        }
    }
    // An option's value is not read as `--boundary`: `--chat --boundary`
    // names a chat, and no boundary was given.
    let mut f = Fake {
        sbx: Some(Ok(())),
        ..Fake::default()
    };
    let c = choose_with(&s(&["pi", "--chat", "--boundary"]), &mut f).unwrap();
    assert_eq!(
        c.argv,
        s(&["pi", "--boundary", "sbx", "--chat", "--boundary"])
    );
}

#[test]
fn a_dry_run_never_asks() {
    let mut f = Fake {
        terminal: true,
        answer: Some("yes".into()),
        ..neither()
    };
    let c = choose_with(&s(&["pi", "--dry-run"]), &mut f).unwrap();
    assert_eq!(c.argv, s(&["pi", "--boundary", "none", "--dry-run"]));
    assert!(f.asked.is_empty());
    assert_eq!(c.record.unwrap()["answeredBy"], "no-one");
}

#[test]
fn reasons_are_capped_for_the_record() {
    let long = "x".repeat(400);
    let r = Reason {
        boundary: "srt",
        why: long.clone(),
        install: Some(long),
    }
    .record();
    assert_eq!(r["why"].as_str().unwrap().chars().count(), 300);
    assert_eq!(r["install"].as_str().unwrap().chars().count(), 300);
}

#[test]
fn every_record_follows_the_schema() {
    // The contract (`contracts/wave5-records.schema.json`,
    // `runStartWave5.boundaryChoice`) with request T-1's `default`: the keys,
    // the enums and no other key.
    let schema: Value = serde_json::from_str(include_str!(
        "../../../../../contracts/wave5-records.schema.json"
    ))
    .unwrap();
    let bc = &schema["$defs"]["runStartWave5"]["properties"]["boundaryChoice"];
    let keys: Vec<&str> = bc["properties"]
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    let mut answered: Vec<String> = bc["properties"]["answeredBy"]["enum"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect();
    // Request T-1 adds it; until integration applies it the test adds it.
    if !answered.iter().any(|a| a == "default") {
        answered.push("default".into());
    }
    let cases = [
        record("sbx", false, &[], "default", None),
        record("none", true, &[], "flag", None),
        record(
            "none",
            false,
            &[Reason {
                boundary: "sbx",
                why: "w".into(),
                install: None,
            }],
            "pre-answer",
            Some(PreAnswer::RunAsYou),
        ),
        record("none", false, &[], "terminal", None),
        record("none", false, &[], "no-one", None),
    ];
    for r in cases {
        for k in r.as_object().unwrap().keys() {
            assert!(keys.contains(&k.as_str()), "{k}");
        }
        assert!(answered.contains(&r["answeredBy"].as_str().unwrap().to_string()));
        for reason in r["reasons"].as_array().unwrap() {
            for k in reason.as_object().unwrap().keys() {
                assert!(["boundary", "why", "install"].contains(&k.as_str()));
            }
        }
    }
}
