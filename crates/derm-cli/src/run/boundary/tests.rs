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
    /// What [`Probe::gate`] answers, and how often it was asked.
    gate: bool,
    gate_asked: usize,
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
    fn gate(&mut self, _: &harness::Harness, _: Option<&str>) -> bool {
        self.gate_asked += 1;
        self.gate
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

#[test]
fn availability_answers_for_a_known_harness_only() {
    assert!(availability("no-such-agent").is_none());
    let [sbx, srt] = availability("goose").unwrap();
    // goose has no sbx kit, so sbx is never available for it here.
    assert!(sbx.unwrap_err().why.contains("no sbx kit"));
    // srt depends on this machine; whichever way, a reason names srt.
    if let Err(r) = srt {
        assert_eq!(r.boundary, "srt");
    }
}

// Phase 4, item 2: srt first for an agent whose derm gate is registered here
// and blocks when it fails (Tony's O1 decision, the interim half).

fn sbx_signed_out() -> Result<(), Reason> {
    no(
        "sbx",
        "sbx is installed and not signed in to Docker",
        Some("sbx login"),
    )
}

#[test]
fn a_gated_agent_gets_srt_first_and_sbx_is_not_probed() {
    let mut f = Fake {
        gate: true,
        srt: Some(Ok(())),
        // sbx left unset: probing it would panic.
        ..Fake::default()
    };
    let c = choose_with(&s(&["claude-code", "--", "-p", "x"]), &mut f).unwrap();
    assert_eq!(
        c.argv,
        s(&["claude-code", "--boundary", "srt", "--", "-p", "x"])
    );
    assert_eq!(f.probed, vec!["srt"], "sbx is not started when srt will do");
    let r = c.record.unwrap();
    assert_eq!(r["chosen"], "srt");
    assert_eq!(r["named"], false);
    assert_eq!(r["answeredBy"], "default");
    let reasons = r["reasons"].as_array().unwrap();
    assert_eq!(reasons.len(), 1);
    assert_eq!(reasons[0]["boundary"], "sbx");
    let why = reasons[0]["why"].as_str().unwrap();
    assert!(
        why.starts_with("not tried first: derm's gate for claude-code"),
        "{why}"
    );
    assert!(why.chars().count() <= 300);
    assert!(
        reasons[0].get("install").is_none(),
        "nothing is missing, so no install line"
    );
    assert_eq!(f.said.len(), 1);
    assert!(
        f.said[0].contains("runs under srt, which keeps derm's gate"),
        "{}",
        f.said[0]
    );
    assert!(
        f.said[0].contains("--boundary sbx still picks sbx"),
        "{}",
        f.said[0]
    );
}

#[test]
fn a_gated_agent_falls_back_to_sbx_and_is_told_the_gate_is_not_in_the_vm() {
    let mut f = Fake {
        gate: true,
        srt: Some(no(
            "srt",
            "srt is not installed (no srt on PATH)",
            Some("npm install -g @anthropic-ai/sandbox-runtime"),
        )),
        sbx: Some(Ok(())),
        ..Fake::default()
    };
    let c = choose_with(&s(&["claude-code"]), &mut f).unwrap();
    assert_eq!(c.argv, s(&["claude-code", "--boundary", "sbx"]));
    assert_eq!(f.probed, vec!["srt", "sbx"]);
    let r = c.record.unwrap();
    assert_eq!(r["chosen"], "sbx");
    assert_eq!(r["reasons"].as_array().unwrap().len(), 1);
    assert_eq!(r["reasons"][0]["boundary"], "srt");
    assert!(
        f.said[0]
            .contains("runs under sbx, without derm's gate in the VM (srt: srt is not installed"),
        "{}",
        f.said[0]
    );
}

#[test]
fn a_gated_agent_with_neither_warns_with_srt_then_sbx_and_still_asks_case_129() {
    let mut f = Fake {
        gate: true,
        srt: Some(no("srt", "srt is not installed (no srt on PATH)", None)),
        sbx: Some(sbx_signed_out()),
        terminal: true,
        answer: Some("no".into()),
        ..Fake::default()
    };
    let e = choose_with(&s(&["claude-code"]), &mut f).unwrap_err();
    assert_eq!(e.0, STOPPED);
    assert_eq!(f.probed, vec!["srt", "sbx"]);
    assert_eq!(f.asked.len(), 1);
    // The warning lists the reasons in the order they were tried.
    let srt_line = f.said.iter().position(|l| l.starts_with("  srt:")).unwrap();
    let sbx_line = f.said.iter().position(|l| l.starts_with("  sbx:")).unwrap();
    assert!(srt_line < sbx_line, "{:?}", f.said);
}

#[test]
fn an_agent_without_a_gate_that_holds_keeps_sbx_first() {
    let mut f = Fake {
        gate: false,
        sbx: Some(Ok(())),
        ..Fake::default()
    };
    let c = choose_with(&s(&["codex"]), &mut f).unwrap();
    assert_eq!(c.argv, s(&["codex", "--boundary", "sbx"]));
    assert_eq!(f.probed, vec!["sbx"]);
    assert_eq!(f.gate_asked, 1);
    assert!(c.record.unwrap()["reasons"].as_array().unwrap().is_empty());
}

#[test]
fn a_named_boundary_does_not_read_the_gate_d1() {
    for b in ["sbx", "srt", "none"] {
        let mut f = Fake {
            gate: true,
            ..Fake::default()
        };
        let argv = s(&["claude-code", "--boundary", b]);
        let c = choose_with(&argv, &mut f).unwrap();
        assert_eq!(c.argv, argv, "{b}");
        assert_eq!(f.gate_asked, 0, "{b}");
        assert!(f.probed.is_empty(), "{b}");
    }
}

#[test]
fn a_gated_agent_in_a_dry_run_is_described_in_the_same_order() {
    let mut f = Fake {
        gate: true,
        srt: Some(Ok(())),
        ..Fake::default()
    };
    let c = choose_with(&s(&["claude-code", "--dry-run"]), &mut f).unwrap();
    assert_eq!(
        c.argv,
        s(&["claude-code", "--boundary", "srt", "--dry-run"])
    );
    assert_eq!(f.probed, vec!["srt"]);
}
