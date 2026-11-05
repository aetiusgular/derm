//! `derm run`'s boundary choice (wave 5, lane T; `plans/toolkit_universal_plan.md`
//! lane T, rules cases 117, 118, 128, 129). `run_io` calls [`choose`] on the
//! raw argv before it is parsed, and adds the returned record to `run.start`
//! as `detail.boundaryChoice` (`contracts/events.md` section 5).
//!
//! With no `--boundary` on the command line:
//!
//! 1. sbx, when the harness has an sbx form, `sbx version` answers and
//!    `sbx ls` works (it fails with "not signed in to Docker" before
//!    `sbx login`, `plans/parallel/tk_sbx_smoke.md` step 1);
//! 2. else srt, when its dependencies pass `preflight::srt` and a probe,
//!    `srt --settings <file> -- true`, exits 0;
//! 3. else a warning that names why each one is unavailable and the line
//!    that would install it, and a question: run as you, or stop. Only a
//!    person at a terminal answers it (stdin and stderr both terminals);
//!    with no one there, derm stops, unless `~/.derm/settings.json` sets
//!    `boundary.preAnswer` (Tony, 4 Nov: "go with warn and allow them to
//!    select whether to go through with it or refuse/reject it").
//!
//! `--boundary none` on the command line skips the question and still warns.
//! The chosen `--boundary` goes into the argv `args::parse` reads, so lane
//! D's "required" check (`args.rs`) never sees a missing one.
//!
//! The question guards against a mistake, not an agent: any process with a
//! pty can answer it (case 89). The gate, the agents' user (lane V) and the
//! person check at the approver are what stand against an agent.

// `io_uring` and `sbx` are built here and called from `run_io` and
// `plan.rs` once integration applies requests T-2 and T-3 (those files are
// integration's in wave 5); until then only their tests call them.
#[cfg_attr(not(test), allow(dead_code))]
mod io_uring;
mod probe;
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) mod sbx;
mod settings;

#[allow(unused_imports)]
pub(crate) use io_uring::mark as io_uring_mark;

use serde_json::{json, Value};

use super::harness;

/// What the choice gives `run_io`: the argv to parse, and the record for
/// `run.start` when a choice was made.
#[derive(Debug, PartialEq)]
pub(crate) struct Choice {
    pub argv: Vec<String>,
    pub record: Option<Value>,
}

/// The exit code when no boundary is available and no one chose to run
/// without one: 2, the code `derm run` gave before wave 5 for a command line
/// with no `--boundary` (lane D's "required" check), so a script that read
/// it as "say which boundary" still does. The message says why.
pub(crate) const STOPPED: u8 = 2;

/// Why a boundary cannot be used for this chat, and the line that would
/// make it usable (the schema caps both at 300 characters).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Reason {
    pub boundary: &'static str,
    pub why: String,
    pub install: Option<String>,
}

impl Reason {
    fn record(&self) -> Value {
        let mut v = json!({"boundary": self.boundary, "why": cap(&self.why)});
        if let Some(i) = &self.install {
            v["install"] = json!(cap(i));
        }
        v
    }
}

/// `boundary.preAnswer` in the user's settings file.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PreAnswer {
    RunAsYou,
    Stop,
}

impl PreAnswer {
    fn name(self) -> &'static str {
        match self {
            PreAnswer::RunAsYou => "run-as-you",
            PreAnswer::Stop => "stop",
        }
    }
}

/// What the choice asks of the machine. [`probe::Real`] reads the process's
/// own environment; tests pass a fake.
pub(crate) trait Probe {
    /// `Ok` when sbx can run this harness now.
    fn sbx(&mut self, harness: &harness::Harness) -> Result<(), Reason>;
    /// `Ok` when srt starts a program here.
    fn srt(&mut self, harness: &harness::Harness, cwd: Option<&str>) -> Result<(), Reason>;
    /// A person can answer: stdin and stderr are terminals.
    fn terminal(&self) -> bool;
    /// Shows the question and reads one line; `None` at end of input.
    fn ask(&mut self, question: &str) -> Option<String>;
    /// The pre-answer and, when the file was there but not used, why.
    fn pre_answer(&mut self) -> (Option<PreAnswer>, Option<String>);
    /// Lines for the person (stderr in the real probe).
    fn say(&mut self, line: &str);
}

/// The real choice, against this process's environment.
pub(crate) fn choose(argv: &[String]) -> Result<Choice, (u8, String)> {
    choose_with(argv, &mut probe::Real::new())
}

/// What the raw argv says before `args::parse` reads it.
struct Shape<'a> {
    /// The harness, when the argv names one derm knows.
    harness: Option<&'static harness::Harness>,
    /// `--boundary <value>` before `--`, as written.
    named: Option<&'a str>,
    /// Where `--boundary` goes when derm adds it.
    insert_at: usize,
    cwd: Option<&'a str>,
    dry_run: bool,
}

fn shape(argv: &[String]) -> Shape<'_> {
    let by_argv = argv.first().is_some_and(|a| a.starts_with("--"));
    let mut s = Shape {
        harness: None,
        named: None,
        insert_at: if by_argv { 0 } else { 1 },
        cwd: None,
        dry_run: false,
    };
    let mut program = None;
    let mut i = if by_argv { 0 } else { 1 };
    while i < argv.len() {
        match argv[i].as_str() {
            "--" => {
                program = argv.get(i + 1).map(String::as_str);
                break;
            }
            // Options that take a value: their value is never an option of
            // ours (`--chat --boundary` names a chat, and `args::parse` says
            // what it thinks of that).
            "--boundary" => {
                s.named = argv.get(i + 1).map(String::as_str);
                i += 1;
            }
            "--cwd" => {
                s.cwd = argv.get(i + 1).map(String::as_str);
                i += 1;
            }
            "--chat" | "--gateway-url" | "--model-url" | "--allow-host" | "--kit" => i += 1,
            "--dry-run" => s.dry_run = true,
            _ => {}
        }
        i += 1;
    }
    s.harness = if by_argv {
        Some(
            program
                .and_then(harness::by_command)
                .unwrap_or(&harness::OTHER),
        )
    } else {
        argv.first().and_then(|id| harness::find(id))
    };
    s
}

pub(crate) fn choose_with(argv: &[String], probe: &mut dyn Probe) -> Result<Choice, (u8, String)> {
    let s = shape(argv);
    // An argv `args::parse` will refuse anyway (no harness, an unknown one,
    // a bad `--boundary` value) goes on unchanged, so its own error names
    // the problem, and nothing is probed for it.
    let Some(h) = s.harness else {
        return Ok(unchanged(argv));
    };
    if let Some(named) = s.named {
        return Ok(match named {
            "none" => {
                warn_none_named(h, probe);
                Choice {
                    argv: argv.to_vec(),
                    record: Some(record("none", true, &[], "flag", None)),
                }
            }
            "sbx" | "srt" => Choice {
                argv: argv.to_vec(),
                record: Some(record(named, true, &[], "flag", None)),
            },
            _ => unchanged(argv),
        });
    }

    let mut reasons = Vec::new();
    match probe.sbx(h) {
        Ok(()) => {
            probe.say(&format!(
                "derm run: no --boundary given; {} runs under sbx (installed and signed in)",
                name_of(h)
            ));
            return Ok(chosen(argv, &s, "sbx", reasons, "default", None));
        }
        Err(r) => reasons.push(r),
    }
    match probe.srt(h, s.cwd) {
        Ok(()) => {
            probe.say(&format!(
                "derm run: no --boundary given; {} runs under srt (sbx: {})",
                name_of(h),
                reasons[0].why
            ));
            return Ok(chosen(argv, &s, "srt", reasons, "default", None));
        }
        Err(r) => reasons.push(r),
    }

    // Neither: warn, then ask a person, or take the pre-answer, or stop.
    for line in warning(h, &reasons) {
        probe.say(&line);
    }
    if s.dry_run {
        // Nothing starts and nothing is recorded in a dry run; the plan is
        // described as the run without a boundary would be.
        probe.say("derm run: dry run: a real run would ask before running without a boundary");
        return Ok(chosen(argv, &s, "none", reasons, "no-one", None));
    }
    if probe.terminal() {
        let answer = probe.ask(&format!(
            "Run {} without a boundary, as you? Type yes to run; anything else stops: ",
            name_of(h)
        ));
        if answer.as_deref().map(str::trim).is_some_and(is_yes) {
            return Ok(chosen(argv, &s, "none", reasons, "terminal", None));
        }
        return Err((
            STOPPED,
            "stopped: no boundary, and the answer was not yes".into(),
        ));
    }
    let (pre, problem) = probe.pre_answer();
    if let Some(p) = problem {
        probe.say(&format!(
            "derm run: {p}; boundary.preAnswer counts as unset"
        ));
    }
    match pre {
        Some(PreAnswer::RunAsYou) => {
            probe.say(&format!(
                "derm run: no one is at a terminal; ~/.derm/settings.json pre-answers \"run-as-you\", so {} runs without a boundary",
                name_of(h)
            ));
            Ok(chosen(
                argv,
                &s,
                "none",
                reasons,
                "pre-answer",
                Some(PreAnswer::RunAsYou),
            ))
        }
        Some(PreAnswer::Stop) => Err((
            STOPPED,
            "stopped: no boundary, and ~/.derm/settings.json pre-answers \"stop\"".into(),
        )),
        None => Err((
            STOPPED,
            "stopped: no boundary, and no one is at a terminal to answer (stdin or stderr is not a terminal). \
             To run without one anyway, pass --boundary none, or set \"boundary\": {\"preAnswer\": \"run-as-you\"} in ~/.derm/settings.json"
                .into(),
        )),
    }
}

fn unchanged(argv: &[String]) -> Choice {
    Choice {
        argv: argv.to_vec(),
        record: None,
    }
}

fn chosen(
    argv: &[String],
    s: &Shape,
    boundary: &'static str,
    reasons: Vec<Reason>,
    answered_by: &'static str,
    pre: Option<PreAnswer>,
) -> Choice {
    let mut out = argv.to_vec();
    let at = s.insert_at.min(out.len());
    out.splice(at..at, ["--boundary".to_string(), boundary.to_string()]);
    Choice {
        argv: out,
        record: Some(record(boundary, false, &reasons, answered_by, pre)),
    }
}

/// `run.start`'s `boundaryChoice` (`contracts/wave5-records.schema.json`,
/// `$defs.runStartWave5`). `answeredBy: "default"` is an automatic pick with
/// no question; the schema gains it with this lane's request T-1.
fn record(
    chosen: &str,
    named: bool,
    reasons: &[Reason],
    answered_by: &str,
    pre: Option<PreAnswer>,
) -> Value {
    json!({
        "chosen": chosen,
        "named": named,
        "reasons": reasons.iter().map(Reason::record).collect::<Vec<_>>(),
        "answeredBy": answered_by,
        "preAnswer": pre.map(PreAnswer::name),
    })
}

fn is_yes(s: &str) -> bool {
    s.eq_ignore_ascii_case("yes") || s.eq_ignore_ascii_case("y")
}

fn name_of(h: &harness::Harness) -> &'static str {
    if h.id == "other" {
        "this program"
    } else {
        h.id
    }
}

/// The warning before the question (case 129).
fn warning(h: &harness::Harness, reasons: &[Reason]) -> Vec<String> {
    let mut lines = vec![format!(
        "derm run: no boundary is available for {}:",
        name_of(h)
    )];
    for r in reasons {
        lines.push(match &r.install {
            Some(i) => format!("  {}: {}. To use it: {}", r.boundary, r.why, i),
            None => format!("  {}: {}", r.boundary, r.why),
        });
    }
    lines.push(format!(
        "Without a boundary {} runs as you: your files, your logins, your network. Only its own gate and the OS feed watch it, and an agent can answer its own asks.",
        name_of(h)
    ));
    lines
}

/// `--boundary none` on the command line: no question, still a warning.
fn warn_none_named(h: &harness::Harness, probe: &mut dyn Probe) {
    probe.say(&format!(
        "derm run: --boundary none: {} runs as you, with no sandbox. Only its own gate and the OS feed watch it. \
         With no --boundary, derm picks sbx, then srt, and asks before it runs without either.",
        name_of(h)
    ));
}

/// At most 300 characters (the schema's `maxLength` for `why` and
/// `install`), cut on a character boundary.
fn cap(s: &str) -> String {
    if s.chars().count() <= 300 {
        return s.to_string();
    }
    let mut out: String = s.chars().take(299).collect();
    out.push('…');
    out
}

#[cfg(test)]
mod tests;
