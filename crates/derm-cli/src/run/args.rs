//! `derm run <harness> --boundary sbx|srt|none [options] [-- harness args]`,
//! or `derm run --boundary sbx|srt|none [options] -- <program> [args]` for a
//! command line derm has no preset for (rules case 80; toolkit plan T2.9).
//! A program whose name is a preset's command (`claude`, `codex`) is that
//! harness; any other is `other`, with the outside shape only.
//!
//! Every value is taken literally; nothing is split or expanded. The
//! harness's own arguments go after `--` and reach it as separate argv
//! items (rules section 5, item 3).

use super::harness::{self, Harness};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Boundary {
    Sbx,
    Srt,
    None,
}

impl Boundary {
    pub fn name(self) -> &'static str {
        match self {
            Boundary::Sbx => "sbx",
            Boundary::Srt => "srt",
            Boundary::None => "none",
        }
    }
}

#[derive(Debug)]
pub struct Args {
    pub harness: &'static Harness,
    pub boundary: Boundary,
    pub chat: Option<String>,
    pub cwd: Option<String>,
    pub gateway_url: Option<String>,
    pub model_url: Option<String>,
    pub allow_hosts: Vec<String>,
    pub kit: Option<String>,
    pub no_daemon: bool,
    /// `--no-tap`: this chat runs untapped (case 127); its gate and the OS
    /// feed still record it.
    pub no_tap: bool,
    pub dry_run: bool,
    pub rest: Vec<String>,
    /// The program from `-- <program> ...` (case 80), when no harness id was
    /// given. `None` means the harness's own command.
    pub program: Option<String>,
}

pub const USAGE: &str =
    "usage: derm run <harness> --boundary sbx|srt|none [--chat ID] [--cwd DIR] \
[--gateway-url URL] [--model-url URL] [--allow-host HOST:PORT]... [--kit REF] [--no-daemon] \
[--no-tap] [--dry-run] [-- harness args...]
       derm run --boundary sbx|srt|none [options] -- <program> [args...]";

/// A program named after `--` (case 80): an absolute path, or a bare name
/// looked up on PATH. Never a relative path (it would name a file in
/// whatever folder the chat starts in), an option, or anything with a
/// control character.
pub fn valid_program(p: &str) -> bool {
    !p.is_empty()
        && !p.starts_with('-')
        && !p.chars().any(char::is_control)
        && (p.starts_with('/') || !p.contains('/'))
        && p != "/"
}

/// A chat id: 1 to 64 of `[A-Za-z0-9._-]`, not starting with `-` or `.`.
pub fn valid_chat(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 64
        && !id.starts_with(['-', '.'])
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

/// `host:port` for srt's allow list: a host name or IPv4 literal, or a
/// bracketed IPv6 literal, then a port. No wildcard: `derm run` widens srt's
/// network by named destinations only.
pub fn valid_host_port(s: &str) -> bool {
    let (host, port, v6) = if let Some(rest) = s.strip_prefix('[') {
        match rest.split_once("]:") {
            Some((h, p)) => (h, p, true),
            None => return false,
        }
    } else {
        match s.rsplit_once(':') {
            Some((h, p)) => (h, p, false),
            None => return false,
        }
    };
    let host_ok = !host.is_empty()
        && host.len() <= 253
        && if v6 {
            host.bytes().all(|b| b.is_ascii_hexdigit() || b == b':')
        } else {
            host.bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-'))
        };
    host_ok && port.parse::<u16>().is_ok_and(|p| p > 0) && port.bytes().all(|b| b.is_ascii_digit())
}

/// Codex's `-c` is a clap global argument, and clap 4.5.58 keeps one side
/// of it: given both before and after a subcommand, the root's are dropped
/// (`clap_builder` `parser/arg_matcher.rs:53-78`; run against Codex 0.163.0,
/// Mac test w5 retest 4, MW5-15). derm's own `-c` pairs go right after a
/// session subcommand that is the first word, and first otherwise; so a
/// session subcommand later in the words with a `-c` after it would drop
/// derm's pairs and the chat would run untapped and unrecorded without a
/// word. That command line is refused, with the way to write it.
fn codex_config_split(rest: &[String]) -> Option<String> {
    // Where derm's own `-c` pairs sit: after a leading session subcommand,
    // else at the root (`wire_export`, the tap's pairs). clap keeps a global
    // `-c` from the deepest level that has one, so a user's `-c` after any
    // subcommand below that level drops derm's (fix pass 4's review,
    // FP4-S1: `exec resume`, `agents`). Any deeper level lives under one of
    // these names, so naming the next level is enough.
    let lead = rest
        .first()
        .filter(|w| super::tap::CODEX_SESSION_SUBCOMMANDS.contains(&w.as_str()))
        .map(String::as_str);
    let below: &[&str] = match lead {
        None => CODEX_ROOT_SUBCOMMANDS,
        Some("exec" | "e") => CODEX_EXEC_SUBCOMMANDS,
        Some("app-server") => CODEX_APP_SERVER_SUBCOMMANDS,
        Some(_) => &[],
    };
    let from = usize::from(lead.is_some());
    let config = |w: &String| {
        w == "-c"
            || w == "--config"
            || w.starts_with("--config=")
            || (w.starts_with("-c") && !w.starts_with("--") && w.len() > 2)
    };
    let sub = (from..rest.len())
        .find(|&i| below.contains(&rest[i].as_str()) && rest[i + 1..].iter().any(config))?;
    let word = &rest[sub];
    Some(match lead {
        None if super::tap::CODEX_SESSION_SUBCOMMANDS.contains(&word.as_str()) => format!(
            "codex: put {word:?} first (derm run codex -- {word} ...): Codex keeps `-c` from \
             one side of a subcommand only, so a `-c` after {word:?} would drop derm's own and \
             this chat would run untapped and unrecorded"
        ),
        _ => format!(
            "codex: put your `-c` before {word:?}: Codex keeps `-c` from the deepest \
             subcommand that has one, so a `-c` after {word:?} would drop derm's own and this \
             chat would run untapped and unrecorded"
        ),
    })
}

/// Codex 0.163.0's subcommands at its root, with their aliases and the
/// hidden ones (`codex-rs/cli/src/main.rs:147-227`, `codex --help`).
const CODEX_ROOT_SUBCOMMANDS: &[&str] = &[
    "agents",
    "tcp-tunnel",
    "exec",
    "e",
    "review",
    "login",
    "logout",
    "mcp",
    "plugin",
    "app-server",
    "remote-control",
    "app",
    "completion",
    "update",
    "doctor",
    "sandbox",
    "debug",
    "execpolicy",
    "apply",
    "a",
    "resume",
    "queue",
    "archive",
    "delete",
    "migrate-rollouts",
    "unarchive",
    "fork",
    "cloud",
    "exec-server",
    "features",
    "help",
];

/// `codex exec`'s own subcommands (`codex-rs/exec/src/cli.rs:172-182`).
const CODEX_EXEC_SUBCOMMANDS: &[&str] = &["resume", "fork", "review", "help"];

/// `codex app-server`'s own subcommands (`codex app-server --help`, 0.163.0).
const CODEX_APP_SERVER_SUBCOMMANDS: &[&str] = &[
    "daemon",
    "proxy",
    "generate-ts",
    "generate-json-schema",
    "help",
];

pub fn parse(args: &[String]) -> Result<Args, String> {
    let Some(id) = args.first() else {
        return Err(USAGE.to_string());
    };
    // No harness id: options first, the program after `--` (case 80).
    let by_argv = id.starts_with("--");
    let harness = match harness::find(id) {
        _ if by_argv => &harness::OTHER,
        Some(h) => h,
        None if harness::NOT_RUN.contains(&id.as_str()) => {
            return Err(format!(
                "derm run does not start {id}: its preset names no agent command line to wrap"
            ))
        }
        None => {
            return Err(format!(
                "unknown harness {id:?}; for a command line derm has no preset for, \
                 give it after --: derm run --boundary <b> -- {id} ...\n{USAGE}"
            ))
        }
    };
    let mut out = Args {
        harness,
        boundary: Boundary::None,
        chat: None,
        cwd: None,
        gateway_url: None,
        model_url: None,
        allow_hosts: Vec::new(),
        kit: None,
        no_daemon: false,
        no_tap: false,
        dry_run: false,
        rest: Vec::new(),
        program: None,
    };
    let mut boundary = None;
    let mut i = if by_argv { 0 } else { 1 };
    while i < args.len() {
        let a = args[i].as_str();
        let mut take = |name: &str| -> Result<String, String> {
            i += 1;
            args.get(i)
                .cloned()
                .ok_or_else(|| format!("{name} needs a value"))
        };
        match a {
            "--" => {
                out.rest = args[i + 1..].to_vec();
                break;
            }
            "--boundary" => {
                boundary = Some(match take("--boundary")?.as_str() {
                    "sbx" => Boundary::Sbx,
                    "srt" => Boundary::Srt,
                    "none" => Boundary::None,
                    other => return Err(format!("--boundary is sbx, srt or none, not {other:?}")),
                })
            }
            "--chat" => {
                let v = take("--chat")?;
                if !valid_chat(&v) {
                    return Err(format!("--chat {v:?}: 1 to 64 of A-Z a-z 0-9 . _ -"));
                }
                out.chat = Some(v);
            }
            "--cwd" => out.cwd = Some(take("--cwd")?),
            "--gateway-url" => out.gateway_url = Some(take("--gateway-url")?),
            "--model-url" => out.model_url = Some(take("--model-url")?),
            "--allow-host" => {
                let v = take("--allow-host")?;
                if !valid_host_port(&v) {
                    return Err(format!("--allow-host {v:?}: give HOST:PORT, no wildcard"));
                }
                out.allow_hosts.push(v);
            }
            "--kit" => out.kit = Some(take("--kit")?),
            "--no-daemon" => out.no_daemon = true,
            "--no-tap" => out.no_tap = true,
            "--dry-run" => out.dry_run = true,
            other => {
                return Err(format!(
                    "unknown option {other:?}; harness arguments go after --\n{USAGE}"
                ))
            }
        }
        i += 1;
    }
    // The boundary is never assumed: running a harness with no sandbox is a
    // choice the command line states.
    out.boundary = boundary.ok_or("--boundary is required: sbx, srt or none")?;
    if by_argv {
        let Some(program) = out.rest.first().cloned() else {
            return Err(format!("no program after --\n{USAGE}"));
        };
        if !valid_program(&program) {
            return Err(format!(
                "{program:?}: give the program as an absolute path or a bare name on PATH"
            ));
        }
        out.rest.remove(0);
        // A preset's own command is that harness, with what derm knows of it.
        if let Some(h) = harness::by_command(&program) {
            out.harness = h;
        }
        out.program = Some(program);
    }
    if out.harness.id == "codex" {
        if let Some(why) = codex_config_split(&out.rest) {
            return Err(why);
        }
    }
    if out.boundary != Boundary::Srt && (!out.allow_hosts.is_empty() || out.model_url.is_some()) {
        return Err(
            "--allow-host and --model-url shape srt's allow list; they need --boundary srt".into(),
        );
    }
    if out.kit.is_some() && out.boundary != Boundary::Sbx {
        return Err("--kit needs --boundary sbx".into());
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| x.to_string()).collect()
    }

    #[test]
    fn the_harness_args_after_the_separator_are_kept_whole() {
        let a = parse(&s(&[
            "pi",
            "--boundary",
            "srt",
            "--",
            "-c",
            "--model",
            "a b; rm -rf ~",
        ]))
        .unwrap();
        assert_eq!(a.harness.id, "pi");
        assert_eq!(a.boundary, Boundary::Srt);
        assert_eq!(a.rest, s(&["-c", "--model", "a b; rm -rf ~"]));
    }

    #[test]
    fn the_boundary_is_required_and_checked() {
        assert!(parse(&s(&["pi"])).unwrap_err().contains("required"));
        assert!(parse(&s(&["pi", "--boundary", "docker"])).is_err());
        assert!(parse(&s(&["pi", "--boundary"])).is_err());
    }

    #[test]
    fn a_command_line_with_no_preset_runs_as_other() {
        let a = parse(&s(&[
            "--boundary",
            "none",
            "--",
            "/opt/agent/bin/aider",
            "--model",
            "x",
        ]))
        .unwrap();
        assert_eq!(a.harness.id, "other");
        assert_eq!(a.program.as_deref(), Some("/opt/agent/bin/aider"));
        assert_eq!(a.rest, s(&["--model", "x"]));
        assert_eq!(a.boundary, Boundary::None);
        // A preset's command is that harness from a bare name only; a path
        // is an unknown program (security review L15; this test asserted
        // the opposite before).
        let c = parse(&s(&[
            "--boundary",
            "srt",
            "--",
            "/usr/bin/claude",
            "-p",
            "hi",
        ]))
        .unwrap();
        assert_eq!(c.harness.id, "other");
        let c2 = parse(&s(&["--boundary", "srt", "--", "claude"])).unwrap();
        assert_eq!(c2.harness.id, "claude-code");
        assert_eq!(c.program.as_deref(), Some("/usr/bin/claude"));
        assert_eq!(c.rest, s(&["-p", "hi"]));
        // The boundary is still required, and a program must follow `--`.
        assert!(parse(&s(&["--", "aider"]))
            .unwrap_err()
            .contains("required"));
        assert!(parse(&s(&["--boundary", "none", "--"]))
            .unwrap_err()
            .contains("no program"));
        assert!(parse(&s(&["--boundary", "none"]))
            .unwrap_err()
            .contains("no program"));
        // Relative paths, options and control characters are refused.
        for bad in ["./agent", "bin/agent", "-x", "", "/", "a\nb"] {
            assert!(
                parse(&s(&["--boundary", "none", "--", bad])).is_err(),
                "{bad:?}"
            );
        }
        // An unknown id names the form to use.
        assert!(parse(&s(&["aider", "--boundary", "none"]))
            .unwrap_err()
            .contains("-- aider"));
    }

    #[test]
    fn unknown_harnesses_and_options_are_refused() {
        assert!(parse(&s(&["vim", "--boundary", "none"]))
            .unwrap_err()
            .contains("unknown harness"));
        assert!(parse(&s(&["zed", "--boundary", "none"]))
            .unwrap_err()
            .contains("derm run does not start"));
        // Cursor's CLI is started since fix pass 1 for the Mac test w4
        // (MW4-8); it was refused here with Zed until then.
        assert_eq!(
            parse(&s(&["cursor", "--boundary", "none"]))
                .unwrap()
                .harness
                .command,
            "cursor-agent"
        );
        assert!(parse(&s(&["pi", "--boundary", "none", "--model", "x"]))
            .unwrap_err()
            .contains("after --"));
        assert!(parse(&s(&[])).is_err());
    }

    #[test]
    fn chat_ids_and_hosts_are_shaped() {
        assert!(valid_chat("chat-b_1.2"));
        for bad in ["", "-x", ".x", "a/b", "a b", &"a".repeat(65)] {
            assert!(!valid_chat(bad), "{bad:?}");
        }
        for ok in [
            "127.0.0.1:8811",
            "localhost:8080",
            "[::1]:4318",
            "api.example.com:443",
        ] {
            assert!(valid_host_port(ok), "{ok}");
        }
        for bad in [
            "*.example.com:443",
            "127.0.0.1",
            "h:0",
            "h:99999",
            "a b:1",
            "[::1]",
            "::1:443",
        ] {
            assert!(!valid_host_port(bad), "{bad}");
        }
        assert!(parse(&s(&["pi", "--boundary", "srt", "--allow-host", "*:443"])).is_err());
    }

    #[test]
    fn srt_and_sbx_options_need_their_boundary() {
        assert!(parse(&s(&["pi", "--boundary", "none", "--allow-host", "h:1"])).is_err());
        assert!(parse(&s(&["pi", "--boundary", "srt", "--kit", "x"])).is_err());
        assert!(parse(&s(&["pi", "--boundary", "sbx", "--kit", "x"])).is_ok());
    }

    /// MW5-15's Codex half: clap keeps one side of a global `-c` (Codex
    /// 0.163.0, clap 4.5.58), so a session subcommand that is not the first
    /// word, with `-c` after it, would drop every `-c` derm puts first: the
    /// chat would run untapped and unrecorded without a word. Refused.
    #[test]
    fn codex_with_config_on_both_sides_of_a_later_subcommand_is_refused() {
        for rest in [
            &["-m", "gpt", "exec", "-c", "a=1", "hi"][..],
            &["--full-auto", "exec", "--config", "a=1"][..],
            &["--full-auto", "exec", "--config=a=1"][..],
            &["-p", "work", "app-server", "-ca=1"][..],
        ] {
            let mut argv = s(&["codex", "--boundary", "none", "--"]);
            argv.extend(s(rest));
            let e = parse(&argv).unwrap_err();
            assert!(
                e.contains("first") && e.contains("untapped"),
                "{rest:?}: {e}"
            );
        }
        for rest in [
            &["exec", "-c", "a=1", "hi"][..],
            &["-c", "a=1", "fix the tests"][..],
            &["-m", "gpt", "exec", "hi"][..],
            &["-c", "a=1", "exec", "hi"][..],
            &["app-server"][..],
        ] {
            let mut argv = s(&["codex", "--boundary", "none", "--"]);
            argv.extend(s(rest));
            assert!(parse(&argv).is_ok(), "{rest:?}");
        }
        // Another harness's words are its own.
        let argv = s(&[
            "pi",
            "--boundary",
            "none",
            "--",
            "-m",
            "x",
            "exec",
            "-c",
            "a",
        ]);
        assert!(parse(&argv).is_ok());
    }

    /// Fix pass 4's review, FP4-S1: Codex keeps a global `-c` from the
    /// deepest level only, so a `-c` below derm's level is refused at every
    /// depth (`exec resume`, `e fork`, `exec review`, `agents`; run against
    /// the real 0.163.0 binary by the reviewer).
    #[test]
    fn fp4_s1_codex_nested_session_subcommand_with_config_is_refused() {
        for rest in [
            &["exec", "resume", "--last", "-c", "a=1"][..],
            &["e", "fork", "abc", "--config=a=1", "go"][..],
            &["exec", "review", "--uncommitted", "-ca=1"][..],
            &["agents", "-c", "a=1"][..],
            &["exec", "-m", "x", "resume", "--last", "--config", "a=1"][..],
            &["mcp", "list", "-c", "a=1"][..],
            &["app-server", "proxy", "-c", "a=1"][..],
        ] {
            let mut argv = s(&["codex", "--boundary", "none", "--"]);
            argv.extend(s(rest));
            let err = parse(&argv).expect_err(&format!("{rest:?} was accepted"));
            assert!(err.contains("untapped"), "{err}");
        }
        // A `-c` at derm's own level, or none below it, still runs.
        for rest in [
            &["exec", "-c", "a=1", "resume", "--last"][..],
            &["exec", "resume", "--last"][..],
            &["-c", "a=1", "exec", "hi"][..],
            &["exec", "-c", "a=1", "fix the review"][..],
            &["mcp", "list"][..],
        ] {
            let mut argv = s(&["codex", "--boundary", "none", "--"]);
            argv.extend(s(rest));
            assert!(parse(&argv).is_ok(), "{rest:?} was refused");
        }
    }
}
