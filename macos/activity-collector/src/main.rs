//! derm's activity collector: a root launchd daemon around
//! `/usr/bin/eslogger` (PROTOCOL.md).
//!
//! Detection only: nothing here blocks an action. It never installs or runs
//! itself on its own: you install it, by the commands `derm-daemon
//! collector-plan` prints (rules, section 5, item 2).
//!
//! Modes:
//! - `run [--dev-peer-path <abs path>] [--log-dir <dir>] [--socket-dir <dir>]`
//! - `register`, `unregister`, `service-status`: the app bundle's launchd
//!   job through `SMAppService` (lane Y), run as you from inside
//!   `derm Activity.app`; macOS then asks you to allow it
//! - `parse-fixture <file> --pid <n> --chat <id> [--grant <chat> <bundle> <app path>]...`
//! - `verify <log file>` (plain or `.gz`)
//! - `--version`

use std::fs::File;
use std::io::{self, BufReader, Write};
use std::path::PathBuf;
use std::process::ExitCode;

use derm_activity_collector::service::ServiceOp;
use derm_activity_collector::{daemon, log, protocol, replay};

const USAGE: &str = "usage:
  derm-activity-collector run [--dev-peer-path <abs path>] [--log-dir <dir>] [--socket-dir <dir>]
  derm-activity-collector register | unregister | service-status   (from inside derm Activity.app)
  derm-activity-collector parse-fixture <file> --pid <n> --chat <id> [--grant <chat> <bundle id> <app path>]...
  derm-activity-collector verify <log file>
  derm-activity-collector --version";

fn usage() -> ExitCode {
    eprintln!("{USAGE}");
    ExitCode::from(64)
}

/// `run`'s options.
#[derive(Debug, Default)]
struct RunArgs {
    dev_peer_path: Option<PathBuf>,
    config: daemon::Config,
}

fn parse_run(args: &[String]) -> Result<RunArgs, String> {
    let mut out = RunArgs::default();
    let mut it = args.iter();
    while let Some(flag) = it.next() {
        let value = it
            .next()
            .ok_or_else(|| format!("{flag} needs a value"))
            .map(PathBuf::from)?;
        if !value.is_absolute() {
            return Err(format!("{flag} needs an absolute path"));
        }
        match flag.as_str() {
            "--dev-peer-path" => out.dev_peer_path = Some(value),
            "--log-dir" => out.config.log_dir = value,
            "--socket-dir" => out.config.socket_dir = value,
            _ => return Err(format!("unknown option {flag}")),
        }
    }
    Ok(out)
}

fn parse_fixture_args(args: &[String]) -> Result<(PathBuf, replay::Setup), String> {
    let mut file = None;
    let mut pid = None;
    let mut chat = None;
    let mut setup = replay::Setup::default();
    let mut it = args.iter();
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--pid" => {
                let v = it.next().ok_or("--pid needs a value")?;
                pid = Some(v.parse::<u32>().map_err(|_| "bad --pid")?);
            }
            "--chat" => {
                let v = it.next().ok_or("--chat needs a value")?;
                if !protocol::valid_chat_id(v) {
                    return Err("bad --chat".into());
                }
                chat = Some(v.clone());
            }
            "--grant" => {
                let mut take = || it.next().cloned().ok_or("--grant needs 3 values");
                let (c, b, a) = (take()?, take()?, take()?);
                if !protocol::valid_chat_id(&c)
                    || !protocol::valid_bundle_id(&b)
                    || !protocol::valid_app_path(&a)
                {
                    return Err("bad --grant".into());
                }
                setup.grants.push((c, b, a));
            }
            _ if file.is_none() && !arg.starts_with("--") => file = Some(PathBuf::from(arg)),
            _ => return Err(format!("unexpected {arg}")),
        }
    }
    let file = file.ok_or("missing <file>")?;
    match (pid, chat) {
        (Some(pid), Some(chat)) => setup.roots.push((pid, chat)),
        (None, None) => {}
        _ => return Err("--pid and --chat go together".into()),
    }
    Ok((file, setup))
}

fn cmd_parse_fixture(args: &[String]) -> ExitCode {
    let (path, setup) = match parse_fixture_args(args) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("{e}");
            return usage();
        }
    };
    let events = File::open(&path).and_then(|f| replay::replay(BufReader::new(f), &setup));
    match events {
        Ok(events) => {
            let stdout = io::stdout();
            let mut out = stdout.lock();
            for ev in &events {
                if out.write_all(protocol::reply_event(ev).as_bytes()).is_err() {
                    return ExitCode::from(1);
                }
            }
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("{}: {e}", path.display());
            ExitCode::from(1)
        }
    }
}

fn cmd_verify(args: &[String]) -> ExitCode {
    let [path] = args else {
        return usage();
    };
    let path = PathBuf::from(path);
    let compressed = path.extension().is_some_and(|e| e == "gz");
    let report = log::open_log(&path, compressed).and_then(log::verify);
    match report {
        Ok(r) => {
            let first_bad = r
                .first_bad_line
                .map_or_else(|| "null".to_owned(), |n| n.to_string());
            println!(
                "{{\"ok\":{},\"lines\":{},\"firstBadLine\":{first_bad},\"cut\":{}}}",
                r.ok, r.lines, r.cut
            );
            if r.ok {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(1)
            }
        }
        Err(e) => {
            eprintln!("{}: {e}", path.display());
            ExitCode::from(1)
        }
    }
}

#[cfg(target_os = "macos")]
fn cmd_run(args: RunArgs) -> ExitCode {
    // macOS glue: the signature check (caller::ffi, not compiled in the
    // cloud) gates every socket connection.
    use derm_activity_collector::caller::ffi::Checker;
    use std::os::fd::AsRawFd;
    use std::sync::Arc;
    let checker = Checker::new(args.dev_peer_path);
    if !checker.signed_mode() {
        eprintln!(
            "activity-collector: no usable code requirement; only a dev peer path is accepted"
        );
    }
    let allow: Arc<daemon::Allow> =
        Arc::new(move |s: &std::os::unix::net::UnixStream| checker.allows(s.as_raw_fd()));
    match daemon::run(&args.config, allow) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("activity-collector: {e}");
            ExitCode::from(1)
        }
    }
}

#[cfg(not(target_os = "macos"))]
fn cmd_run(_args: RunArgs) -> ExitCode {
    eprintln!("derm-activity-collector: run works only on macOS");
    ExitCode::from(2)
}

#[cfg(target_os = "macos")]
fn cmd_service(op: ServiceOp) -> ExitCode {
    use derm_activity_collector::bundle;
    use derm_activity_collector::service::{next_step, service_line};
    use derm_activity_collector::sm_app_service::{self, ffi, Status};
    // SAFETY: geteuid has no failure mode.
    if unsafe { libc::geteuid() } == 0 {
        // SMAppService registers a daemon for the app a person runs, and
        // macOS then asks that person; a root shell is not that person.
        eprintln!("derm-activity-collector: run this as yourself, not with sudo; macOS asks you to allow it");
        return ExitCode::from(2);
    }
    let exe = match std::env::current_exe().and_then(std::fs::canonicalize) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("derm-activity-collector: cannot find this executable: {e}");
            return ExitCode::from(1);
        }
    };
    let service = match bundle::locate(&exe) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("derm-activity-collector: {e}");
            return ExitCode::from(1);
        }
    };
    let result = match op {
        ServiceOp::Register => ffi::register(&service.plist_name),
        ServiceOp::Unregister => ffi::unregister(&service.plist_name),
        ServiceOp::Status => ffi::status(&service.plist_name).ok_or((
            sm_app_service::Refusal {
                domain: String::new(),
                code: 0,
                description: "SMAppService is not available (macOS 13 or later)".into(),
            },
            Status::NotFound,
        )),
    };
    let (status, refusal) = match &result {
        Ok(s) => (*s, None),
        Err((r, s)) => (*s, Some(r)),
    };
    println!("{}", service_line(&service.label, status, refusal));
    eprintln!("{}", next_step(op, status));
    let done = match op {
        ServiceOp::Register => matches!(status, Status::Enabled | Status::RequiresApproval),
        ServiceOp::Unregister => matches!(status, Status::NotRegistered | Status::NotFound),
        ServiceOp::Status => refusal.is_none(),
    };
    if done {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    }
}

#[cfg(not(target_os = "macos"))]
fn cmd_service(_op: ServiceOp) -> ExitCode {
    eprintln!("derm-activity-collector: the app bundle's service commands work only on macOS");
    ExitCode::from(2)
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let Some((mode, rest)) = args.split_first() else {
        return usage();
    };
    match mode.as_str() {
        "--version" => {
            println!("derm-activity-collector {}", env!("CARGO_PKG_VERSION"));
            ExitCode::SUCCESS
        }
        "run" => match parse_run(rest) {
            Ok(run) => cmd_run(run),
            Err(e) => {
                eprintln!("{e}");
                usage()
            }
        },
        "register" | "unregister" | "service-status" if rest.is_empty() => {
            cmd_service(match mode.as_str() {
                "register" => ServiceOp::Register,
                "unregister" => ServiceOp::Unregister,
                _ => ServiceOp::Status,
            })
        }
        "parse-fixture" => cmd_parse_fixture(rest),
        "verify" => cmd_verify(rest),
        _ => usage(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| (*x).to_owned()).collect()
    }

    #[test]
    fn run_args() {
        let r = parse_run(&s(&[
            "--dev-peer-path",
            "/a/b",
            "--log-dir",
            "/l",
            "--socket-dir",
            "/s",
        ]))
        .unwrap();
        assert_eq!(r.dev_peer_path, Some(PathBuf::from("/a/b")));
        assert_eq!(r.config.log_dir, PathBuf::from("/l"));
        assert_eq!(r.config.socket_dir, PathBuf::from("/s"));
        let d = parse_run(&[]).unwrap();
        assert_eq!(d.config.log_dir, PathBuf::from(daemon::LOG_DIR));
        assert_eq!(d.dev_peer_path, None);
        assert!(parse_run(&s(&["--dev-peer-path", "rel"])).is_err());
        assert!(parse_run(&s(&["--dev-peer-path"])).is_err());
        assert!(parse_run(&s(&["--other", "/x"])).is_err());
    }

    #[test]
    fn fixture_args() {
        let (f, setup) = parse_fixture_args(&s(&[
            "x.jsonl", "--pid", "5", "--chat", "c1", "--grant", "c1", "com.a", "/A.app",
        ]))
        .unwrap();
        assert_eq!(f, PathBuf::from("x.jsonl"));
        assert_eq!(setup.roots, vec![(5, "c1".to_owned())]);
        assert_eq!(setup.grants.len(), 1);
        assert!(parse_fixture_args(&s(&["x", "--pid", "5"])).is_err());
        assert!(parse_fixture_args(&s(&["x", "--pid", "-1", "--chat", "c"])).is_err());
        assert!(parse_fixture_args(&s(&["--pid", "1", "--chat", "c"])).is_err());
        assert!(parse_fixture_args(&s(&["x", "--grant", "c", "b"])).is_err());
    }
}
