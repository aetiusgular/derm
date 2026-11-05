//! The real [`Probe`](super::Probe): what this machine can run, read from the
//! process's own environment (`PATH`, `HOME`, the terminal), as `RunEnv::real`
//! reads it (lane S made the same choice for its seam, its D15).
//!
//! Every program here is started by absolute path, as an argv list, with
//! stdin closed and a deadline; a program it leaves running cannot hold
//! derm past the deadline through its pipes (case 102's rule, as
//! `watch::status::probe_version` keeps it). sbx is told not to send
//! telemetry (`SBX_NO_TELEMETRY=1`, Docker's FAQ,
//! https://docs.docker.com/ai/sandboxes/faq.md).

use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use super::{settings, PreAnswer, Probe, Reason};
use crate::run::{harness, preflight};

/// `sbx version` and `sbx ls` are local calls to sbx's daemon; the first
/// one may start it.
const SBX_LIMIT: Duration = Duration::from_secs(30);
/// srt starts a program in about 0.4 s here (lane T, by run).
const SRT_LIMIT: Duration = Duration::from_secs(30);

pub(crate) struct Real {
    path: String,
    home: Option<String>,
    userns: Option<String>,
}

impl Real {
    pub(crate) fn new() -> Real {
        Real {
            path: std::env::var("PATH").unwrap_or_default(),
            home: derm_core::runtime::home_dir()
                .filter(|h| h.is_absolute())
                .and_then(|h| h.into_os_string().into_string().ok()),
            userns: std::fs::read_to_string(
                "/proc/sys/kernel/apparmor_restrict_unprivileged_userns",
            )
            .ok(),
        }
    }
}

impl Probe for Real {
    fn sbx(&mut self, h: &harness::Harness) -> Result<(), Reason> {
        sbx_probe(h, &self.path, &|p, a, l| run(p, a, l))
    }

    fn srt(&mut self, h: &harness::Harness, cwd: Option<&str>) -> Result<(), Reason> {
        let cwd = match cwd {
            Some(c) => c.to_string(),
            None => std::env::current_dir()
                .map(|d| d.to_string_lossy().into_owned())
                .unwrap_or_else(|_| "/".into()),
        };
        srt_probe(
            h,
            &self.path,
            self.home.as_deref(),
            self.userns.as_deref(),
            &cwd,
            &|p, a, l| run(p, a, l),
        )
    }

    fn terminal(&self) -> bool {
        // SAFETY: isatty reads only the descriptor number.
        unsafe { libc::isatty(0) == 1 && libc::isatty(2) == 1 }
    }

    fn ask(&mut self, question: &str) -> Option<String> {
        use std::io::Write;
        let mut err = std::io::stderr();
        let _ = write!(err, "{question}");
        let _ = err.flush();
        read_line_from_fd0()
    }

    fn pre_answer(&mut self) -> (Option<PreAnswer>, Option<String>) {
        match &self.home {
            Some(h) => settings::load(&settings::path_for(h)),
            None => (None, None),
        }
    }

    fn say(&mut self, line: &str) {
        eprintln!("{line}");
    }

    fn gate(&mut self, h: &harness::Harness, cwd: Option<&str>) -> bool {
        let mut env = crate::watch::status::Env::real();
        if let Some(c) = cwd {
            env.cwd = Some(PathBuf::from(c));
        }
        gate_holds(h.id, &env)
    }
}

/// Whether derm's gate for `id` runs here and blocks the call when it
/// fails: the preset row's gate is `built`, its `coverage.failMode` is
/// `blocks` or `blocks-with-switch` (derm sets the switch when it registers,
/// rules case 70), and `derm status`'s own registration check says yes for
/// the folder the chat starts in (`watch::register::check`, case 103). An
/// agent whose gate lets a call through when it fails or times out
/// (`open`, `open-on-timeout`) gains less from srt over sbx, so it keeps the
/// default order. The registration's detail is not returned: it holds text
/// from files an agent can write (`register.rs`, fix pass 3's review).
pub(crate) fn gate_holds(id: &str, env: &crate::watch::status::Env) -> bool {
    use crate::watch::register::{check, Registered};
    let Ok(table) =
        serde_json::from_str::<serde_json::Value>(crate::connect::presets::table_json())
    else {
        return false;
    };
    let Some(row) = table
        .get("harnesses")
        .and_then(serde_json::Value::as_array)
        .and_then(|rows| {
            rows.iter()
                .find(|r| r.get("id").and_then(|v| v.as_str()) == Some(id))
        })
    else {
        return false;
    };
    let built = row
        .pointer("/coverage/gate/status")
        .and_then(|v| v.as_str())
        == Some("built");
    let blocks = matches!(
        row.pointer("/coverage/failMode").and_then(|v| v.as_str()),
        Some("blocks" | "blocks-with-switch")
    );
    built && blocks && matches!(check(id, env), Registered::Yes(_) | Registered::YesNote(_))
}

/// One line from descriptor 0, a byte at a time, so nothing past the line
/// is taken from the harness's input. At most 256 bytes.
fn read_line_from_fd0() -> Option<String> {
    let mut out = Vec::new();
    loop {
        let mut b = [0u8; 1];
        // SAFETY: the buffer is valid for one byte.
        let n = unsafe { libc::read(0, b.as_mut_ptr().cast(), 1) };
        if n <= 0 {
            return (!out.is_empty()).then(|| String::from_utf8_lossy(&out).into_owned());
        }
        if b[0] == b'\n' || out.len() >= 256 {
            return Some(String::from_utf8_lossy(&out).into_owned());
        }
        out.push(b[0]);
    }
}

/// What a probe's run gave: whether it exited 0, and its first non-empty
/// line (stderr first, since both tools write their errors there).
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Ran {
    pub ok: bool,
    pub line: String,
}

pub(crate) type Runner<'a> = &'a dyn Fn(&Path, &[String], Duration) -> Result<Ran, String>;

/// The line that installs sbx on this system (https://docs.docker.com/ai/sandboxes/install.md,
/// read 4 Nov 2026), then the sign-in. derm runs none of it.
pub(crate) fn sbx_install_line() -> &'static str {
    if cfg!(target_os = "macos") {
        "brew trust docker/tap && brew install docker/tap/sbx, then sbx login (Apple silicon, macOS 14 or later)"
    } else if cfg!(windows) {
        "winget install -h Docker.sbx, then sbx login (Windows 11 with the Windows Hypervisor Platform)"
    } else {
        "curl -fsSL https://get.docker.com | sudo REPO_ONLY=1 sh, then sudo apt install docker-sbx and sbx login (Ubuntu 24.04 or later, KVM, your user in the kvm group)"
    }
}

/// The line that installs srt (`@anthropic-ai/sandbox-runtime`; its README
/// names bubblewrap, socat and ripgrep on Linux and ripgrep on macOS).
pub(crate) fn srt_install_line() -> &'static str {
    if cfg!(target_os = "linux") {
        "npm install -g @anthropic-ai/sandbox-runtime, and the bubblewrap, socat and ripgrep packages"
    } else {
        "npm install -g @anthropic-ai/sandbox-runtime, and ripgrep"
    }
}

pub(crate) fn sbx_probe(h: &harness::Harness, path: &str, run: Runner) -> Result<(), Reason> {
    let reason = |why: String, install: Option<&str>| Reason {
        boundary: "sbx",
        why,
        install: install.map(str::to_string),
    };
    if h.sbx().is_none() {
        return Err(reason(
            format!(
                "derm knows no sbx kit for {}",
                if h.id == "other" {
                    "this program"
                } else {
                    h.id
                }
            ),
            None,
        ));
    }
    let Some(sbx) = crate::watch::status::find_on_path("sbx", path) else {
        return Err(reason(
            "sbx is not installed (no sbx on PATH)".into(),
            Some(sbx_install_line()),
        ));
    };
    match run(&sbx, &["version".into()], SBX_LIMIT) {
        Ok(r) if r.ok => {}
        Ok(r) => return Err(reason(format!("sbx version failed: {}", r.line), None)),
        Err(e) => return Err(reason(format!("sbx version: {e}"), None)),
    }
    // Before `sbx login`, `sbx ls --no-input` fails with "error: not signed
    // in to Docker" (sbx 0.51.0, the smoke test). `-q` lists names only.
    match run(
        &sbx,
        &["ls".into(), "-q".into(), "--no-input".into()],
        SBX_LIMIT,
    ) {
        Ok(r) if r.ok => Ok(()),
        Ok(r) if r.line.to_ascii_lowercase().contains("not signed in") => Err(reason(
            "sbx is installed and not signed in to Docker".into(),
            Some("sbx login"),
        )),
        Ok(r) => Err(reason(format!("sbx ls failed: {}", r.line), None)),
        Err(e) => Err(reason(
            format!("sbx ls: {e} (is its daemon down? sbx diagnose says why)"),
            None,
        )),
    }
}

pub(crate) fn srt_probe(
    h: &harness::Harness,
    path: &str,
    home: Option<&str>,
    userns: Option<&str>,
    cwd: &str,
    run: Runner,
) -> Result<(), Reason> {
    let reason = |why: String, install: Option<&str>| Reason {
        boundary: "srt",
        why,
        install: install.map(str::to_string),
    };
    let Some(srt) = crate::watch::status::find_on_path("srt", path) else {
        return Err(reason(
            "srt is not installed (no srt on PATH)".into(),
            Some(srt_install_line()),
        ));
    };
    // The folders a chat's srt settings let it write, as `run_io` builds
    // them: the working folder, the harness's state and /tmp.
    let mut writable = vec![cwd.to_string(), "/tmp".to_string()];
    if let Some(home) = home {
        for s in h.state {
            writable.push(format!("{}/{s}", home.trim_end_matches('/')));
        }
    }
    let linux = cfg!(target_os = "linux");
    let tools = match preflight::srt(path, linux, userns, &writable, cwd) {
        Ok((_, tools)) => tools,
        Err(e) => return Err(reason(e, None)),
    };
    // A probe start, as the chat's own will be: a settings file derm wrote,
    // with the tools srt would run outside the sandbox named by path.
    let mut settings = serde_json::json!({
        "network": {"allowedDomains": [], "deniedDomains": []},
        "filesystem": {"denyRead": [], "allowWrite": [], "denyWrite": []},
    });
    if let Some(t) = tools {
        settings["bwrapPath"] = serde_json::json!(t.bwrap);
        settings["socatPath"] = serde_json::json!(t.socat);
        settings["ripgrep"] = serde_json::json!({ "command": t.rg });
    }
    let dir = match private_temp_dir() {
        Ok(d) => d,
        Err(e) => return Err(reason(format!("no folder for srt's probe: {e}"), None)),
    };
    let file = dir.join("settings.json");
    let written = write_private(&file, &settings.to_string());
    let result = written
        .map_err(|e| format!("srt's probe settings: {e}"))
        .and_then(|_| {
            let truth = if Path::new("/usr/bin/true").exists() {
                "/usr/bin/true"
            } else {
                "/bin/true"
            };
            run(
                &srt,
                &[
                    "--settings".into(),
                    file.to_string_lossy().into_owned(),
                    "--".into(),
                    truth.into(),
                ],
                SRT_LIMIT,
            )
        });
    let _ = std::fs::remove_file(&file);
    let _ = std::fs::remove_dir(&dir);
    match result {
        Ok(r) if r.ok => Ok(()),
        Ok(r) => {
            let mut why = format!("srt could not start a program here: {}", r.line);
            if linux && userns.map(str::trim) == Some("1") {
                why.push_str(
                    "; kernel.apparmor_restrict_unprivileged_userns is 1, which srt's README says to set to 0 or answer with an AppArmor profile that allows userns for bwrap",
                );
            }
            Err(reason(why, None))
        }
        Err(e) => Err(reason(e, None)),
    }
}

#[cfg(unix)]
fn private_temp_dir() -> std::io::Result<PathBuf> {
    use std::os::unix::fs::DirBuilderExt;
    let base = std::env::temp_dir();
    for _ in 0..8 {
        let d = base.join(format!(
            "derm-srt-probe-{}-{}",
            std::process::id(),
            &uuid::Uuid::new_v4().simple().to_string()[..8]
        ));
        match std::fs::DirBuilder::new().mode(0o700).create(&d) {
            Ok(()) => return Ok(d),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e),
        }
    }
    Err(std::io::Error::other("could not make a private folder"))
}

/// Windows (lane Z): a new folder, then a user-only DACL.
#[cfg(windows)]
fn private_temp_dir() -> std::io::Result<PathBuf> {
    let base = std::env::temp_dir();
    for _ in 0..8 {
        let d = base.join(format!(
            "derm-srt-probe-{}-{}",
            std::process::id(),
            &uuid::Uuid::new_v4().simple().to_string()[..8]
        ));
        match std::fs::create_dir(&d) {
            Ok(()) => {
                derm_core::platform::set_private_dir(&d)?;
                return Ok(d);
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e),
        }
    }
    Err(std::io::Error::other("could not make a private folder"))
}

fn write_private(path: &Path, text: &str) -> std::io::Result<()> {
    use std::io::Write;
    // The seam's `private_no_follow` is `.mode(0o600).custom_flags(O_NOFOLLOW)`
    // on Unix.
    let mut f = derm_core::platform::private_no_follow(
        std::fs::OpenOptions::new().write(true).create_new(true),
    )
    .open(path)?;
    f.write_all(text.as_bytes())
}

/// Runs `program` with `args`, stdin closed, the environment inherited plus
/// `SBX_NO_TELEMETRY=1`, killed at `limit`.
pub(crate) fn run(program: &Path, args: &[String], limit: Duration) -> Result<Ran, String> {
    let mut child = Command::new(program)
        .args(args)
        .env("SBX_NO_TELEMETRY", "1")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("{} did not start: {e}", program.display()))?;
    let out = drain(
        child
            .stdout
            .take()
            .map(|p| Box::new(p) as Box<dyn Read + Send>),
    );
    let err = drain(
        child
            .stderr
            .take()
            .map(|p| Box::new(p) as Box<dyn Read + Send>),
    );
    let start = Instant::now();
    let status = loop {
        match child.try_wait() {
            Ok(Some(s)) => break s,
            Ok(None) if start.elapsed() < limit => std::thread::sleep(Duration::from_millis(25)),
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(format!("no answer in {} s", limit.as_secs()));
            }
        }
    };
    // What it wrote is in the pipes now; only something it left running can
    // hold them open (sbx's own daemon, started by the first call). A short
    // grace, never past the deadline.
    let grace = Instant::now() + Duration::from_millis(300);
    for (_, t) in [&out, &err] {
        while t.as_ref().is_some_and(|t| !t.is_finished())
            && Instant::now() < grace
            && start.elapsed() < limit
        {
            std::thread::sleep(Duration::from_millis(10));
        }
    }
    let line = first_line(&err.0)
        .or_else(|| first_line(&out.0))
        .unwrap_or_default();
    Ok(Ran {
        ok: status.success(),
        line: clean(&line),
    })
}

type Drained = (Arc<Mutex<Vec<u8>>>, Option<std::thread::JoinHandle<()>>);

fn drain(pipe: Option<Box<dyn Read + Send>>) -> Drained {
    let buf = Arc::new(Mutex::new(Vec::new()));
    let into = buf.clone();
    let t = pipe.map(|mut p| {
        std::thread::spawn(move || {
            let mut chunk = [0u8; 1024];
            loop {
                match p.read(&mut chunk) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        let mut b = into.lock().unwrap_or_else(|e| e.into_inner());
                        b.extend_from_slice(&chunk[..n]);
                        if b.len() >= 16 * 1024 {
                            break;
                        }
                    }
                }
            }
        })
    });
    (buf, t)
}

fn first_line(buf: &Arc<Mutex<Vec<u8>>>) -> Option<String> {
    let b = buf.lock().unwrap_or_else(|e| e.into_inner());
    String::from_utf8_lossy(&b)
        .lines()
        .map(str::trim)
        .find(|l| !l.is_empty())
        .map(str::to_string)
}

/// Control characters out, at most 200 characters: the line is a stranger's
/// text on the terminal and in `run.start`.
fn clean(s: &str) -> String {
    let t: String = s
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .take(200)
        .collect();
    t.trim().to_string()
}

#[cfg(test)]
mod tests {
    #[cfg(unix)]
    use super::*;
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;

    /// Writes an executable script from a child process, so this test
    /// process never holds the file open for write. A thread of another test
    /// that forks keeps a copy of every open descriptor until it execs, and
    /// exec of a file open for write fails with ETXTBSY ("Text file busy",
    /// os error 26): the flake lane Z saw on `f90d0ab`, reproduced outside
    /// derm (3 of 3,000 execs with a direct write, 0 of 3,000 written from a
    /// child). The same cause as W-F1's lock test.
    #[cfg(unix)]
    fn script(dir: &Path, name: &str, body: &str) -> PathBuf {
        let p = dir.join(name);
        let mut w = std::process::Command::new("/bin/sh")
            .args(["-c", "cat > \"$1\" && chmod 755 \"$1\"", "sh"])
            .arg(&p)
            .stdin(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        std::io::Write::write_all(
            &mut w.stdin.take().unwrap(),
            format!("#!/bin/sh\n{body}\n").as_bytes(),
        )
        .unwrap();
        assert!(w.wait().unwrap().success());
        p
    }

    #[cfg(unix)]
    /// A folder outside /tmp: srt's writable list always holds /tmp, and a
    /// tool there is refused (preflight's rule), which these tests are not
    /// about.
    fn tmp(name: &str) -> PathBuf {
        let base = ["/var/tmp"]
            .iter()
            .map(PathBuf::from)
            .find(|b| b.is_dir())
            .or_else(|| std::env::var_os("HOME").map(PathBuf::from))
            .unwrap_or_else(std::env::temp_dir);
        let d = base.join(format!(
            "derm-boundary-{name}-{}-{}",
            std::process::id(),
            &uuid::Uuid::new_v4().simple().to_string()[..6]
        ));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[cfg(unix)]
    fn pi() -> &'static harness::Harness {
        harness::find("pi").unwrap()
    }

    #[cfg(unix)]
    #[test]
    fn the_runner_reads_the_first_line_and_the_status_and_keeps_its_deadline() {
        let d = tmp("runner");
        let ok = script(&d, "ok", "echo '  first\tline  '; echo second");
        assert_eq!(
            run(&ok, &[], Duration::from_secs(5)).unwrap(),
            Ran {
                ok: true,
                line: "first line".into()
            }
        );
        let bad = script(
            &d,
            "bad",
            "echo out; echo 'error: not signed in to Docker' >&2; exit 1",
        );
        let r = run(&bad, &[], Duration::from_secs(5)).unwrap();
        assert!(!r.ok);
        assert_eq!(r.line, "error: not signed in to Docker", "stderr first");
        // Something left holding the pipes cannot keep the probe waiting.
        let left = script(&d, "left", "sleep 30 & echo started; exit 0");
        let t = Instant::now();
        assert!(run(&left, &[], Duration::from_secs(5)).unwrap().ok);
        assert!(t.elapsed() < Duration::from_secs(3), "{:?}", t.elapsed());
        // A program that does not answer is killed at the deadline.
        let slow = script(&d, "slow", "sleep 30");
        let t = Instant::now();
        assert!(run(&slow, &[], Duration::from_millis(500))
            .unwrap_err()
            .contains("no answer"));
        assert!(t.elapsed() < Duration::from_secs(3));
        // sbx is told not to send telemetry.
        let env = script(&d, "env", "echo \"telemetry=$SBX_NO_TELEMETRY\"");
        assert_eq!(
            run(&env, &[], Duration::from_secs(5)).unwrap().line,
            "telemetry=1"
        );
        let _ = std::fs::remove_dir_all(&d);
    }

    #[cfg(unix)]
    #[test]
    fn sbx_is_unavailable_without_a_kit_without_a_binary_or_signed_out() {
        let d = tmp("sbx");
        let path = d.to_string_lossy().into_owned();
        // No kit: not even looked for.
        let goose = harness::find("goose").unwrap();
        let r = sbx_probe(goose, &path, &|_, _, _| panic!("no run")).unwrap_err();
        assert_eq!(r.boundary, "sbx");
        assert!(r.why.contains("no sbx kit for goose"), "{}", r.why);
        // Not on PATH: the install line.
        let r = sbx_probe(pi(), &path, &|_, _, _| panic!("no run")).unwrap_err();
        assert!(r.why.contains("not installed"));
        assert_eq!(r.install.as_deref(), Some(sbx_install_line()));
        // Installed, signed out (the smoke test's words).
        script(
            &d,
            "sbx",
            "case \"$1\" in version) echo 'sbx version v0.51.0';; ls) echo 'error: not signed in to Docker' >&2; exit 1;; esac",
        );
        let real: Runner = &|p, a, l| run(p, a, l);
        let r = sbx_probe(pi(), &path, real).unwrap_err();
        assert!(r.why.contains("not signed in"), "{}", r.why);
        assert_eq!(r.install.as_deref(), Some("sbx login"));
        // Signed in: usable.
        script(&d, "sbx", "exit 0");
        assert!(sbx_probe(pi(), &path, real).is_ok());
        // Its daemon does not answer: the reason says where to look.
        let r = sbx_probe(pi(), &path, &|_, a, _| {
            if a[0] == "ls" {
                Err("no answer in 30 s".into())
            } else {
                Ok(Ran {
                    ok: true,
                    line: String::new(),
                })
            }
        })
        .unwrap_err();
        assert!(r.why.contains("sbx diagnose"), "{}", r.why);
        let _ = std::fs::remove_dir_all(&d);
    }

    #[cfg(unix)]
    #[test]
    fn srt_is_unavailable_when_missing_or_when_its_probe_fails() {
        let d = tmp("srt");
        let path = d.to_string_lossy().into_owned();
        let r = srt_probe(pi(), &path, None, None, "/", &|_, _, _| panic!("no run")).unwrap_err();
        assert!(r.why.contains("not installed"));
        assert_eq!(r.install.as_deref(), Some(srt_install_line()));
        // srt on PATH, its tools beside it, and a probe that fails.
        script(&d, "srt", "exit 0");
        for t in ["bwrap", "socat", "rg"] {
            script(&d, t, "exit 0");
        }
        let fail: Runner = &|p, a, _| {
            assert!(p.ends_with("srt"));
            assert_eq!(a[0], "--settings");
            assert_eq!(a[2], "--");
            // The settings file is there while srt runs, private, and lists
            // the tools by absolute path.
            let f = Path::new(&a[1]);
            let meta = std::fs::metadata(f).unwrap();
            assert_eq!(meta.permissions().mode() & 0o777, 0o600);
            let v: serde_json::Value =
                serde_json::from_str(&std::fs::read_to_string(f).unwrap()).unwrap();
            if cfg!(target_os = "linux") {
                assert!(v["bwrapPath"].as_str().unwrap().starts_with('/'));
            }
            Ok(Ran {
                ok: false,
                line: "bwrap: setting up uid map: Permission denied".into(),
            })
        };
        let cwd = d.join("cwd");
        std::fs::create_dir_all(&cwd).unwrap();
        let cwd = cwd.to_string_lossy().into_owned();
        let r = srt_probe(pi(), &path, None, Some("1\n"), &cwd, fail).unwrap_err();
        assert!(r.why.contains("Permission denied"), "{}", r.why);
        if cfg!(target_os = "linux") {
            assert!(r.why.contains("apparmor_restrict_unprivileged_userns"));
        }
        let ok: Runner = &|_, _, _| {
            Ok(Ran {
                ok: true,
                line: String::new(),
            })
        };
        assert!(srt_probe(pi(), &path, None, None, &cwd, ok).is_ok());
        // The probe's folder is gone afterwards.
        let left: Vec<_> = std::fs::read_dir(std::env::temp_dir())
            .unwrap()
            .flatten()
            .filter(|e| {
                e.file_name()
                    .to_string_lossy()
                    .starts_with(&format!("derm-srt-probe-{}-", std::process::id()))
            })
            .collect();
        assert!(left.is_empty(), "{left:?}");
        let _ = std::fs::remove_dir_all(&d);
    }

    #[cfg(unix)]
    #[test]
    fn srt_in_a_folder_the_sandbox_can_write_is_not_a_boundary() {
        // preflight's rule (fix pass review R3): the tool srt runs outside
        // the sandbox must not sit where the agent can write.
        let d = tmp("srt-writable");
        let path = d.to_string_lossy().into_owned();
        script(&d, "srt", "exit 0");
        for t in ["bwrap", "socat", "rg"] {
            script(&d, t, "exit 0");
        }
        let cwd = d.to_string_lossy().into_owned();
        let r = srt_probe(pi(), &path, None, None, &cwd, &|_, _, _| {
            panic!("not started")
        });
        if cfg!(target_os = "linux") || cfg!(target_os = "macos") {
            let r = r.unwrap_err();
            assert!(r.why.contains("which the sandbox can write"), "{}", r.why);
        }
        let _ = std::fs::remove_dir_all(&d);
    }

    fn status_env(home: &Path, cwd: Option<&Path>) -> crate::watch::status::Env {
        crate::watch::status::Env {
            home: Some(home.to_path_buf()),
            path: String::new(),
            vars: Vec::new(),
            cwd: cwd.map(Path::to_path_buf),
        }
    }

    fn put(path: &Path, text: &str) {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, text).unwrap();
    }

    /// Phase 4, item 2: srt first only where derm's gate runs here and
    /// blocks when it fails, read as `derm status` reads it.
    #[test]
    fn the_gate_holds_only_when_built_registered_and_failing_closed() {
        let d = tmp("gate");
        let env = status_env(&d, None);
        // Nothing registered: no.
        assert!(!gate_holds("claude-code", &env));
        // Claude Code's plugin installed for the user: its row blocks with
        // derm's switch set (`onFailure: block`), so yes.
        let installed = d.join(".claude/plugins/installed_plugins.json");
        put(
            &installed,
            r#"{"version":2,"plugins":{"derm@derm":[{"scope":"user","installPath":"/x","version":"0.0.0"}]}}"#,
        );
        assert!(gate_holds("claude-code", &env));
        // Turned off in the user's settings: no.
        put(
            &d.join(".claude/settings.json"),
            r#"{"enabledPlugins":{"derm@derm":false}}"#,
        );
        assert!(!gate_holds("claude-code", &env));
        put(&d.join(".claude/settings.json"), "{}");
        assert!(gate_holds("claude-code", &env));
        // An agent whose gate lets a call through when it fails keeps the
        // default order, registered or not (codex: `failMode: open`).
        assert!(!gate_holds("codex", &env));
        // An agent derm does not know, and the program form.
        assert!(!gate_holds("no-such-agent", &env));
        assert!(!gate_holds("other", &env));
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Case 103: a project-scope install counts only in its own folder, the
    /// one `--cwd` names when the command line gives it.
    #[test]
    fn a_project_install_holds_only_in_its_folder_case_103() {
        let d = tmp("gate-project");
        let project = d.join("proj");
        std::fs::create_dir_all(&project).unwrap();
        put(
            &d.join(".claude/plugins/installed_plugins.json"),
            &format!(
                r#"{{"version":2,"plugins":{{"derm@derm":[{{"scope":"project","projectPath":"{}","installPath":"/x","version":"0.0.0"}}]}}}}"#,
                project.display()
            ),
        );
        assert!(gate_holds("claude-code", &status_env(&d, Some(&project))));
        assert!(!gate_holds("claude-code", &status_env(&d, Some(&d))));
        let _ = std::fs::remove_dir_all(&d);
    }
}
