//! What `derm run --boundary srt` checks before it starts srt (box test w1,
//! findings BX3 and BX4). On the box srt failed twice with its own errors:
//! first "ripgrep (rg) not found", then, with rg on PATH, its seccomp helper
//! could not write `/proc/self/setgroups` because Ubuntu 26.04 sets
//! `kernel.apparmor_restrict_unprivileged_userns = 1`.
//!
//! Sources, srt 0.0.81 README (the installed package, read 27 Oct):
//! lines 686 to 698 name bubblewrap, socat and ripgrep as the Linux
//! dependencies and ripgrep alone on macOS (732); line 701 is the Ubuntu
//! 24.04+ note: the sysctl "strips capabilities from the resulting
//! namespace", and the fix is the sysctl at 0 or an AppArmor profile that
//! grants `userns` to the binaries. Line 599: srt can be pointed at another
//! ripgrep with the `ripgrep` setting; derm does not point it at Pi's own
//! `~/.pi/agent/bin/rg`, because srt runs ripgrep outside the sandbox and
//! the agent can write that folder (it is one of Pi's state folders, which
//! srt leaves writable).

use std::path::Path;

/// The tools srt will start outside the sandbox, as absolute paths, for its
/// settings (`bwrapPath`, `socatPath`, `ripgrep.command`; srt 0.0.81
/// `dist/sandbox/sandbox-config.js:1025-1048`, all Linux only).
#[derive(Debug, PartialEq, Eq)]
pub struct Tools {
    pub bwrap: String,
    pub socat: String,
    pub rg: String,
}

/// A missing dependency stops the run before srt starts; so does one whose
/// first copy on PATH, the one srt's `which` finds (`dist/utils/which.js`),
/// sits in a relative PATH entry or in a folder the sandbox can write (fix
/// pass review R3: `PATH=.:/usr/bin` gave srt `./rg`, which runs outside the
/// sandbox). The userns sysctl only warns, since an AppArmor profile can
/// grant what the sysctl takes away and derm cannot read profiles.
pub fn srt(
    path_var: &str,
    linux: bool,
    userns_sysctl: Option<&str>,
    writable: &[String],
    cwd: &str,
) -> Result<(Vec<String>, Option<Tools>), String> {
    srt_with(path_var, linux, userns_sysctl, false, writable, cwd)
}

/// The bubblewrap Ubuntu's `bwrap-userns-restrict` attaches to, by path
/// (`profile bwrap /usr/bin/bwrap`, line 15 of apparmor
/// 5.0.2-0ubuntu1~26.04.1's file).
pub const UBUNTU_BWRAP: &str = "/usr/bin/bwrap";

/// What derm says when AppArmor may stop srt on Linux, one text for
/// `derm run`'s start note and for the boundary probe's reason (box test w5
/// retest, BW5R-4: the start note still offered the sysctl, which did not
/// fix Ubuntu 26.04 on 5 Nov, and did not name Ubuntu's bubblewrap profile,
/// while `derm setup sandbox` did). `bwrap_profile`: Ubuntu's
/// `/etc/apparmor.d/bwrap-userns-restrict` is installed.
///
/// Why srt fails there (BW5-10, each read on 8 Nov at the versions on
/// Ubuntu 26.04 and in use):
/// - Ubuntu's profile attaches to `/usr/bin/bwrap` by path, so the sysctl
///   does not turn it off, and stacks everything bubblewrap starts under
///   `unpriv_bwrap`, which has `audit deny capability` (apparmor
///   5.0.2-0ubuntu1~26.04.1, `etc/apparmor.d/bwrap-userns-restrict` lines
///   15, 50, 59, 77, 79; the same file in 26.04's release pocket). Ubuntu
///   24.04 ships it unloaded, in apparmor-profiles' extra profiles
///   (4.0.1really4.0.1-0ubuntu0.24.04.9), which is why srt's own Ubuntu
///   note (README line 701, sysctl or a profile granting `userns`) is about
///   24.04 and does not fix 26.04.
/// - srt 0.0.81's `apply-seccomp` cannot unshare its PID and mount
///   namespaces inside bubblewrap (bwrap is run with `--cap-drop ALL`,
///   `src/sandbox/linux-sandbox-utils.ts:797`), so
///   it makes a user namespace and writes `/proc/self/setgroups`
///   (`vendor/seccomp-src/apply-seccomp.c:710-778` at `c40cf14`); opening
///   that file for write needs CAP_SYS_ADMIN in the namespace (Linux 7.0
///   `fs/proc/base.c:3193-3196`), which `unpriv_bwrap` denies.
/// - bubblewrap 0.11.1 sets no_new_privs (`bubblewrap.c:2915`), and under
///   it AppArmor refuses any exec to a profile that is not a subset of the
///   one held (Linux 7.0 `security/apparmor/domain.c:980-992`), so a
///   profile for srt's own programs cannot give them back a capability.
///
/// So srt runs on such a host only if root keeps srt's bubblewrap out of
/// that profile, and every way to do that hands any local program a user
/// namespace with capabilities; `docs/install/linux.md` lists them with
/// their undo.
///
/// `bwrap` is the bubblewrap srt will run, by its real path. A bubblewrap
/// anywhere but [`UBUNTU_BWRAP`] is not under Ubuntu's profile,
/// so with the profile installed there is nothing to say about it (box
/// retest of fix pass 13r, BW5R5-2: the copy `docs/install/linux.md`
/// describes started srt on the box, and the note still said it could not).
pub fn apparmor_note_for(
    linux: bool,
    bwrap_profile: bool,
    userns_sysctl: Option<&str>,
    bwrap: &str,
) -> Option<String> {
    if !linux {
        return None;
    }
    if bwrap_profile && bwrap != UBUNTU_BWRAP {
        return None;
    }
    if bwrap_profile {
        return Some(format!(
            "Ubuntu's AppArmor profile {} runs everything bubblewrap starts under unpriv_bwrap, which denies every capability, and srt's seccomp step needs CAP_SYS_ADMIN in a user namespace of its own (it fails opening /proc/self/setgroups). kernel.apparmor_restrict_unprivileged_userns does not change that profile, and a profile for srt's own programs cannot lift it, because bubblewrap sets no_new_privs. srt starts here only if root takes srt's bubblewrap out of that profile, which lets any local program make a user namespace with capabilities; derm makes no such change (docs/install/linux.md says how and what it costs). Use --boundary sbx, or none",
            crate::run::boundary::probe::UBUNTU_BWRAP_PROFILE
        ));
    }
    (userns_sysctl.map(str::trim) == Some("1")).then(|| {
        "kernel.apparmor_restrict_unprivileged_userns is 1, which takes the capabilities srt's bubblewrap and seccomp layer need (srt README, Ubuntu 24.04+ note); srt will fail with \"Permission denied\" on /proc/self/setgroups. The fix is root's, and either way it lets any local program make a user namespace with capabilities: `sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0`, or an AppArmor profile that allows userns for srt's bubblewrap and leaves what it starts its capabilities, not Ubuntu's own bwrap-userns-restrict, under which srt fails the same way (docs/install/linux.md)".to_string()
    })
}

/// Why derm does not start srt on Windows (WW5-8, Windows test w5 4.2). srt
/// 0.0.81 runs the command there as its `srt-sandbox` account, from a fresh
/// profile environment of that account (its own `USERPROFILE` and `TEMP`),
/// and passes on only `PATH`, `PATHEXT`, its proxy variables and git's
/// (`src/sandbox/windows-sandbox-utils.ts:4155-4165, 4236-4262, 4290-4296`,
/// at `v0.0.81`). derm's srt plan is built for one user and one home: the
/// chat's variables, the harness's sign-in and its state would not reach the
/// harness, and the plan's paths are written the Unix way. Until srt on
/// Windows has a design of its own, `--boundary srt` stops here and the
/// default choice never picks it.
pub const SRT_ON_WINDOWS: &str = "derm does not start srt on Windows yet: srt runs the agent there as its own srt-sandbox account, and inside it derm's gate does not run yet and a deny for a path not made yet is not held, so the agent would run ungated with folders it could plant code in. Use --boundary sbx, or none";

/// `srt` with whether Ubuntu's bubblewrap profile is installed, for the note.
pub fn srt_with(
    path_var: &str,
    linux: bool,
    userns_sysctl: Option<&str>,
    bwrap_profile: bool,
    writable: &[String],
    cwd: &str,
) -> Result<(Vec<String>, Option<Tools>), String> {
    if cfg!(windows) {
        // Wave 5b lane 5bD's seam (the wave 5b base).
        if let Some(why) = super::boundary::windows_srt::refusal() {
            return Err(why.to_string());
        }
    }
    // srt 0.0.81 checks rg only on Linux (`sandbox-manager.ts:1641-1649`);
    // its README still asks for it on macOS (line 732), so macOS keeps it.
    // On Windows srt 0.0.82 runs none of these (ripgrep "is Linux-only",
    // `src/sandbox/sandbox-manager.ts:1895`; request 5bD-1).
    let needed: &[(&str, &str)] = if cfg!(windows) {
        &[]
    } else if linux {
        &[
            ("bwrap", "bubblewrap"),
            ("socat", "socat"),
            ("rg", "ripgrep"),
        ]
    } else {
        &[("rg", "ripgrep")]
    };
    let mut found = Vec::new();
    let mut missing = Vec::new();
    for (bin, pkg) in needed {
        match first_on_path(path_var, bin, cwd) {
            None => missing.push(format!("{bin} (package {pkg})")),
            Some(p) if !absolute(&p) => {
                return Err(format!(
                    "srt would run `{p}`, the first {bin} on PATH, from a relative PATH entry and outside the sandbox; take the relative entry out of PATH"
                ))
            }
            Some(p) => {
                let real = std::fs::canonicalize(&p)
                    .map(|r| r.to_string_lossy().into_owned())
                    .unwrap_or_else(|_| p.clone());
                if let Some(w) = writable.iter().find(|w| under(&real, w)) {
                    return Err(format!(
                        "srt would run {real}, the first {bin} on PATH, outside the sandbox, and it sits in {w}, which the sandbox can write; put a system {bin} first on PATH"
                    ));
                }
                found.push(real);
            }
        }
    }
    if !missing.is_empty() {
        return Err(format!(
            "srt needs {} on PATH and will not start without it; install it, or use --boundary sbx or none{}",
            missing.join(", "),
            if missing.iter().any(|m| m.starts_with("rg ")) {
                ". Pi's own rg in ~/.pi/agent/bin is not used: srt runs rg outside the sandbox, and the agent can write that folder"
            } else {
                ""
            }
        ));
    }
    let mut notes = Vec::new();
    let bwrap = found.first().map(String::as_str).unwrap_or(UBUNTU_BWRAP);
    if let Some(n) = apparmor_note_for(linux, bwrap_profile, userns_sysctl, bwrap) {
        notes.push(format!("derm run: {n}."));
    }
    let tools = linux.then(|| Tools {
        bwrap: found[0].clone(),
        socat: found[1].clone(),
        rg: found[2].clone(),
    });
    Ok((notes, tools))
}

/// The companion `derm run` starts beside the harness (lane P's Cline
/// responder), as the argv to start: absolute paths only. It runs as the
/// user, outside any sandbox, with the chat token, so it is held to the rule
/// srt's own tools are held to: not from a relative PATH entry, not from a
/// folder the sandbox can write (security review L8). A script whose first
/// line is `#!/usr/bin/env <name>` would have the kernel look `<name>` up on
/// PATH when it starts, so `<name>` is found and checked the same way here and
/// started by its absolute path, with the script as its argument (review
/// W4-S4). An absolute interpreter is checked against the writable folders.
pub fn companion(
    program: &str,
    path_var: &str,
    writable: &[String],
    cwd: &str,
) -> Result<Vec<String>, String> {
    let script = checked(program, path_var, writable, cwd)?;
    let head = {
        use std::io::Read;
        let mut buf = [0u8; 256];
        let n = std::fs::File::open(&script)
            .and_then(|mut f| f.read(&mut buf))
            .map_err(|e| format!("{script}: {e}"))?;
        String::from_utf8_lossy(&buf[..n]).into_owned()
    };
    let Some(line) = head.strip_prefix("#!") else {
        return Ok(vec![script]);
    };
    let line = line.lines().next().unwrap_or("");
    let words: Vec<&str> = line.split_whitespace().collect();
    match words.as_slice() {
        [env, name] if env.rsplit('/').next() == Some("env") && !name.starts_with('-') => {
            let interp = checked(name, path_var, writable, cwd)
                .map_err(|e| format!("{script} runs `{name}` from PATH: {e}"))?;
            Ok(vec![interp, script])
        }
        [interp, ..] if interp.starts_with('/') && !interp.rsplit('/').next().is_some_and(|b| b == "env") => {
            let real = std::fs::canonicalize(interp)
                .map(|r| r.to_string_lossy().into_owned())
                .map_err(|e| format!("{script}: its interpreter {interp}: {e}"))?;
            if let Some(w) = writable.iter().find(|w| under(&real, w)) {
                return Err(format!(
                    "{script}'s interpreter {real} sits in {w}, which the sandbox can write"
                ));
            }
            Ok(vec![script])
        }
        _ => Err(format!(
            "{script}: derm cannot tell which program its first line `#!{line}` starts; start it with an absolute interpreter or `#!/usr/bin/env <name>`"
        )),
    }
}

/// The PATH the companion runs with: the entries of `path_var` that are
/// absolute and not inside a folder the sandbox can write, in order. The
/// companion's own interpreter is checked by `companion`, but what it starts
/// by name later (a `#!/bin/sh` wrapper's `exec node`, an asdf shim's
/// `#!/usr/bin/env bash`) is looked up on this PATH, so a program planted in
/// a writable folder on the user's PATH is never found there (re-review
/// W4-R1).
///
/// With a sandbox (`writable` not empty), an entry that does not exist at
/// start is dropped too: it holds nothing now, and compared as written it
/// can miss a writable folder reached through a link (`/tmp` is
/// `/private/tmp` on macOS), which the sandbox could then fill (Mac test w4,
/// MW4-1).
pub fn companion_path(path_var: &str, writable: &[String]) -> String {
    // PATH as this OS reads it: `:` on Unix, `;` on Windows (WW5-8: split on
    // `:`, a Windows PATH broke at every drive letter and lost every entry).
    let kept: Vec<std::path::PathBuf> = std::env::split_paths(path_var)
        .filter(|d| d.is_absolute())
        .filter(|d| {
            let d = d.to_string_lossy();
            let real = match std::fs::canonicalize(&*d) {
                Ok(r) => r.to_string_lossy().into_owned(),
                Err(_) if !writable.is_empty() => return false,
                Err(_) => d.to_string(),
            };
            !writable.iter().any(|w| under(&real, w) || under(&d, w))
        })
        .collect();
    std::env::join_paths(kept)
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_default()
}

/// One program, found and held to the companion's rule, as an absolute path.
fn checked(
    program: &str,
    path_var: &str,
    writable: &[String],
    cwd: &str,
) -> Result<String, String> {
    let found = if absolute(program) {
        Path::new(program).is_file().then(|| program.to_string())
    } else if program.contains('/') || (cfg!(windows) && program.contains('\\')) {
        return Err(format!(
            "{program}: a relative path; give an absolute one or a bare name on PATH"
        ));
    } else {
        first_on_path(path_var, program, cwd)
    };
    let Some(p) = found else {
        return Err(format!("{program} not found on PATH; it answers the harness's gated calls, and without it they wait and are denied"));
    };
    if !absolute(&p) {
        return Err(format!(
            "derm would start `{p}`, the first {program} on PATH, from a relative PATH entry and outside the sandbox; take the relative entry out of PATH"
        ));
    }
    let real = std::fs::canonicalize(&p)
        .map(|r| r.to_string_lossy().into_owned())
        .map_err(|e| format!("{p}: {e}"))?;
    if let Some(w) = writable.iter().find(|w| under(&real, w)) {
        return Err(format!(
            "derm would start {real} outside the sandbox with the chat token, and it sits in {w}, which the sandbox can write; put the installed {program} first on PATH"
        ));
    }
    Ok(real)
}

/// The first executable `bin` along PATH, as `which` searches it: every
/// entry in order, an empty one meaning the current folder, which for srt is
/// the chat's folder (`derm run` starts it there). A relative entry's match is
/// returned relative, for the caller to refuse.
#[cfg(unix)]
pub(crate) fn first_on_path(path_var: &str, bin: &str, cwd: &str) -> Option<String> {
    use std::os::unix::fs::PermissionsExt;
    path_var.split(':').find_map(|d| {
        let d = if d.is_empty() { "." } else { d };
        let p = Path::new(d).join(bin);
        let at = if d.starts_with('/') {
            p.clone()
        } else {
            Path::new(cwd).join(&p)
        };
        std::fs::metadata(&at)
            .is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
            .then(|| p.to_string_lossy().into_owned())
    })
}

/// Windows (lane Z): PATH split on `;`, the name tried with Windows'
/// program extensions (`platform::windows::shim::find_program`).
#[cfg(windows)]
pub(crate) fn first_on_path(path_var: &str, bin: &str, _cwd: &str) -> Option<String> {
    crate::platform::windows::shim::find_program(bin, Some(path_var), &|p| p.is_file())
        .map(|p| p.to_string_lossy().into_owned())
}

/// `path` is `dir` or inside it, both compared canonical where they exist.
#[cfg(not(windows))]
fn under(path: &str, dir: &str) -> bool {
    let dir = std::fs::canonicalize(dir)
        .map(|d| d.to_string_lossy().into_owned())
        .unwrap_or_else(|_| dir.to_string());
    let dir = dir.trim_end_matches('/');
    path == dir || path.starts_with(&format!("{dir}/"))
}

/// Windows (WW5-8): `canonicalize` gives `\\?\C:\...`, the plan writes
/// `C:\...` or `C:/...`, and names compare without case, so both sides are
/// put in lane Z's one comparable form before the prefix test.
#[cfg(windows)]
fn under(path: &str, dir: &str) -> bool {
    use derm_core::platform::windows::comparable;
    let dir = std::fs::canonicalize(dir)
        .map(|d| d.to_string_lossy().into_owned())
        .unwrap_or_else(|_| dir.to_string());
    let (path, dir) = (comparable(path), comparable(&dir));
    path == dir || path.starts_with(&format!("{dir}\\"))
}

fn absolute(p: &str) -> bool {
    crate::run::args::absolute(p)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// WW5-8 (the Windows test): the srt check stopped at "srt needs rg",
    /// then at "a relative PATH entry" for every Windows entry. Fails on
    /// `2ce607d` on Windows. Lane 5bD's request 5bD-1 let srt start there;
    /// the wave 5b close held it off again (W5B-S2, W5B-S3), so the check
    /// refuses for that reason, never for rg or the PATH.
    #[cfg(windows)]
    #[test]
    fn ww5_8_srt_is_refused_on_windows_for_the_true_reason() {
        let path = std::env::var("PATH").unwrap_or_default();
        let cwd = std::env::temp_dir().to_string_lossy().into_owned();
        let e = srt_with(&path, false, None, false, &[], &cwd).unwrap_err();
        assert_eq!(e, SRT_ON_WINDOWS);
        assert!(!e.contains("ripgrep") && !e.contains("relative"), "{e}");
    }

    /// WW5-8's PATH half: the companion's PATH was split on `:` and kept only
    /// entries starting with `/`, so on Windows it was always empty, and a
    /// writable folder was compared in another spelling than the one
    /// `canonicalize` gives (`\\?\C:\...`). Fails on `2ce607d` on Windows.
    #[cfg(windows)]
    #[test]
    fn ww5_8_the_companions_path_is_read_the_windows_way() {
        let sys = std::env::var("SystemRoot").unwrap();
        let s32 = format!(r"{sys}\System32");
        let path = format!(r"{s32};relative\bin;;{sys}");
        assert_eq!(companion_path(&path, &[]), format!("{s32};{sys}"));
        // Both lie in a writable folder, however the plan spells it.
        let w = vec![sys.replace('\\', "/").to_lowercase()];
        assert_eq!(companion_path(&path, &w), "");
        assert!(under(&format!(r"\\?\{s32}"), &w[0]));
        assert!(!under(&format!(r"{sys}x"), &w[0]));
    }

    #[cfg(unix)]
    fn dir_with(name: &str, bins: &[&str]) -> String {
        let d = std::env::temp_dir().join(format!("derm-pre-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        for b in bins {
            let p = d.join(b);
            std::fs::write(&p, "#!/bin/sh\n").unwrap();
            #[cfg(unix)]
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        d.to_string_lossy().into_owned()
    }

    #[cfg(unix)]
    #[test]
    fn a_missing_dependency_stops_the_run_and_names_it() {
        // BX4: the box had bwrap and socat, and rg only in ~/.pi/agent/bin.
        let d = dir_with("norg", &["bwrap", "socat"]);
        let e = srt(&d, true, Some("0"), &[], "/").unwrap_err();
        assert!(e.contains("rg (package ripgrep)"), "{e}");
        assert!(!e.contains("bwrap"), "{e}");
        assert!(e.contains("not used"), "{e}");
        // Relative PATH entries are not searched.
        let e = srt("bin:/nonexistent", false, None, &[], "/").unwrap_err();
        assert!(e.contains("rg"), "{e}");
    }

    #[cfg(unix)]
    #[test]
    fn the_userns_sysctl_warns_before_the_start() {
        // BX3.
        let d = dir_with("all", &["bwrap", "socat", "rg"]);
        let n = srt(&d, true, Some("1\n"), &[], "/").unwrap().0;
        assert_eq!(n.len(), 1);
        assert!(
            n[0].contains("apparmor_restrict_unprivileged_userns"),
            "{n:?}"
        );
        assert!(srt(&d, true, Some("0"), &[], "/").unwrap().0.is_empty());
        assert!(
            srt(&d, true, None, &[], "/").unwrap().0.is_empty(),
            "no such sysctl"
        );
        // macOS needs rg only, and has no such sysctl.
        let d = dir_with("mac", &["rg"]);
        assert!(srt(&d, false, Some("1"), &[], "/").unwrap().0.is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn the_copy_srt_would_run_must_not_be_relative_or_in_a_writable_folder() {
        // Fix pass review R3.
        let sys = dir_with("sys", &["bwrap", "socat", "rg"]);
        let agent = dir_with("agentbin", &["rg"]);
        // The agent's folder first: refused, even though a system rg follows.
        let e = srt(
            &format!("{agent}:{sys}"),
            true,
            None,
            std::slice::from_ref(&agent),
            "/",
        )
        .unwrap_err();
        assert!(e.contains("which the sandbox can write"), "{e}");
        // A folder inside a writable one counts too.
        let parent = Path::new(&agent)
            .parent()
            .unwrap()
            .to_string_lossy()
            .into_owned();
        assert!(srt(&format!("{agent}:{sys}"), true, None, &[parent], "/").is_err());
        // A relative entry that holds rg: refused.
        let e = srt(&format!(".:{sys}"), true, None, &[], &agent).unwrap_err();
        assert!(e.contains("relative PATH entry"), "{e}");
        let e = srt(&format!(":{sys}"), true, None, &[], &agent).unwrap_err();
        assert!(e.contains("relative PATH entry"), "an empty entry: {e}");
        // The system copies, as absolute paths for srt's settings.
        let (_, t) = srt(
            &format!("{sys}:{agent}"),
            true,
            None,
            std::slice::from_ref(&agent),
            "/",
        )
        .unwrap();
        let t = t.unwrap();
        let real = std::fs::canonicalize(&sys)
            .unwrap()
            .to_string_lossy()
            .into_owned();
        assert_eq!(t.rg, format!("{real}/rg"));
        assert_eq!(t.bwrap, format!("{real}/bwrap"));
        assert!(
            srt(&sys, false, None, &[], "/").unwrap().1.is_none(),
            "macOS: no paths"
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_file_that_is_not_executable_does_not_count() {
        let d = dir_with("noexec", &["bwrap", "socat"]);
        std::fs::write(Path::new(&d).join("rg"), "x").unwrap();
        assert!(srt(&d, true, None, &[], "/").is_err());
    }

    #[cfg(unix)]
    /// Security review L8: the companion runs outside the sandbox with the
    /// chat token, so it is held to the same rule as srt's own tools.
    #[test]
    fn the_companion_is_never_taken_from_a_folder_the_sandbox_can_write() {
        #[cfg(unix)]
        use std::os::unix::fs::PermissionsExt;
        let root = std::env::temp_dir().join(format!(
            "derm-pre-comp-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4().simple()
        ));
        let sys = root.join("sys");
        let planted = root.join("work/node_modules/.bin");
        for d in [&sys, &planted] {
            std::fs::create_dir_all(d).unwrap();
            let f = d.join("derm-cline-responder");
            std::fs::write(&f, "#!/bin/sh\n").unwrap();
            std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        let s = |p: &std::path::Path| p.to_string_lossy().into_owned();
        let work = s(&root.join("work"));
        let writable = vec![work.clone()];
        // The planted copy first on PATH: refused.
        let path = format!("{}:{}", s(&planted), s(&sys));
        let e = companion("derm-cli-responder-missing", &path, &writable, &work).unwrap_err();
        assert!(e.contains("not found"), "{e}");
        let e = companion("derm-cline-responder", &path, &writable, &work).unwrap_err();
        assert!(e.contains("can write"), "{e}");
        // The system copy first: its absolute path.
        let path = format!("{}:{}", s(&sys), s(&planted));
        let got = companion("derm-cline-responder", &path, &writable, &work).unwrap();
        assert_eq!(
            got,
            vec![s(
                &std::fs::canonicalize(sys.join("derm-cline-responder")).unwrap()
            )]
        );
        // A relative PATH entry is refused, as for srt's tools.
        let e = companion(
            "derm-cline-responder",
            ".:/usr/bin",
            &writable,
            &s(&planted),
        )
        .unwrap_err();
        assert!(e.contains("relative"), "{e}");
        // An absolute program is checked the same way.
        let e = companion(
            &s(&planted.join("derm-cline-responder")),
            "",
            &writable,
            &work,
        )
        .unwrap_err();
        assert!(e.contains("can write"), "{e}");
        let _ = std::fs::remove_dir_all(&root);
    }

    /// Re-review W4-R1: the companion's PATH keeps only absolute entries
    /// outside the folders the sandbox can write.
    #[test]
    fn the_companions_path_drops_relative_and_writable_entries() {
        let root = std::env::temp_dir().join(format!(
            "derm-pre-path-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4().simple()
        ));
        let work = root.join("work");
        std::fs::create_dir_all(work.join("node_modules/.bin")).unwrap();
        let s = |p: &std::path::Path| p.to_string_lossy().into_owned();
        let w = s(&work);
        // Folders that exist on this OS and that no sandbox here can write,
        // and one under a writable folder that does not exist. Windows has
        // no /usr/bin: its system folders stand in (case 224).
        #[cfg(not(windows))]
        let (system, writable_tmp, missing) = (
            vec!["/usr/local/bin".to_string(), "/usr/bin".to_string()],
            "/tmp".to_string(),
            "/tmp/x".to_string(),
        );
        #[cfg(windows)]
        let (system, writable_tmp, missing) = {
            let sys = std::env::var("SystemRoot").unwrap();
            (
                vec![format!(r"{sys}\System32"), sys],
                s(&root),
                s(&root.join("x")),
            )
        };
        let join = |parts: &[&str]| s(std::path::Path::new(&std::env::join_paths(parts).unwrap()));
        let work_bin = format!("{w}/node_modules/.bin");
        let path = join(&[
            "node_modules/.bin",
            "",
            &work_bin,
            &system[0],
            &system[1],
            ".",
            &missing,
        ]);
        assert_eq!(
            companion_path(&path, &[w.clone(), writable_tmp]),
            join(&[&system[0], &system[1]])
        );
        // Under no boundary nothing is writable to the sandbox; relative
        // and empty entries still go.
        assert_eq!(
            companion_path(&path, &[]),
            join(&[&work_bin, &system[0], &system[1], &missing])
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[cfg(unix)]
    /// Mac test w4, MW4-1: on macOS `/tmp` is a link to `/private/tmp`, so a
    /// PATH entry `/tmp/x` that did not exist at start was compared as
    /// written against the folder's real path and kept, and the sandbox could
    /// make it later and put a `node` there for the companion. Reproduced
    /// here with a link of our own: with a sandbox, an entry that does not
    /// exist is dropped, and one that exists is compared by its real path.
    #[test]
    fn a_missing_path_entry_under_a_linked_writable_folder_is_dropped() {
        let root = std::env::temp_dir().join(format!(
            "derm-pre-link-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4().simple()
        ));
        let real = root.join("real");
        let kept = root.join("kept");
        std::fs::create_dir_all(real.join("bin")).unwrap();
        std::fs::create_dir_all(&kept).unwrap();
        let link = root.join("link");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        let s = |p: &std::path::Path| p.to_string_lossy().into_owned();
        let path = format!(
            "{}:{}:{}:{}",
            s(&link.join("x")),
            s(&link.join("bin")),
            s(&kept),
            s(&root.join("gone"))
        );
        assert_eq!(companion_path(&path, &[s(&link)]), s(&kept));
        assert_eq!(companion_path(&path, &[s(&real)]), s(&kept));
        // With no sandbox nothing can be planted by it; entries stay.
        assert_eq!(companion_path(&path, &[]), path);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[cfg(unix)]
    /// Review W4-S4: lane P's responder is a `#!/usr/bin/env node` script,
    /// so the kernel looks `node` up on PATH when it starts. That `node` runs
    /// outside the sandbox with the chat token, so it is held to the same
    /// rule as the script.
    #[test]
    fn the_companions_interpreter_is_held_to_the_same_rule() {
        #[cfg(unix)]
        use std::os::unix::fs::PermissionsExt;
        let root = std::env::temp_dir().join(format!(
            "derm-pre-interp-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4().simple()
        ));
        let sys = root.join("sys");
        let planted = root.join("work/node_modules/.bin");
        let pkg = root.join("pkg");
        for d in [&sys, &planted, &pkg] {
            std::fs::create_dir_all(d).unwrap();
        }
        let exe = |f: &std::path::Path, body: &str| {
            std::fs::write(f, body).unwrap();
            std::fs::set_permissions(f, std::fs::Permissions::from_mode(0o755)).unwrap();
        };
        exe(&sys.join("node"), "#!/bin/sh\n");
        exe(&planted.join("node"), "#!/bin/sh\necho planted\n");
        exe(
            &pkg.join("derm-cline-responder"),
            "#!/usr/bin/env node\n// x\n",
        );
        let s = |p: &std::path::Path| p.to_string_lossy().into_owned();
        let work = s(&root.join("work"));
        let script = s(&pkg.join("derm-cline-responder"));
        // A planted node first on PATH, in a folder the sandbox can write.
        let path = format!("{}:{}", s(&planted), s(&sys));
        let e = companion(&script, &path, std::slice::from_ref(&work), &work).unwrap_err();
        assert!(e.contains("node"), "{e}");
        // A relative PATH entry that reaches a node, under any boundary.
        let e = companion(
            &script,
            &format!("node_modules/.bin:{}", s(&sys)),
            &[],
            &work,
        )
        .unwrap_err();
        assert!(e.contains("relative"), "{e}");
        // The system node first: derm starts that node with the script.
        let path = format!("{}:{}", s(&sys), s(&planted));
        let got = companion(&script, &path, std::slice::from_ref(&work), &work).unwrap();
        let real = |p: &std::path::Path| s(&std::fs::canonicalize(p).unwrap());
        assert_eq!(
            got,
            vec![
                real(&sys.join("node")),
                real(&pkg.join("derm-cline-responder"))
            ]
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    /// Box test w5 retest, BW5R-4: with Ubuntu's bubblewrap profile in
    /// place the start note names it and no longer offers the sysctl, as the
    /// boundary probe and `derm setup sandbox` say.
    #[cfg(unix)]
    #[test]
    fn bw5r_4_the_start_note_names_ubuntus_bubblewrap_profile() {
        // Since BW5R5-2 the note is for the system bubblewrap, the one
        // Ubuntu's profile attaches to; the temporary one below is not.
        let d = dir_with("bw5r4", &["bwrap", "socat", "rg"]);
        let n = vec![apparmor_note_for(true, true, Some("1\n"), UBUNTU_BWRAP).unwrap()];
        assert!(n[0].contains("bwrap-userns-restrict"), "{n:?}");
        assert!(!n[0].contains("sysctl -w"), "{n:?}");
        // Whatever the sysctl says.
        let n = vec![apparmor_note_for(true, true, Some("0"), UBUNTU_BWRAP).unwrap()];
        assert!(n[0].contains("bwrap-userns-restrict"), "{n:?}");
        // Without the profile, the sysctl's note as before; on macOS none.
        let n = srt_with(&d, true, Some("1"), false, &[], "/").unwrap().0;
        assert!(n[0].contains("sysctl -w"), "{n:?}");
        assert_eq!(
            apparmor_note_for(false, true, Some("1"), UBUNTU_BWRAP),
            None
        );
    }
    /// Box test w5, BW5-10, researched on 8 Nov: under Ubuntu 26.04's
    /// `bwrap-userns-restrict` (apparmor 5.0.2-0ubuntu1~26.04.1, lines 50,
    /// 77, 79) everything bubblewrap starts runs under `unpriv_bwrap`, which
    /// denies every capability; srt 0.0.81's `apply-seccomp` makes a user
    /// namespace and opens `/proc/self/setgroups`, which needs CAP_SYS_ADMIN
    /// there (Linux 7.0 `fs/proc/base.c:3193-3196`); bubblewrap 0.11.1 sets
    /// no_new_privs (`bubblewrap.c:2915`), so no profile for srt's own
    /// programs can widen what they hold (`security/apparmor/domain.c:
    /// 980-992`). The note says that, says what a root fix costs, and no
    /// longer sends the reader to srt's README, whose Ubuntu note is about
    /// 24.04, where that profile is not loaded.
    #[test]
    fn bw5_10_the_note_says_why_srt_fails_under_ubuntus_bubblewrap_profile() {
        let n = apparmor_note_for(true, true, Some("1"), UBUNTU_BWRAP).unwrap();
        for want in [
            "bwrap-userns-restrict",
            "unpriv_bwrap",
            "denies every capability",
            "CAP_SYS_ADMIN",
            "/proc/self/setgroups",
            "no_new_privs",
            "any local program",
            "derm makes no such change",
            "--boundary sbx",
            "docs/install/linux.md",
        ] {
            assert!(n.contains(want), "{want:?} not in {n}");
        }
        assert!(!n.contains("srt README"), "{n}");
        assert!(!n.contains("allows userns for the bubblewrap"), "{n}");
        assert_eq!(
            apparmor_note_for(true, true, Some("0"), UBUNTU_BWRAP),
            Some(n)
        );
    }

    /// Box retest of fix pass 13r, BW5R5-2: Ubuntu's profile attaches to
    /// `/usr/bin/bwrap` by path (its line 15), so a bubblewrap srt runs from
    /// anywhere else (the copy `docs/install/linux.md` describes, run on the
    /// box: srt started) is not under it, and the note must not say srt
    /// cannot start.
    #[cfg(unix)]
    #[test]
    fn bw5r5_2_no_bubblewrap_profile_note_for_a_bwrap_it_does_not_attach_to() {
        let d = dir_with("bw5r52", &["bwrap", "socat", "rg"]);
        let n = srt_with(&d, true, Some("1"), true, &[], "/").unwrap().0;
        assert!(
            n.iter().all(|x| !x.contains("bwrap-userns-restrict")),
            "{n:?}"
        );
        assert!(apparmor_note_for(true, true, Some("1"), "/usr/bin/bwrap").is_some());
        assert!(
            apparmor_note_for(true, true, Some("1"), "/usr/local/libexec/derm-srt/bwrap").is_none()
        );
    }

    /// BW5-10's other half: with only the sysctl (Ubuntu 24.04, where
    /// `bwrap-userns-restrict` ships in apparmor-profiles' extra profiles,
    /// not loaded), Ubuntu's own bubblewrap profile is not a fix for srt:
    /// loaded, it fails srt as on 26.04.
    #[test]
    fn bw5_10_the_sysctl_note_does_not_offer_ubuntus_own_profile() {
        let n = apparmor_note_for(true, false, Some("1"), UBUNTU_BWRAP).unwrap();
        assert!(
            n.contains("sysctl -w kernel.apparmor_restrict_unprivileged_userns=0"),
            "{n}"
        );
        assert!(n.contains("not Ubuntu's own bwrap-userns-restrict"), "{n}");
        assert!(n.contains("any local program"), "{n}");
        assert!(n.contains("docs/install/linux.md"), "{n}");
        assert_eq!(
            apparmor_note_for(true, false, Some("0"), UBUNTU_BWRAP),
            None
        );
    }
}
