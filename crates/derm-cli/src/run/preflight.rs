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
    let needed: &[(&str, &str)] = if linux {
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
            Some(p) if !p.starts_with('/') => {
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
    if linux && userns_sysctl.map(str::trim) == Some("1") {
        notes.push(
            "derm run: kernel.apparmor_restrict_unprivileged_userns is 1, which takes the capabilities srt's bubblewrap and seccomp layer need (srt README, Ubuntu 24.04+ note); unless an AppArmor profile grants `userns` to srt's binaries, srt will fail with \"Permission denied\" on /proc/self/setgroups. The fix is root's: `sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0`, or such a profile."
                .to_string(),
        );
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
    path_var
        .split(':')
        .filter(|d| d.starts_with('/'))
        .filter(|d| {
            let real = match std::fs::canonicalize(d) {
                Ok(r) => r.to_string_lossy().into_owned(),
                Err(_) if !writable.is_empty() => return false,
                Err(_) => d.to_string(),
            };
            !writable.iter().any(|w| under(&real, w) || under(d, w))
        })
        .collect::<Vec<_>>()
        .join(":")
}

/// One program, found and held to the companion's rule, as an absolute path.
fn checked(
    program: &str,
    path_var: &str,
    writable: &[String],
    cwd: &str,
) -> Result<String, String> {
    let found = if program.starts_with('/') {
        Path::new(program).is_file().then(|| program.to_string())
    } else if program.contains('/') {
        return Err(format!(
            "{program}: a relative path; give an absolute one or a bare name on PATH"
        ));
    } else {
        first_on_path(path_var, program, cwd)
    };
    let Some(p) = found else {
        return Err(format!("{program} not found on PATH; it answers the harness's gated calls, and without it they wait and are denied"));
    };
    if !p.starts_with('/') {
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
fn first_on_path(path_var: &str, bin: &str, cwd: &str) -> Option<String> {
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

/// `path` is `dir` or inside it, both compared canonical where they exist.
fn under(path: &str, dir: &str) -> bool {
    let dir = std::fs::canonicalize(dir)
        .map(|d| d.to_string_lossy().into_owned())
        .unwrap_or_else(|_| dir.to_string());
    let dir = dir.trim_end_matches('/');
    path == dir || path.starts_with(&format!("{dir}/"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dir_with(name: &str, bins: &[&str]) -> String {
        let d = std::env::temp_dir().join(format!("derm-pre-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        for b in bins {
            let p = d.join(b);
            std::fs::write(&p, "#!/bin/sh\n").unwrap();
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        d.to_string_lossy().into_owned()
    }

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

    #[test]
    fn a_file_that_is_not_executable_does_not_count() {
        let d = dir_with("noexec", &["bwrap", "socat"]);
        std::fs::write(Path::new(&d).join("rg"), "x").unwrap();
        assert!(srt(&d, true, None, &[], "/").is_err());
    }

    /// Security review L8: the companion runs outside the sandbox with the
    /// chat token, so it is held to the same rule as srt's own tools.
    #[test]
    fn the_companion_is_never_taken_from_a_folder_the_sandbox_can_write() {
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
        let path =
            format!("node_modules/.bin::{w}/node_modules/.bin:/usr/local/bin:/usr/bin:.:/tmp/x");
        assert_eq!(
            companion_path(&path, &[w.clone(), "/tmp".to_string()]),
            "/usr/local/bin:/usr/bin"
        );
        // Under no boundary nothing is writable to the sandbox; relative
        // and empty entries still go.
        assert_eq!(
            companion_path(&path, &[]),
            format!("{w}/node_modules/.bin:/usr/local/bin:/usr/bin:/tmp/x")
        );
        let _ = std::fs::remove_dir_all(&root);
    }

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

    /// Review W4-S4: lane P's responder is a `#!/usr/bin/env node` script,
    /// so the kernel looks `node` up on PATH when it starts. That `node` runs
    /// outside the sandbox with the chat token, so it is held to the same
    /// rule as the script.
    #[test]
    fn the_companions_interpreter_is_held_to_the_same_rule() {
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
}
