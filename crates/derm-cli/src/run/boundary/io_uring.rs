//! `run.start`'s `ioUring` mark (case 128, miss 5; `contracts/events.md`
//! section 5). Tony, 4 Nov: "io_uring leave on in sandbox", so derm never
//! changes `kernel.io_uring_disabled`; it says where the audit feed cannot
//! see io_uring operations instead.
//!
//! - Linux, no boundary: `not-audited`. auditd's syscall rules do not see
//!   io_uring operations (case 69), and nothing blocks them (lane T, by run:
//!   `io_uring_setup` returned a ring outside srt).
//! - Linux, srt: `blocked`. srt 0.0.81's seccomp helper refuses
//!   `io_uring_setup`, `io_uring_enter` and `io_uring_register` (its README,
//!   line 1214; lane T, by run: `EPERM` under srt with derm's settings). The
//!   helper is skipped when `network.allowAllUnixSockets` is set or the
//!   architecture has no helper binary (x86_64 and aarch64 ship one,
//!   `dist/sandbox/linux-sandbox-utils.js:2895-2911`): then `not-audited`.
//!   `blocked` is new to the schema with request T-1.
//! - sbx, on any system: `own-kernel`. The agent runs on the VM's kernel;
//!   the host's audit rules never applied to it.
//! - Elsewhere (macOS, Windows, no sbx): absent. There is no io_uring.

use serde_json::Value;

/// The mark for a chat under `boundary`, with srt's settings text when it
/// has one. `linux` and `arch` are the build's (`cfg!` in the caller).
pub(crate) fn mark(
    boundary: &str,
    srt_settings: Option<&str>,
    linux: bool,
    arch: &str,
) -> Option<&'static str> {
    match boundary {
        "sbx" => Some("own-kernel"),
        "none" if linux => Some("not-audited"),
        "srt" if linux => {
            let helper = matches!(arch, "x86_64" | "aarch64");
            let all_sockets = srt_settings
                .and_then(|t| serde_json::from_str::<Value>(t).ok())
                .and_then(|v| v.pointer("/network/allowAllUnixSockets").cloned())
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            Some(if helper && !all_sockets {
                "blocked"
            } else {
                "not-audited"
            })
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_boundary_gets_its_mark() {
        let derm_srt = r#"{"network":{"allowedDomains":[],"deniedDomains":[]}}"#;
        assert_eq!(mark("none", None, true, "x86_64"), Some("not-audited"));
        assert_eq!(mark("srt", Some(derm_srt), true, "x86_64"), Some("blocked"));
        assert_eq!(
            mark("srt", Some(derm_srt), true, "aarch64"),
            Some("blocked")
        );
        // No helper binary for the architecture, or the helper turned off.
        assert_eq!(
            mark("srt", Some(derm_srt), true, "riscv64"),
            Some("not-audited")
        );
        let all = r#"{"network":{"allowAllUnixSockets":true}}"#;
        assert_eq!(mark("srt", Some(all), true, "x86_64"), Some("not-audited"));
        assert_eq!(mark("sbx", None, true, "x86_64"), Some("own-kernel"));
        assert_eq!(mark("sbx", None, false, "aarch64"), Some("own-kernel"));
        // No io_uring off Linux.
        assert_eq!(mark("none", None, false, "aarch64"), None);
        assert_eq!(mark("srt", Some(derm_srt), false, "aarch64"), None);
    }

    /// srt's filter, by run, on this machine (Linux with srt under
    /// `/tmp/cli`, as the contract checks install it): a ring outside srt,
    /// `EPERM` inside it. Skipped where srt or Python is not there.
    #[test]
    fn srt_refuses_io_uring_setup_where_it_runs() {
        if !cfg!(target_os = "linux") {
            return;
        }
        let srt = std::path::Path::new("/tmp/cli/node_modules/.bin/srt");
        let py = std::path::Path::new("/usr/bin/python3");
        if !srt.exists() || !py.exists() || std::fs::metadata("/usr/bin/bwrap").is_err() {
            eprintln!("skipped: srt, bwrap or python3 not installed");
            return;
        }
        let d = std::env::temp_dir().join(format!("derm-iou-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        let script = d.join("iou.py");
        std::fs::write(
            &script,
            "import ctypes\nlibc=ctypes.CDLL(None,use_errno=True)\np=ctypes.create_string_buffer(120)\n\
             fd=libc.syscall(425,4,p)\nprint('ring' if fd>=0 else 'errno %d' % ctypes.get_errno())\n",
        )
        .unwrap();
        let settings = d.join("s.json");
        std::fs::write(
            &settings,
            format!(
                r#"{{"network":{{"allowedDomains":[],"deniedDomains":[]}},"filesystem":{{"denyRead":[],"allowWrite":["{}"],"denyWrite":[]}}}}"#,
                d.display()
            ),
        )
        .unwrap();
        let outside = std::process::Command::new(py)
            .args(["-I", script.to_str().unwrap()])
            .output()
            .unwrap();
        let inside = std::process::Command::new(srt)
            .args([
                "--settings",
                settings.to_str().unwrap(),
                "--",
                "/usr/bin/python3",
                "-I",
                script.to_str().unwrap(),
            ])
            .output()
            .unwrap();
        let _ = std::fs::remove_dir_all(&d);
        let outside = String::from_utf8_lossy(&outside.stdout).trim().to_string();
        let inside = String::from_utf8_lossy(&inside.stdout).trim().to_string();
        if outside != "ring" {
            eprintln!("skipped: io_uring is off on this kernel ({outside})");
            return;
        }
        assert_eq!(inside, "errno 1", "srt's helper must refuse io_uring_setup");
    }
}
