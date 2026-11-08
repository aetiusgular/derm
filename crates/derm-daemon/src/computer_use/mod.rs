//! Computer use, served by the daemon (`derm cu`; toolkit plan T1.5, lane K).
//! Copied from the fork (`src-tauri/src/computer_use/` at `159ef3e`, wave 3
//! lane C); lane K took it out of Tauri. What changed is listed here; the
//! engine (`core.rs`, `facade.rs`, `grants.rs`, `manifest.rs`, `apps.rs`,
//! `helper_client.rs`) is the fork's, with its user-facing words changed
//! from MonoCode to derm.
//!
//! - The grants sit with the separate helper app, which embeds Cua Driver
//!   (`macos/computer-use-helper/`, unchanged). The daemon starts it through
//!   Launch Services and talks to it over one Unix socket; the helper takes
//!   only the process it was started for, checked by code signature in a
//!   release build and by pid in a debug one.
//! - A harness reaches computer use through `derm-daemon cu-mcp`, a stdio MCP
//!   server (`bridge_cli.rs`, `relay.rs`). It presents the chat token `derm
//!   run` gave the harness (`DERM_CHAT_TOKEN` or `DERM_CHAT_TOKEN_FILE`), not a
//!   token of its own: the fork's `MONOCODE_CU_TOKEN` reached the agent's
//!   shell, and here no new secret enters the harness's environment (lane A,
//!   wave 1; `service.rs`).
//! - Apps are granted per chat, only through the daemon's approver channel
//!   (`approve`), and held in memory for the chat's run (`grants.rs`). The
//!   chat's `run.stop` revokes its tokens; the service then ends the chat's
//!   grants and runtime.
//! - Gone with Tauri: the window's cards and commands, the menu bar Stop
//!   item, and the spawn-argument scan that gave MonoCode's harness children
//!   their token (`configure_child`); its tests went with it.

#[path = "app_pids.rs"]
mod app_pids;
#[path = "apps.rs"]
mod apps;
#[path = "bridge.rs"]
mod bridge;
#[path = "bridge_cli.rs"]
pub mod bridge_cli;
#[path = "core.rs"]
mod core;
#[cfg(target_os = "linux")]
mod desktop;
#[cfg(target_os = "linux")]
#[path = "direct.rs"]
mod direct;
#[path = "facade.rs"]
mod facade;
#[path = "grants.rs"]
mod grants;
#[path = "helper_client.rs"]
mod helper_client;
#[path = "manifest.rs"]
mod manifest;
#[path = "relay.rs"]
pub mod relay;
#[path = "service.rs"]
pub mod service;
#[path = "settings.rs"]
pub mod settings;
#[path = "tool.rs"]
pub mod tool;

use std::path::PathBuf;
use std::sync::Arc;

use self::core::{Core, HelperLauncher};
pub use self::core::{Notice, Status, StopReport};
use self::helper_client::{EventSink, HelperClient};

/// The helper's bundle name, as `macos/computer-use-helper/bundle.sh` builds
/// it. Renamed with the toolkit (toolkit plan, section 11, call 1).
pub const HELPER_APP: &str = "derm Computer Use.app";
/// The bridge's endpoint file, beside the daemon's socket (0600).
pub const ENDPOINT_FILE: &str = "cu.endpoint";
/// The MCP server name to register `derm-daemon cu-mcp` under. Claude Code
/// reserves `computer-use` (lane C, wave 1).
pub const SERVER_NAME: &str = "derm_cu";

/// The helper launcher for this machine: the signed helper app on macOS,
/// and on Linux the daemon's own thread with a `cua-driver mcp` child per
/// runtime (`direct.rs`, lane U).
fn system_launcher(data: Option<PathBuf>) -> Box<dyn HelperLauncher> {
    #[cfg(target_os = "linux")]
    {
        let home = std::env::var_os("HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("/"));
        let uid = derm_core::platform::real_user();
        let driver = direct::debug_driver(uid)
            .or_else(|| direct::find_driver(&direct::driver_candidates(Some(&home)), uid));
        Box::new(direct::DirectLauncher {
            driver,
            data,
            env: std::env::vars().collect(),
            home,
            proc_root: PathBuf::from("/proc"),
            gnome_shell: PathBuf::from(desktop::GNOME_SHELL),
        })
    }
    #[cfg(not(target_os = "linux"))]
    Box::new(SystemLauncher {
        app: helper_location(),
        data,
    })
}

/// Where computer use runs: macOS (the helper app) and Linux (`direct.rs`).
/// Windows is lane Z's.
pub const SUPPORTED: bool = cfg!(any(target_os = "macos", target_os = "linux"));

/// Where the helper is looked for. A debug build also takes `DERM_CU_HELPER`,
/// for a helper built beside the repository. A release build looks only in
/// `/Applications`, a folder an installer writes. The daemon is a plain
/// binary, not a bundle, so the fork's `Contents/Helpers` has no equivalent.
#[cfg_attr(target_os = "linux", allow(dead_code, reason = "Linux runs direct.rs"))]
fn helper_location() -> Option<PathBuf> {
    #[cfg(debug_assertions)]
    if let Some(path) = std::env::var_os("DERM_CU_HELPER") {
        return Some(PathBuf::from(path));
    }
    Some(PathBuf::from("/Applications").join(HELPER_APP))
}

#[cfg_attr(target_os = "linux", allow(dead_code, reason = "Linux runs direct.rs"))]
struct SystemLauncher {
    app: Option<PathBuf>,
    data: Option<PathBuf>,
}

impl HelperLauncher for SystemLauncher {
    fn location(&self) -> Option<String> {
        cfg!(target_os = "macos")
            .then(|| self.app.as_ref().map(|p| p.to_string_lossy().into_owned()))
            .flatten()
    }

    fn installed(&self) -> bool {
        self.app
            .as_ref()
            .is_some_and(|app| app.join("Contents").join("MacOS").is_dir())
    }

    /// The helper writes each runtime's recording under
    /// `<daemon data>/computer-use/recordings/<runtime>/`.
    fn recordings_root(&self) -> Option<PathBuf> {
        Some(self.data.as_ref()?.join("computer-use").join("recordings"))
    }
    /// BW5-19's Mac half: this user's processes of the approved app, read
    /// with libproc, so a listing reaches the helper with a pid.
    fn app_pids(&self, app: &std::path::Path) -> Option<Vec<u64>> {
        app_pids::pids_in_app(app)
    }
    fn lists_by_app(&self) -> bool {
        cfg!(target_os = "macos")
    }

    #[cfg(not(target_os = "macos"))]
    fn launch(&self, _events: EventSink) -> Result<HelperClient, String> {
        Err("Computer use runs on macOS only.".into())
    }

    /// Runs `/usr/bin/open -n -g -a <helper> --args serve ...` (rules
    /// section 5, item 2: a process the daemon starts outside any sandbox).
    /// Launch Services makes the helper its own app, so macOS credits the
    /// Accessibility and Screen Recording grants to it, not to the daemon.
    /// `--derm-pid` is the helper's own flag name: the daemon's pid.
    #[cfg(target_os = "macos")]
    fn launch(&self, events: EventSink) -> Result<HelperClient, String> {
        use std::os::unix::fs::DirBuilderExt;
        use std::os::unix::net::UnixStream;
        use std::process::Command;
        use std::time::{Duration, Instant};

        let app = self
            .app
            .as_ref()
            .filter(|_| self.installed())
            .ok_or("The computer-use helper is not installed in /Applications.")?;
        let data = self
            .data
            .as_ref()
            .ok_or("No daemon data folder.")?
            .join("computer-use");
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&data)
            .map_err(|e| e.to_string())?;
        // A fresh private folder per launch for the socket. $TMPDIR is this
        // user's own; the random name keeps a stale or planted socket out.
        let dir = std::env::temp_dir().join(format!(
            "dermcu-{}",
            &uuid::Uuid::new_v4().simple().to_string()[..10]
        ));
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&dir)
            .map_err(|e| format!("Cannot make the helper's folder: {e}"))?;
        let socket = dir.join("h.sock");
        let status = Command::new("/usr/bin/open")
            .args(["-n", "-g", "-a"])
            .arg(app)
            .arg("--args")
            .arg("serve")
            .arg("--socket")
            .arg(&socket)
            .arg("--derm-pid")
            .arg(std::process::id().to_string())
            .arg("--data")
            .arg(&data)
            .status()
            .map_err(|e| format!("Cannot start the computer-use helper: {e}"))?;
        if !status.success() {
            return Err("macOS did not open the computer-use helper.".into());
        }
        let started = Instant::now();
        let stream = loop {
            match UnixStream::connect(&socket) {
                Ok(stream) => break stream,
                Err(_) if started.elapsed() < Duration::from_secs(15) => {
                    std::thread::sleep(Duration::from_millis(100))
                }
                Err(error) => {
                    return Err(format!("The computer-use helper did not answer: {error}"))
                }
            }
        };
        let reader = stream.try_clone().map_err(|e| e.to_string())?;
        Ok(HelperClient::new(reader, stream, events))
    }
}

/// The engine with the system's helper launcher. `notify` hears of new
/// cards and changes; `service.rs` turns cards into `approve` requests.
pub(crate) fn system_core(
    data: Option<PathBuf>,
    notify: Box<dyn Fn(Notice) + Send + Sync>,
) -> Arc<Core> {
    Core::new(system_launcher(data), notify, SUPPORTED)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The helper keeps its own copy of the relayed tool list. Both must say
    /// the same, name for name.
    #[test]
    fn the_helpers_tool_list_matches_the_daemons() {
        let source = include_str!("../../../../macos/computer-use-helper/src/tools.rs");
        let section = |name: &str| -> Vec<String> {
            let start = source.find(name).expect("list in helper");
            let body = &source[start..];
            let body = &body[body.find('[').unwrap() + 1..body.find("];").unwrap()];
            body.split('"')
                .skip(1)
                .step_by(2)
                .map(str::to_string)
                .collect()
        };
        let allowed: Vec<String> = manifest::ALLOWED_TOOLS
            .iter()
            .map(|s| s.to_string())
            .collect();
        assert_eq!(section("pub const ALLOWED_TOOLS"), allowed);
        let helper_only: Vec<String> = manifest::HELPER_ONLY_TOOLS
            .iter()
            .map(|s| s.to_string())
            .collect();
        assert_eq!(section("pub const HELPER_ONLY_TOOLS"), helper_only);
    }

    #[test]
    fn a_release_build_looks_for_the_helper_only_in_applications() {
        // A debug build may take DERM_CU_HELPER; without it, both builds look
        // in /Applications, never next to the daemon's binary, which can sit
        // in a folder the agent writes (~/.cargo/bin).
        if std::env::var_os("DERM_CU_HELPER").is_none() {
            assert_eq!(
                helper_location(),
                Some(PathBuf::from("/Applications/derm Computer Use.app"))
            );
        }
    }

    #[test]
    fn off_macos_and_linux_the_launcher_refuses_and_the_engine_says_unsupported() {
        let core = system_core(None, Box::new(|_| {}));
        if SUPPORTED {
            // Lane U: Linux runs `direct.rs`; with no data folder it cannot
            // start a runtime, and the grant still needs a card.
            assert_ne!(core.status().helper, "unsupported");
            return;
        }
        assert_eq!(core.status().helper, "unsupported");
        core.set_chat("c1", true);
        assert!(core
            .grant("c1", "pi", "com.apple.calculator", None, None)
            .is_err());
    }
}
