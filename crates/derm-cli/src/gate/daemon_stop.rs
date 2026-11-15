//! A command that stops derm's daemon or one of its feeds asks (fix pass 6;
//! note BE section 2.3, item 3, Tony's call of 15 Nov).
//!
//! Windows test w6 retest 3 (WW6R3-1, run on the box): with no boundary the
//! agent ran `Stop-Process` on `derm-daemon` (the same user may), and the
//! gate then fell back to a file the agent could write. The gate no longer
//! falls back (`gate/taint/mod.rs`), and the daemon keeps taint across a
//! restart (`derm-daemon` `taint`); this check makes the stop itself a
//! question, so a mistake is caught before it lands.
//!
//! **Best effort.** It reads the shell text of a shell tool's call, through
//! wrappers, `sh -c` and `eval` (`taint::shell::effective`), and asks when a
//! program that stops or signals a process or a service (`kill`, `pkill`,
//! `killall`, `systemctl`, `launchctl`, `taskkill`, `sc`, PowerShell's
//! `Stop-Process`, `Stop-Service` and `Remove-Service`) appears in the same
//! call as one of derm's own service names. An agent that wants to stop the
//! daemon finds another way (a script it writes first, a signal by a pid it
//! read earlier); with no boundary the same user can (note BE section 2.3),
//! and `derm status` says so. Under srt and sbx the daemon runs outside the
//! sandbox, where the agent cannot signal it (srt's PID namespace on Linux,
//! the VM under sbx).
//!
//! Only raises: an allow becomes an ask; an ask or a deny keeps its answer.

use derm_core::policy::Action;

use super::core::{GateAnswer, GateCall};

/// Programs that stop or signal a process or a service, by their base name,
/// in lower case (PowerShell's cmdlets are not case sensitive).
const STOPPERS: &[&str] = &[
    "kill",
    "pkill",
    "killall",
    "skill",
    "systemctl",
    "launchctl",
    "service",
    "taskkill",
    "taskkill.exe",
    "sc",
    "sc.exe",
    "stop-process",
    "spps",
    "stop-service",
    "remove-service",
];

/// derm's own long-running programs and service names: the daemon
/// (`derm-daemon`, its systemd unit, its launchd label
/// `io.github.aetiusgular.derm.daemon`), the Linux feed and the Windows
/// reader service, which hold the record a chat's taint is read beside.
const NAMES: &[&str] = &[
    "derm-daemon",
    "io.github.aetiusgular.derm.daemon",
    "derm-audit-feed",
    "derm-sysmon",
];

/// Service managers, which stop a service only with one of [`VERBS`].
const MANAGERS: &[&str] = &["systemctl", "launchctl", "service", "sc", "sc.exe"];

/// The words with which a service manager stops, signals or unloads a
/// service (systemctl(1), launchctl(1), service(8), `sc.exe`'s own help).
const VERBS: &[&str] = &[
    "stop",
    "kill",
    "disable",
    "mask",
    "restart",
    "try-restart",
    "reload-or-restart",
    "bootout",
    "unload",
    "remove",
    "delete",
];

/// Whether one command's words stop or signal something.
fn stopping(words: &[String]) -> bool {
    let Some(first) = words.first() else {
        return false;
    };
    let base = first.rsplit(['/', '\\']).next().unwrap_or(first);
    if !STOPPERS.contains(&base) {
        return false;
    }
    !MANAGERS.contains(&base) || words[1..].iter().any(|w| VERBS.contains(&w.as_str()))
}

/// The derm service a call's shell text stops, if it does.
pub fn stops(text: &str) -> Option<&'static str> {
    let lower = text.to_ascii_lowercase();
    let named = NAMES.iter().copied().find(|n| lower.contains(n))?;
    let (cmds, _) = super::taint::shell::effective(&lower);
    // The shell's reading, then each piece split at a pipe, a separator or
    // a substitution by its words as written: a Windows path such as
    // `C:\Windows\System32\taskkill.exe` loses its backslashes to the
    // shell's quoting, and PowerShell has no POSIX reading.
    let raw = lower
        .split(['|', ';', '&', '\n', '(', ')', '`'])
        .map(|piece| {
            piece
                .split_whitespace()
                .map(|w| w.trim_start_matches('$').to_string())
                .filter(|w| !w.is_empty())
                .collect::<Vec<_>>()
        });
    let stopper = cmds.iter().any(|c| stopping(&c.words)) || raw.into_iter().any(|w| stopping(&w));
    stopper.then_some(named)
}

/// Raises an allow to an ask when a shell call stops one of derm's own
/// services.
pub fn adjust(mut answer: GateAnswer, call: &GateCall) -> GateAnswer {
    if answer.action != Action::Allow || !super::core::is_shell_tool(&answer.normalized_tool) {
        return answer;
    }
    let Ok(text) = super::core::input_text_for(&answer.normalized_tool, &call.tool_input) else {
        return answer;
    };
    if let Some(name) = stops(&text) {
        answer.action = Action::Ask;
        answer.reason = format!(
            "stops derm's {name}, which keeps this chat's record and taint (a best-effort check); {}",
            answer.reason
        );
        answer.updated_input = None;
    }
    answer
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_ways_to_stop_derms_daemon_are_seen() {
        for text in [
            "systemctl --user stop derm-daemon",
            "systemctl --user kill derm-daemon.service",
            "systemctl --user disable --now derm-daemon",
            "launchctl bootout gui/501/io.github.aetiusgular.derm.daemon",
            "launchctl unload ~/Library/LaunchAgents/io.github.aetiusgular.derm.daemon.plist",
            "pkill derm-daemon",
            "pkill -f derm-daemon",
            "killall -9 derm-daemon",
            "kill $(pidof derm-daemon)",
            "kill -9 `pgrep derm-daemon`",
            "sudo -u me pkill derm-daemon",
            "sh -c 'pkill derm-daemon'",
            "Stop-Process -Name derm-daemon -Force",
            "Get-Process derm-daemon | Stop-Process",
            "taskkill /IM derm-daemon.exe /F",
            "C:\\Windows\\System32\\taskkill.exe /im derm-daemon.exe",
            "sc.exe stop derm-sysmon",
            "systemctl --user stop derm-audit-feed",
        ] {
            assert!(stops(text).is_some(), "{text}");
        }
    }

    #[test]
    fn a_command_that_only_names_derm_or_only_kills_is_not() {
        for text in [
            "systemctl --user status derm-daemon",
            "journalctl --user -u derm-daemon",
            "ps aux | grep derm-daemon",
            "kill %1",
            "pkill node",
            "git commit -m 'kill the derm-daemon bug'",
            "echo derm-daemon",
            "derm status",
        ] {
            assert!(stops(text).is_none(), "{text}");
        }
    }

    #[test]
    fn an_allowed_stop_asks_and_nothing_else_changes() {
        let answer = |a: Action| GateAnswer {
            action: a,
            normalized_tool: "bash".into(),
            reason: "rule bash allow".into(),
            updated_input: None,
            redacted: 0,
            ask_timeout_seconds: 60,
        };
        let call = |cmd: &str| GateCall {
            harness: "claude-code".into(),
            tool: "Bash".into(),
            tool_input: serde_json::json!({"command": cmd}),
            chat: Some("c-1".into()),
            tool_use_id: Some("toolu_1".into()),
            full_access: None,
        };
        let r = adjust(answer(Action::Allow), &call("pkill derm-daemon"));
        assert_eq!(r.action, Action::Ask, "{}", r.reason);
        assert!(
            r.reason.contains("stops derm's derm-daemon"),
            "{}",
            r.reason
        );
        let r = adjust(answer(Action::Deny), &call("pkill derm-daemon"));
        assert_eq!(r.action, Action::Deny, "a deny stays");
        let r = adjust(answer(Action::Allow), &call("ls"));
        assert_eq!(r.action, Action::Allow);
        let mut other = answer(Action::Allow);
        other.normalized_tool = "write".into();
        let r = adjust(other, &call("pkill derm-daemon"));
        assert_eq!(r.action, Action::Allow, "a shell tool's only");
    }
}
