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
//! wrappers, `sh -c`, `eval`, PowerShell's `-Command` and `-EncodedCommand`
//! and cmd's `/c` (`taint::shell::effective`; WW6R4-1), and asks when a
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

/// The derm service a call's shell text stops, if it does: a command that
/// stops or signals something and, among its own words, names one of
/// derm's services or a word a process matcher reads as one (`derm`,
/// `derm-d`, `derm*`, `'derm-*'`; fix pass 6's review, and its re-review:
/// the name must be the stopping command's own, so `cargo test -p
/// derm-cli; pkill node` does not ask).
pub fn stops(text: &str) -> Option<&'static str> {
    let lower = text.to_ascii_lowercase();
    let name_of = |words: &[String]| -> Option<&'static str> {
        words.iter().find_map(|w| {
            NAMES
                .iter()
                .copied()
                .find(|n| w.contains(n))
                .or_else(|| derm_like(w).then_some("derm-daemon"))
        })
    };
    // The text as written, so a PowerShell `-EncodedCommand`'s base64 keeps
    // its case (WW6R4-1); each word is compared in lower case.
    let (cmds, _) = super::taint::shell::effective(text);
    for c in &cmds {
        let words: Vec<String> = c.words.iter().map(|w| w.to_ascii_lowercase()).collect();
        if stopping(&words) {
            if let Some(n) = name_of(&words) {
                return Some(n);
            }
        }
    }
    // Each command split at a pipe or a separator, by its words as written
    // (a substitution's words with it, so `kill $(pidof derm-daemon)` names
    // the daemon): a Windows path such as
    // `C:\\Windows\\System32\\taskkill.exe` loses its backslashes to the
    // shell's quoting, and PowerShell has no POSIX reading.
    // A pipeline is one: `Get-Process derm-daemon | Stop-Process`.
    let words_of = |t: &str| -> Vec<String> {
        t.split(|c: char| c.is_whitespace() || "()`".contains(c))
            .map(|w| {
                // A quote a command string opened or closed is not part of
                // the word (`-Command "Get-Process derm-daemon | Stop-Process"`).
                w.trim_matches(['\'', '"'])
                    .trim_start_matches('$')
                    .to_string()
            })
            .filter(|w| !w.is_empty())
            .collect()
    };
    for line in lower.split([';', '&', '\n']) {
        if line.split('|').any(|cmd| stopping(&words_of(cmd))) {
            if let Some(n) = name_of(&words_of(line)) {
                return Some(n);
            }
        }
    }
    // PowerShell's `(Get-Process derm-daemon).Kill()`: the process the
    // getter names, then its Kill.
    let mut rest = lower.as_str();
    while let Some(i) = rest.find("get-process") {
        let after = &rest[i..];
        let close = after.find(')').unwrap_or(after.len());
        let words: Vec<String> = after[..close]
            .split_whitespace()
            .skip(1)
            .map(str::to_string)
            .collect();
        if after[close..].starts_with(").kill(") {
            if let Some(n) = name_of(&words) {
                return Some(n);
            }
        }
        rest = &after["get-process".len()..];
    }
    None
}

/// A word naming derm's programs loosely: `derm`, a name starting `derm-`,
/// or either with a glob, quoted or not.
fn derm_like(w: &str) -> bool {
    let w = w.trim_matches(['\'', '"']);
    let w = w.rsplit(['/', '\\']).next().unwrap_or(w);
    let Some(rest) = w.strip_prefix("derm") else {
        return false;
    };
    rest.is_empty()
        || rest == "*"
        || rest == ".*"
        || rest.starts_with('-')
            && rest[1..]
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || "-*.".contains(c))
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

    /// Fix pass 6's review: names a process matcher reads loosely.
    #[test]
    fn loose_names_and_powershells_kill_are_seen() {
        for text in [
            "pkill derm",
            "pkill -f derm-d",
            "killall -r derm",
            "Stop-Process -Name derm*",
            "taskkill /IM derm* /F",
            "systemctl --user stop 'derm-*'",
            "(Get-Process derm-daemon).Kill()",
        ] {
            assert!(stops(text).is_some(), "{text}");
        }
        for text in [
            "pkill dermatology",
            "kill 4242",
            "ls derm",
            "echo derm-daemon",
            "cat ~/.derm/policy.json",
            // Fix pass 6's re-review: the name is not the stopper's own.
            "cargo test -p derm-cli; pkill node",
            "kill %1 && ls target/debug/derm",
            "kill $PID; cd crates/derm-daemon",
            "node -e \"c.kill()\" packages/derm-pi/x.js",
        ] {
            assert!(stops(text).is_none(), "{text}");
        }
    }

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

    /// Windows test w6 retest 4 (WW6R4-1, run on the box): Claude Code's Bash
    /// ran `powershell.exe -NoProfile -Command "Stop-Process -Name
    /// derm-daemon -Force"` and the gate allowed it. PowerShell 5.1 and 7.6
    /// take any prefix of `-Command` (`-c`, `-co`, `-com`), `/` for `-`, any
    /// case, and the rest of the line as the command; `-e`, `-en`, `-ec`,
    /// `-enc` and `/enc` take base64 of UTF-16LE; 5.1 runs a bare word as the
    /// command; cmd.exe runs what follows `/c`, `/k` or `/r`, with or without
    /// a space (`w11a.ps1` on the box, 15 Nov). dcg reads the same forms
    /// (`src/heredoc.rs`, `extract_windows_inline_scripts`, at 37d1473).
    #[test]
    fn ww6r4_1_a_stop_inside_another_shells_command_string_asks() {
        let enc = |s: &str| {
            use base64::Engine;
            let bytes: Vec<u8> = s.encode_utf16().flat_map(u16::to_le_bytes).collect();
            base64::engine::general_purpose::STANDARD.encode(bytes)
        };
        let stop = enc("Stop-Process -Name derm-daemon -Force");
        for text in [
            "powershell.exe -NoProfile -Command \"Stop-Process -Name derm-daemon -Force\"".to_string(),
            "pwsh -c 'Stop-Process -Name derm-daemon'".to_string(),
            "powershell -nop -ex bypass -w hidden -com \"Get-Process derm-daemon | Stop-Process\"".to_string(),
            "PowerShell /COMMAND Stop-Process -Name derm-daemon".to_string(),
            "powershell Stop-Process -Name derm-daemon".to_string(),
            "\"C:\\WINDOWS\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\" -Command \"Stop-Process -Name derm-daemon\"".to_string(),
            "bash -c 'powershell.exe -Command \"Stop-Process -Name derm-daemon\"'".to_string(),
            "cmd /c taskkill /IM derm-daemon.exe /F".to_string(),
            "cmd.exe /d /c \"taskkill /im derm-daemon.exe /f\"".to_string(),
            "CMD /Ctaskkill /im derm-daemon.exe".to_string(),
            "cmd /k sc.exe stop derm-sysmon".to_string(),
            format!("powershell -EncodedCommand {stop}"),
            format!("powershell.exe -NoProfile -enc {stop}"),
            format!("pwsh -e {stop}"),
            format!("powershell /ec {stop}"),
        ] {
            assert!(stops(&text).is_some(), "{text}");
        }
        for text in [
            "powershell -c \"Get-Process derm-daemon\"",
            "powershell -File stop-derm-daemon.ps1",
            "pwsh -c 'Stop-Process -Name node'",
            "cmd /c echo derm-daemon",
            "powershell -EncodedCommand !!notbase64!!",
        ] {
            assert!(stops(text).is_none(), "{text}");
        }
    }

    /// Fix pass 11: PowerShell's own parameter table (`CommandLineParameterParser.cs`
    /// at PowerShell `cb9cf48`: `MatchSwitch`, `GetSwitchKey`, `IsDash`):
    /// a parameter that takes a value hides nothing after it
    /// (`-EncodedArguments`, `-InputFormat`, `-WorkingDirectory`, `-Token`,
    /// `-UtcTimestamp`, `-SettingsFile`); `--` and the Unicode dashes mark a
    /// switch; base64 may hold white space, as .NET's decoder allows.
    #[test]
    fn fp11_powershells_own_parameter_table_reads_the_command() {
        let enc = |s: &str| {
            use base64::Engine;
            let b: Vec<u8> = s.encode_utf16().flat_map(u16::to_le_bytes).collect();
            base64::engine::general_purpose::STANDARD.encode(b)
        };
        let stop = "Stop-Process -Name derm-daemon";
        let b64 = enc(stop);
        let spaced: String = b64
            .chars()
            .enumerate()
            .flat_map(|(i, c)| {
                if i > 0 && i % 8 == 0 {
                    vec![' ', c]
                } else {
                    vec![c]
                }
            })
            .collect();
        for text in [
            format!("pwsh -ea {} -c \"{stop}\"", enc("x")),
            format!("pwsh -encodeda {} -command \"{stop}\"", enc("x")),
            format!("powershell -inp text -c \"{stop}\""),
            format!("pwsh -wo C:\\w -c \"{stop}\""),
            format!("pwsh -to abc -c \"{stop}\""),
            format!("pwsh -utc 2026-11-15T00:00:00Z -c \"{stop}\""),
            format!("pwsh -settings s.json -c \"{stop}\""),
            format!("powershell -Version 2 -c \"{stop}\""),
            format!("powershell --command \"{stop}\""),
            format!("powershell \u{2013}Command \"{stop}\""),
            format!("powershell \u{2014}c \"{stop}\""),
            format!("powershell -enc \"{spaced}\""),
        ] {
            assert!(stops(&text).is_some(), "{text}");
        }
        for text in [
            format!("pwsh -ea {b64}"),
            format!("powershell -help {stop}"),
            format!("powershell -File stop.ps1 {stop}"),
        ] {
            assert!(stops(&text).is_none(), "{text}");
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
            permission: None,
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
