//! Case 82: the core's shell checks (case 30's unreadable tokens, the
//! control files, the reject list's git keys read as a command) run only on
//! the tool names it knows (`derm_core::policy::SHELL_TOOLS`). Each native
//! agent names its shell otherwise, so a dialect maps the agent's shell tools
//! to `bash`, and the field that holds the command to `command`, before the
//! core sees the call. The names are the preset row's
//! `coverage.shellAliases` (`crates/derm-cli/src/connect/presets/<id>.json`);
//! a test holds the two lists equal.
//!
//! Ported from `packages/derm-hooks-native/src/shell.ts` at `e29ce27`.

use serde_json::{Map, Value};

/// An agent's shell tools and the fields that hold the command.
pub struct ShellForm {
    /// The agent's own shell tool names, exactly as its hook input spells them.
    pub names: &'static [&'static str],
    /// Fields that may hold the command line, first present wins. An array of
    /// strings is joined with spaces (an argv). Every other field stays and
    /// is read by the core too (a working folder, an env block).
    pub command_fields: &'static [&'static str],
}

/// `JSON.stringify(v ?? null)` as the TypeScript wrote it.
fn stringify(v: &Value) -> String {
    serde_json::to_string(v).unwrap_or_else(|_| "null".into())
}

/// Turns an agent shell call into the core's `bash` call; anything else is
/// left as it came (`asCoreShell`).
pub fn as_core_shell(form: &ShellForm, tool: &str, tool_input: &Value) -> (String, Value) {
    if !form.names.contains(&tool) {
        return (tool.to_string(), tool_input.clone());
    }
    let Value::Object(fields) = tool_input else {
        // A shell call whose input is not an object: the core reads its text
        // as a whole, as `bash` (so case 30 still applies).
        let command = match tool_input {
            Value::String(s) => s.clone(),
            other => stringify(other),
        };
        let mut out = Map::new();
        out.insert("command".into(), Value::String(command));
        return ("bash".into(), Value::Object(out));
    };
    let mut command: Option<String> = None;
    for f in form.command_fields {
        match fields.get(*f) {
            Some(Value::String(s)) => command = Some(s.clone()),
            Some(Value::Array(a)) if a.iter().all(Value::is_string) => {
                command = Some(
                    a.iter()
                        .filter_map(Value::as_str)
                        .collect::<Vec<_>>()
                        .join(" "),
                )
            }
            _ => {}
        }
        if command.is_some() {
            break;
        }
    }
    let mut out = Map::new();
    for (k, v) in fields {
        if k == "command" && command.is_some() {
            continue;
        }
        out.insert(k.clone(), v.clone());
    }
    // No command field the dialect knows: the whole input becomes the command
    // text, so nothing in it escapes the shell checks.
    let command = command.unwrap_or_else(|| stringify(tool_input));
    out.insert("command".into(), Value::String(command));
    ("bash".into(), Value::Object(out))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const FORM: ShellForm = ShellForm {
        names: &["run"],
        command_fields: &["CommandLine", "Input"],
    };

    #[test]
    fn a_shell_tool_becomes_bash_with_its_command() {
        let (t, i) = as_core_shell(&FORM, "run", &json!({"CommandLine": "ls", "Cwd": "/w"}));
        assert_eq!(t, "bash");
        assert_eq!(
            i,
            json!({"command": "ls", "CommandLine": "ls", "Cwd": "/w"})
        );
        let (t, i) = as_core_shell(&FORM, "run", &json!({"Input": ["git", "push"]}));
        assert_eq!((t.as_str(), &i["command"]), ("bash", &json!("git push")));
    }

    #[test]
    fn no_known_field_or_no_object_reads_the_whole_input() {
        let (_, i) = as_core_shell(&FORM, "run", &json!({"other": 1}));
        assert_eq!(i["command"], json!("{\"other\":1}"));
        let (_, i) = as_core_shell(&FORM, "run", &json!("rm -rf /"));
        assert_eq!(i, json!({"command": "rm -rf /"}));
        let (_, i) = as_core_shell(&FORM, "run", &Value::Null);
        assert_eq!(i, json!({"command": "null"}));
    }

    #[test]
    fn another_tool_is_left_as_it_came() {
        let (t, i) = as_core_shell(&FORM, "read", &json!({"path": "a"}));
        assert_eq!((t.as_str(), i), ("read", json!({"path": "a"})));
    }
}
