//! The launch route (the universal plan's miss 1): a shim per agent in
//! `~/.derm/bin` that execs `derm run <agent>`, so an agent started from a
//! plain terminal goes through derm's boundary, gate and records. The shim
//! takes its own folder off `PATH` before it runs derm, so `derm run` finds
//! the real agent and not the shim again. Written only behind a question;
//! derm never edits a shell's startup file: it prints the `PATH` line.

use std::path::{Path, PathBuf};

use serde_json::Value;

/// The line every shim derm writes holds, so a later run replaces only its own.
pub const MARKER: &str = "# derm setup shim (wave 5 lane W)";

/// `~/.derm/bin`.
pub fn folder(home: &Path) -> PathBuf {
    home.join(".derm").join("bin")
}

/// A path that can sit inside single quotes in `sh`: absolute, no quote, no
/// control character.
fn quotable(p: &str) -> bool {
    p.starts_with('/') && !p.contains('\'') && !p.chars().any(char::is_control)
}

/// The shim's text, or why there is none.
pub fn text(exe: &str, id: &str, derm: &Path, dir: &Path) -> Result<String, String> {
    let derm = derm.to_str().ok_or("derm's path is not text")?;
    let dir = dir.to_str().ok_or("the shim folder's path is not text")?;
    if !quotable(derm) || !quotable(dir) {
        return Err("derm's path or the shim folder holds a quote or is not absolute".into());
    }
    if !is_name(exe) || !is_name(id) {
        return Err(format!("{exe:?} is not a plain program name"));
    }
    Ok(format!(
        "#!/bin/sh
{MARKER}: runs {exe} through `derm run {id}` (derm's boundary, gate and records).
# Remove this file, or this folder from PATH, to run {exe} without derm.
set -f
derm_shims='{dir}'
p=''
IFS=:
for e in $PATH; do
  [ \"$e\" = \"$derm_shims\" ] || [ \"$e\" = \"$derm_shims/\" ] || p=\"${{p:+$p:}}$e\"
done
unset IFS
PATH=$p
export PATH
exec '{derm}' run '{id}' -- \"$@\"
"
    ))
}

fn is_name(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'+' | b'-'))
        && !s.starts_with(['-', '.'])
}

/// (executable, agent id) for each installed agent `derm run` knows, from the
/// preset rows' `executables` (`presets/wave5/executables.json`).
pub fn plan(rows: &[Value], installed: &[String]) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for row in rows {
        let Some(id) = row.get("id").and_then(Value::as_str) else {
            continue;
        };
        if !installed.iter().any(|i| i == id) || crate::run::harness::find(id).is_none() {
            continue;
        }
        for exe in row
            .get("executables")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
        {
            out.push((exe.to_string(), id.to_string()));
        }
    }
    out
}

/// The line to put in a shell's startup file, which derm does not edit.
pub fn path_line(dir: &Path) -> String {
    format!("export PATH=\"{}:$PATH\"", dir.display())
}

/// What Orca's per-agent command override (`agentCmdOverrides`, note AQ
/// section 8) would hold for an agent: derm prints it, and you set it in
/// Orca's settings. Orca appends its own arguments after it.
pub fn orca_override(id: &str) -> String {
    format!("derm run {id} --")
}
