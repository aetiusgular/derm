//! How `derm run --boundary sbx` starts and ends a sandbox (lane T; the sbx
//! smoke test's findings SB1, SB2, SB3 and SB6, case 117). Built here and
//! wired into `run_io` and `plan.rs` by integration (request T-2).
//!
//! `plan.rs` builds one `sbx run` argv:
//! `run --name N -e NAME... [--kit KIT] AGENT CWD [-- ARGS]`. That form has
//! three problems on sbx 0.51.0:
//!
//! - SB1: a sandbox kit passed with `--kit` is deprecated ("pass it as the
//!   first positional argument instead"); `--kit` is for mixins
//!   (https://docs.docker.com/reference/cli/sbx/run/).
//! - SB3: the sandbox outlives `derm run`, its read-write mount of the
//!   project still up, with no chat to credit a write to.
//! - Case 117: the VM reaches derm's ports on the host (the OTLP receiver,
//!   the gateway) only with a `localhost:<port>` rule, which
//!   the smoke test proved works scoped to one sandbox
//!   (`sbx policy allow network --sandbox <name> localhost:<port>`). A rule
//!   needs the sandbox to exist first (I: the reference does not say), and
//!   without it the harness's model calls get 403 and its records never
//!   reach the daemon.
//!
//! So the run becomes four steps, each an sbx command documented for 0.51.0:
//!
//! 1. `sbx create --name N -e NAME... WORKLOAD CWD`, the workload being the
//!    kit when there is one (positional, SB1), else the built-in agent
//!    (https://docs.docker.com/reference/cli/sbx/create/);
//! 2. `sbx policy allow network --sandbox N localhost:<port>` for each of
//!    derm's ports the plan points the VM at; a refusal stops the chat
//!    before the agent starts (case 117: never untapped or unrecorded in
//!    silence);
//! 3. `sbx run --name N -e NAME... [-- ARGS]`, the attach ("Use sbx run
//!    --name SANDBOX to attach to the agent after creation", the create
//!    page; `-e` "Applies on re-attach too", lane D's read of the run page);
//! 4. `sbx rm --force N` when the harness ends, or on any way out after the
//!    create (SB3). sbx keeps host-mount folders on `rm` (its `--help`, the
//!    smoke test), so the project is untouched.
//!
//! SB2: the chat id already starts with `derm-`, so the sandbox is named
//! after the chat as it is, not `derm-derm-<id>`.

use std::path::Path;
use std::process::{Command, Stdio};
use std::time::Duration;

use crate::run::plan::{split_url, Plan};

const POLICY_LIMIT: Duration = Duration::from_secs(30);
const RM_LIMIT: Duration = Duration::from_secs(60);

/// A sandbox name sbx accepts for the chat (sbx create: two or more
/// characters, a letter or digit first, then letters, digits, hyphens and
/// periods). A chat id from `derm run` is `derm-<12 hex>` and stays as it
/// is; an id given with `--chat` gains `derm-` and has every other
/// character turned into a hyphen (an underscore is valid in a chat id,
/// `args::valid_chat`, and not in a sandbox name).
pub(crate) fn sandbox_name(chat: &str) -> String {
    let clean: String = chat
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '.' {
                c
            } else {
                '-'
            }
        })
        .collect();
    if clean.starts_with("derm-") {
        clean
    } else {
        format!("derm-{clean}")
    }
}

/// The four steps for one chat.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Stages {
    pub name: String,
    /// The agent or kit the sandbox runs.
    pub workload: String,
    pub create: Vec<String>,
    pub allow: Vec<Vec<String>>,
    pub attach: Vec<String>,
    pub remove: Vec<String>,
    /// derm's ports on the host the VM is pointed at.
    pub ports: Vec<u16>,
}

/// The steps from the `sbx run` argv `plan.rs` built and the plan's
/// variables. `interactive` is whether a person can answer sbx's own
/// questions (a kit's credential question, the first-run policy); without
/// one, `--no-input` makes such a question fail and say what to run.
/// `mixins` are kits layered on the workload at the create (derm's own,
/// [`super::kit`]); the attach does not name them.
pub(crate) fn stages(
    args: &[String],
    env_set: &[(String, String)],
    interactive: bool,
    mixins: &[String],
) -> Result<Stages, String> {
    if args.first().map(String::as_str) != Some("run") {
        return Err("the sbx argv does not start with run".into());
    }
    let mut name = None;
    let mut env: Vec<String> = Vec::new();
    let mut kit = None;
    let mut positional: Vec<String> = Vec::new();
    let mut rest: Option<Vec<String>> = None;
    let mut i = 1;
    while i < args.len() {
        let a = args[i].as_str();
        let value = || {
            args.get(i + 1)
                .cloned()
                .ok_or_else(|| format!("{a} has no value in the sbx argv"))
        };
        match a {
            "--" => {
                rest = Some(args[i + 1..].to_vec());
                break;
            }
            "--name" => {
                name = Some(value()?);
                i += 1;
            }
            "-e" => {
                let v = value()?;
                // A bare name: sbx copies the value from its own
                // environment, so no value sits in an argv.
                if v.contains('=') || v.is_empty() {
                    return Err(format!("-e {v:?} in the sbx argv is not a bare name"));
                }
                env.extend(["-e".to_string(), v]);
                i += 1;
            }
            "--kit" => {
                kit = Some(value()?);
                i += 1;
            }
            s if s.starts_with('-') => return Err(format!("unexpected {s} in the sbx argv")),
            _ => positional.push(args[i].clone()),
        }
        i += 1;
    }
    let name = name.ok_or("no --name in the sbx argv")?;
    if positional.len() < 2 {
        return Err(format!(
            "the sbx argv names {} things, not an agent and a folder",
            positional.len()
        ));
    }
    // E1-8: after the folder, the paths in it held read-only, each an
    // absolute path with sbx's `:ro` (the create page: "PATH [PATH...]").
    let readonly = positional.split_off(2);
    if let Some(bad) = readonly
        .iter()
        .find(|p| !p.starts_with('/') || !p.ends_with(":ro") || p.len() < 5)
    {
        return Err(format!(
            "the sbx argv names {bad:?} after the folder, which is not a read-only path"
        ));
    }
    let cwd = positional.pop().unwrap_or_default();
    let agent = positional.pop().unwrap_or_default();
    let workload = kit.unwrap_or(agent);

    let mut create = vec!["create".to_string(), "--name".into(), name.clone()];
    create.extend(env.iter().cloned());
    // A mixin goes with --kit, as sbx means it ("Adds a mixin kit
    // reference", the run and create pages); the workload stays positional.
    for m in mixins {
        create.extend(["--kit".to_string(), m.clone()]);
    }
    if !interactive {
        create.push("--no-input".into());
    }
    create.extend([workload.clone(), cwd]);
    create.extend(readonly);

    let ports = ports(env_set);
    let allow = ports
        .iter()
        .map(|p| {
            vec![
                "policy".to_string(),
                "allow".into(),
                "network".into(),
                "--sandbox".into(),
                name.clone(),
                format!("localhost:{p}"),
            ]
        })
        .collect();

    let mut attach = vec!["run".to_string(), "--name".into(), name.clone()];
    attach.extend(env);
    if let Some(r) = rest.filter(|r| !r.is_empty()) {
        attach.push("--".into());
        attach.extend(r);
    }
    let remove = vec!["rm".to_string(), "--force".into(), name.clone()];
    Ok(Stages {
        name,
        workload,
        create,
        allow,
        attach,
        remove,
        ports,
    })
}

/// What a dry run prints for sbx (box test w5, BW5-5's rest): the steps
/// `start` runs, not the one-step `sbx run` argv the plan holds. derm's kit,
/// when it goes on, is added to the create at the start (`--kit <kit>`).
pub(crate) fn describe_steps(args: &[String], env_set: &[(String, String)]) -> Option<String> {
    let st = stages(args, env_set, interactive(), &[]).ok()?;
    let mut out = String::from("sbx steps derm runs (in order):\n");
    let line = |w: &[String]| format!("  sbx {}\n", w.join(" "));
    out.push_str(&line(&st.create));
    for a in &st.allow {
        out.push_str(&line(a));
    }
    out.push_str(&line(&st.attach));
    out.push_str(&line(&st.remove));
    out.push_str("  (derm's kit, when it goes on, is added to the create as --kit <kit>, which sbx builds with Docker's API, so Docker must be running; the rules go with the sandbox)\n");
    Some(out)
}

/// The host ports the plan points the VM at: every variable whose value is
/// an http or https URL on `host.docker.internal` (plan.rs rewrites
/// loopback to that name under sbx).
fn ports(env_set: &[(String, String)]) -> Vec<u16> {
    let mut out: Vec<u16> = env_set
        .iter()
        .filter_map(|(_, v)| split_url(v))
        .filter(|(_, host, _, _)| host == "host.docker.internal")
        .map(|(_, _, port, _)| port)
        .collect();
    out.sort_unstable();
    out.dedup();
    out
}

/// Whether a person can answer sbx's questions: stdin is a terminal.
#[allow(dead_code)]
pub(crate) fn interactive() -> bool {
    // SAFETY: isatty reads only the descriptor number.
    unsafe { libc::isatty(0) == 1 }
}

/// A created sandbox. Dropping it removes it (SB3), on every way out of
/// `run_io` after the create; [`Sandbox::remove`] does it at the end of a
/// run and says how it went.
pub(crate) struct Sandbox {
    sbx: String,
    // Read only by a test with a shell-script sbx (Unix; lane Z).
    #[cfg_attr(all(test, not(unix)), allow(dead_code))]
    name: String,
    remove: Vec<String>,
    done: bool,
    /// Whether derm's kit went on the create, and why not (lane T's P4-R3).
    kit: Option<String>,
}

impl Sandbox {
    /// `run.start`'s `sbxKit`: `{"added": true}`, or `{"added": false,
    /// "why": ...}` (P4-R3; `derm status` reads it to say whether derm's
    /// gate is in the VM).
    pub(crate) fn kit_record(&self) -> serde_json::Value {
        match &self.kit {
            None => serde_json::json!({"added": true}),
            Some(why) => serde_json::json!({
                "added": false,
                "why": why.chars().take(200).collect::<String>(),
            }),
        }
    }

    #[cfg_attr(all(test, not(unix)), allow(dead_code))]
    pub(crate) fn name(&self) -> &str {
        &self.name
    }

    /// `sbx rm --force <name>`; an error says what to run by hand.
    pub(crate) fn remove(mut self) -> Result<(), String> {
        self.done = true;
        remove_now(&self.sbx, &self.remove)
    }
}

impl Drop for Sandbox {
    fn drop(&mut self) {
        if !self.done {
            if let Err(e) = remove_now(&self.sbx, &self.remove) {
                eprintln!("derm run: {e}");
            }
        }
    }
}

fn remove_now(sbx: &str, remove: &[String]) -> Result<(), String> {
    let name = remove.last().cloned().unwrap_or_default();
    match super::probe::run(Path::new(sbx), remove, RM_LIMIT) {
        Ok(r) if r.ok => Ok(()),
        Ok(r) => Err(format!(
            "sbx did not remove the sandbox {name} ({}); remove it with: sbx rm --force {name}",
            r.line
        )),
        Err(e) => Err(format!(
            "sbx did not remove the sandbox {name} ({e}); remove it with: sbx rm --force {name}"
        )),
    }
}

/// Steps 1 and 2, then the plan's argv becomes the attach (step 3). The
/// returned [`Sandbox`] is step 4. `sbx` is the program to run (`sbx`, or a
/// test's fake); it gets the plan's own environment, so the bare `-e` names
/// copy this chat's values.
pub(crate) fn start(
    sbx: &str,
    plan: &mut Plan,
    interactive: bool,
) -> Result<Sandbox, (u8, String)> {
    let policy = derm_core::policy::default_path();
    let switch = std::env::var(super::kit::SWITCH).ok();
    start_with(
        sbx,
        plan,
        interactive,
        &KitInputs {
            policy: policy.as_deref(),
            parent: &std::env::temp_dir(),
            switch: switch.as_deref(),
        },
    )
}

/// Where [`start`] finds what derm's kit needs; tests give their own.
pub(crate) struct KitInputs<'a> {
    /// The person's policy file.
    pub policy: Option<&'a Path>,
    /// Where the chat's kit folder is made.
    pub parent: &'a Path,
    /// [`super::kit::SWITCH`]'s value.
    pub switch: Option<&'a str>,
}

pub(crate) fn start_with(
    sbx: &str,
    plan: &mut Plan,
    interactive: bool,
    inputs: &KitInputs,
) -> Result<Sandbox, (u8, String)> {
    let harness = plan
        .env_set
        .iter()
        .find(|(k, _)| k == "DERM_HARNESS")
        .map(|(_, v)| v.as_str())
        .unwrap_or("");
    // derm's gate in the VM (Tony's O1 decision): built for the chat now,
    // read by sbx at the create, removed right after it.
    let kit = super::kit::prepare(harness, inputs.policy, inputs.parent, inputs.switch)
        .map_err(|e| (1, e))?;
    let mixins: Vec<String> = match &kit {
        super::kit::Kit::Built(p) => vec![p.path().to_string_lossy().into_owned()],
        super::kit::Kit::Without(_) => Vec::new(),
    };
    let st = stages(&plan.args, &plan.env_set, interactive, &mixins).map_err(|e| (1, e))?;
    let exported = plan
        .env_set
        .iter()
        .any(|(k, _)| k == "OTEL_EXPORTER_OTLP_ENDPOINT");
    match &kit {
        super::kit::Kit::Built(_) => eprintln!(
            "derm run: inside the sbx VM {} runs with derm's gate: derm's kit registers it in Claude Code's managed settings, with your policy as it is now. \
             The agent runs in full access there with no one to ask, so what your policy would ask is allowed and recorded (the VM is the boundary; a deny rule still denies). The agent has sudo in the VM and could remove the gate; \
             the VM stays the boundary. sbx's policy log records the VM's network calls{} \
             The host's OS feed does not see inside the VM: it records only sbx's own client (the model tap is off under sbx: MW5-37). \
             The gate's records and asks reach the host over the daemon's port. To run without the kit: {}=off",
            st.workload,
            // Review 6-4: said only when the export was applied.
            if exported {
                ", and Claude Code's own telemetry reaches the daemon over its port."
            } else {
                ". Claude Code's own telemetry is NOT exported for this chat (run.start's otelExport says why)."
            },
            super::kit::SWITCH
        ),
        super::kit::Kit::Without(why) => eprintln!(
            "derm run: inside the sbx VM {} runs without derm's gate ({why}): your host's hooks, plugins and extensions are not in the VM. \
             The VM is the boundary; sbx's policy log records the VM's network calls. The host's OS feed does not see inside the VM: \
             it records only sbx's own client (the model tap is off under sbx: MW5-37).",
            st.workload
        ),
    }
    let mut cmd = Command::new(sbx);
    cmd.args(&st.create).env("SBX_NO_TELEMETRY", "1");
    for k in &plan.env_remove {
        cmd.env_remove(k);
    }
    for (k, v) in &plan.env_set {
        cmd.env(k, v);
    }
    if !interactive {
        cmd.stdin(Stdio::null());
    }
    let status = cmd.status().map_err(|e| (127, format!("{sbx}: {e}")))?;
    // sbx has read the kit (SPEC-v2 5.8: files are copied at the create).
    let kit_note = match &kit {
        super::kit::Kit::Built(_) => None,
        super::kit::Kit::Without(why) => Some(why.clone()),
    };
    let kit_went_on = kit_note.is_none();
    drop(kit);
    if !status.success() {
        return Err((1, create_failed(&st.name, status.code(), kit_went_on)));
    }
    let sandbox = Sandbox {
        sbx: sbx.to_string(),
        name: st.name.clone(),
        remove: st.remove.clone(),
        done: false,
        kit: kit_note,
    };
    for (rule, port) in st.allow.iter().zip(&st.ports) {
        let r = super::probe::run(Path::new(sbx), rule, POLICY_LIMIT);
        let failed = match r {
            Ok(r) if r.ok => None,
            Ok(r) => Some(r.line),
            Err(e) => Some(e),
        };
        if let Some(why) = failed {
            // `sandbox` drops here, and the sandbox goes with it.
            return Err((
                1,
                format!(
                    "sbx would not let the sandbox reach derm on the host's port {port} \
                     (sbx policy allow network --sandbox {} localhost:{port}: {why}). Without it the chat \
                     would run with its model calls and its records refused, so it did not start (case 117)",
                    st.name
                ),
            ));
        }
    }
    if !st.ports.is_empty() {
        eprintln!(
            "derm run: the sandbox {} may reach the host's port{} {} (a rule for this sandbox only, gone with it)",
            st.name,
            if st.ports.len() == 1 { "" } else { "s" },
            st.ports
                .iter()
                .map(u16::to_string)
                .collect::<Vec<_>>()
                .join(", ")
        );
    }
    let key_in_env = plan
        .env_set
        .iter()
        .any(|(k, v)| k == "ANTHROPIC_API_KEY" && !v.is_empty())
        || (std::env::var_os("ANTHROPIC_API_KEY").is_some_and(|v| !v.is_empty())
            && !plan.env_remove.iter().any(|k| k == "ANTHROPIC_API_KEY"));
    // After the create and the rules, before the attach: the sandbox is
    // there, and the note is the last thing said before the agent's own.
    if let Some(note) = credential_note(harness, key_in_env, &super::probe::run, sbx) {
        eprintln!("{note}");
    }
    plan.args = st.attach;
    plan.sandbox_name = Some(st.name);
    Ok(sandbox)
}

/// E1-9 (eval pass 1): on the box, Claude Code under sbx answered every
/// turn "Not logged in" and nothing derm printed said why. sbx keeps the
/// model credential itself (`sbx secret set`, "Available services:
/// anthropic, ..." in its help, 0.51.0); `sbx secret ls --service anthropic`
/// prints `No secrets found for service "anthropic"` with none stored (the
/// box, 0.51.0) and a table with one (the Mac, 0.53.0: `(global) anthropic
/// (oauth configured)`), exit 0 both times. A note when that first line
/// says none is stored and the key is not in derm's environment; nothing
/// when sbx does not answer or says anything else. Claude Code only: the
/// other agents' services were not run.
pub(crate) fn credential_note(
    harness: &str,
    key_in_env: bool,
    run: super::probe::Runner,
    sbx: &str,
) -> Option<String> {
    if harness != "claude-code" || key_in_env {
        return None;
    }
    let args = [
        "secret".to_string(),
        "ls".into(),
        "--service".into(),
        "anthropic".into(),
    ];
    let r = run(Path::new(sbx), &args, Duration::from_secs(10)).ok()?;
    (r.ok && r.line.starts_with("No secrets found")).then(|| {
        "derm run: sbx has no Anthropic credential stored (sbx secret ls --service anthropic) and ANTHROPIC_API_KEY is not set here,          so Claude Code in the sandbox will answer \"Not logged in\" until you log in inside it (/login).          To store one for every sandbox: sbx secret set anthropic"
            .to_string()
    })
}

/// Why a create made no sandbox, and what to do. sbx prints its own error
/// above. With derm's kit on the create, sbx builds the kit first, which
/// needs Docker's API (Mac test w6, MW6-2: `dial unix
/// ~/.docker/run/docker.sock: connect: no such file or directory` with
/// Docker Desktop not running); sbx also refuses with its OS keychain locked
/// (box test w6, BW6-8). derm's kit is v3 since fix pass 11 (MW5-7,
/// `kit/tests.rs`, `the_kit_is_a_v3_mixin_whose_parts_agree`).
fn create_failed(name: &str, code: Option<i32>, kit_went_on: bool) -> String {
    let mut why = format!(
        "sbx create did not make the sandbox {name} (exit {code:?}); nothing started. \
         If one by that name is left from an earlier run: sbx rm --force {name}"
    );
    if kit_went_on {
        why.push_str(&format!(
            ". derm's gate went on this create as a kit (v3), which sbx builds with Docker's API first; \
             sbx's error above names the cause, such as Docker not running (docker.sock) or the OS keychain locked \
             (unlock it, or sign in to the desktop). \
             To run under sbx without derm's gate in the VM: {}=off; to keep the gate: --boundary srt",
            super::kit::SWITCH
        ));
    }
    why
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| x.to_string()).collect()
    }

    /// E1-9: with no Anthropic credential in sbx and none in the
    /// environment, a Claude Code chat is told before it starts. The lines
    /// are sbx's own (the box, 0.51.0; the Mac, 0.53.0).
    #[test]
    fn e1_9_a_missing_sbx_credential_is_said_before_the_chat() {
        use super::super::probe::Ran;
        let none = |_: &Path, a: &[String], _: Duration| {
            assert_eq!(a, s(&["secret", "ls", "--service", "anthropic"]));
            Ok(Ran {
                ok: true,
                line: "No secrets found for service \"anthropic\"".into(),
            })
        };
        let note = credential_note("claude-code", false, &none, "sbx").expect("a note");
        assert!(note.contains("Not logged in"), "{note}");
        assert!(note.contains("sbx secret set anthropic"), "{note}");
        // The key is in the environment, or the agent is not Claude Code.
        assert_eq!(credential_note("claude-code", true, &none, "sbx"), None);
        assert_eq!(credential_note("pi", false, &none, "sbx"), None);
        // One is stored.
        let stored = |_: &Path, _: &[String], _: Duration| {
            Ok(Ran {
                ok: true,
                line: "SCOPE      SERVICE     SECRET".into(),
            })
        };
        assert_eq!(credential_note("claude-code", false, &stored, "sbx"), None);
        // sbx did not answer, or failed: nothing is claimed.
        let silent = |_: &Path, _: &[String], _: Duration| Err("no answer in 10 s".to_string());
        assert_eq!(credential_note("claude-code", false, &silent, "sbx"), None);
        let failed = |_: &Path, _: &[String], _: Duration| {
            Ok(Ran {
                ok: false,
                line: "No secrets found".into(),
            })
        };
        assert_eq!(credential_note("claude-code", false, &failed, "sbx"), None);
    }

    /// E1-8: the read-only paths go on the create, after the folder; the
    /// attach names no folder, so none there. A word after the folder that
    /// is not an absolute `:ro` path is refused, not passed to sbx.
    #[test]
    fn e1_8_read_only_paths_go_on_the_create_alone() {
        let args = s(&[
            "run",
            "--name",
            "derm-c1",
            "claude",
            "/work",
            "/work/.git/hooks:ro",
            "/work/.git/config:ro",
            "--",
            "-p",
            "hi",
        ]);
        let st = stages(&args, &[], false, &[]).unwrap();
        assert_eq!(
            st.create,
            s(&[
                "create",
                "--name",
                "derm-c1",
                "--no-input",
                "claude",
                "/work",
                "/work/.git/hooks:ro",
                "/work/.git/config:ro",
            ])
        );
        assert_eq!(
            st.attach,
            s(&["run", "--name", "derm-c1", "--", "-p", "hi"])
        );
        for bad in ["/work/.git/hooks", "relative:ro", "/etc"] {
            let args = s(&["run", "--name", "derm-c1", "claude", "/work", bad]);
            let e = stages(&args, &[], false, &[]).unwrap_err();
            assert!(e.contains("not a read-only path"), "{e}");
        }
        let one = s(&["run", "--name", "derm-c1", "claude"]);
        assert!(stages(&one, &[], false, &[])
            .unwrap_err()
            .contains("names 1 things"));
    }

    /// Box test w5, BW5-5's rest: the dry run printed the one-step `sbx run`
    /// argv, not the create, rule, attach and remove derm runs.
    #[test]
    fn the_dry_run_names_the_four_steps() {
        let args = s(&[
            "run",
            "--name",
            "derm-c1",
            "-e",
            "DERM_OTLP_ENDPOINT",
            "claude",
            "/work",
        ]);
        let env = vec![(
            "DERM_OTLP_ENDPOINT".to_string(),
            "http://host.docker.internal:4318".to_string(),
        )];
        let t = describe_steps(&args, &env).unwrap();
        let lines: Vec<&str> = t.lines().collect();
        assert!(
            lines[1].starts_with("  sbx create --name derm-c1 -e DERM_OTLP_ENDPOINT"),
            "{t}"
        );
        assert!(lines[1].ends_with("claude /work"), "{t}");
        assert_eq!(
            lines[2], "  sbx policy allow network --sandbox derm-c1 localhost:4318",
            "{t}"
        );
        assert_eq!(
            lines[3], "  sbx run --name derm-c1 -e DERM_OTLP_ENDPOINT",
            "{t}"
        );
        assert_eq!(lines[4], "  sbx rm --force derm-c1", "{t}");
        assert!(describe_steps(&s(&["exec"]), &env).is_none());
    }

    #[test]
    fn a_sandbox_is_named_after_its_chat_once() {
        assert_eq!(sandbox_name("derm-922f0a7cbe4d"), "derm-922f0a7cbe4d");
        assert_eq!(sandbox_name("c1"), "derm-c1");
        assert_eq!(sandbox_name("my_chat.2"), "derm-my-chat.2");
    }

    #[test]
    fn pi_runs_its_kit_positionally_and_attaches_with_its_variables() {
        // The argv plan.rs builds for `derm run pi --boundary sbx -- -p hi`.
        let args = s(&[
            "run",
            "--name",
            "derm-c1",
            "-e",
            "DERM_CHAT_TOKEN",
            "-e",
            "DERM_OTLP_ENDPOINT",
            "--kit",
            "docker.io/sbx/pi-kit:latest",
            "pi",
            "/work",
            "--",
            "-p",
            "hi",
        ]);
        let env = vec![
            ("DERM_CHAT_TOKEN".to_string(), "t".to_string()),
            (
                "DERM_OTLP_ENDPOINT".to_string(),
                "http://host.docker.internal:4318".to_string(),
            ),
            (
                "ANTHROPIC_BASE_URL".to_string(),
                "http://host.docker.internal:43017/r/abc/anthropic".to_string(),
            ),
            ("OTHER".to_string(), "http://example.com:9".to_string()),
        ];
        let st = stages(&args, &env, true, &[]).unwrap();
        assert_eq!(st.workload, "docker.io/sbx/pi-kit:latest");
        assert_eq!(
            st.create,
            s(&[
                "create",
                "--name",
                "derm-c1",
                "-e",
                "DERM_CHAT_TOKEN",
                "-e",
                "DERM_OTLP_ENDPOINT",
                "docker.io/sbx/pi-kit:latest",
                "/work"
            ]),
            "no --kit for a sandbox kit (SB1), and the agent name goes"
        );
        assert_eq!(st.ports, vec![4318, 43017]);
        assert_eq!(
            st.allow,
            vec![
                s(&[
                    "policy",
                    "allow",
                    "network",
                    "--sandbox",
                    "derm-c1",
                    "localhost:4318"
                ]),
                s(&[
                    "policy",
                    "allow",
                    "network",
                    "--sandbox",
                    "derm-c1",
                    "localhost:43017"
                ]),
            ],
            "scoped to this sandbox, never global"
        );
        assert_eq!(
            st.attach,
            s(&[
                "run",
                "--name",
                "derm-c1",
                "-e",
                "DERM_CHAT_TOKEN",
                "-e",
                "DERM_OTLP_ENDPOINT",
                "--",
                "-p",
                "hi"
            ])
        );
        assert_eq!(st.remove, s(&["rm", "--force", "derm-c1"]));
        // With no one to answer sbx's own questions, they fail instead.
        let quiet = stages(&args, &env, false, &[]).unwrap();
        assert!(quiet.create.contains(&"--no-input".to_string()));
        assert!(!quiet.attach.contains(&"--no-input".to_string()));
    }

    #[test]
    fn a_built_in_agent_is_its_own_workload_and_no_value_rides_in_the_argv() {
        let args = s(&[
            "run",
            "--name",
            "derm-c2",
            "-e",
            "DERM_CHAT_ID",
            "claude",
            "/w",
        ]);
        let st = stages(&args, &[], true, &[]).unwrap();
        assert_eq!(st.workload, "claude");
        assert_eq!(
            st.attach,
            s(&["run", "--name", "derm-c2", "-e", "DERM_CHAT_ID"])
        );
        assert!(st.allow.is_empty() && st.ports.is_empty());
        // `-e NAME=VALUE` would put a value (a token) in an argv: refused.
        let bad = s(&[
            "run",
            "--name",
            "n",
            "-e",
            "DERM_CHAT_TOKEN=x",
            "claude",
            "/w",
        ]);
        assert!(stages(&bad, &[], true, &[])
            .unwrap_err()
            .contains("bare name"));
        // Anything plan.rs does not build is refused rather than guessed.
        assert!(stages(&s(&["exec", "x"]), &[], true, &[]).is_err());
        assert!(stages(
            &s(&["run", "--name", "n", "--rm", "claude", "/w"]),
            &[],
            true,
            &[]
        )
        .is_err());
        assert!(stages(&s(&["run", "--name", "n", "claude"]), &[], true, &[]).is_err());
        assert!(stages(&s(&["run", "claude", "/w"]), &[], true, &[]).is_err());
    }

    #[cfg(unix)]
    fn fake_sbx(dir: &Path, fail_on: &str) -> String {
        let log = dir.join("calls");
        let p = dir.join("sbx");
        std::fs::write(
            &p,
            format!(
                "#!/bin/sh\necho \"$* | token=${{DERM_CHAT_TOKEN:-none}} telemetry=${{SBX_NO_TELEMETRY:-}}\" >> {}\n\
                 case \"$1\" in {fail_on}) echo 'refused by policy' >&2; exit 1;; esac\nexit 0\n",
                log.display()
            ),
        )
        .unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
        p.to_string_lossy().into_owned()
    }

    #[cfg(unix)]
    fn plan_for(args: Vec<String>) -> Plan {
        Plan {
            program: "sbx".into(),
            args,
            env_set: vec![
                ("DERM_CHAT_TOKEN".into(), "tok".into()),
                (
                    "DERM_OTLP_ENDPOINT".into(),
                    "http://host.docker.internal:4318".into(),
                ),
            ],
            env_remove: vec![],
            kit: None,
            sandbox_name: Some("derm-c3".into()),
            srt_settings: None,
            folders: vec![],
            state_dirs: vec![],
            notes: vec![],
            full_access: vec![],
            asks_allow: false,
            companion: None,
            scratch_dir: None,
        }
    }

    #[cfg(unix)]
    fn tmp(name: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!(
            "derm-sbx-{name}-{}-{}",
            std::process::id(),
            &uuid::Uuid::new_v4().simple().to_string()[..6]
        ));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    /// BW5-6 and MW5-7: with derm's kit on the create, a failure names both
    /// ways on; without the kit, it does not. Box test w6 BW6-8 and Mac test
    /// w6 MW6-2: derm's kit is v3 since fix pass 11, and the two failures
    /// seen were sbx's own (Docker's API not running for the kit's build,
    /// `docker.sock`; the OS keychain locked), so the hint names those and
    /// no "v2 kit".
    #[test]
    fn a_failed_create_with_the_kit_names_the_way_on() {
        let with = create_failed("derm-x", Some(1), true);
        assert!(!with.contains("v2"), "{with}");
        assert!(with.contains("docker.sock"), "{with}");
        assert!(with.contains("keychain"), "{with}");
        assert!(with.contains("DERM_SBX_KIT=off"), "{with}");
        assert!(with.contains("--boundary srt"), "{with}");
        let without = create_failed("derm-x", Some(1), false);
        assert!(!without.contains("v3"), "{without}");
        assert!(without.contains("sbx rm --force derm-x"), "{without}");
    }

    #[cfg(unix)]
    #[test]
    fn create_then_allow_then_attach_then_remove() {
        let d = tmp("seq");
        let sbx = fake_sbx(&d, "never");
        let mut p = plan_for(s(&[
            "run",
            "--name",
            "derm-c3",
            "-e",
            "DERM_CHAT_TOKEN",
            "claude",
            "/w",
            "--",
            "-p",
            "x",
        ]));
        let sandbox = start(&sbx, &mut p, false).unwrap();
        assert_eq!(sandbox.name(), "derm-c3");
        assert_eq!(
            p.args,
            s(&[
                "run",
                "--name",
                "derm-c3",
                "-e",
                "DERM_CHAT_TOKEN",
                "--",
                "-p",
                "x"
            ])
        );
        sandbox.remove().unwrap();
        let calls = std::fs::read_to_string(d.join("calls")).unwrap();
        let lines: Vec<&str> = calls.lines().collect();
        assert_eq!(
            lines,
            vec![
                "create --name derm-c3 -e DERM_CHAT_TOKEN --no-input claude /w | token=tok telemetry=1",
                "policy allow network --sandbox derm-c3 localhost:4318 | token=none telemetry=1",
                "rm --force derm-c3 | token=none telemetry=1",
            ],
            "the create sees the chat's variables (sbx copies the bare -e names); nothing else does"
        );
        let _ = std::fs::remove_dir_all(&d);
    }

    #[cfg(unix)]
    #[test]
    fn a_refused_rule_stops_the_chat_and_removes_the_sandbox() {
        let d = tmp("refused");
        let sbx = fake_sbx(&d, "policy");
        let mut p = plan_for(s(&["run", "--name", "derm-c3", "claude", "/w"]));
        let before = p.args.clone();
        let (code, msg) = start(&sbx, &mut p, false).err().unwrap();
        assert_eq!(code, 1);
        assert!(msg.contains("case 117") && msg.contains("4318"), "{msg}");
        assert!(msg.contains("refused by policy"), "{msg}");
        assert_eq!(p.args, before, "the plan is left as it was");
        let calls = std::fs::read_to_string(d.join("calls")).unwrap();
        assert!(
            calls
                .lines()
                .last()
                .unwrap()
                .starts_with("rm --force derm-c3"),
            "{calls}"
        );
        let _ = std::fs::remove_dir_all(&d);
    }

    #[cfg(unix)]
    #[test]
    fn a_failed_create_starts_nothing_and_removes_nothing() {
        let d = tmp("nocreate");
        let sbx = fake_sbx(&d, "create");
        let mut p = plan_for(s(&["run", "--name", "derm-c3", "claude", "/w"]));
        let (_, msg) = start(&sbx, &mut p, false).err().unwrap();
        assert!(msg.contains("sbx rm --force derm-c3"), "{msg}");
        let calls = std::fs::read_to_string(d.join("calls")).unwrap();
        assert_eq!(calls.lines().count(), 1, "{calls}");
        let _ = std::fs::remove_dir_all(&d);
    }

    #[cfg(unix)]
    #[test]
    fn a_sandbox_dropped_on_an_error_path_is_removed() {
        let d = tmp("drop");
        let sbx = fake_sbx(&d, "never");
        let mut p = plan_for(s(&["run", "--name", "derm-c3", "claude", "/w"]));
        {
            let _sandbox = start(&sbx, &mut p, false).unwrap();
            // An error between the create and the end of the run.
        }
        let calls = std::fs::read_to_string(d.join("calls")).unwrap();
        assert!(
            calls
                .lines()
                .last()
                .unwrap()
                .starts_with("rm --force derm-c3"),
            "{calls}"
        );
        let _ = std::fs::remove_dir_all(&d);
    }

    /// A fake sbx that, on `create`, writes what the kit folder named with
    /// `--kit` held at that moment: derm removes it right after.
    #[cfg(unix)]
    fn fake_sbx_reading_the_kit(dir: &Path) -> String {
        let log = dir.join("calls");
        let seen = dir.join("kit-seen");
        let p = dir.join("sbx");
        std::fs::write(
            &p,
            format!(
                "#!/bin/sh\necho \"$*\" >> {log}\n\
                 if [ \"$1\" = create ]; then\n\
                   prev=\n\
                   for a in \"$@\"; do\n\
                     if [ \"$prev\" = --kit ]; then\n\
                       (cd \"$a\" && find . -type f | sort) > {seen}\n\
                       cat \"$a/derm-kit/policy.json\" >> {seen}\n\
                     fi\n\
                     prev=$a\n\
                   done\n\
                 fi\nexit 0\n",
                log = log.display(),
                seen = seen.display()
            ),
        )
        .unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
        p.to_string_lossy().into_owned()
    }

    #[cfg(unix)]
    fn claude_plan() -> Plan {
        let mut p = plan_for(s(&[
            "run",
            "--name",
            "derm-c3",
            "-e",
            "DERM_CHAT_TOKEN",
            "claude",
            "/w",
        ]));
        p.env_set
            .push(("DERM_HARNESS".into(), "claude-code".into()));
        p
    }

    /// Eval pass 1, E1-12: under sbx the export stood down, so an sbx chat's
    /// record held no telemetry. Claude Code in the VM gets the export's
    /// variables by name (`-e`, on the create and the attach), the token in
    /// the header variable and in no argument, and the user's words stay
    /// last.
    #[cfg(unix)]
    #[test]
    fn e1_12_the_export_reaches_claude_code_in_the_vm_by_name() {
        let token = derm_core::token::mint().unwrap();
        let rest = s(&["-p", "hi"]);
        let argv = s(&[
            "run",
            "--name",
            "derm-c3",
            "-e",
            "DERM_CHAT_TOKEN",
            "-e",
            "DERM_OTLP_ENDPOINT",
            "claude",
            "/w",
            "/w/.git/config:ro",
            "--",
            "-p",
            "hi",
        ]);
        let mut p = plan_for(argv.clone());
        let (what, range) = crate::run::wire_export(
            &mut p,
            &rest,
            "claude-code",
            Some("http://127.0.0.1:4318"),
            Some(&token),
            None,
            false,
            true,
        );
        assert_eq!(what, "claude-code, token in OTEL_EXPORTER_OTLP_HEADERS");
        let agent = p.args.iter().position(|a| a == "claude").unwrap();
        for name in [
            "CLAUDE_CODE_ENABLE_TELEMETRY",
            "OTEL_LOGS_EXPORTER",
            "OTEL_EXPORTER_OTLP_PROTOCOL",
            "OTEL_EXPORTER_OTLP_ENDPOINT",
            "OTEL_LOGS_EXPORT_INTERVAL",
            "OTEL_LOG_TOOL_DETAILS",
            "OTEL_EXPORTER_OTLP_HEADERS",
        ] {
            assert!(
                p.args[..agent].windows(2).any(|w| w == ["-e", name]),
                "{name}: {:?}",
                p.args
            );
            assert!(p.env_set.iter().any(|(k, _)| k == name), "{name}");
        }
        assert!(!p.args.iter().any(|a| a == "OTEL_LOG_USER_PROMPTS"));
        assert!(p.args.iter().all(|a| !a.contains(&token)), "{:?}", p.args);
        assert!(p.args.ends_with(&rest));
        let value = |k: &str| {
            p.env_set
                .iter()
                .find(|(n, _)| n == k)
                .map(|(_, v)| v.clone())
        };
        assert_eq!(
            value("OTEL_EXPORTER_OTLP_ENDPOINT").as_deref(),
            Some("http://host.docker.internal:4318")
        );
        assert_eq!(
            value("OTEL_EXPORTER_OTLP_HEADERS"),
            Some(format!("x-derm-token={token}"))
        );
        // No word was added for the harness: the range is empty and sits
        // where the user's words start.
        let range = range.unwrap();
        assert!(range.is_empty());
        assert_eq!(&p.args[range.start..], &rest[..]);
        let st = stages(&p.args, &p.env_set, false, &[]).unwrap();
        for part in [&st.create, &st.attach] {
            assert!(
                part.windows(2)
                    .any(|w| w == ["-e", "OTEL_EXPORTER_OTLP_HEADERS"]),
                "{part:?}"
            );
        }
        assert_eq!(st.ports, vec![4318]);
        // Review 6-7: the user's own words after `--` do not count as
        // naming a variable to sbx.
        let mut user = argv.clone();
        user.extend(s(&["-e", "OTEL_EXPORTER_OTLP_HEADERS"]));
        let mut rest2 = rest.clone();
        rest2.extend(s(&["-e", "OTEL_EXPORTER_OTLP_HEADERS"]));
        let mut p = plan_for(user);
        crate::run::wire_export(
            &mut p,
            &rest2,
            "claude-code",
            Some("http://127.0.0.1:4318"),
            Some(&token),
            None,
            false,
            true,
        );
        let agent = p.args.iter().position(|a| a == "claude").unwrap();
        assert!(
            p.args[..agent]
                .windows(2)
                .any(|w| w == ["-e", "OTEL_EXPORTER_OTLP_HEADERS"]),
            "{:?}",
            p.args
        );
        // With prompts in the record, their switch goes too.
        let mut p = plan_for(argv.clone());
        crate::run::wire_export(
            &mut p,
            &rest,
            "claude-code",
            Some("http://127.0.0.1:4318"),
            Some(&token),
            None,
            true,
            true,
        );
        assert!(p
            .args
            .windows(2)
            .any(|w| w == ["-e", "OTEL_LOG_USER_PROMPTS"]));
        // Codex in a VM (until the review of E1-12 this stood down): its
        // two header variables are named to sbx before the agent, its `-c`
        // words sit with the user's, and no word holds the token.
        let cargv = s(&[
            "run",
            "--name",
            "derm-c3",
            "-e",
            "DERM_CHAT_TOKEN",
            "codex",
            "/w",
            "--",
            "-p",
            "hi",
        ]);
        let mut p = plan_for(cargv);
        let (what, range) = crate::run::wire_export(
            &mut p,
            &rest,
            "codex",
            Some("http://127.0.0.1:4318"),
            Some(&token),
            None,
            false,
            true,
        );
        assert_eq!(what, "codex");
        let agent = p.args.iter().position(|a| a == "codex").unwrap();
        let split = p.args.iter().position(|a| a == "--").unwrap();
        for name in [
            "OTEL_EXPORTER_OTLP_HEADERS",
            "OTEL_EXPORTER_OTLP_LOGS_HEADERS",
        ] {
            assert!(
                p.args[..agent].windows(2).any(|w| w == ["-e", name]),
                "{name}: {:?}",
                p.args
            );
        }
        let range = range.unwrap();
        assert!(range.start > split && !range.is_empty());
        assert!(p.args[range]
            .iter()
            .any(|a| a.contains("http://host.docker.internal:4318/v1/logs")));
        assert!(p.args.iter().all(|a| !a.contains(&token)), "{:?}", p.args);
        assert!(p.args.ends_with(&rest));
    }

    /// Phase 4, item 4: Claude Code under sbx gets derm's kit on the create,
    /// as a mixin, with the person's policy; the attach does not name it,
    /// and the folder is gone once the create has read it.
    #[cfg(unix)]
    #[test]
    fn claude_code_gets_derms_kit_on_the_create_and_the_folder_goes_after() {
        let d = tmp("kit");
        let sbx = fake_sbx_reading_the_kit(&d);
        let policy = d.join("policy.json");
        std::fs::write(&policy, r#"{"version":1}"#).unwrap();
        std::fs::set_permissions(&policy, std::fs::Permissions::from_mode(0o600)).unwrap();
        let parent = d.join("kits");
        std::fs::create_dir_all(&parent).unwrap();
        let mut p = claude_plan();
        let inputs = KitInputs {
            policy: Some(&policy),
            parent: &parent,
            switch: None,
        };
        let sandbox = start_with(&sbx, &mut p, false, &inputs).unwrap();
        let calls = std::fs::read_to_string(d.join("calls")).unwrap();
        let create = calls.lines().next().unwrap();
        let words: Vec<&str> = create.split(' ').collect();
        let at = words.iter().position(|w| *w == "--kit").expect(create);
        assert!(words[at + 1].contains("derm-sbx-kit-"), "{create}");
        assert_eq!(
            &words[at + 2..],
            &["--no-input", "claude", "/w"],
            "the kit is a mixin; the agent stays the workload"
        );
        let seen = std::fs::read_to_string(d.join("kit-seen")).unwrap();
        // The v3 layout (fix pass 11, MW5-7): descriptor and Dockerfile at
        // the top, the gate under derm-kit/.
        assert!(seen.contains("./derm-gate-claude.yaml"), "{seen}");
        assert!(seen.contains("./derm-gate-claude.dockerfile"), "{seen}");
        assert!(!seen.contains("./spec.yaml"), "{seen}");
        assert!(
            seen.contains("./derm-kit/plugin/bin/derm-hook.mjs"),
            "{seen}"
        );
        assert!(seen.trim_end().ends_with(r#"{"version":1}"#), "{seen}");
        assert!(!p.args.iter().any(|a| a == "--kit"), "{:?}", p.args);
        assert_eq!(
            std::fs::read_dir(&parent).unwrap().count(),
            0,
            "the kit folder is removed after the create"
        );
        // P4-R3: run.start says the kit went on.
        assert_eq!(sandbox.kit_record(), serde_json::json!({"added": true}));
        sandbox.remove().unwrap();
        let _ = std::fs::remove_dir_all(&d);
    }

    #[cfg(unix)]
    #[test]
    fn no_kit_without_a_usable_policy_or_with_the_switch_off_and_none_for_others() {
        let d = tmp("nokit");
        let sbx = fake_sbx_reading_the_kit(&d);
        let parent = d.join("kits");
        std::fs::create_dir_all(&parent).unwrap();
        let policy = d.join("policy.json");
        std::fs::write(&policy, r#"{"version":1}"#).unwrap();
        std::fs::set_permissions(&policy, std::fs::Permissions::from_mode(0o600)).unwrap();
        let missing = d.join("missing.json");
        let cases: Vec<(Plan, KitInputs)> = vec![
            (
                claude_plan(),
                KitInputs {
                    policy: Some(&missing),
                    parent: &parent,
                    switch: None,
                },
            ),
            (
                claude_plan(),
                KitInputs {
                    policy: Some(&policy),
                    parent: &parent,
                    switch: Some("off"),
                },
            ),
            (
                plan_for(s(&["run", "--name", "derm-c3", "claude", "/w"])),
                KitInputs {
                    policy: Some(&policy),
                    parent: &parent,
                    switch: None,
                },
            ),
        ];
        for (mut p, inputs) in cases {
            let _ = std::fs::remove_file(d.join("calls"));
            let sandbox = start_with(&sbx, &mut p, false, &inputs).unwrap();
            let calls = std::fs::read_to_string(d.join("calls")).unwrap();
            assert!(!calls.lines().next().unwrap().contains("--kit"), "{calls}");
            // P4-R3: run.start says the kit did not go on, and why.
            let rec = sandbox.kit_record();
            assert_eq!(rec["added"], false, "{rec}");
            assert!(rec["why"].as_str().is_some_and(|w| !w.is_empty()), "{rec}");
            sandbox.remove().unwrap();
        }
        assert_eq!(std::fs::read_dir(&parent).unwrap().count(), 0);
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn a_mixin_goes_on_the_create_only() {
        let args = s(&[
            "run", "--name", "n", "-e", "A", "claude", "/w", "--", "-p", "x",
        ]);
        let st = stages(&args, &[], true, &["/k".to_string()]).unwrap();
        assert_eq!(
            st.create,
            s(&["create", "--name", "n", "-e", "A", "--kit", "/k", "claude", "/w"])
        );
        assert_eq!(
            st.attach,
            s(&["run", "--name", "n", "-e", "A", "--", "-p", "x"])
        );
        assert_eq!(st.workload, "claude");
    }
}
