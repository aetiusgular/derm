//! derm's sbx kit: derm's gate inside the VM (lane T, phase 4; Tony's O1
//! decision, 4 Nov 2026). Under `--boundary sbx`, [`super::sbx::start`]
//! builds the kit for the chat with [`prepare`] and passes it to
//! `sbx create` as a mixin (`--kit <folder>`).
//!
//! The kit's text lives in `packaging/sbx-kit/` and the hook's code in
//! `packages/derm-claude-plugin/`; both are compiled into derm, so the gate
//! in the VM is the one this derm was built with, not whatever a plugin
//! cache or a download holds. Each chat gets its own copy in a private
//! folder, with the person's policy as it is at the start, and the folder
//! is removed once sbx has built it at the create.
//!
//! The kit is a v3 mixin (docker/sandbox-kit-spec SPEC-v3 at 6838e3e): a
//! descriptor, a Dockerfile whose overlay carries the hook, its own Node and
//! the install script, and the context the model reads. sbx 0.51.0 ships its
//! `claude` workload as a v3 kit and refuses a v1 or v2 mixin beside it
//! ("compositions are single-format"; Mac test w5, MW5-7), so the v2 form
//! this file wrote until fix pass 11 never went on a create there.
//!
//! Seven agents have a kit: Claude Code (its own hook package, registered
//! in its managed settings); from 17 Nov 2026 Copilot CLI, Droid, Cursor
//! and Kiro (derm's command-hook packages, registered in the agent's own
//! config under its home: `packaging/sbx-kit/hooks/`); Codex
//! (`packaging/sbx-kit/codex/`), whose gate is the Rust `derm hook`, so its
//! kit carries a Linux derm for the VM and derm's Codex plugin, and no
//! Node; and Pi (`packaging/sbx-kit/pi/`), whose kit is a v2 mixin because
//! Docker's Pi kit is a v2 sandbox, and carries derm's Pi package. The
//! first six are v3 workloads in sbx 0.51.0. Each form composed with its
//! workload on the box.
//!
//! A second form of the Claude Code kit and of the four command-hook kits
//! (19 Nov 2026, `plans/parallel/tk_kit_rust.md`), built when
//! [`SWITCH`] is `rust`: the gate is the Rust `derm hook`, as in Codex's
//! kit, so the kit carries a Linux derm for the VM and no Node, and derm
//! registers the hook itself (`derm kit register`, `crate::vmkit`). The
//! Node form stays the default until the box and the Mac have run this one.
//!
//! What the kit holds against: a model's mistakes inside the VM, the gap
//! sbx's own docs leave (the read-write mount, allowed hosts). What it does
//! not: an agent that sets out to remove it, since the agent has
//! passwordless sudo in the VM (the claude image's agent is in group sudo,
//! seen in the VM at fix pass 11; Docker's
//! security page). Lane T's status doc, P4-O1.

use std::path::{Path, PathBuf};

/// The kit's own files, from `packaging/sbx-kit/`. The descriptor and its
/// Dockerfile pair by file stem (SPEC-v3 3.1, the companion pair).
#[cfg_attr(not(unix), allow(dead_code))]
const DESCRIPTOR: &str =
    include_str!("../../../../../packaging/sbx-kit/claude/derm-gate-claude.yaml");
#[cfg_attr(not(unix), allow(dead_code))]
const DOCKERFILE: &str =
    include_str!("../../../../../packaging/sbx-kit/claude/derm-gate-claude.dockerfile");
#[cfg_attr(not(unix), allow(dead_code))]
const CONTEXT: &str = include_str!("../../../../../packaging/sbx-kit/claude/derm-context.md");
#[cfg_attr(not(unix), allow(dead_code))]
const INSTALL: &str = include_str!("../../../../../packaging/sbx-kit/claude/install.sh");
#[cfg_attr(not(unix), allow(dead_code))]
const REGISTER: &str = include_str!("../../../../../packaging/sbx-kit/register-hooks.mjs");

/// The generic kit for a command-hook agent (`packaging/sbx-kit/hooks/`):
/// one descriptor with three placeholder words [`write_kit`] fills in, its
/// Dockerfile, the install script and the registrar.
#[cfg_attr(not(unix), allow(dead_code))]
const HOOKS_DESCRIPTOR: &str =
    include_str!("../../../../../packaging/sbx-kit/hooks/derm-gate-hooks.yaml");
#[cfg_attr(not(unix), allow(dead_code))]
const HOOKS_DOCKERFILE: &str =
    include_str!("../../../../../packaging/sbx-kit/hooks/derm-gate-hooks.dockerfile");
#[cfg_attr(not(unix), allow(dead_code))]
const HOOKS_INSTALL: &str = include_str!("../../../../../packaging/sbx-kit/hooks/install.sh");
#[cfg_attr(not(unix), allow(dead_code))]
const REGISTER_AGENT: &str = include_str!("../../../../../packaging/sbx-kit/register-agent.mjs");

/// The Claude Code kit with derm as the gate (`packaging/sbx-kit/claude-rs/`):
/// its descriptor, Dockerfile and install script. The context file is the
/// Node form's.
#[cfg_attr(not(unix), allow(dead_code))]
const RS_DESCRIPTOR: &str =
    include_str!("../../../../../packaging/sbx-kit/claude-rs/derm-gate-claude.yaml");
#[cfg_attr(not(unix), allow(dead_code))]
const RS_DOCKERFILE: &str =
    include_str!("../../../../../packaging/sbx-kit/claude-rs/derm-gate-claude.dockerfile");
#[cfg_attr(not(unix), allow(dead_code))]
const RS_INSTALL: &str = include_str!("../../../../../packaging/sbx-kit/claude-rs/install.sh");

/// The command-hook kit with derm as the gate (`packaging/sbx-kit/hooks-rs/`).
#[cfg_attr(not(unix), allow(dead_code))]
const RS_HOOKS_DESCRIPTOR: &str =
    include_str!("../../../../../packaging/sbx-kit/hooks-rs/derm-gate-hooks.yaml");
#[cfg_attr(not(unix), allow(dead_code))]
const RS_HOOKS_DOCKERFILE: &str =
    include_str!("../../../../../packaging/sbx-kit/hooks-rs/derm-gate-hooks.dockerfile");
#[cfg_attr(not(unix), allow(dead_code))]
const RS_HOOKS_INSTALL: &str = include_str!("../../../../../packaging/sbx-kit/hooks-rs/install.sh");

/// Codex's kit (`packaging/sbx-kit/codex/`): the descriptor, its Dockerfile,
/// root's install script, the agent's setup script, and the trust entries
/// for the plugin's two hooks (a vitest test holds them equal to what
/// Codex computes from hooks.json).
#[cfg_attr(not(unix), allow(dead_code))]
const CODEX_DESCRIPTOR: &str =
    include_str!("../../../../../packaging/sbx-kit/codex/derm-gate-codex.yaml");
#[cfg_attr(not(unix), allow(dead_code))]
const CODEX_DOCKERFILE: &str =
    include_str!("../../../../../packaging/sbx-kit/codex/derm-gate-codex.dockerfile");
#[cfg_attr(not(unix), allow(dead_code))]
const CODEX_INSTALL: &str = include_str!("../../../../../packaging/sbx-kit/codex/install.sh");
#[cfg_attr(not(unix), allow(dead_code))]
const CODEX_SETUP: &str = include_str!("../../../../../packaging/sbx-kit/codex/setup.sh");
#[cfg_attr(not(unix), allow(dead_code))]
const CODEX_TRUST: &str = include_str!("../../../../../packaging/sbx-kit/codex/trust.toml");

/// The local marketplace Codex adds derm's plugin from, as the
/// Terminal-Bench bundle writes it (`tests/eval/lib/terminal-bench.mjs`).
#[cfg_attr(not(unix), allow(dead_code))]
const CODEX_MARKETPLACE: &str =
    r#"{"name":"derm","plugins":[{"name":"derm","source":{"source":"local","path":"./derm"}}]}"#;

/// Pi's kit (`packaging/sbx-kit/pi/`): a v2 mixin's spec and its two
/// scripts.
#[cfg_attr(not(unix), allow(dead_code))]
const PI_SPEC: &str = include_str!("../../../../../packaging/sbx-kit/pi/spec.yaml");
#[cfg_attr(not(unix), allow(dead_code))]
const PI_INSTALL: &str = include_str!("../../../../../packaging/sbx-kit/pi/install.sh");
#[cfg_attr(not(unix), allow(dead_code))]
const PI_SETUP: &str = include_str!("../../../../../packaging/sbx-kit/pi/setup.sh");

/// A hook package's own files (everything its hook loads outside
/// `src/core/`, which is the same text in every package and comes from
/// [`PLUGIN`]). A test checks each list against the hook's imports.
macro_rules! own {
    ($pkg:literal: $($rel:literal),+ $(,)?) => {
        &[$(($rel, include_str!(concat!("../../../../../packages/", $pkg, "/", $rel)))),+]
    };
}

/// derm-hooks-claude-compat: Copilot CLI and Droid.
#[cfg_attr(not(unix), allow(dead_code))]
pub(crate) const COMPAT_OWN: &[(&str, &str)] = own!("derm-hooks-claude-compat":
    "package.json",
    "bin/derm-hook.mjs",
    "src/agents.ts",
    "src/control.ts",
    "src/dialect.ts",
    "src/env.ts",
    "src/hook.ts",
);

/// derm-hooks-native: Cursor and Kiro.
#[cfg_attr(not(unix), allow(dead_code))]
pub(crate) const NATIVE_OWN: &[(&str, &str)] = own!("derm-hooks-native":
    "package.json",
    "bin/derm-hook.mjs",
    "bin/fallback.mjs",
    "src/control.ts",
    "src/crushServers.ts",
    "src/dialects/antigravity.ts",
    "src/dialects/crush.ts",
    "src/dialects/cursor.ts",
    "src/dialects/goose.ts",
    "src/dialects/kiro.ts",
    "src/dialects/mistralVibe.ts",
    "src/hook.ts",
    "src/kiroServers.ts",
    "src/mcpSplit.ts",
    "src/runner.ts",
    "src/shell.ts",
);

/// derm's Codex plugin, whole: what Codex copies when the plugin is added.
#[cfg_attr(not(unix), allow(dead_code))]
pub(crate) const CODEX_PLUGIN: &[(&str, &str)] = own!("derm-codex-plugin":
    ".codex-plugin/plugin.json",
    "hooks/hooks.json",
    "hooks/derm-gate.sh",
);

/// derm's Pi package as Pi loads it: package.json, its three extensions and
/// everything they import. A test checks the list against the imports.
#[cfg_attr(not(unix), allow(dead_code))]
pub(crate) const PI_PACKAGE: &[(&str, &str)] = own!("derm-pi":
    "package.json",
    "extensions/emitter.ts",
    "extensions/gate.ts",
    "extensions/memory.ts",
    "src/ask.ts",
    "src/command.ts",
    "src/confusables.ts",
    "src/content-switch.ts",
    "src/destructive.ts",
    "src/fold.ts",
    "src/freeze.ts",
    "src/harness.ts",
    "src/input-text.ts",
    "src/installs/index.ts",
    "src/installs/lockfile.ts",
    "src/installs/parse.ts",
    "src/otlp.ts",
    "src/owner.ts",
    "src/pi-api.ts",
    "src/policy.ts",
    "src/redact.ts",
    "src/serve/client.ts",
    "src/vm.ts",
);

/// What a kit is made of.
#[derive(Debug, Clone, Copy)]
#[cfg_attr(not(unix), allow(dead_code))]
enum Pack {
    /// Claude Code's own hook package and registrar.
    Claude,
    /// A command-hook package's own files, with the shared core.
    Hooks(&'static [(&'static str, &'static str)]),
    /// A derm for the VM and derm's Codex plugin.
    Codex,
    /// Claude Code with derm itself as the gate: a derm for the VM.
    ClaudeRust,
    /// A command-hook agent with derm itself as the gate: a derm for the VM.
    HooksRust,
    /// derm's Pi package, in a v2 mixin.
    Pi,
}

/// What derm's kit is for one harness.
#[derive(Debug, Clone, Copy)]
#[cfg_attr(not(unix), allow(dead_code))]
pub(crate) struct Spec {
    /// sbx's name for the agent's workload, which the mixin requires.
    pub workload: &'static str,
    /// The agent's name in a sentence.
    pub name: &'static str,
    /// Where the hook is registered in the VM, for the start line.
    pub registered: &'static str,
    pack: Pack,
}

/// derm's kit for this harness id, if it has one.
pub(crate) fn spec(harness: &str) -> Option<Spec> {
    let s = |workload, name, registered, pack| Spec {
        workload,
        name,
        registered,
        pack,
    };
    Some(match harness {
        "claude-code" => s(
            "claude",
            "Claude Code",
            "Claude Code's managed settings",
            Pack::Claude,
        ),
        "copilot-cli" => s(
            "copilot",
            "Copilot CLI",
            "~/.copilot/hooks/derm.json",
            Pack::Hooks(COMPAT_OWN),
        ),
        "droid" => s(
            "droid",
            "Droid",
            "~/.factory/settings.json",
            Pack::Hooks(COMPAT_OWN),
        ),
        "cursor" => s(
            "cursor",
            "Cursor",
            "~/.cursor/hooks.json",
            Pack::Hooks(NATIVE_OWN),
        ),
        "kiro" => s(
            "kiro",
            "Kiro",
            "~/.kiro/hooks/derm.json",
            Pack::Hooks(NATIVE_OWN),
        ),
        "codex" => s(
            "codex",
            "Codex",
            "Codex's own plugins and config.toml (~/.codex)",
            Pack::Codex,
        ),
        "pi" => s(
            "docker.io/sbx/pi-kit:latest",
            "Pi",
            "~/.pi/agent/settings.json",
            Pack::Pi,
        ),
        _ => return None,
    })
}

/// Whether [`SWITCH`]'s value asks for the kits whose gate is derm itself.
pub(crate) fn rust_gate(switch: Option<&str>) -> bool {
    switch.is_some_and(|v| v.eq_ignore_ascii_case("rust"))
}

/// derm's kit for this harness id under this value of [`SWITCH`]: with
/// `rust`, Claude Code and the four command-hook agents get the form whose
/// gate is `derm hook`; Codex's is that already, and Pi's gate is its
/// extension, which Pi loads as JavaScript, so both are as [`spec`] has them.
pub(crate) fn spec_for(harness: &str, switch: Option<&str>) -> Option<Spec> {
    let s = spec(harness)?;
    if !rust_gate(switch) {
        return Some(s);
    }
    Some(Spec {
        pack: match s.pack {
            Pack::Claude => Pack::ClaudeRust,
            Pack::Hooks(_) => Pack::HooksRust,
            p => p,
        },
        ..s
    })
}

/// Whether the kit built for this harness under this switch has derm itself
/// as its gate because the switch asked for it (the start line says so).
pub(crate) fn rust_form(harness: &str, switch: Option<&str>) -> bool {
    matches!(
        spec_for(harness, switch).map(|s| s.pack),
        Some(Pack::ClaudeRust | Pack::HooksRust)
    )
}

/// derm's Claude Code hook as it runs: the launcher, the hook and every
/// module it imports, by their paths in the package. A test checks this
/// list against the hook's imports, so a new core file cannot be left out.
#[cfg_attr(not(unix), allow(dead_code))]
pub(crate) const PLUGIN: &[(&str, &str)] = &[
    (
        "package.json",
        include_str!("../../../../../packages/derm-claude-plugin/package.json"),
    ),
    (
        "bin/derm-hook.mjs",
        include_str!("../../../../../packages/derm-claude-plugin/bin/derm-hook.mjs"),
    ),
    (
        "src/hook.ts",
        include_str!("../../../../../packages/derm-claude-plugin/src/hook.ts"),
    ),
    (
        "src/core/command.ts",
        include_str!("../../../../../packages/derm-claude-plugin/src/core/command.ts"),
    ),
    (
        "src/core/confusables.ts",
        include_str!("../../../../../packages/derm-claude-plugin/src/core/confusables.ts"),
    ),
    (
        "src/core/daemon.ts",
        include_str!("../../../../../packages/derm-claude-plugin/src/core/daemon.ts"),
    ),
    // Step 7e's reader (eval pass 1, E1-1): policy.ts imports it.
    (
        "src/core/destructive.ts",
        include_str!("../../../../../packages/derm-claude-plugin/src/core/destructive.ts"),
    ),
    (
        "src/core/fold.ts",
        include_str!("../../../../../packages/derm-claude-plugin/src/core/fold.ts"),
    ),
    (
        "src/core/gate.ts",
        include_str!("../../../../../packages/derm-claude-plugin/src/core/gate.ts"),
    ),
    (
        "src/core/owner.ts",
        include_str!("../../../../../packages/derm-claude-plugin/src/core/owner.ts"),
    ),
    (
        "src/core/policy.ts",
        include_str!("../../../../../packages/derm-claude-plugin/src/core/policy.ts"),
    ),
    (
        "src/core/redact.ts",
        include_str!("../../../../../packages/derm-claude-plugin/src/core/redact.ts"),
    ),
    (
        "src/core/installs/index.ts",
        include_str!("../../../../../packages/derm-claude-plugin/src/core/installs/index.ts"),
    ),
    (
        "src/core/installs/lockfile.ts",
        include_str!("../../../../../packages/derm-claude-plugin/src/core/installs/lockfile.ts"),
    ),
    (
        "src/core/installs/parse.ts",
        include_str!("../../../../../packages/derm-claude-plugin/src/core/installs/parse.ts"),
    ),
];

/// The variable that turns the kit off for one run (`DERM_SBX_KIT=off`):
/// the way back to phase 3's behaviour if the kit's create fails on an
/// image derm has not seen (its Node cannot run the hook, say). The start
/// line says the gate is not in the VM, as it did before the kit.
/// `DERM_SBX_KIT=rust` builds the kit whose gate is derm itself
/// ([`spec_for`]).
pub(crate) const SWITCH: &str = "DERM_SBX_KIT";

/// Policy files bigger than this are not copied (`derm_core::policy`'s cap).
#[cfg_attr(not(unix), allow(dead_code))]
const MAX_POLICY: u64 = derm_core::policy::MAX_POLICY_BYTES;

/// Whether derm has a kit for this harness id.
pub(crate) fn has_kit(harness: &str) -> bool {
    spec(harness).is_some()
}

/// A kit folder built for one chat; dropping it removes the folder.
#[derive(Debug)]
pub(crate) struct Prepared {
    dir: PathBuf,
}

impl Prepared {
    pub(crate) fn path(&self) -> &Path {
        &self.dir
    }
}

impl Drop for Prepared {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// What [`prepare`] decided for the chat.
#[derive(Debug)]
pub(crate) enum Kit {
    /// The kit is built; pass it to the create. Built only on Unix
    /// ([`prepare`]); sbx's start matches it on every system.
    #[cfg_attr(
        not(unix),
        expect(dead_code, reason = "prepare builds a kit on Unix hosts only")
    )]
    Built(Prepared),
    /// No kit for this run, and why, for the start line.
    Without(String),
}

/// The kit for `harness`, with the policy at `policy` (the person's,
/// `derm_core::policy::default_path`), in a new private folder under
/// `parent`. `switch` is [`SWITCH`]'s value.
///
/// No kit when derm has none for the harness, when the switch is `off`, or
/// when the policy cannot be used: missing, invalid, a link, not the
/// person's, or writable by others. With no usable policy every call in the
/// VM would ask, and under the kit's full access every ask is a deny, so the
/// agent could do nothing; the chat runs as before the kit and the start
/// line says why. An error building the folder stops the chat.
pub(crate) fn prepare(
    harness: &str,
    policy: Option<&Path>,
    parent: &Path,
    switch: Option<&str>,
) -> Result<Kit, String> {
    if !has_kit(harness) {
        return Ok(Kit::Without(format!(
            "derm has no sbx kit for {harness} yet"
        )));
    }
    if switch.is_some_and(|v| v.eq_ignore_ascii_case("off")) {
        return Ok(Kit::Without(format!("{SWITCH}=off is set")));
    }
    // The kit's private folder and files are written with Unix modes; on a
    // Windows host derm runs the chat without the kit and says so
    // (integration w5's close; the Windows form goes through the seam).
    #[cfg(not(unix))]
    {
        let _ = (policy, parent);
        Ok(Kit::Without(
            "derm's sbx kit is built for Linux and macOS hosts only in this build".into(),
        ))
    }
    #[cfg(unix)]
    {
        let Some(policy) = policy else {
            return Ok(Kit::Without(
                "no policy path (HOME and DERM_POLICY are unset)".into(),
            ));
        };
        let text = match policy_text(policy) {
            Ok(t) => t,
            Err(why) => return Ok(Kit::Without(why)),
        };
        // Codex's gate is derm itself, so its kit needs a derm the VM can
        // run. With none there is no kit, and the chat runs as it did
        // before Codex had one. The same holds for the kits `rust` asks
        // for: derm does not fall back to the Node form without a word,
        // since the person asked for this one; the reason names the way
        // back.
        let pack = spec_for(harness, switch).map(|s| s.pack);
        let derm = match pack {
            Some(Pack::Codex) => match vm_derm() {
                Ok(p) => Some(p),
                Err(why) => return Ok(Kit::Without(why)),
            },
            Some(Pack::ClaudeRust | Pack::HooksRust) => match vm_derm() {
                Ok(p) => Some(p),
                Err(why) => {
                    return Ok(Kit::Without(format!(
                        "{SWITCH}=rust is set and {why}; unset {SWITCH} for derm's kit that carries Node"
                    )))
                }
            },
            _ => None,
        };
        let dir = private_dir(parent).map_err(|e| format!("derm's sbx kit: {e}"))?;
        let prepared = Prepared { dir };
        write_kit(prepared.path(), harness, switch, &text, derm.as_deref())
            .map_err(|e| format!("derm's sbx kit: {e}"))?;
        Ok(Kit::Built(prepared))
    }
}

#[cfg(unix)]
/// The policy's text, when it is one the hook in the VM would trust were it
/// on the host: a regular file, not a link, the person's own, writable by
/// no one else, under the size cap, and valid.
fn policy_text(path: &Path) -> Result<String, String> {
    let shown = path.display();
    let meta = match std::fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(format!(
                "no policy file at {shown}, and with none every call in the VM would be denied"
            ))
        }
        Err(e) => {
            return Err(format!(
                "the policy at {shown} cannot be read ({})",
                e.kind()
            ))
        }
    };
    use std::os::unix::fs::PermissionsExt;
    if !meta.file_type().is_file() {
        return Err(format!("the policy at {shown} is not a regular file"));
    }
    if derm_core::platform::owner(&meta) != derm_core::platform::real_user() {
        return Err(format!("the policy at {shown} is not yours"));
    }
    if meta.permissions().mode() & 0o022 != 0 {
        return Err(format!("the policy at {shown} is writable by others"));
    }
    if meta.len() > MAX_POLICY {
        return Err(format!("the policy at {shown} is over 1 MiB"));
    }
    let text = std::fs::read_to_string(path)
        .map_err(|e| format!("the policy at {shown} cannot be read ({})", e.kind()))?;
    derm_core::policy::parse(&text).map_err(|e| format!("the policy at {shown}: {e}"))?;
    Ok(text)
}

#[cfg(unix)]
fn private_dir(parent: &Path) -> std::io::Result<PathBuf> {
    use std::os::unix::fs::DirBuilderExt;
    let dir = parent.join(format!("derm-sbx-kit-{}", uuid::Uuid::new_v4().simple()));
    std::fs::DirBuilder::new().mode(0o700).create(&dir)?;
    Ok(dir)
}

#[cfg(unix)]
/// The kit's layout (SPEC-v3 3.1): the descriptor and its Dockerfile at the
/// top, the context the descriptor names beside them, and under `derm-kit/`
/// what the Dockerfile copies into `/opt/derm-kit-src` in the VM.
fn write_kit(
    dir: &Path,
    harness: &str,
    switch: Option<&str>,
    policy: &str,
    derm: Option<&Path>,
) -> std::io::Result<()> {
    let spec = spec_for(harness, switch)
        .ok_or_else(|| std::io::Error::other("no kit for this harness"))?;
    // A v2 kit's payload is files/home/, which sbx copies into the agent's
    // home; a v3 kit's is whatever its Dockerfile copies.
    let stage = match spec.pack {
        Pack::Pi => dir.join("files/home/.derm-kit-src"),
        _ => dir.join("derm-kit"),
    };
    write(&stage.join("policy.json"), policy)?;
    match spec.pack {
        Pack::Pi => {
            write(&dir.join("spec.yaml"), PI_SPEC)?;
            write(&stage.join("install.sh"), PI_INSTALL)?;
            write(&stage.join("setup.sh"), PI_SETUP)?;
            for (rel, text) in PI_PACKAGE {
                write(&stage.join("derm-pi").join(rel), text)?;
            }
        }
        Pack::Claude => {
            write(&dir.join("derm-gate-claude.yaml"), DESCRIPTOR)?;
            write(&dir.join("derm-gate-claude.dockerfile"), DOCKERFILE)?;
            write(&dir.join("derm-context.md"), CONTEXT)?;
            write(&stage.join("install.sh"), INSTALL)?;
            write(&stage.join("register-hooks.mjs"), REGISTER)?;
            for (rel, text) in PLUGIN {
                write(&stage.join("plugin").join(rel), text)?;
            }
        }
        Pack::Hooks(own) => {
            let descriptor = HOOKS_DESCRIPTOR
                .replace("@WORKLOAD@", spec.workload)
                .replace("@AGENT@", harness)
                .replace("@NAME@", spec.name);
            write(&dir.join("derm-gate-hooks.yaml"), &descriptor)?;
            write(&dir.join("derm-gate-hooks.dockerfile"), HOOKS_DOCKERFILE)?;
            write(&stage.join("install.sh"), HOOKS_INSTALL)?;
            write(&stage.join("register-agent.mjs"), REGISTER_AGENT)?;
            for (rel, text) in own.iter().chain(core()) {
                write(&stage.join("plugin").join(rel), text)?;
            }
        }
        Pack::Codex => {
            let derm = derm.ok_or_else(|| std::io::Error::other("no derm for the VM"))?;
            write(&dir.join("derm-gate-codex.yaml"), CODEX_DESCRIPTOR)?;
            write(&dir.join("derm-gate-codex.dockerfile"), CODEX_DOCKERFILE)?;
            write(&stage.join("install.sh"), CODEX_INSTALL)?;
            write(&stage.join("setup.sh"), CODEX_SETUP)?;
            write(&stage.join("trust.toml"), CODEX_TRUST)?;
            let mkt = stage.join("mkt");
            write(
                &mkt.join(".agents/plugins/marketplace.json"),
                CODEX_MARKETPLACE,
            )?;
            for (rel, text) in CODEX_PLUGIN {
                write(&mkt.join("derm").join(rel), text)?;
            }
            // The binary, into a file made here and the person's alone.
            write(&stage.join("derm"), "")?;
            std::fs::write(stage.join("derm"), std::fs::read(derm)?)?;
        }
        Pack::ClaudeRust => {
            let derm = derm.ok_or_else(|| std::io::Error::other("no derm for the VM"))?;
            write(&dir.join("derm-gate-claude.yaml"), RS_DESCRIPTOR)?;
            write(&dir.join("derm-gate-claude.dockerfile"), RS_DOCKERFILE)?;
            write(&dir.join("derm-context.md"), CONTEXT)?;
            write(&stage.join("install.sh"), RS_INSTALL)?;
            write(&stage.join("derm"), "")?;
            std::fs::write(stage.join("derm"), std::fs::read(derm)?)?;
        }
        Pack::HooksRust => {
            let derm = derm.ok_or_else(|| std::io::Error::other("no derm for the VM"))?;
            let descriptor = RS_HOOKS_DESCRIPTOR
                .replace("@WORKLOAD@", spec.workload)
                .replace("@AGENT@", harness)
                .replace("@NAME@", spec.name);
            write(&dir.join("derm-gate-hooks.yaml"), &descriptor)?;
            write(&dir.join("derm-gate-hooks.dockerfile"), RS_HOOKS_DOCKERFILE)?;
            write(&stage.join("install.sh"), RS_HOOKS_INSTALL)?;
            write(&stage.join("derm"), "")?;
            std::fs::write(stage.join("derm"), std::fs::read(derm)?)?;
        }
    }
    Ok(())
}

#[cfg(test)]
thread_local! {
    /// A test's stand-in for the derm the Codex kit carries.
    pub(crate) static TEST_VM_DERM: std::cell::RefCell<Option<Result<PathBuf, String>>> =
        const { std::cell::RefCell::new(None) };
}

#[cfg(unix)]
/// The Linux derm the Codex kit carries into the VM. On a Linux host it is
/// this derm (the VM has the host's architecture; whether it runs there is
/// the install script's to find out). On another host it is a file the
/// person put at `~/.derm/kit/derm-linux-<arch>`, since derm has no Linux
/// build of itself to hand. Either must pass [`checked_vm_derm`].
fn vm_derm() -> Result<PathBuf, String> {
    #[cfg(test)]
    if let Some(r) = TEST_VM_DERM.with(|t| t.borrow().clone()) {
        return r.and_then(|p| checked_vm_derm(&p));
    }
    if cfg!(target_os = "linux") {
        let exe = std::env::current_exe()
            .and_then(std::fs::canonicalize)
            .map_err(|e| format!("derm cannot read its own path for the kit ({})", e.kind()))?;
        return checked_vm_derm(&exe);
    }
    let name = format!("derm-linux-{}", std::env::consts::ARCH);
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .filter(|h| h.is_absolute())
        .ok_or_else(|| {
            format!(
                "no Linux derm for the VM: HOME is unset, so ~/.derm/kit/{name} cannot be found"
            )
        })?;
    checked_vm_derm(&home.join(".derm").join("kit").join(name))
}

#[cfg(unix)]
/// A derm fit to carry into the VM: a regular file, not a link, the
/// person's own or root's, writable by no one else. What it is copied from
/// is what the agent's gate will be.
fn checked_vm_derm(path: &Path) -> Result<PathBuf, String> {
    use std::os::unix::fs::PermissionsExt;
    let shown = path.display();
    let meta = match std::fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(format!(
                "no Linux derm for the VM at {shown} (a kit whose gate is derm itself carries one; on a host that is not Linux, put a Linux build of derm for this machine's architecture there)"
            ))
        }
        Err(e) => return Err(format!("the derm for the VM at {shown} cannot be read ({})", e.kind())),
    };
    if !meta.file_type().is_file() {
        return Err(format!(
            "the derm for the VM at {shown} is not a regular file"
        ));
    }
    let owner = derm_core::platform::owner(&meta);
    if owner != derm_core::platform::real_user() && owner != 0 {
        return Err(format!(
            "the derm for the VM at {shown} is not yours or root's"
        ));
    }
    if meta.permissions().mode() & 0o022 != 0 {
        return Err(format!(
            "the derm for the VM at {shown} is writable by others"
        ));
    }
    Ok(path.to_path_buf())
}

#[cfg(unix)]
/// The shared gate core, `src/core/`: the same text in every hook package
/// (scripts/sync-core.mjs; a test here holds it), so the kit takes it from
/// the Claude Code package's list.
fn core() -> impl Iterator<Item = &'static (&'static str, &'static str)> {
    PLUGIN
        .iter()
        .filter(|(rel, _)| rel.starts_with("src/core/"))
}

#[cfg(unix)]
fn write(path: &Path, text: &str) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
    if let Some(p) = path.parent() {
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(p)?;
    }
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    f.write_all(text.as_bytes())
}

#[cfg(all(test, unix))]
mod tests;
