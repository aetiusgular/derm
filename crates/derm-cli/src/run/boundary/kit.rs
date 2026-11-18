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
//! Five agents have a kit: Claude Code (its own hook package, registered in
//! its managed settings) and, from 17 Nov 2026, Copilot CLI, Droid, Cursor
//! and Kiro (derm's command-hook packages, registered in the agent's own
//! config under its home: `packaging/sbx-kit/hooks/`). All five are v3
//! workloads in sbx 0.51.0, where a v3 mixin composed with each on the box.
//! Codex's gate is the Rust `derm hook`, which the VM has no binary of, and
//! Pi's is an extension whose emitter refuses the VM's host name; both are
//! later steps.
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
    /// The hook package's own files; `None` is Claude Code's kit.
    own: Option<&'static [(&'static str, &'static str)]>,
}

/// derm's kit for this harness id, if it has one.
pub(crate) fn spec(harness: &str) -> Option<Spec> {
    let s = |workload, name, registered, own| Spec {
        workload,
        name,
        registered,
        own,
    };
    Some(match harness {
        "claude-code" => s(
            "claude",
            "Claude Code",
            "Claude Code's managed settings",
            None,
        ),
        "copilot-cli" => s(
            "copilot",
            "Copilot CLI",
            "~/.copilot/hooks/derm.json",
            Some(COMPAT_OWN),
        ),
        "droid" => s(
            "droid",
            "Droid",
            "~/.factory/settings.json",
            Some(COMPAT_OWN),
        ),
        "cursor" => s("cursor", "Cursor", "~/.cursor/hooks.json", Some(NATIVE_OWN)),
        "kiro" => s("kiro", "Kiro", "~/.kiro/hooks/derm.json", Some(NATIVE_OWN)),
        _ => return None,
    })
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
        let dir = private_dir(parent).map_err(|e| format!("derm's sbx kit: {e}"))?;
        let prepared = Prepared { dir };
        write_kit(prepared.path(), harness, &text).map_err(|e| format!("derm's sbx kit: {e}"))?;
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
fn write_kit(dir: &Path, harness: &str, policy: &str) -> std::io::Result<()> {
    let spec = spec(harness).ok_or_else(|| std::io::Error::other("no kit for this harness"))?;
    let stage = dir.join("derm-kit");
    write(&stage.join("policy.json"), policy)?;
    let Some(own) = spec.own else {
        write(&dir.join("derm-gate-claude.yaml"), DESCRIPTOR)?;
        write(&dir.join("derm-gate-claude.dockerfile"), DOCKERFILE)?;
        write(&dir.join("derm-context.md"), CONTEXT)?;
        write(&stage.join("install.sh"), INSTALL)?;
        write(&stage.join("register-hooks.mjs"), REGISTER)?;
        for (rel, text) in PLUGIN {
            write(&stage.join("plugin").join(rel), text)?;
        }
        return Ok(());
    };
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
    Ok(())
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
