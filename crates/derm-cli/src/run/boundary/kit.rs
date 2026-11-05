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
//! is removed once sbx has read it at the create (SPEC-v2 5.8: "copied
//! into the container at create time").
//!
//! Only Claude Code has a kit yet. Codex's gate lets a call through when it
//! fails (`coverage.failMode: open`) and Pi's kit runs Pi 1.5.0 past the
//! preset's 1.4.0 (case 81); both are later steps.
//!
//! What the kit holds against: a model's mistakes inside the VM, the gap
//! sbx's own docs leave (the read-write mount, allowed hosts). What it does
//! not: an agent that sets out to remove it, since the agent has
//! passwordless sudo in the VM (sbx-kits-contrib SPEC-v2 9.1; Docker's
//! security page). Lane T's status doc, P4-O1.

use std::path::{Path, PathBuf};

/// The kit's own files, from `packaging/sbx-kit/`.
const SPEC: &str = include_str!("../../../../../packaging/sbx-kit/claude/spec.yaml");
const INSTALL: &str = include_str!("../../../../../packaging/sbx-kit/claude/install.sh");
const REGISTER: &str = include_str!("../../../../../packaging/sbx-kit/register-hooks.mjs");

/// derm's Claude Code hook as it runs: the launcher, the hook and every
/// module it imports, by their paths in the package. A test checks this
/// list against the hook's imports, so a new core file cannot be left out.
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
const MAX_POLICY: u64 = derm_core::policy::MAX_POLICY_BYTES;

/// Whether derm has a kit for this harness id.
pub(crate) fn has_kit(harness: &str) -> bool {
    harness == "claude-code"
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
    /// The kit is built; pass it to the create.
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
    write_kit(prepared.path(), &text).map_err(|e| format!("derm's sbx kit: {e}"))?;
    Ok(Kit::Built(prepared))
}

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

fn private_dir(parent: &Path) -> std::io::Result<PathBuf> {
    use std::os::unix::fs::DirBuilderExt;
    let dir = parent.join(format!("derm-sbx-kit-{}", uuid::Uuid::new_v4().simple()));
    std::fs::DirBuilder::new().mode(0o700).create(&dir)?;
    Ok(dir)
}

/// The kit's layout (SPEC-v2 5.8): `spec.yaml` at the top, and under
/// `files/home/` what lands in `/home/agent/`.
fn write_kit(dir: &Path, policy: &str) -> std::io::Result<()> {
    let stage = dir.join("files/home/.derm-kit");
    write(&dir.join("spec.yaml"), SPEC)?;
    write(&stage.join("install.sh"), INSTALL)?;
    write(&stage.join("register-hooks.mjs"), REGISTER)?;
    write(&stage.join("policy.json"), policy)?;
    for (rel, text) in PLUGIN {
        write(&stage.join("plugin").join(rel), text)?;
    }
    Ok(())
}

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

#[cfg(test)]
mod tests;
