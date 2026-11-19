//! derm's sbx kit: derm's gate inside the VM (lane T, phase 4; Tony's O1
//! decision, 4 Nov 2026). Under `--boundary sbx`, [`super::sbx::start`]
//! builds the kit for the chat with [`prepare`] and passes it to
//! `sbx create` as a mixin (`--kit <folder>`).
//!
//! The kit's text lives in `packaging/sbx-kit/` and is compiled into derm,
//! with derm's Codex plugin and derm's Pi package; the gate in the VM is
//! the one this derm was built with, not whatever a plugin cache or a
//! download holds. Each chat gets its own copy in a private folder, with
//! the person's policy as it is at the start, and the folder is removed
//! once sbx has built it at the create.
//!
//! Seven agents have a kit. For six the gate in the VM is derm itself, the
//! Rust `derm hook`: the kit carries a Linux derm for the VM ([`vm_derm`])
//! and no Node. Claude Code's (`packaging/sbx-kit/claude/`) registers the
//! hooks in Claude Code's managed settings; Copilot CLI's, Droid's,
//! Cursor's and Kiro's (`packaging/sbx-kit/hooks/`) in the agent's own
//! config under its home, both with `derm kit register` (`crate::vmkit`);
//! Codex's (`packaging/sbx-kit/codex/`) through derm's Codex plugin. Those
//! six are v3 mixins (docker/sandbox-kit-spec SPEC-v3 at 6838e3e): sbx
//! 0.51.0 ships these workloads as v3 kits and refuses a v1 or v2 mixin
//! beside one ("compositions are single-format"; Mac test w5, MW5-7). Pi's
//! (`packaging/sbx-kit/pi/`) is a v2 mixin because Docker's Pi kit is a v2
//! sandbox; its gate is derm's Pi package, which Pi loads as JavaScript.
//!
//! Until 19 Nov 2026 the Claude Code kit and the four command-hook kits
//! carried a Node and derm's TypeScript hook packages. The derm form ran
//! beside them under `DERM_SBX_KIT=rust`, gave the same decisions in real
//! VMs and in real Claude Code turns on Linux and on a Mac
//! (`plans/parallel/tk_kit_rust.md`), and replaced them; `rust` is still
//! taken as a value and changes nothing.
//!
//! What the kit holds against: a model's mistakes inside the VM, the gap
//! sbx's own docs leave (the read-write mount, allowed hosts). What it does
//! not: an agent that sets out to remove it, since the agent has
//! passwordless sudo in the VM (the claude image's agent is in group sudo,
//! seen in the VM at fix pass 11; Docker's
//! security page). Lane T's status doc, P4-O1.

use std::path::{Path, PathBuf};

/// Claude Code's kit (`packaging/sbx-kit/claude/`). The descriptor and its
/// Dockerfile pair by file stem (SPEC-v3 3.1, the companion pair); the
/// overlay holds the install script, the policy and a derm for the VM.
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

/// The kit for a command-hook agent (`packaging/sbx-kit/hooks/`): one
/// descriptor with three words derm fills in (the workload, derm's id for
/// the agent, its name), and root's install script.
#[cfg_attr(not(unix), allow(dead_code))]
const HOOKS_DESCRIPTOR: &str =
    include_str!("../../../../../packaging/sbx-kit/hooks/derm-gate-hooks.yaml");
#[cfg_attr(not(unix), allow(dead_code))]
const HOOKS_DOCKERFILE: &str =
    include_str!("../../../../../packaging/sbx-kit/hooks/derm-gate-hooks.dockerfile");
#[cfg_attr(not(unix), allow(dead_code))]
const HOOKS_INSTALL: &str = include_str!("../../../../../packaging/sbx-kit/hooks/install.sh");

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

/// A package's files as the kit carries them, by their paths in the
/// package. A test checks Pi's list against its imports.
macro_rules! own {
    ($pkg:literal: $($rel:literal),+ $(,)?) => {
        &[$(($rel, include_str!(concat!("../../../../../packages/", $pkg, "/", $rel)))),+]
    };
}

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
    "src/content-switch.ts",
    "src/freeze.ts",
    "src/harness.ts",
    "src/input-text.ts",
    "src/otlp.ts",
    "src/owner.ts",
    "src/pi-api.ts",
    "src/redact.ts",
    "src/serve/client.ts",
    "src/vm.ts",
);

/// What a kit is made of.
#[derive(Debug, Clone, Copy)]
#[cfg_attr(not(unix), allow(dead_code))]
enum Pack {
    /// Claude Code, with derm itself as the gate: a derm for the VM.
    Claude,
    /// A command-hook agent, with derm itself as the gate: a derm for the VM.
    Hooks,
    /// A derm for the VM and derm's Codex plugin.
    Codex,
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
            Pack::Hooks,
        ),
        "droid" => s("droid", "Droid", "~/.factory/settings.json", Pack::Hooks),
        "cursor" => s("cursor", "Cursor", "~/.cursor/hooks.json", Pack::Hooks),
        "kiro" => s("kiro", "Kiro", "~/.kiro/hooks/derm.json", Pack::Hooks),
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

/// Whether the gate derm's kit puts in the VM for this harness is derm
/// itself (`derm hook`), which keeps a chat's taint in the daemon over the
/// VM route. Pi's is its extension, which keeps none.
pub(crate) fn gate_is_derm(harness: &str) -> bool {
    matches!(
        spec(harness).map(|s| s.pack),
        Some(Pack::Claude | Pack::Hooks | Pack::Codex)
    )
}

/// The variable that turns the kit off for one run (`DERM_SBX_KIT=off`):
/// the way back to phase 3's behaviour if the kit's create fails on an
/// image derm has not seen (the derm it carries cannot run there, say). The
/// start line says the gate is not in the VM, as it did before the kit.
/// Any other value changes nothing (`rust` chose the derm form while it was
/// the second one).
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
        // Where the gate is derm itself the kit needs a derm the VM can
        // run. With none there is no kit, and the chat runs as it did
        // before the agent had one; the reason says where derm looked.
        let derm = if gate_is_derm(harness) {
            match vm_derm() {
                Ok(p) => Some(p),
                Err(why) => return Ok(Kit::Without(why)),
            }
        } else {
            None
        };
        let dir = private_dir(parent).map_err(|e| format!("derm's sbx kit: {e}"))?;
        let prepared = Prepared { dir };
        write_kit(prepared.path(), harness, &text, derm.as_deref())
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
fn write_kit(dir: &Path, harness: &str, policy: &str, derm: Option<&Path>) -> std::io::Result<()> {
    let spec = spec(harness).ok_or_else(|| std::io::Error::other("no kit for this harness"))?;
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
        Pack::Claude => {
            let derm = derm.ok_or_else(|| std::io::Error::other("no derm for the VM"))?;
            write(&dir.join("derm-gate-claude.yaml"), DESCRIPTOR)?;
            write(&dir.join("derm-gate-claude.dockerfile"), DOCKERFILE)?;
            write(&dir.join("derm-context.md"), CONTEXT)?;
            write(&stage.join("install.sh"), INSTALL)?;
            write(&stage.join("derm"), "")?;
            std::fs::write(stage.join("derm"), std::fs::read(derm)?)?;
        }
        Pack::Hooks => {
            let derm = derm.ok_or_else(|| std::io::Error::other("no derm for the VM"))?;
            let descriptor = HOOKS_DESCRIPTOR
                .replace("@WORKLOAD@", spec.workload)
                .replace("@AGENT@", harness)
                .replace("@NAME@", spec.name);
            write(&dir.join("derm-gate-hooks.yaml"), &descriptor)?;
            write(&dir.join("derm-gate-hooks.dockerfile"), HOOKS_DOCKERFILE)?;
            write(&stage.join("install.sh"), HOOKS_INSTALL)?;
            write(&stage.join("derm"), "")?;
            std::fs::write(stage.join("derm"), std::fs::read(derm)?)?;
        }
    }
    Ok(())
}

#[cfg(test)]
thread_local! {
    /// A test's stand-in for the derm a kit carries.
    pub(crate) static TEST_VM_DERM: std::cell::RefCell<Option<Result<PathBuf, String>>> =
        const { std::cell::RefCell::new(None) };
}

#[cfg(unix)]
/// The Linux derm a kit carries into the VM. On a Linux host it is this
/// derm (the VM has the host's architecture; whether it runs there is the
/// install script's to find out). On another host derm has no Linux build
/// of itself in hand, so it is a file: [`vm_derm_off_linux`]. Either must
/// pass [`checked_vm_derm`].
fn vm_derm() -> Result<PathBuf, String> {
    #[cfg(test)]
    if let Some(r) = TEST_VM_DERM.with(|t| t.borrow().clone()) {
        return r.and_then(|p| checked_vm_derm(&p));
    }
    let exe = std::env::current_exe().and_then(std::fs::canonicalize);
    if cfg!(target_os = "linux") {
        let exe =
            exe.map_err(|e| format!("derm cannot read its own path for the kit ({})", e.kind()))?;
        return checked_vm_derm(&exe);
    }
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .filter(|h| h.is_absolute());
    vm_derm_off_linux(home.as_deref(), exe.ok().as_deref(), std::env::consts::ARCH)
}

#[cfg(unix)]
/// The Linux derm for the VM on a host that is not Linux, for this
/// machine's architecture (`derm-linux-aarch64`, `derm-linux-x86_64`). Two
/// places, in order: the person's own, `~/.derm/kit/`, which wins so a build
/// of their own can be tried; then beside the install, `../libexec/kit/`
/// from the folder derm itself is in, where derm's Homebrew formula puts
/// the one from the same release (`packaging/homebrew/derm.rb.in`). A file
/// that is there and fails [`checked_vm_derm`] is an error, not a reason to
/// look further: the person should hear that it was refused.
fn vm_derm_off_linux(
    home: Option<&Path>,
    exe: Option<&Path>,
    arch: &str,
) -> Result<PathBuf, String> {
    let name = format!("derm-linux-{arch}");
    let own = home.map(|h| h.join(".derm").join("kit").join(&name));
    let beside = exe
        .and_then(Path::parent)
        .and_then(Path::parent)
        .map(|prefix| prefix.join("libexec").join("kit").join(&name));
    for at in [&own, &beside].into_iter().flatten() {
        if std::fs::symlink_metadata(at).is_ok() {
            return checked_vm_derm(at);
        }
    }
    let looked: Vec<String> = [&own, &beside]
        .into_iter()
        .flatten()
        .map(|p| p.display().to_string())
        .collect();
    Err(format!(
        "no Linux derm for the VM ({}): the kit carries one as the agent's gate. derm's Homebrew formula installs it; with another install, put a Linux build of derm for this machine's architecture at ~/.derm/kit/{name}",
        if looked.is_empty() {
            "HOME is unset and derm cannot read its own path".to_string()
        } else {
            format!("looked at {}", looked.join(" and "))
        }
    ))
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
            return Err(format!("no Linux derm for the VM at {shown}"))
        }
        Err(e) => {
            return Err(format!(
                "the derm for the VM at {shown} cannot be read ({})",
                e.kind()
            ))
        }
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
