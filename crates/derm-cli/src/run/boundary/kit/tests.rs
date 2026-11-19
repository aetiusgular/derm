//! derm's sbx kit for one chat (lane T, phase 4).

use super::*;
use std::collections::BTreeSet;
use std::os::unix::fs::PermissionsExt;

const POLICY: &str = r#"{"version":1,"rules":[{"tool":"bash","action":"ask"}]}"#;

fn tmp(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!(
        "derm-kit-{name}-{}-{}",
        std::process::id(),
        &uuid::Uuid::new_v4().simple().to_string()[..6]
    ));
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn policy_at(dir: &Path, text: &str, mode: u32) -> PathBuf {
    let p = dir.join("policy.json");
    std::fs::write(&p, text).unwrap();
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(mode)).unwrap();
    p
}

fn files_under(dir: &Path) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        for e in std::fs::read_dir(&d).unwrap() {
            let p = e.unwrap().path();
            if p.is_dir() {
                stack.push(p);
            } else {
                out.insert(p.strip_prefix(dir).unwrap().to_string_lossy().into_owned());
            }
        }
    }
    out
}

#[test]
fn claude_code_gets_a_private_kit_with_its_policy_and_the_hook() {
    let d = tmp("built");
    let policy = policy_at(&d, POLICY, 0o600);
    let kit = prepare("claude-code", Some(&policy), &d, None).unwrap();
    let Kit::Built(p) = kit else {
        panic!("no kit: {kit:?}")
    };
    let root = p.path().to_path_buf();
    assert_eq!(
        std::fs::metadata(&root).unwrap().permissions().mode() & 0o777,
        0o700
    );
    let files = files_under(&root);
    for want in [
        "derm-gate-claude.yaml",
        "derm-gate-claude.dockerfile",
        "derm-context.md",
        "derm-kit/install.sh",
        "derm-kit/register-hooks.mjs",
        "derm-kit/policy.json",
        "derm-kit/plugin/bin/derm-hook.mjs",
        "derm-kit/plugin/src/hook.ts",
        "derm-kit/plugin/src/core/gate.ts",
        "derm-kit/plugin/package.json",
    ] {
        assert!(files.contains(want), "{want} missing from {files:?}");
    }
    assert_eq!(files.len(), 6 + PLUGIN.len(), "{files:?}");
    assert_eq!(
        std::fs::read_to_string(root.join("derm-kit/policy.json")).unwrap(),
        POLICY,
        "the policy as it is at the start"
    );
    let staged = root.join("derm-kit/policy.json");
    assert_eq!(
        std::fs::metadata(&staged).unwrap().permissions().mode() & 0o777,
        0o600
    );
    drop(p);
    assert!(!root.exists(), "the folder goes with the kit");
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn no_kit_and_why_for_another_agent_the_switch_and_every_policy_it_cannot_use() {
    let d = tmp("without");
    let good = policy_at(&d, POLICY, 0o600);
    let why = |k: Kit| match k {
        Kit::Without(w) => w,
        Kit::Built(_) => panic!("a kit was built"),
    };
    // 17 Nov 2026: Codex has a kit now, so the agent with none is OpenCode.
    assert!(why(prepare("opencode", Some(&good), &d, None).unwrap())
        .contains("no sbx kit for opencode"));
    // 17 Nov 2026: Pi has a kit now; Gemini is another agent with none.
    assert!(
        why(prepare("gemini", Some(&good), &d, None).unwrap()).contains("no sbx kit for gemini")
    );
    assert!(
        why(prepare("claude-code", Some(&good), &d, Some("off")).unwrap())
            .contains("DERM_SBX_KIT=off")
    );
    assert!(
        why(prepare("claude-code", Some(&good), &d, Some("OFF")).unwrap())
            .contains("DERM_SBX_KIT=off")
    );
    assert!(why(prepare("claude-code", None, &d, None).unwrap()).contains("no policy path"));
    let missing = d.join("nope.json");
    assert!(
        why(prepare("claude-code", Some(&missing), &d, None).unwrap())
            .contains("every call in the VM would be denied")
    );
    let loose_dir = tmp("loose");
    let loose = policy_at(&loose_dir, POLICY, 0o666);
    assert!(
        why(prepare("claude-code", Some(&loose), &d, None).unwrap()).contains("writable by others")
    );
    let bad_dir = tmp("bad");
    let bad = policy_at(&bad_dir, r#"{"version":2}"#, 0o600);
    assert!(why(prepare("claude-code", Some(&bad), &d, None).unwrap()).contains("invalid"));
    let link = d.join("link.json");
    std::os::unix::fs::symlink(&good, &link).unwrap();
    assert!(
        why(prepare("claude-code", Some(&link), &d, None).unwrap()).contains("not a regular file")
    );
    // Nothing was built for any of them.
    let left: Vec<_> = std::fs::read_dir(&d)
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_name().to_string_lossy().starts_with("derm-sbx-kit-"))
        .collect();
    assert!(left.is_empty(), "{left:?}");
    for x in [&d, &loose_dir, &bad_dir] {
        let _ = std::fs::remove_dir_all(x);
    }
}

/// The hook's files in the kit are exactly what `bin/derm-hook.mjs` loads:
/// `src/hook.ts` and every module it imports, by relative import, and
/// nothing else (no tests, no fixtures). A core file added later fails here
/// until it is listed.
/// Every file `src/hook.ts` of a package loads by a relative import.
fn closure(package: &str) -> BTreeSet<String> {
    closure_from(package, &["src/hook.ts".to_string()])
}

/// Every file the entries of a package load by a relative import, the
/// entries included.
fn closure_from(package: &str, entries: &[String]) -> BTreeSet<String> {
    let pkg = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../packages")
        .join(package);
    let mut seen: BTreeSet<String> = BTreeSet::new();
    let mut todo = entries.to_vec();
    let import = |line: &str| -> Option<String> {
        let l = line.trim_start();
        if !(l.starts_with("import ") || l.starts_with("export ")) {
            return None;
        }
        let q = l.find(" from \"")? + " from \"".len();
        let end = l[q..].find('"')? + q;
        let spec = &l[q..end];
        spec.starts_with('.').then(|| spec.to_string())
    };
    while let Some(rel) = todo.pop() {
        if !seen.insert(rel.clone()) {
            continue;
        }
        let text = std::fs::read_to_string(pkg.join(&rel)).unwrap();
        let base = Path::new(&rel).parent().unwrap().to_path_buf();
        for spec in text.lines().filter_map(import) {
            let mut parts: Vec<String> = base
                .components()
                .map(|c| c.as_os_str().to_string_lossy().into_owned())
                .collect();
            for seg in spec.split('/') {
                match seg {
                    "." => {}
                    ".." => {
                        parts.pop();
                    }
                    s => parts.push(s.to_string()),
                }
            }
            todo.push(parts.join("/"));
        }
    }
    seen
}

#[test]
fn the_kit_carries_the_hooks_whole_import_closure() {
    let mut seen = closure("derm-claude-plugin");
    seen.insert("bin/derm-hook.mjs".into());
    seen.insert("package.json".into());
    let listed: BTreeSet<String> = PLUGIN.iter().map(|(p, _)| p.to_string()).collect();
    assert_eq!(listed, seen);
    // And the launcher loads the hook from where the kit puts it.
    let launcher = PLUGIN
        .iter()
        .find(|(p, _)| *p == "bin/derm-hook.mjs")
        .unwrap()
        .1;
    assert!(launcher.contains(r#"new URL("../src/hook.ts", import.meta.url)"#));
}

/// Fix pass 11, MW5-7: sbx 0.51.0 refuses a v2 mixin beside its v3 claude
/// kit, so the kit is v3 (SPEC-v3 at 6838e3e): schema "3", a mixin that
/// requires claude, the full-access hint exported by an arg's `env`, and a
/// root install hook at the path the Dockerfile copies the kit to. The
/// Dockerfile pins its Node by digest and copies `derm-kit/` where the
/// install script reads it.
#[test]
fn the_kit_is_a_v3_mixin_whose_parts_agree() {
    assert!(DESCRIPTOR.starts_with("# syntax=docker/sandbox-kit:3\n"));
    assert!(DESCRIPTOR.contains("\nschemaVersion: \"3\"\n"));
    assert!(DESCRIPTOR.contains("\nkind: mixin\n"));
    assert!(!DESCRIPTOR.contains("schemaVersion: \"2\""));
    assert!(DESCRIPTOR.contains("requires: [\"claude\"]"));
    assert!(DESCRIPTOR.contains("env: DERM_FULL_ACCESS"));
    assert!(DESCRIPTOR.contains("enum: [\"1\"]"));
    assert!(DESCRIPTOR.contains("type: com.docker.sandbox/lifecycle@1"));
    assert!(
        DESCRIPTOR.contains("command: \"sh /opt/derm-kit-src/install.sh\"\n          user: \"0\"")
    );
    assert!(DESCRIPTOR.contains("contentFile: ./derm-context.md"));
    let from = DOCKERFILE
        .lines()
        .find(|l| l.starts_with("FROM docker.io/library/node:"))
        .expect("the kit's Node comes from the official image");
    let digest = from.split("@sha256:").nth(1).expect("pinned by digest");
    assert!(digest.starts_with("0820eaa85e07"), "{from}");
    assert_eq!(digest.split_whitespace().next().unwrap().len(), 64);
    assert!(DOCKERFILE.contains("COPY --from=node /usr/local/bin/node /opt/derm-kit-src/node"));
    assert!(DOCKERFILE.contains("COPY derm-kit/ /opt/derm-kit-src/"));
    assert!(INSTALL.contains("src=/opt/derm-kit-src"));
    assert!(INSTALL.contains("node_bin=\"$src/node\""));
    assert!(INSTALL.contains("$src/register-hooks.mjs"));
    assert!(INSTALL.contains("$src/policy.json"));
    assert!(INSTALL.contains("/home/agent/.derm/policy.json"));
    assert!(INSTALL.contains("dest=/opt/derm-kit"));
    assert!(INSTALL.contains("\"$dest/bin/derm-hook.mjs\""));
    assert!(INSTALL.starts_with("#!/bin/sh\n"));
    assert!(INSTALL.contains("set -eu"));
    // The hooks run the kit's own Node from root's folder, never one found
    // on PATH, which the agent can change.
    let copied = INSTALL.find("cp \"$node_bin\" \"$dest/node\"").unwrap();
    let repointed = INSTALL.find("node_bin=\"$dest/node\"").unwrap();
    let registered = INSTALL
        .find("register-hooks.mjs\" \"$settings\" \"$node_bin\"")
        .unwrap();
    assert!(copied < repointed && repointed < registered);
    assert!(!INSTALL.contains("command -v node"));
    // FP11-S6: the staging folder goes on every exit, a failure's too.
    assert!(INSTALL.contains("trap 'rm -rf \"$src\"' EXIT"));
    // FP11R-5: dash runs no EXIT trap on a signal; each one exits instead.
    for sig in ["HUP", "INT", "TERM"] {
        assert!(INSTALL.contains(&format!("' {sig}\n")), "a trap for {sig}");
    }
}

/// Security finding W5C-S2 (integration w5 continue): the install writes the
/// root-owned marker the hook's VM route needs, at the very path the hook in
/// the kit reads, and makes it root's alone.
#[test]
fn the_install_writes_the_vm_marker_the_kits_hook_reads() {
    assert!(INSTALL.contains("> \"$dest/sbx-vm\""));
    assert!(INSTALL.contains("chown root:root \"$dest/sbx-vm\""));
    assert!(INSTALL.contains("chmod 0644 \"$dest/sbx-vm\""));
    let daemon = PLUGIN
        .iter()
        .find(|(rel, _)| *rel == "src/core/daemon.ts")
        .map(|(_, text)| *text)
        .expect("the kit carries the hook's daemon client");
    assert!(daemon.contains("export const VM_MARKER = \"/opt/derm-kit/sbx-vm\";"));
    // The marker goes in after the gate's code is copied and its modes set,
    // so the recursive chmod and the rm -rf before it cannot undo it.
    let copied = INSTALL.find("chmod -R u=rwX,go=rX \"$dest\"").unwrap();
    let marker = INSTALL.find("> \"$dest/sbx-vm\"").unwrap();
    assert!(copied < marker);
}

/// 17 Nov 2026, the kits for Copilot CLI, Droid, Cursor and Kiro. Each is
/// the generic command-hook kit with the agent's workload, id and name
/// filled in, the agent's hook package whole, and the shared core.
#[test]
fn a_command_hook_agent_gets_its_kit_for_its_own_workload() {
    for (harness, workload, name, own) in [
        ("copilot-cli", "copilot", "Copilot CLI", COMPAT_OWN),
        ("droid", "droid", "Droid", COMPAT_OWN),
        ("cursor", "cursor", "Cursor", NATIVE_OWN),
        ("kiro", "kiro", "Kiro", NATIVE_OWN),
    ] {
        let d = tmp(harness);
        let policy = policy_at(&d, POLICY, 0o600);
        let kit = prepare(harness, Some(&policy), &d, None).unwrap();
        let Kit::Built(p) = kit else {
            panic!("{harness}: no kit: {kit:?}")
        };
        let root = p.path().to_path_buf();
        let files = files_under(&root);
        for want in [
            "derm-gate-hooks.yaml",
            "derm-gate-hooks.dockerfile",
            "derm-kit/install.sh",
            "derm-kit/register-agent.mjs",
            "derm-kit/policy.json",
            "derm-kit/plugin/package.json",
            "derm-kit/plugin/bin/derm-hook.mjs",
            "derm-kit/plugin/src/hook.ts",
            "derm-kit/plugin/src/core/gate.ts",
            "derm-kit/plugin/src/core/daemon.ts",
        ] {
            assert!(
                files.contains(want),
                "{harness}: {want} missing from {files:?}"
            );
        }
        let core = PLUGIN
            .iter()
            .filter(|(rel, _)| rel.starts_with("src/core/"))
            .count();
        assert_eq!(files.len(), 5 + own.len() + core, "{harness}: {files:?}");
        // Nothing of Claude Code's kit.
        assert!(!files.iter().any(|f| f.contains("claude")), "{files:?}");
        let y = std::fs::read_to_string(root.join("derm-gate-hooks.yaml")).unwrap();
        assert!(
            !y.replace("lifecycle@1", "").contains('@'),
            "{harness}: a word was left unfilled"
        );
        assert!(y.contains(&format!("requires: [\"{workload}\"]")), "{y}");
        assert!(y.contains(&format!("displayName: derm gate for {name}\n")));
        assert!(y.contains(&format!(
            "command: \"sh /opt/derm-kit-src/install.sh {harness}\"\n          user: \"0\""
        )));
        assert_eq!(
            std::fs::read_to_string(root.join("derm-kit/policy.json")).unwrap(),
            POLICY
        );
        assert_eq!(spec(harness).unwrap().workload, workload);
        drop(p);
        assert!(!root.exists());
        let _ = std::fs::remove_dir_all(&d);
    }
}

/// Each package's list is exactly what its hook loads outside the core, and
/// the core it loads is the one the kit takes from the Claude Code package:
/// the same paths and the same text.
#[test]
fn the_command_hook_kits_carry_each_hooks_whole_import_closure() {
    for (package, own, extra) in [
        ("derm-hooks-claude-compat", COMPAT_OWN, &[][..]),
        ("derm-hooks-native", NATIVE_OWN, &["bin/fallback.mjs"][..]),
    ] {
        let mut seen = closure(package);
        seen.insert("bin/derm-hook.mjs".into());
        seen.insert("package.json".into());
        for e in extra {
            seen.insert(e.to_string());
        }
        let listed: BTreeSet<String> = own
            .iter()
            .map(|(p, _)| p.to_string())
            .chain(
                PLUGIN
                    .iter()
                    .filter(|(rel, _)| rel.starts_with("src/core/"))
                    .map(|(p, _)| p.to_string()),
            )
            .collect();
        assert_eq!(listed, seen, "{package}");
        assert!(
            !own.iter().any(|(p, _)| p.starts_with("src/core/")),
            "{package}: the core comes from the shared list"
        );
        let pkg = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../packages")
            .join(package);
        for (rel, text) in PLUGIN
            .iter()
            .filter(|(rel, _)| rel.starts_with("src/core/"))
        {
            assert_eq!(
                std::fs::read_to_string(pkg.join(rel))
                    .unwrap()
                    .replace("\r\n", "\n"),
                text.replace("\r\n", "\n"),
                "{package}/{rel} is not the shared core"
            );
        }
        let launcher = own
            .iter()
            .find(|(p, _)| *p == "bin/derm-hook.mjs")
            .unwrap()
            .1;
        assert!(launcher.contains(r#"new URL("../src/hook.ts", import.meta.url)"#));
    }
    // The native launcher's one static import.
    let native = NATIVE_OWN
        .iter()
        .find(|(p, _)| *p == "bin/derm-hook.mjs")
        .unwrap()
        .1;
    assert!(native.contains(r#"from "./fallback.mjs""#));
}

/// The generic kit's parts agree with each other and with Claude Code's
/// kit where they share a fact: schema 3, a mixin, the same Node by the
/// same digest, the same staging and install paths, the VM marker.
#[test]
fn the_command_hook_kit_is_a_v3_mixin_whose_parts_agree() {
    assert!(HOOKS_DESCRIPTOR.starts_with("# syntax=docker/sandbox-kit:3\n"));
    assert!(HOOKS_DESCRIPTOR.contains("\nschemaVersion: \"3\"\n"));
    assert!(HOOKS_DESCRIPTOR.contains("\nkind: mixin\n"));
    assert!(HOOKS_DESCRIPTOR.contains("requires: [\"@WORKLOAD@\"]"));
    assert!(HOOKS_DESCRIPTOR.contains("type: com.docker.sandbox/lifecycle@1"));
    // DERM_FULL_ACCESS is derm run's to pass, per agent: Droid's kit does
    // not start it with its approvals off.
    assert!(!HOOKS_DESCRIPTOR.contains("env: DERM_FULL_ACCESS"));
    let from = |text: &'static str| {
        text.lines()
            .find(|l| l.starts_with("FROM docker.io/library/node:"))
            .expect("the kit's Node comes from the official image")
    };
    assert_eq!(from(HOOKS_DOCKERFILE), from(DOCKERFILE));
    assert!(
        HOOKS_DOCKERFILE.contains("COPY --from=node /usr/local/bin/node /opt/derm-kit-src/node")
    );
    assert!(HOOKS_DOCKERFILE.contains("COPY derm-kit/ /opt/derm-kit-src/"));
    let i = HOOKS_INSTALL;
    assert!(i.starts_with("#!/bin/sh\n"));
    assert!(i.contains("set -eu"));
    assert!(i.contains("src=/opt/derm-kit-src"));
    assert!(i.contains("dest=/opt/derm-kit\n"));
    assert!(i.contains("copilot-cli | droid | cursor | kiro) ;;"));
    assert!(i.contains("\"$home/.derm/policy.json\""));
    // The hook runs the kit's own Node from root's folder, never one found
    // on PATH.
    let copied = i.find("cp \"$node_bin\" \"$dest/node\"").unwrap();
    let repointed = i.find("node_bin=\"$dest/node\"").unwrap();
    let registered = i
        .find("\"$src/register-agent.mjs\" \"$agent\" \"$home\" \"$node_bin\" \"$dest/bin/derm-hook.mjs\"")
        .unwrap();
    assert!(copied < repointed && repointed < registered);
    assert!(!i.contains("command -v node"));
    assert!(i.contains("trap 'rm -rf \"$src\"' EXIT"));
    for sig in ["HUP", "INT", "TERM"] {
        assert!(i.contains(&format!("' {sig}\n")), "a trap for {sig}");
    }
    // The VM marker, as Claude Code's kit writes it, after the modes are set.
    assert!(i.contains("> \"$dest/sbx-vm\""));
    assert!(i.contains("chown root:root \"$dest/sbx-vm\""));
    let modes = i.find("chmod -R u=rwX,go=rX \"$dest\"").unwrap();
    assert!(modes < i.find("> \"$dest/sbx-vm\"").unwrap());
    // The registrar knows the same four agents the script takes.
    for a in ["copilot-cli", "droid", "cursor", "kiro"] {
        assert!(REGISTER_AGENT.contains(&format!("case \"{a}\":")), "{a}");
        assert!(has_kit(a));
    }
    assert!(!has_kit("opencode") && !has_kit("gemini"));
}

/// A small stand-in for the Linux derm the Codex kit carries.
fn vm_derm_at(dir: &Path, mode: u32) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let p = dir.join("derm-for-the-vm");
    std::fs::write(&p, b"\x7fELF stand-in").unwrap();
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(mode)).unwrap();
    p
}

/// 17 Nov 2026, Codex's kit. Codex's gate is the Rust `derm hook`, so the
/// kit carries a derm for the VM, derm's Codex plugin as a local
/// marketplace, the plugin's trust entries and the policy, and no Node.
#[test]
fn codex_gets_a_kit_with_a_derm_for_the_vm_and_its_plugin() {
    let d = tmp("codex");
    let policy = policy_at(&d, POLICY, 0o600);
    let derm = vm_derm_at(&d, 0o755);
    TEST_VM_DERM.with(|t| *t.borrow_mut() = Some(Ok(derm.clone())));
    let kit = prepare("codex", Some(&policy), &d, None).unwrap();
    TEST_VM_DERM.with(|t| *t.borrow_mut() = None);
    let Kit::Built(p) = kit else {
        panic!("no kit: {kit:?}")
    };
    let root = p.path().to_path_buf();
    let files = files_under(&root);
    let want: BTreeSet<String> = [
        "derm-gate-codex.yaml",
        "derm-gate-codex.dockerfile",
        "derm-kit/install.sh",
        "derm-kit/setup.sh",
        "derm-kit/policy.json",
        "derm-kit/trust.toml",
        "derm-kit/derm",
        "derm-kit/mkt/.agents/plugins/marketplace.json",
        "derm-kit/mkt/derm/.codex-plugin/plugin.json",
        "derm-kit/mkt/derm/hooks/hooks.json",
        "derm-kit/mkt/derm/hooks/derm-gate.sh",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    assert_eq!(files, want);
    assert_eq!(
        std::fs::read(root.join("derm-kit/derm")).unwrap(),
        std::fs::read(&derm).unwrap()
    );
    assert_eq!(
        std::fs::read_to_string(root.join("derm-kit/policy.json")).unwrap(),
        POLICY
    );
    let read = |rel: &str| std::fs::read_to_string(root.join(rel)).unwrap();
    // The plugin is the one in the repository, file for file.
    let pkg = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../packages/derm-codex-plugin");
    for rel in [
        ".codex-plugin/plugin.json",
        "hooks/hooks.json",
        "hooks/derm-gate.sh",
    ] {
        assert_eq!(
            read(&format!("derm-kit/mkt/derm/{rel}")),
            std::fs::read_to_string(pkg.join(rel)).unwrap(),
            "{rel}"
        );
    }
    let mkt: serde_json::Value =
        serde_json::from_str(&read("derm-kit/mkt/.agents/plugins/marketplace.json")).unwrap();
    assert_eq!(mkt["name"], "derm");
    assert_eq!(mkt["plugins"][0]["name"], "derm");
    assert_eq!(mkt["plugins"][0]["source"]["path"], "./derm");
    // Everything in the folder is the person's alone.
    use std::os::unix::fs::PermissionsExt;
    for f in &files {
        let m = std::fs::metadata(root.join(f))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(m & 0o077, 0, "{f} is {m:o}");
    }
    assert_eq!(spec("codex").unwrap().workload, "codex");
    drop(p);
    assert!(!root.exists());
    let _ = std::fs::remove_dir_all(&d);
}

/// With no derm that could run in the VM there is no kit, and the reason
/// says what is missing. Nothing is built.
#[test]
fn codex_has_no_kit_without_a_derm_for_the_vm() {
    let d = tmp("codex-none");
    let policy = policy_at(&d, POLICY, 0o600);
    TEST_VM_DERM.with(|t| {
        *t.borrow_mut() = Some(Err(
            "no Linux derm for the VM at /x/derm-linux-aarch64".into()
        ))
    });
    let kit = prepare("codex", Some(&policy), &d, None).unwrap();
    TEST_VM_DERM.with(|t| *t.borrow_mut() = None);
    match kit {
        Kit::Without(why) => assert!(why.contains("no Linux derm for the VM"), "{why}"),
        Kit::Built(_) => panic!("a kit was built"),
    }
    let left = std::fs::read_dir(&d)
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_name().to_string_lossy().starts_with("derm-sbx-kit-"))
        .count();
    assert_eq!(left, 0);
    // A derm others can write is not carried into the VM.
    let loose = vm_derm_at(&d, 0o777);
    assert!(checked_vm_derm(&loose)
        .unwrap_err()
        .contains("writable by others"));
    let link = d.join("link");
    std::os::unix::fs::symlink(&loose, &link).unwrap();
    assert!(checked_vm_derm(&link)
        .unwrap_err()
        .contains("not a regular file"));
    assert!(checked_vm_derm(&d.join("absent"))
        .unwrap_err()
        .contains("no Linux derm for the VM"));
    assert_eq!(
        checked_vm_derm(&vm_derm_at(&tmp("codex-ok"), 0o755)).map(|_| ()),
        Ok(())
    );
    let _ = std::fs::remove_dir_all(&d);
}

/// The Codex kit's parts agree with each other and with what they stand on.
#[test]
fn the_codex_kit_is_a_v3_mixin_whose_parts_agree() {
    let y = CODEX_DESCRIPTOR;
    assert!(y.starts_with("# syntax=docker/sandbox-kit:3\n"));
    assert!(y.contains("\nschemaVersion: \"3\"\n"));
    assert!(y.contains("\nkind: mixin\n"));
    assert!(y.contains("requires: [\"codex\"]"));
    // Root's step, then the agent's.
    let root_step = y
        .find("command: \"sh /opt/derm-kit-src/install.sh\"\n          user: \"0\"")
        .unwrap();
    let agent_step = y
        .find("command: \"sh /opt/derm-kit/setup.sh\"\n          user: agent")
        .unwrap();
    assert!(root_step < agent_step);
    assert!(CODEX_DOCKERFILE.contains("FROM scratch\nCOPY derm-kit/ /opt/derm-kit-src/"));
    // No Node: the gate is derm itself.
    assert!(!CODEX_DOCKERFILE.contains("node"));
    let i = CODEX_INSTALL;
    assert!(i.starts_with("#!/bin/sh\n") && i.contains("set -eu"));
    assert!(i.contains("src=/opt/derm-kit-src") && i.contains("dest=/opt/derm-kit\n"));
    assert!(i.contains("bin=/usr/local/bin/derm"));
    // The derm is run before anything is installed, and never replaces one.
    let ran = i.find("\"$src/derm\" --version").unwrap();
    let placed = i
        .find("install -o root -g root -m 0755 \"$src/derm\" \"$bin\"")
        .unwrap();
    let refused = i.find("if [ -e \"$bin\" ]; then fail").unwrap();
    assert!(ran < refused && refused < placed);
    assert!(i.contains("> \"$dest/sbx-vm\"") && i.contains("chown root:root \"$dest/sbx-vm\""));
    assert!(i.contains("\"$home/.derm/policy.json\""));
    assert!(i.contains("trap 'rm -rf \"$src\"' EXIT"));
    // The launcher looks where the script puts derm, and for the marker
    // where the script writes it.
    let launcher = CODEX_PLUGIN
        .iter()
        .find(|(p, _)| *p == "hooks/derm-gate.sh")
        .unwrap()
        .1;
    assert!(launcher.contains("/usr/local/bin/derm"));
    assert_eq!(crate::gate::daemon::VM_MARKER, "/opt/derm-kit/sbx-vm");
    let s = CODEX_SETUP;
    assert!(s.starts_with("#!/bin/sh\n") && s.contains("set -eu"));
    let added = s.find("codex plugin marketplace add \"$kit/mkt\"").unwrap();
    let plugin = s.find("codex plugin add derm@derm").unwrap();
    let trusted = s.find("cat \"$kit/trust.toml\" >> \"$cfg\"").unwrap();
    assert!(added < plugin && plugin < trusted);
    assert!(CODEX_TRUST.contains("[hooks.state.\"derm@derm:hooks/hooks.json:pre_tool_use:0:0\"]"));
    assert!(CODEX_TRUST.contains("trusted_hash = \"sha256:"));
    assert!(has_kit("codex"));
}

/// 17 Nov 2026, Pi's kit: a v2 mixin (Docker's Pi kit is a v2 sandbox),
/// whose payload is files/home/, with derm's Pi package whole.
#[test]
fn pi_gets_a_v2_mixin_with_derms_pi_package() {
    let d = tmp("pi");
    let policy = policy_at(&d, POLICY, 0o600);
    let kit = prepare("pi", Some(&policy), &d, None).unwrap();
    let Kit::Built(p) = kit else {
        panic!("no kit: {kit:?}")
    };
    let root = p.path().to_path_buf();
    let files = files_under(&root);
    let stage = "files/home/.derm-kit-src";
    for want in [
        "spec.yaml".to_string(),
        format!("{stage}/install.sh"),
        format!("{stage}/setup.sh"),
        format!("{stage}/policy.json"),
        format!("{stage}/derm-pi/package.json"),
        format!("{stage}/derm-pi/extensions/gate.ts"),
        format!("{stage}/derm-pi/extensions/emitter.ts"),
        format!("{stage}/derm-pi/src/vm.ts"),
    ] {
        assert!(files.contains(&want), "{want} missing from {files:?}");
    }
    assert_eq!(files.len(), 4 + PI_PACKAGE.len(), "{files:?}");
    // No v3 descriptor, no Dockerfile: sbx reads a v2 kit's spec.yaml.
    assert!(!files
        .iter()
        .any(|f| f.ends_with(".dockerfile") || f.starts_with("derm-kit/")));
    assert_eq!(
        std::fs::read_to_string(root.join(stage).join("policy.json")).unwrap(),
        POLICY
    );
    // The package is the one in the repository, file for file.
    let pkg = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../packages/derm-pi");
    for (rel, _) in PI_PACKAGE {
        assert_eq!(
            std::fs::read_to_string(root.join(stage).join("derm-pi").join(rel)).unwrap(),
            std::fs::read_to_string(pkg.join(rel)).unwrap(),
            "{rel}"
        );
    }
    drop(p);
    assert!(!root.exists());
    let _ = std::fs::remove_dir_all(&d);
}

/// The Pi kit's list is what Pi loads: package.json's three extensions and
/// every file they import. And the kit's parts agree.
#[test]
fn the_pi_kit_carries_the_packages_whole_import_closure_and_its_parts_agree() {
    let pkg = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../packages/derm-pi");
    let manifest: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(pkg.join("package.json")).unwrap()).unwrap();
    let entries: Vec<String> = manifest["pi"]["extensions"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e.as_str().unwrap().trim_start_matches("./").to_string())
        .collect();
    assert_eq!(entries.len(), 3);
    let mut seen = closure_from("derm-pi", &entries);
    seen.insert("package.json".into());
    let listed: BTreeSet<String> = PI_PACKAGE.iter().map(|(p, _)| p.to_string()).collect();
    assert_eq!(listed, seen);

    let y = PI_SPEC;
    assert!(y.contains("\nschemaVersion: \"2\"\n"));
    assert!(y.contains("\nkind: mixin\n"));
    assert!(y.contains("\nname: derm-gate-pi\n"));
    let root_step = y
        .find("command: \"sh /home/agent/.derm-kit-src/install.sh\"\n      user: \"0\"")
        .unwrap();
    let agent_step = y
        .find("command: \"sh /opt/derm-kit/setup.sh\"\n      user: \"1000\"")
        .unwrap();
    assert!(root_step < agent_step);
    let i = PI_INSTALL;
    assert!(i.starts_with("#!/bin/sh\n") && i.contains("set -eu"));
    assert!(i.contains("src=/home/agent/.derm-kit-src") && i.contains("dest=/opt/derm-kit\n"));
    assert!(i.contains("trap 'rm -rf \"$src\"' EXIT"));
    assert!(i.contains("chown -R root:root \"$dest\""));
    let modes = i.find("chmod -R u=rwX,go=rX \"$dest\"").unwrap();
    assert!(modes < i.find("> \"$dest/sbx-vm\"").unwrap());
    assert!(i.contains("\"$home/.derm/policy.json\""));
    // The marker the script writes is the one the emitter looks for.
    let vm = PI_PACKAGE
        .iter()
        .find(|(p, _)| *p == "src/vm.ts")
        .unwrap()
        .1;
    assert!(vm.contains("export const VM_MARKER = \"/opt/derm-kit/sbx-vm\";"));
    let s = PI_SETUP;
    assert!(s.contains("pkg=/opt/derm-kit/derm-pi"));
    assert!(s.contains("pi install \"$pkg\""));
    assert!(!s.contains("--local"));
    assert!(has_kit("pi"));
}

/// 19 Nov 2026, the second form of the Claude Code kit (`DERM_SBX_KIT=rust`):
/// the gate is derm itself, so the kit carries a derm for the VM, the
/// policy and the install script, and no Node, hook package or registrar.
#[test]
fn with_the_rust_switch_claude_code_gets_a_kit_whose_gate_is_derm_itself() {
    let d = tmp("claude-rust");
    let policy = policy_at(&d, POLICY, 0o600);
    let derm = vm_derm_at(&d, 0o755);
    for switch in ["rust", "RUST", "Rust"] {
        TEST_VM_DERM.with(|t| *t.borrow_mut() = Some(Ok(derm.clone())));
        let kit = prepare("claude-code", Some(&policy), &d, Some(switch)).unwrap();
        TEST_VM_DERM.with(|t| *t.borrow_mut() = None);
        let Kit::Built(p) = kit else {
            panic!("no kit: {kit:?}")
        };
        let root = p.path().to_path_buf();
        let files = files_under(&root);
        let want: BTreeSet<String> = [
            "derm-gate-claude.yaml",
            "derm-gate-claude.dockerfile",
            "derm-context.md",
            "derm-kit/install.sh",
            "derm-kit/policy.json",
            "derm-kit/derm",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        assert_eq!(files, want, "{switch}");
        let read = |rel: &str| std::fs::read_to_string(root.join(rel)).unwrap();
        assert_eq!(read("derm-gate-claude.yaml"), RS_DESCRIPTOR);
        assert_eq!(read("derm-gate-claude.dockerfile"), RS_DOCKERFILE);
        assert_eq!(read("derm-kit/install.sh"), RS_INSTALL);
        assert_eq!(read("derm-context.md"), CONTEXT);
        assert_eq!(read("derm-kit/policy.json"), POLICY);
        assert_eq!(
            std::fs::read(root.join("derm-kit/derm")).unwrap(),
            std::fs::read(&derm).unwrap()
        );
        use std::os::unix::fs::PermissionsExt;
        for f in &files {
            let m = std::fs::metadata(root.join(f))
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(m & 0o077, 0, "{f} is {m:o}");
        }
        drop(p);
        assert!(!root.exists());
    }
    assert!(rust_form("claude-code", Some("rust")));
    assert!(!rust_form("claude-code", None));
    assert!(!rust_form("claude-code", Some("off")));
    // Codex's gate is derm already and Pi's is its extension: the switch
    // changes neither kit.
    assert!(!rust_form("codex", Some("rust")) && !rust_form("pi", Some("rust")));
    assert!(!rust_form("opencode", Some("rust")));
    let _ = std::fs::remove_dir_all(&d);
}

/// Without the switch nothing changes: Claude Code's kit is the one with
/// Node and the hook package, whether or not a derm for the VM is at hand.
#[test]
fn without_the_rust_switch_the_kits_are_the_node_ones() {
    let d = tmp("claude-default");
    let policy = policy_at(&d, POLICY, 0o600);
    let derm = vm_derm_at(&d, 0o755);
    for switch in [None, Some(""), Some("node"), Some("rusty")] {
        TEST_VM_DERM.with(|t| *t.borrow_mut() = Some(Ok(derm.clone())));
        let kit = prepare("claude-code", Some(&policy), &d, switch).unwrap();
        TEST_VM_DERM.with(|t| *t.borrow_mut() = None);
        let Kit::Built(p) = kit else {
            panic!("no kit: {kit:?}")
        };
        let files = files_under(p.path());
        assert!(files.contains("derm-kit/register-hooks.mjs"), "{switch:?}");
        assert!(files.contains("derm-kit/plugin/src/hook.ts"), "{switch:?}");
        assert!(!files.contains("derm-kit/derm"), "{switch:?}");
        assert_eq!(
            std::fs::read_to_string(p.path().join("derm-gate-claude.yaml")).unwrap(),
            DESCRIPTOR
        );
    }
    let _ = std::fs::remove_dir_all(&d);
}

/// The four command-hook agents under the switch: the generic kit with the
/// agent's workload, id and name filled in, a derm for the VM, and none of
/// the hook packages.
#[test]
fn with_the_rust_switch_a_command_hook_agent_gets_derm_and_no_hook_package() {
    for (harness, workload, name) in [
        ("copilot-cli", "copilot", "Copilot CLI"),
        ("droid", "droid", "Droid"),
        ("cursor", "cursor", "Cursor"),
        ("kiro", "kiro", "Kiro"),
    ] {
        let d = tmp(&format!("rust-{harness}"));
        let policy = policy_at(&d, POLICY, 0o600);
        let derm = vm_derm_at(&d, 0o755);
        TEST_VM_DERM.with(|t| *t.borrow_mut() = Some(Ok(derm.clone())));
        let kit = prepare(harness, Some(&policy), &d, Some("rust")).unwrap();
        TEST_VM_DERM.with(|t| *t.borrow_mut() = None);
        let Kit::Built(p) = kit else {
            panic!("no kit for {harness}: {kit:?}")
        };
        let root = p.path().to_path_buf();
        let want: BTreeSet<String> = [
            "derm-gate-hooks.yaml",
            "derm-gate-hooks.dockerfile",
            "derm-kit/install.sh",
            "derm-kit/policy.json",
            "derm-kit/derm",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        assert_eq!(files_under(&root), want, "{harness}");
        let yaml = std::fs::read_to_string(root.join("derm-gate-hooks.yaml")).unwrap();
        for word in ["@WORKLOAD@", "@AGENT@", "@NAME@"] {
            assert!(!yaml.contains(word), "{harness}: {word} is left: {yaml}");
        }
        assert!(
            yaml.contains(&format!("requires: [\"{workload}\"]")),
            "{yaml}"
        );
        assert!(yaml.contains(&format!(
            "provides: [\"io.github.aetiusgular/derm-gate-{workload}\"]"
        )));
        assert!(yaml.contains(&format!("displayName: derm gate for {name}\n")));
        assert!(yaml.contains(&format!(
            "command: \"sh /opt/derm-kit-src/install.sh {harness}\"\n          user: \"0\""
        )));
        assert!(yaml.contains(&format!(
            "command: \"/usr/local/bin/derm kit register {harness} --home /home/agent\"\n          user: agent"
        )));
        assert_eq!(
            std::fs::read(root.join("derm-kit/derm")).unwrap(),
            std::fs::read(&derm).unwrap()
        );
        assert!(rust_form(harness, Some("rust")) && !rust_form(harness, None));
        // The workload and the place the start line names are the Node kit's.
        let (a, b) = (
            spec(harness).unwrap(),
            spec_for(harness, Some("rust")).unwrap(),
        );
        assert_eq!(
            (a.workload, a.name, a.registered),
            (b.workload, b.name, b.registered)
        );
        drop(p);
        let _ = std::fs::remove_dir_all(&d);
    }
}

/// The switch asks for a kit that needs a derm the VM can run. With none
/// there is no kit; derm does not put the Node kit on without a word, and
/// the reason names the way back. Nothing is built.
#[test]
fn the_rust_switch_with_no_derm_for_the_vm_gives_no_kit_and_says_how_to_get_the_other() {
    let d = tmp("rust-none");
    let policy = policy_at(&d, POLICY, 0o600);
    for harness in ["claude-code", "droid", "cursor", "kiro", "copilot-cli"] {
        TEST_VM_DERM.with(|t| {
            *t.borrow_mut() = Some(Err(
                "no Linux derm for the VM at /x/derm-linux-aarch64".into()
            ))
        });
        let kit = prepare(harness, Some(&policy), &d, Some("rust")).unwrap();
        TEST_VM_DERM.with(|t| *t.borrow_mut() = None);
        match kit {
            Kit::Without(why) => {
                assert!(why.contains("DERM_SBX_KIT=rust is set"), "{why}");
                assert!(why.contains("no Linux derm for the VM"), "{why}");
                assert!(why.contains("unset DERM_SBX_KIT"), "{why}");
            }
            Kit::Built(_) => panic!("a kit was built for {harness}"),
        }
    }
    let left = std::fs::read_dir(&d)
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_name().to_string_lossy().starts_with("derm-sbx-kit-"))
        .count();
    assert_eq!(left, 0);
    // `off` still wins over everything.
    match prepare("claude-code", Some(&policy), &d, Some("off")).unwrap() {
        Kit::Without(why) => assert!(why.contains("DERM_SBX_KIT=off"), "{why}"),
        Kit::Built(_) => panic!("a kit was built"),
    }
    let _ = std::fs::remove_dir_all(&d);
}

/// The two new kits' parts agree with each other, with the spec's grammar
/// as the other kits use it, and with what derm reads in the VM.
#[test]
fn the_rust_kits_are_v3_mixins_whose_parts_agree() {
    for (yaml, dockerfile, install) in [
        (RS_DESCRIPTOR, RS_DOCKERFILE, RS_INSTALL),
        (RS_HOOKS_DESCRIPTOR, RS_HOOKS_DOCKERFILE, RS_HOOKS_INSTALL),
    ] {
        assert!(yaml.starts_with("# syntax=docker/sandbox-kit:3\n"));
        assert!(yaml.contains("\nschemaVersion: \"3\"\n"));
        assert!(yaml.contains("\nkind: mixin\n"));
        assert!(yaml.contains("type: com.docker.sandbox/lifecycle@1"));
        // No Node anywhere: the overlay is what derm run staged, nothing else.
        let recipe: Vec<&str> = dockerfile
            .lines()
            .filter(|l| !l.starts_with('#') && !l.trim().is_empty())
            .collect();
        assert_eq!(
            recipe,
            ["FROM scratch", "COPY derm-kit/ /opt/derm-kit-src/"]
        );
        assert!(!install.contains("node"), "the install script names Node");
        assert!(install.starts_with("#!/bin/sh\n"));
        assert!(install.contains("set -eu"));
        assert!(install.contains("src=/opt/derm-kit-src"));
        assert!(install.contains("dest=/opt/derm-kit"));
        assert!(install.contains("bin=/usr/local/bin/derm"));
        // The derm it carries is run once before anything is installed, and
        // one already in the image is never replaced.
        let ran = install.find("\"$src/derm\" --version").unwrap();
        let refused = install.find("if [ -e \"$bin\" ]; then fail").unwrap();
        let installed = install
            .find("install -o root -g root -m 0755 \"$src/derm\" \"$bin\"")
            .unwrap();
        assert!(ran < refused && refused < installed);
        // W5C-S2: the marker at the path derm's VM route and `derm kit
        // register` read, root's alone, written after the folder is reset.
        let reset = install.find("rm -rf \"$dest\"").unwrap();
        let marker = install.find("> \"$dest/sbx-vm\"").unwrap();
        assert!(reset < marker && installed < marker);
        assert!(install.contains("chown -R root:root \"$dest\""));
        assert!(install.contains("chmod 0644 \"$dest/sbx-vm\""));
        assert_eq!(crate::gate::daemon::VM_MARKER, "/opt/derm-kit/sbx-vm");
        assert!(install.contains("$home/.derm/policy.json"));
        assert!(install.contains("chown agent:agent \"$home/.derm\" \"$home/.derm/policy.json\""));
        // FP11-S6, FP11R-5: the staging folder goes on every exit.
        assert!(install.contains("trap 'rm -rf \"$src\"' EXIT"));
        for sig in ["HUP", "INT", "TERM"] {
            assert!(install.contains(&format!("' {sig}\n")), "a trap for {sig}");
        }
    }
    // Claude Code: the same workload, argument and context as the Node kit,
    // one install command as root, and the hooks registered by derm after
    // the marker is there (`derm kit register` writes only where it holds).
    assert!(RS_DESCRIPTOR.contains("requires: [\"claude\"]"));
    assert!(RS_DESCRIPTOR.contains("env: DERM_FULL_ACCESS"));
    assert!(RS_DESCRIPTOR.contains("enum: [\"1\"]"));
    assert!(RS_DESCRIPTOR.contains("contentFile: ./derm-context.md"));
    assert!(RS_DESCRIPTOR
        .contains("command: \"sh /opt/derm-kit-src/install.sh\"\n          user: \"0\""));
    let provides = |y: &str| {
        y.lines()
            .find(|l| l.starts_with("provides:"))
            .map(str::to_string)
    };
    assert_eq!(provides(RS_DESCRIPTOR), provides(DESCRIPTOR));
    assert_eq!(provides(RS_HOOKS_DESCRIPTOR), provides(HOOKS_DESCRIPTOR));
    let marker = RS_INSTALL.find("> \"$dest/sbx-vm\"").unwrap();
    let registered = RS_INSTALL
        .find("\"$bin\" kit register claude-code")
        .unwrap();
    assert!(marker < registered);
    assert!(RS_INSTALL.contains(&format!("settings={}", crate::vmkit::MANAGED)));
    assert!(RS_INSTALL.contains("chown root:root /etc/claude-code \"$settings\""));
    assert!(RS_INSTALL.contains("chmod 0644 \"$settings\""));
    // The four agents: root's half takes the agent's id and registers
    // nothing; the agent's own user registers, by derm's absolute path.
    assert!(RS_HOOKS_INSTALL.contains("copilot-cli | droid | cursor | kiro) ;;"));
    assert!(!RS_HOOKS_INSTALL.contains("kit register \""));
    assert!(RS_HOOKS_DESCRIPTOR.contains(
        "command: \"/usr/local/bin/derm kit register @AGENT@ --home /home/agent\"\n          user: agent"
    ));
    for agent in crate::vmkit::HOME_AGENTS {
        assert!(RS_HOOKS_INSTALL.contains(agent), "{agent}");
        assert!(has_kit(agent));
    }
}
