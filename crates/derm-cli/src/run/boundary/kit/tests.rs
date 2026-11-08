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
    assert!(why(prepare("codex", Some(&good), &d, None).unwrap()).contains("no sbx kit for codex"));
    assert!(why(prepare("pi", Some(&good), &d, None).unwrap()).contains("no sbx kit for pi"));
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
#[test]
fn the_kit_carries_the_hooks_whole_import_closure() {
    let pkg = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../packages/derm-claude-plugin");
    let mut seen: BTreeSet<String> = BTreeSet::new();
    let mut todo = vec!["src/hook.ts".to_string()];
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
