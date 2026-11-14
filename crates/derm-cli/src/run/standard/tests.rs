//! Lane 6A's tests for the Standard tier's delivery and refusals. The
//! refusals' reasons are the runs in `plans/parallel/tk_lane_6A.md`
//! (Research); the real CLIs' behaviour is held by the contract checks in
//! `tests/cli-contract/checks/6A/`.

use super::*;

fn plan(program: &str, args: &[&str], folders: &[&str]) -> Plan {
    Plan {
        program: program.into(),
        args: args.iter().map(|s| s.to_string()).collect(),
        env_set: Vec::new(),
        env_remove: Vec::new(),
        kit: None,
        sandbox_name: None,
        srt_settings: None,
        folders: folders.iter().map(|s| s.to_string()).collect(),
        state_dirs: Vec::new(),
        notes: Vec::new(),
        full_access: Vec::new(),
        companion: None,
        scratch_dir: None,
    }
}

/// A scratch home and working folder, with nothing in them.
struct Scratch {
    root: PathBuf,
}

impl Scratch {
    fn new(name: &str) -> Scratch {
        let root = std::env::temp_dir().join(format!("d6a-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("home")).unwrap();
        std::fs::create_dir_all(root.join("work")).unwrap();
        std::fs::create_dir_all(root.join("etc")).unwrap();
        Scratch { root }
    }
    fn home(&self) -> String {
        self.root.join("home").to_string_lossy().into_owned()
    }
    fn work(&self) -> String {
        self.root.join("work").to_string_lossy().into_owned()
    }
    fn inputs(&self) -> Inputs {
        Inputs {
            home: Some(self.home()),
            cwd: Some(self.work()),
            claude_config_dir: None,
            codex_home: None,
            claude_managed: self.root.join("etc/claude-code/managed-settings.json"),
            codex_system: self.root.join("etc/codex/config.toml"),
            daemon_dir: Some("/run/user/1000/derm".into()),
            data_dir: Some(format!("{}/.local/share/derm", self.home())),
            windows: false,
            linux_bwrap: None,
        }
    }
    fn write(&self, rel: &str, text: &str) {
        let p = self.root.join(rel);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, text).unwrap();
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

fn run(
    s: &Scratch,
    harness: &str,
    boundary: Boundary,
    tier: Option<Tier>,
    p: &mut Plan,
) -> Result<Option<Value>, (u8, String)> {
    environment_with(harness, boundary, tier, p, &s.inputs())
}

fn claude_plan(s: &Scratch, words: &[&str]) -> Plan {
    plan("claude", words, &[&s.work()])
}

/// The value of the last `--settings` in `args`.
fn last_settings(args: &[String]) -> Value {
    let i = args
        .iter()
        .rposition(|a| a == "--settings")
        .expect("a --settings");
    serde_json::from_str(&args[i + 1]).unwrap()
}

// --- the choice -------------------------------------------------------------

/// Tony's call of 12 Nov: with no `--tier` and no setting, nothing changes.
#[test]
fn with_no_tier_and_no_setting_nothing_changes() {
    let s = Scratch::new("none");
    let mut p = claude_plan(&s, &["-p", "hi"]);
    let before = format!("{p:?}");
    assert_eq!(
        run(&s, "claude-code", Boundary::None, None, &mut p).unwrap(),
        None
    );
    assert_eq!(format!("{p:?}"), before);
}

#[test]
fn an_explicit_whole_tier_is_recorded_and_changes_nothing_else() {
    let s = Scratch::new("whole");
    let mut p = claude_plan(&s, &["-p", "hi"]);
    let args = p.args.clone();
    let r = run(&s, "claude-code", Boundary::Srt, Some(Tier::Whole), &mut p)
        .unwrap()
        .unwrap();
    assert_eq!(r["tier"], "whole");
    assert_eq!(p.args, args);
}

#[cfg(unix)]
fn settings_file(s: &Scratch, text: &str) {
    use std::os::unix::fs::PermissionsExt;
    s.write("home/.derm/settings.json", text);
    std::fs::set_permissions(
        s.root.join("home/.derm/settings.json"),
        std::fs::Permissions::from_mode(0o600),
    )
    .unwrap();
}

/// `tier.default: standard` in the person's settings picks the tier when no
/// `--tier` is given; a bad value is said and the default, whole, applies.
#[cfg(unix)]
#[test]
fn the_settings_default_is_read_and_a_bad_one_is_said() {
    let s = Scratch::new("setting");
    settings_file(&s, r#"{"version":1,"tier":{"default":"standard"}}"#);
    let mut p = claude_plan(&s, &["-p", "hi"]);
    let r = run(&s, "claude-code", Boundary::None, None, &mut p)
        .unwrap()
        .unwrap();
    assert_eq!(r["tier"], "standard");
    settings_file(&s, r#"{"version":1,"tier":{"default":"vendor"}}"#);
    let mut q = claude_plan(&s, &["-p", "hi"]);
    assert_eq!(
        run(&s, "claude-code", Boundary::None, None, &mut q).unwrap(),
        None
    );
    assert!(
        q.notes
            .iter()
            .any(|n| n.contains("tier the schema does not allow")),
        "{:?}",
        q.notes
    );
}

// --- Claude Code --------------------------------------------------------------

#[test]
fn claude_codes_block_is_the_last_settings_of_its_command_line() {
    let s = Scratch::new("cc");
    let mut p = claude_plan(&s, &["-p", "hi", "--model", "x"]);
    let r = run(
        &s,
        "claude-code",
        Boundary::None,
        Some(Tier::Standard),
        &mut p,
    )
    .unwrap()
    .unwrap();
    assert_eq!(r["tier"], "standard");
    assert_eq!(r["via"], "settings-flag");
    let n = p.args.len();
    assert_eq!(p.args[n - 2], "--settings");
    assert_eq!(&p.args[..4], &["-p", "hi", "--model", "x"]);
    let b = last_settings(&p.args);
    assert_eq!(b["sandbox"]["enabled"], true);
    assert_eq!(b["sandbox"]["failIfUnavailable"], true);
    assert!(b["sandbox"].get("excludedCommands").is_none());
    let deny = b["sandbox"]["filesystem"]["denyRead"].to_string();
    assert!(deny.contains(&format!("{}/.ssh", s.home())), "{deny}");
    assert!(deny.contains(&format!("{}/.derm", s.home())), "{deny}");
    assert_eq!(r["pinSha256"], json!(writers::pin(&p.args[n - 1])));
    assert!(p.notes.iter().any(|n| n.contains("tier: standard")));
}

/// Mac test w6, MW6-4: a brokered chat's secret hosts were not on derm's
/// block's `allowedDomains`, so Claude Code's own proxy refused every request
/// to them (403, "deny network-outbound api.github.com:443 (user denied)")
/// and derm-egress was never reached. Claude Code chains a host on its list
/// to the parent `HTTPS_PROXY` (note AZ C1, run on the Mac; on Linux, the
/// run in `tk_integration_w6_fp1.md`, Research). The block now lists each
/// secret's hosts when the chat is brokered (the Standard tier with no
/// srt), and nothing else.
#[test]
fn mw6_4_a_brokered_chats_secret_hosts_are_on_the_blocks_allowed_domains() {
    let s = Scratch::new("mw64");
    s.write(
        "home/.derm/secrets.json",
        r#"{"version":1,"secrets":[{"id":"gh","hosts":["api.github.com","uploads.github.com"],"from":{"env":"GH_TOKEN"}},{"id":"x","hosts":["api.example.com"],"from":{"env":"X_TOKEN"}}]}"#,
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let f = s.root.join("home/.derm/secrets.json");
        std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::set_permissions(
            s.root.join("home/.derm"),
            std::fs::Permissions::from_mode(0o700),
        )
        .unwrap();
    }
    let mut p = claude_plan(&s, &["-p", "hi"]);
    run(
        &s,
        "claude-code",
        Boundary::None,
        Some(Tier::Standard),
        &mut p,
    )
    .unwrap()
    .unwrap();
    let b = last_settings(&p.args);
    assert_eq!(
        b["sandbox"]["network"]["allowedDomains"],
        json!(["api.example.com", "api.github.com", "uploads.github.com"]),
        "{b}"
    );
    // Under sbx nothing is brokered (case 218), so nothing is opened.
    let mut p = claude_plan(&s, &["-p", "hi"]);
    run(
        &s,
        "claude-code",
        Boundary::Sbx,
        Some(Tier::Standard),
        &mut p,
    )
    .unwrap()
    .unwrap();
    let b = last_settings(&p.args);
    assert_eq!(b["sandbox"]["network"]["allowedDomains"], json!([]), "{b}");
}

/// Box test w6, BW6-1: on Ubuntu with its `bwrap-userns-restrict` profile
/// and the system bubblewrap first on PATH, Claude Code's own sandbox kills
/// every command, so the tier is refused before it starts, naming the
/// profile and the way on; the bubblewrap copy first on PATH, or no profile
/// and the sysctl at 0, lets it through; Codex's sandbox ran there (box A2)
/// and is not refused; under sbx the VM's kernel decides.
#[test]
fn bw6_1_claude_codes_tier_is_refused_where_ubuntus_profile_kills_its_commands() {
    let s = Scratch::new("bw61");
    let mut i = s.inputs();
    i.linux_bwrap = Some(LinuxBwrap {
        bwrap: Some("/usr/bin/bwrap".into()),
        profile: true,
        userns: Some("1\n".into()),
    });
    let mut p = claude_plan(&s, &["-p", "hi"]);
    let e = environment_with(
        "claude-code",
        Boundary::None,
        Some(Tier::Standard),
        &mut p,
        &i,
    )
    .unwrap_err();
    assert_eq!(e.0, 2);
    assert!(
        e.1.contains("bwrap-userns-restrict") && e.1.contains("docs/install/linux.md"),
        "{}",
        e.1
    );
    assert!(!p.args.iter().any(|a| a == "--settings"), "nothing written");
    // The sysctl alone (Ubuntu 24.04's case) refuses too.
    i.linux_bwrap = Some(LinuxBwrap {
        bwrap: Some("/usr/bin/bwrap".into()),
        profile: false,
        userns: Some("1".into()),
    });
    let mut p = claude_plan(&s, &["-p", "hi"]);
    assert!(environment_with(
        "claude-code",
        Boundary::None,
        Some(Tier::Standard),
        &mut p,
        &i
    )
    .is_err());
    // srt's copy first on PATH, or no restriction: the tier goes on.
    for b in [
        LinuxBwrap {
            bwrap: Some("/usr/local/libexec/derm-srt/bwrap".into()),
            profile: true,
            userns: Some("1".into()),
        },
        LinuxBwrap {
            bwrap: Some("/usr/bin/bwrap".into()),
            profile: false,
            userns: Some("0".into()),
        },
    ] {
        i.linux_bwrap = Some(b);
        let mut p = claude_plan(&s, &["-p", "hi"]);
        environment_with(
            "claude-code",
            Boundary::None,
            Some(Tier::Standard),
            &mut p,
            &i,
        )
        .unwrap();
        assert!(p.args.iter().any(|a| a == "--settings"));
    }
    // Codex and sbx are not refused.
    i.linux_bwrap = Some(LinuxBwrap {
        bwrap: Some("/usr/bin/bwrap".into()),
        profile: true,
        userns: Some("1".into()),
    });
    let mut p = claude_plan(&s, &["-p", "hi"]);
    environment_with(
        "claude-code",
        Boundary::Sbx,
        Some(Tier::Standard),
        &mut p,
        &i,
    )
    .unwrap();
    let mut p = plan("codex", &["exec", "go"], &[&s.work()]);
    environment_with("codex", Boundary::None, Some(Tier::Standard), &mut p, &i).unwrap();
}

/// Case 214, AZ-7: `excludedCommands` anywhere Claude Code reads it.
#[test]
fn excluded_commands_in_any_settings_file_refuse_the_tier() {
    for (rel, layer) in [
        ("work/.claude/settings.json", "project"),
        ("work/.claude/settings.local.json", "local"),
        ("home/.claude/settings.json", "user"),
        ("etc/claude-code/managed-settings.json", "managed"),
        ("etc/claude-code/managed-settings.d/10-x.json", "managed .d"),
    ] {
        let s = Scratch::new("excl");
        s.write(rel, r#"{"sandbox":{"excludedCommands":["cat *"]}}"#);
        let mut p = claude_plan(&s, &["-p", "hi"]);
        let args = p.args.clone();
        let e = run(
            &s,
            "claude-code",
            Boundary::None,
            Some(Tier::Standard),
            &mut p,
        )
        .unwrap_err();
        assert_eq!(e.0, 2, "{layer}");
        assert!(e.1.contains("excludedCommands"), "{layer}: {}", e.1);
        assert_eq!(p.args, args, "{layer}: nothing added");
    }
}

/// The runs: a user file's `filesystem.allowRead` and `allowWrite` widen the
/// block, a managed `enabled: false` turns it off. Any sandbox key outside
/// derm's block is refused, a project's included (contract section 6).
#[test]
fn any_sandbox_key_beside_derms_block_is_refused_with_its_name() {
    for (rel, text, want) in [
        (
            "home/.claude/settings.json",
            r#"{"sandbox":{"filesystem":{"allowRead":["/x"]}}}"#,
            "sandbox.filesystem.allowRead",
        ),
        (
            "home/.claude/settings.json",
            r#"{"sandbox":{"filesystem":{"allowWrite":["/x"]}}}"#,
            "sandbox.filesystem.allowWrite",
        ),
        (
            "etc/claude-code/managed-settings.json",
            r#"{"sandbox":{"enabled":false}}"#,
            "sandbox.enabled",
        ),
        (
            "work/.claude/settings.json",
            r#"{"sandbox":{"enabled":false}}"#,
            "sandbox.enabled",
        ),
        (
            "home/.claude/settings.json",
            r#"{"sandbox":{"allowUnsandboxedCommands":true}}"#,
            "sandbox.allowUnsandboxedCommands",
        ),
    ] {
        let s = Scratch::new("keys");
        s.write(rel, text);
        let mut p = claude_plan(&s, &["-p", "hi"]);
        let e = run(
            &s,
            "claude-code",
            Boundary::None,
            Some(Tier::Standard),
            &mut p,
        )
        .unwrap_err();
        assert!(e.1.contains(want), "{rel}: {}", e.1);
    }
}

/// The user file is found where `CLAUDE_CONFIG_DIR` says.
#[test]
fn the_user_file_follows_claude_config_dir() {
    let s = Scratch::new("cfgdir");
    s.write(
        "cfg/settings.json",
        r#"{"sandbox":{"filesystem":{"allowWrite":["/"]}}}"#,
    );
    let mut i = s.inputs();
    i.claude_config_dir = Some(s.root.join("cfg").to_string_lossy().into_owned());
    let mut p = claude_plan(&s, &["-p", "hi"]);
    let e = environment_with(
        "claude-code",
        Boundary::None,
        Some(Tier::Standard),
        &mut p,
        &i,
    )
    .unwrap_err();
    assert!(e.1.contains("allowWrite"), "{}", e.1);
}

#[test]
fn dangerously_disable_sandbox_anywhere_refuses_the_tier() {
    let s = Scratch::new("dds");
    s.write(
        "work/.claude/settings.local.json",
        r#"{"permissions":{"allow":["Bash(dangerouslyDisableSandbox)"]}}"#,
    );
    let mut p = claude_plan(&s, &["-p", "hi"]);
    let e = run(
        &s,
        "claude-code",
        Boundary::None,
        Some(Tier::Standard),
        &mut p,
    )
    .unwrap_err();
    assert!(e.1.contains("dangerouslyDisableSandbox"), "{}", e.1);
}

#[test]
fn a_user_files_additional_directories_refuse_and_a_projects_do_not() {
    let s = Scratch::new("adddirs");
    s.write(
        "work/.claude/settings.json",
        r#"{"permissions":{"additionalDirectories":["/x"]}}"#,
    );
    let mut p = claude_plan(&s, &["-p", "hi"]);
    assert!(run(
        &s,
        "claude-code",
        Boundary::None,
        Some(Tier::Standard),
        &mut p
    )
    .is_ok());
    s.write(
        "home/.claude/settings.json",
        r#"{"permissions":{"additionalDirectories":["/x"]}}"#,
    );
    let mut q = claude_plan(&s, &["-p", "hi"]);
    let e = run(
        &s,
        "claude-code",
        Boundary::None,
        Some(Tier::Standard),
        &mut q,
    )
    .unwrap_err();
    assert!(
        e.1.contains("additionalDirectories") && e.1.contains("--add-dir"),
        "{}",
        e.1
    );
}

/// A file derm cannot read is refused: it cannot tell what it says.
#[test]
fn a_settings_file_derm_cannot_read_refuses_the_tier() {
    let s = Scratch::new("badjson");
    s.write("work/.claude/settings.json", "{ not json");
    let mut p = claude_plan(&s, &["-p", "hi"]);
    let e = run(
        &s,
        "claude-code",
        Boundary::None,
        Some(Tier::Standard),
        &mut p,
    )
    .unwrap_err();
    assert!(e.1.contains("not JSON"), "{}", e.1);
}

#[test]
fn the_harnesss_own_settings_flag_or_a_double_dash_refuses_the_tier() {
    for words in [
        &["-p", "hi", "--settings", "{}"][..],
        &["--settings={}", "-p", "hi"][..],
        &["-p", "--", "hi"][..],
    ] {
        let s = Scratch::new("ownsettings");
        let mut p = claude_plan(&s, words);
        let e = run(
            &s,
            "claude-code",
            Boundary::None,
            Some(Tier::Standard),
            &mut p,
        )
        .unwrap_err();
        assert_eq!(e.0, 2, "{words:?}");
    }
}

/// `--add-dir` is the person's own word: it widens writes, so the folder is
/// one of the chat's.
#[test]
fn an_add_dir_on_the_command_line_becomes_a_chat_folder() {
    let s = Scratch::new("adddir");
    let mut p = claude_plan(&s, &["-p", "hi", "--add-dir", "/srv/data", "--add-dir=rel"]);
    run(
        &s,
        "claude-code",
        Boundary::None,
        Some(Tier::Standard),
        &mut p,
    )
    .unwrap();
    assert!(p.folders.contains(&"/srv/data".to_string()));
    assert!(p.folders.contains(&format!("{}/rel", s.work())));
    let b = last_settings(&p.args);
    assert!(b["sandbox"]["filesystem"]["allowWrite"]
        .to_string()
        .contains("/srv/data"));
}

// --- one tier per chat ------------------------------------------------------------

/// Case 215: under srt the vendor sandbox is off and derm says one tier.
#[test]
fn under_srt_one_tier_runs_and_derm_says_which() {
    for harness in ["claude-code", "codex"] {
        let s = Scratch::new("srt");
        let mut p = plan(
            "srt",
            &["--settings", "/s.json", "--", "x", "-p", "hi"],
            &[&s.work()],
        );
        let args = p.args.clone();
        let r = run(&s, harness, Boundary::Srt, Some(Tier::Standard), &mut p)
            .unwrap()
            .unwrap();
        assert_eq!(r["tier"], "whole");
        assert_eq!(r["why"], "srt-no-nesting");
        assert_eq!(p.args, args);
        assert!(
            p.notes.iter().any(|n| n.contains("one tier: whole (srt)")),
            "{:?}",
            p.notes
        );
    }
}

/// Note AZ A8: under sbx the vendor sandbox starts inside the VM; derm keeps
/// it on and records it. The block goes after sbx's `--`, made if missing.
#[test]
fn under_sbx_the_vendor_sandbox_stays_on_inside_the_vm() {
    let s = Scratch::new("sbx");
    let mut p = plan(
        "sbx",
        &["run", "--name", "derm-x", "claude", "/w"],
        &[&s.work()],
    );
    let r = run(
        &s,
        "claude-code",
        Boundary::Sbx,
        Some(Tier::Standard),
        &mut p,
    )
    .unwrap()
    .unwrap();
    assert_eq!(r["vendorUnderSbx"], "on");
    let dd = p.args.iter().position(|a| a == "--").unwrap();
    assert_eq!(p.args[dd + 1], "--settings");
    let mut q = plan(
        "sbx",
        &["run", "--name", "derm-x", "codex", "/w", "--", "exec", "hi"],
        &[&s.work()],
    );
    run(&s, "codex", Boundary::Sbx, Some(Tier::Standard), &mut q).unwrap();
    assert_eq!(&q.args[6..8], &["exec", "-c"]);
}

/// An agent derm writes no sandbox for: the Whole tier under a boundary,
/// a refusal under none (nothing would be around it).
#[test]
fn an_agent_with_no_row_runs_whole_or_is_refused_under_none() {
    let s = Scratch::new("norow");
    let mut p = plan("pi", &["-p", "hi"], &[&s.work()]);
    let r = run(&s, "pi", Boundary::Srt, Some(Tier::Standard), &mut p)
        .unwrap()
        .unwrap();
    assert_eq!(r["why"], "no-sandbox-row");
    let mut q = plan("pi", &["-p", "hi"], &[&s.work()]);
    let e = run(&s, "pi", Boundary::None, Some(Tier::Standard), &mut q).unwrap_err();
    assert!(e.1.contains("nothing around it"), "{}", e.1);
}

/// Contract section 4: Cursor's tier is advisory, and a repository file
/// that widens it is named.
#[test]
fn cursors_tier_is_advisory_and_names_a_widening_repository_file() {
    let s = Scratch::new("cursor");
    s.write(
        "work/.cursor/sandbox.json",
        r#"{"additionalReadwritePaths":["/"]}"#,
    );
    let mut p = plan("cursor-agent", &["-p", "hi"], &[&s.work()]);
    let r = run(&s, "cursor", Boundary::Sbx, Some(Tier::Standard), &mut p)
        .unwrap()
        .unwrap();
    assert_eq!(r["why"], "advisory");
    assert!(
        p.notes
            .iter()
            .any(|n| n.contains("additionalReadwritePaths")),
        "{:?}",
        p.notes
    );
    let mut q = plan("cursor-agent", &["-p", "hi"], &[&s.work()]);
    assert!(run(&s, "cursor", Boundary::None, Some(Tier::Standard), &mut q).is_err());
}

#[test]
fn on_windows_the_tier_is_refused_with_why() {
    let s = Scratch::new("win");
    let mut i = s.inputs();
    i.windows = true;
    let mut p = claude_plan(&s, &["-p", "hi"]);
    let e = environment_with(
        "claude-code",
        Boundary::None,
        Some(Tier::Standard),
        &mut p,
        &i,
    )
    .unwrap_err();
    assert!(e.1.contains("Linux and macOS"), "{}", e.1);
}

// --- Codex ----------------------------------------------------------------------

fn codex(s: &Scratch, words: &[&str]) -> Result<Plan, (u8, String)> {
    let mut p = plan("codex", words, &[&s.work()]);
    run(s, "codex", Boundary::None, Some(Tier::Standard), &mut p).map(|_| p)
}

/// Case 184: the pairs sit at derm's own `-c` level, after a leading
/// session subcommand, else first (the TUI).
#[test]
fn codexs_profile_goes_in_at_derms_own_config_level() {
    let s = Scratch::new("cx");
    let p = codex(&s, &["exec", "--json", "hi"]).unwrap();
    assert_eq!(p.args[0], "exec");
    assert_eq!(&p.args[1..3], &["-c", "default_permissions=\"derm\""]);
    assert!(p.args[4].starts_with("permissions.derm={"));
    assert_eq!(&p.args[5..], &["--json", "hi"]);
    let q = codex(&s, &["fix the tests"]).unwrap();
    assert_eq!(q.args[0], "-c");
    assert_eq!(q.args.last().unwrap(), "fix the tests");
}

#[test]
fn codexs_own_sandbox_words_refuse_the_tier() {
    for words in [
        &["exec", "-s", "workspace-write", "hi"][..],
        &["exec", "--sandbox=read-only", "hi"][..],
        &["exec", "-c", "default_permissions=\":workspace\"", "hi"][..],
        &["exec", "-c", "sandbox_mode=\"workspace-write\"", "hi"][..],
        &["--dangerously-bypass-approvals-and-sandbox", "exec", "hi"][..],
        &["exec", "-c", "permissions.derm.filesystem={}", "hi"][..],
        &["exec", "--config=permissions.other={}", "hi"][..],
        &["exec", "-cpermission_profile=x", "hi"][..],
        &["--full-auto", "exec", "hi"][..],
    ] {
        let s = Scratch::new("cxw");
        let e = codex(&s, words).unwrap_err();
        assert_eq!(e.0, 2, "{words:?}: {}", e.1);
    }
    // Other `-c` pairs are the person's.
    let s = Scratch::new("cxok");
    assert!(codex(&s, &["exec", "-c", "model=\"o4\"", "hi"]).is_ok());
}

/// The run: a layer that defines `[permissions.derm]` merges into derm's
/// profile, so any layer Codex reads that names it is refused.
#[test]
fn a_codex_layer_that_defines_derms_profile_refuses_the_tier() {
    for rel in [
        "home/.codex/config.toml",
        "home/.codex/work.config.toml",
        "work/.codex/config.toml",
        ".codex/config.toml",
        "work/config.toml",
        "etc/codex/config.toml",
    ] {
        let s = Scratch::new("cxlayer");
        s.write(rel, "[permissions.derm.filesystem]\n\"/\" = \"write\"\n");
        let e = codex(&s, &["exec", "hi"]).unwrap_err();
        assert!(e.1.contains("[permissions.derm]"), "{rel}: {}", e.1);
    }
    // A dotted key names it too.
    let s = Scratch::new("cxdot");
    s.write(
        "home/.codex/config.toml",
        "permissions.derm.extends = \":danger-no-sandbox\"\n",
    );
    assert!(codex(&s, &["exec", "hi"]).is_err());
    // Another profile, or a sandbox_mode the session flags outrank, is fine.
    let t = Scratch::new("cxother");
    t.write(
        "home/.codex/config.toml",
        "sandbox_mode = \"danger-full-access\"\n[permissions.mine]\nextends = \":workspace\"\n",
    );
    assert!(codex(&t, &["exec", "hi"]).is_ok());
}

#[test]
fn a_codex_layer_derm_cannot_read_refuses_the_tier() {
    let s = Scratch::new("cxbad");
    s.write("work/.codex/config.toml", "this is = = not toml");
    let e = codex(&s, &["exec", "hi"]).unwrap_err();
    assert!(e.1.contains("not TOML"), "{}", e.1);
}

#[test]
fn codex_home_is_read_where_codex_home_says() {
    let s = Scratch::new("cxhome");
    s.write(
        "ch/config.toml",
        "[permissions.derm]\nextends = \":workspace\"\n",
    );
    let mut i = s.inputs();
    i.codex_home = Some(s.root.join("ch").to_string_lossy().into_owned());
    let mut p = plan("codex", &["exec", "hi"], &[&s.work()]);
    assert!(environment_with("codex", Boundary::None, Some(Tier::Standard), &mut p, &i).is_err());
}

/// The rows carry the version each was verified at (case 81).
#[test]
fn every_sandbox_row_names_its_verified_version() {
    for (h, via) in [
        ("claude-code", "settings-flag"),
        ("codex", "config-override"),
        ("cursor", "advisory"),
    ] {
        let r = sandbox_row(h).unwrap_or_else(|| panic!("{h} has no row"));
        assert_eq!(r["via"], via);
        assert!(r["verifiedAt"].as_str().is_some_and(|v| !v.is_empty()));
    }
    assert_eq!(sandbox_row("gemini"), None);
}

/// Box test w6, BW6-2: Codex's `:workspace` writes `/tmp` (its session
/// header said `workspace-write [workdir, /tmp, $TMPDIR]`, A2). With no
/// boundary derm's profile makes `/tmp` read-only and `derm run` names a
/// `TMPDIR` of the chat's own; under sbx `/tmp` is the VM's and stays.
#[test]
fn bw6_2_codexs_tier_keeps_tmp_to_the_chat_with_no_boundary() {
    let s = Scratch::new("cx-tmp");
    let p = codex(&s, &["exec", "hi"]).unwrap();
    assert!(
        p.args[4].contains("\":slash_tmp\"=\"read\""),
        "{}",
        p.args[4]
    );
    assert!(
        p.notes.iter().any(|n| n.contains("/tmp is read-only")),
        "{:?}",
        p.notes
    );
    let rec = json!({"tier": "standard"});
    assert!(wants_chat_tmp("codex", Boundary::None, Some(&rec)));
    assert!(!wants_chat_tmp("codex", Boundary::Sbx, Some(&rec)));
    assert!(!wants_chat_tmp("claude-code", Boundary::None, Some(&rec)));
    assert!(!wants_chat_tmp(
        "codex",
        Boundary::None,
        Some(&json!({"tier": "whole"}))
    ));
    assert!(!wants_chat_tmp("codex", Boundary::None, None));
    let mut q = plan(
        "sbx",
        &["run", "--name", "derm-x", "codex", "/w", "--", "exec", "hi"],
        &[&s.work()],
    );
    run(&s, "codex", Boundary::Sbx, Some(Tier::Standard), &mut q).unwrap();
    assert!(!q.args.iter().any(|a| a.contains(":slash_tmp")));
}

#[test]
fn bw6_2_the_chats_tmp_folder_is_new_private_and_named_in_a_dry_run() {
    let s = Scratch::new("cx-tmpdir");
    let temp = s.root.join("t");
    std::fs::create_dir_all(&temp).unwrap();
    let named = chat_tmp_dir(&temp, "derm-c1", true).unwrap();
    assert!(named.ends_with("derm-tmp-derm-c1-<random>"));
    assert_eq!(std::fs::read_dir(&temp).unwrap().count(), 0);
    let a = chat_tmp_dir(&temp, "derm-c1", false).unwrap();
    let b = chat_tmp_dir(&temp, "derm-c1", false).unwrap();
    assert_ne!(a, b);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let m = std::fs::metadata(&a).unwrap().permissions().mode() & 0o777;
        assert_eq!(m, 0o700);
    }
    assert!(a
        .file_name()
        .unwrap()
        .to_string_lossy()
        .starts_with("derm-tmp-derm-c1-"));
}

/// Mac test w6, MW6-3: under sbx the VM ran sbx's own Claude Code 2.1.323,
/// not the host's install, while the start line spoke of the installed
/// version `derm doctor` names. Under sbx it says whose program runs.
#[test]
fn mw6_3_under_sbx_the_version_line_names_sbxs_own_program() {
    let s = Scratch::new("sbx-ver");
    let mut p = plan(
        "sbx",
        &["run", "--name", "derm-x", "claude", "/w"],
        &[&s.work()],
    );
    run(
        &s,
        "claude-code",
        Boundary::Sbx,
        Some(Tier::Standard),
        &mut p,
    )
    .unwrap();
    let line = p
        .notes
        .iter()
        .find(|n| n.contains("verified at"))
        .unwrap_or_else(|| panic!("{:?}", p.notes));
    assert!(line.contains("sbx's own"), "{line}");
    assert!(!line.contains("derm doctor"), "{line}");
    let q = codex(&s, &["exec", "hi"]).unwrap();
    let line = q.notes.iter().find(|n| n.contains("verified at")).unwrap();
    assert!(line.contains("derm doctor"), "{line}");
}

/// Windows test w6, WW6-10: a program derm does not know is the harness
/// `other`, and the refusal read "derm writes no sandbox of other's own".
#[test]
fn ww6_10_a_program_derm_does_not_know_is_named_as_a_program() {
    let s = Scratch::new("other");
    let mut p = plan("node", &["x.js"], &[&s.work()]);
    let e = run(&s, "other", Boundary::None, Some(Tier::Standard), &mut p).unwrap_err();
    assert!(!e.1.contains("other's"), "{}", e.1);
    assert!(e.1.contains("this program"), "{}", e.1);
}
