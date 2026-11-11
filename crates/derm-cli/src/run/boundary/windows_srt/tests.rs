use serde_json::{json, Value};

use super::*;
use crate::run::harness::HARNESSES;

const HOME: &str = r"C:\Users\u";
const CWD: &str = r"C:\work\proj";
const DERM: &str = r"C:\Tools\derm\derm.exe";
const CLAUDE: &str =
    r"C:\Users\u\AppData\Roaming\npm\node_modules\@anthropic-ai\claude-code\bin\claude.exe";
const TOKEN: &str = "abababababababababababababababababababababababababababababababab";
const NOW: u64 = 1_762_790_400_000;

fn harness(id: &str) -> &'static Harness {
    HARNESSES.iter().find(|h| h.id == id).unwrap()
}

/// The srt plan `plan::build` makes on any OS, as far as the rewrite reads
/// it: srt, its settings file, `--`, the loopback wrap, the command, words.
fn unix_plan(command: &str) -> Plan {
    Plan {
        program: "srt".into(),
        args: vec![
            "--settings".into(),
            r"C:\Users\u\.derm\run\derm\srt\derm-0123456789ab.json".into(),
            "--".into(),
            "/usr/bin/env".into(),
            "NO_PROXY=x".into(),
            "no_proxy=x".into(),
            command.into(),
            "-p".into(),
            "fix the bug".into(),
        ],
        env_set: vec![
            ("DERM_CHAT_ID".into(), "derm-0123456789ab".into()),
            ("DERM_HARNESS".into(), "claude-code".into()),
            ("DERM_BOUNDARY".into(), "srt".into()),
            ("DERM_CHAT_TOKEN".into(), TOKEN.into()),
            (
                "DERM_OTLP_ENDPOINT".into(),
                "http://[::ffff:127.0.0.1]:41234".into(),
            ),
            ("NODE_USE_ENV_PROXY".into(), "1".into()),
        ],
        env_remove: vec!["DERM_CHAT_TOKEN".into()],
        kit: None,
        sandbox_name: None,
        srt_settings: Some(
            json!({
                "network": {
                    "allowedDomains": ["127.0.0.1:41234", "platform.claude.com:443", "api.anthropic.com:443"],
                    "deniedDomains": [],
                    "allowUnixSockets": ["/run/user/1/derm/derm.sock"],
                },
                "filesystem": {"denyRead": [], "allowRead": [], "allowWrite": ["/tmp"], "denyWrite": []},
                "allowPty": true,
            })
            .to_string(),
        ),
        folders: vec![CWD.into()],
        state_dirs: vec![],
        notes: vec!["derm run: under srt claude-code may reach its sign-in host platform.claude.com:443 to renew".into()],
        full_access: vec![],
        companion: None,
        scratch_dir: None,
    }
}

fn launch_exe(cmd: &str) -> Result<(String, Vec<String>), String> {
    match cmd {
        "claude" => Ok((CLAUDE.into(), vec![])),
        "codex" => Ok((
            r"C:\Program Files\nodejs\node.exe".into(),
            vec![r"C:\Users\u\AppData\Roaming\npm\node_modules\@openai\codex\bin\codex.js".into()],
        )),
        "bat" => Ok((r"C:\x\tool.cmd".into(), vec![])),
        other => Err(format!("{other}: not found")),
    }
}

fn ctx<'a>(h: &'static Harness, policy: &'a derm_core::policy::PolicyFile) -> Ctx<'a> {
    Ctx {
        chat: "derm-0123456789ab",
        harness: h,
        cwd: CWD,
        home: HOME,
        derm_exe: DERM,
        token: Some(TOKEN),
        policy,
        policy_problem: None,
        sandbox_user: Some("srt-sandbox"),
        now_ms: NOW,
        launch: &launch_exe,
        exists: &|_| true,
    }
}

fn settings_of(p: &Plan) -> Value {
    serde_json::from_str(p.srt_settings.as_deref().unwrap()).unwrap()
}

fn paths(v: &Value) -> Vec<String> {
    v.as_array()
        .unwrap()
        .iter()
        .map(|e| e["path"].as_str().unwrap().to_string())
        .collect()
}

#[test]
fn srt_runs_derm_enter_with_one_string_and_the_handoff_holds_the_chat() {
    let policy = derm_core::policy::PolicyFile::default();
    let mut p = unix_plan("claude");
    let r = rewrite(&mut p, &ctx(harness("claude-code"), &policy)).unwrap();
    assert_eq!(p.program, "srt");
    assert_eq!(
        p.args,
        vec![
            "--settings".to_string(),
            r"C:\Users\u\.derm\run\derm\srt\derm-0123456789ab.json".into(),
            "-c".into(),
            format!(
                r#""{DERM}" enter "C:\Users\u\.derm-srt\chats\derm-0123456789ab\handoff.json""#
            ),
        ]
    );
    // Nothing of the chat rides srt's own process, the token least of all.
    assert!(p.env_set.is_empty());
    assert!(!p.args.iter().any(|a| a.contains(TOKEN)));
    let h = &r.handoff;
    assert_eq!(
        h.argv,
        vec![CLAUDE.to_string(), "-p".into(), "fix the bug".into()]
    );
    assert_eq!(h.cwd, CWD);
    assert_eq!(h.token, TOKEN);
    assert_eq!(h.daemon_http, "http://[::ffff:127.0.0.1]:41234");
    assert_eq!(h.expires, NOW + HANDOFF_LIFE_MS);
    assert_eq!(
        h.variables.get("CLAUDE_CONFIG_DIR").map(String::as_str),
        Some(r"C:\Users\u\.derm-srt\state\claude-code\claude")
    );
    assert!(h.variables.contains_key("DERM_OTLP_ENDPOINT"));
    // srt sets these itself, and the token is the handoff's own field.
    assert!(!h.variables.contains_key("NODE_USE_ENV_PROXY"));
    assert!(!h.variables.contains_key("DERM_CHAT_TOKEN"));
    // What `derm enter` will read passes its own rules.
    crate::enter::handoff::parse(
        crate::enter::handoff::to_json(h).to_string().as_bytes(),
        NOW,
    )
    .unwrap();
    assert_eq!(
        r.copies[1],
        (
            r"C:\Users\u\.claude\.credentials.json".to_string(),
            r"C:\Users\u\.derm-srt\state\claude-code\claude\.credentials.json".to_string()
        )
    );
}

#[test]
fn the_settings_are_windows_own_with_the_backend_and_local_binding_pinned() {
    let policy = derm_core::policy::PolicyFile::default();
    let mut p = unix_plan("claude");
    rewrite(&mut p, &ctx(harness("claude-code"), &policy)).unwrap();
    let s = settings_of(&p);
    assert_eq!(s["windows"]["backend"], "srt-win");
    assert_eq!(s["windows"]["sandboxUser"], "srt-sandbox");
    assert_eq!(s["network"]["allowLocalBinding"], false);
    // Unix-only keys are gone.
    assert!(s.get("allowPty").is_none());
    assert!(s["network"].get("allowUnixSockets").is_none());
    // The sign-in host is shut (no renewal inside), the rest kept.
    assert_eq!(
        s["network"]["allowedDomains"],
        json!(["127.0.0.1:41234", "api.anthropic.com:443"])
    );
    assert_eq!(
        paths(&s["filesystem"]["allowWrite"]),
        vec![
            CWD.to_string(),
            r"C:\Users\u\.derm-srt\state\claude-code".into()
        ]
    );
    assert_eq!(paths(&s["filesystem"]["allowRead"]), vec![DERM.to_string()]);
    let dw = paths(&s["filesystem"]["denyWrite"]);
    for want in [
        r"C:\work\proj\.claude\settings.json",
        r"C:\work\proj\.claude\plugins",
        r"C:\work\proj\.git\hooks",
        r"C:\work\proj\.git\config",
        r"C:\Users\u\.derm-srt\state\claude-code\claude\settings.json",
        r"C:\Users\u\.derm-srt\state\claude-code\claude\plugins",
        DERM,
    ] {
        assert!(dw.iter().any(|d| d == want), "{want} in {dw:?}");
    }
    let dr = paths(&s["filesystem"]["denyRead"]);
    for want in [
        r"C:\Users\u\.derm",
        r"C:\Users\u\.claude",
        r"C:\Users\u\.claude.json",
        r"C:\Users\u\.codex",
    ] {
        assert!(dr.iter().any(|d| d == want), "{want} in {dr:?}");
    }
    // Every entry is literal: no path is read as a pattern.
    for list in ["allowWrite", "allowRead", "denyWrite", "denyRead"] {
        for e in s["filesystem"][list].as_array().unwrap() {
            assert_eq!(e["literal"], true, "{list}");
        }
    }
    assert!(p.notes.iter().any(|n| n.contains("one srt chat at a time")));
    assert!(p
        .notes
        .iter()
        .any(|n| n.contains("sign-in host stays shut")));
    assert!(!p
        .notes
        .iter()
        .any(|n| n.contains("may reach its sign-in host")));
}

#[test]
fn a_path_that_is_not_there_is_not_denied() {
    let policy = derm_core::policy::PolicyFile::default();
    let mut p = unix_plan("claude");
    let mut c = ctx(harness("claude-code"), &policy);
    c.exists = &|p: &str| !p.contains(".codex") && !p.ends_with(".git\\hooks");
    rewrite(&mut p, &c).unwrap();
    let s = settings_of(&p);
    let all: Vec<String> = paths(&s["filesystem"]["denyRead"])
        .into_iter()
        .chain(paths(&s["filesystem"]["denyWrite"]))
        .collect();
    assert!(!all
        .iter()
        .any(|d| d.contains(".codex") || d.ends_with(".git\\hooks")));
}

#[test]
fn codex_gets_its_own_home_its_launcher_and_its_project_dot_codex_denied() {
    let policy = derm_core::policy::PolicyFile::default();
    let mut p = unix_plan("codex");
    let r = rewrite(&mut p, &ctx(harness("codex"), &policy)).unwrap();
    assert_eq!(
        r.handoff.argv[..2],
        [
            r"C:\Program Files\nodejs\node.exe".to_string(),
            r"C:\Users\u\AppData\Roaming\npm\node_modules\@openai\codex\bin\codex.js".into()
        ]
    );
    assert_eq!(
        r.handoff.variables["CODEX_HOME"],
        r"C:\Users\u\.derm-srt\state\codex\codex"
    );
    let s = settings_of(&p);
    let dw = paths(&s["filesystem"]["denyWrite"]);
    assert!(dw.contains(&r"C:\work\proj\.codex".to_string()));
    assert!(dw.contains(&r"C:\Users\u\.derm-srt\state\codex\codex\config.toml".to_string()));
    assert!(dw.contains(&r"C:\Users\u\.derm-srt\state\codex\codex\hooks.json".to_string()));
}

#[test]
fn a_harness_with_no_layout_a_batch_file_or_no_daemon_is_refused() {
    let policy = derm_core::policy::PolicyFile::default();
    let mut p = unix_plan("pi");
    let e = rewrite(&mut p, &ctx(harness("pi"), &policy)).unwrap_err();
    assert!(e.contains("no srt state layout for pi"), "{e}");

    let mut p = unix_plan("bat");
    let e = rewrite(&mut p, &ctx(harness("claude-code"), &policy)).unwrap_err();
    assert!(e.contains(".exe"), "{e}");

    let mut p = unix_plan("claude");
    let mut c = ctx(harness("claude-code"), &policy);
    c.token = None;
    assert!(rewrite(&mut p, &c)
        .unwrap_err()
        .contains("needs the daemon"));

    let mut p = unix_plan("claude");
    p.env_set.retain(|(k, _)| k != "DERM_OTLP_ENDPOINT");
    let e = rewrite(&mut p, &ctx(harness("claude-code"), &policy)).unwrap_err();
    assert!(e.contains("loopback port"), "{e}");

    let mut p = unix_plan("claude");
    p.program = "claude".into();
    assert!(rewrite(&mut p, &ctx(harness("claude-code"), &policy)).is_err());
}

#[test]
fn a_path_cmd_would_read_as_more_than_a_path_is_refused() {
    for bad in [
        r#"C:\a"b\derm.exe"#,
        r"C:\%TEMP%\derm.exe",
        r"C:\a!b!\derm.exe",
        "C:\\a\nb\\derm.exe",
        r"C:\a\",
        r"\\server\share\derm.exe",
        r"derm.exe",
    ] {
        assert!(command_string(bad, r"C:\h\handoff.json").is_err(), "{bad}");
    }
    // Quoted, cmd's other characters are only characters.
    let s = command_string(r"C:\Program Files (x86)\a&b\derm.exe", r"C:\h\handoff.json").unwrap();
    assert_eq!(
        s,
        r#""C:\Program Files (x86)\a&b\derm.exe" enter "C:\h\handoff.json""#
    );
    let policy = derm_core::policy::PolicyFile::default();
    let mut p = unix_plan("claude");
    let mut c = ctx(harness("claude-code"), &policy);
    c.home = r"C:\Users\100%";
    assert!(rewrite(&mut p, &c).is_err());
}

#[test]
fn long_path_prefixes_are_taken_back_to_drive_paths() {
    assert_eq!(plain_win(r"\\?\C:\work\proj"), r"C:\work\proj");
    assert_eq!(plain_win(r"\\?\UNC\srv\share"), r"\\?\UNC\srv\share");
    let policy = derm_core::policy::PolicyFile::default();
    let mut p = unix_plan("claude");
    let mut c = ctx(harness("claude-code"), &policy);
    c.cwd = r"\\?\C:\work\proj";
    c.derm_exe = r"\\?\C:\Tools\derm\derm.exe";
    let r = rewrite(&mut p, &c).unwrap();
    assert_eq!(r.handoff.cwd, CWD);
    assert!(p.args[3].starts_with(r#""C:\Tools\derm\derm.exe""#));
    // A UNC folder is refused, as srt-win refuses it (mapped_drive_cwd).
    let mut p = unix_plan("claude");
    let mut c = ctx(harness("claude-code"), &policy);
    c.cwd = r"\\srv\share\proj";
    assert!(rewrite(&mut p, &c).is_err());
}

#[test]
fn the_policy_and_its_problem_reach_the_handoff_and_the_chat_file() {
    let policy: derm_core::policy::PolicyFile = serde_json::from_value(
        json!({"version": 1, "rules": [{"tool": "bash", "action": "deny"}]}),
    )
    .unwrap();
    let mut p = unix_plan("claude");
    let mut c = ctx(harness("claude-code"), &policy);
    c.policy_problem = Some("someone other than you may write this policy file");
    let r = rewrite(&mut p, &c).unwrap();
    let chat = crate::enter::handoff::chat_file_json(&r.handoff);
    assert_eq!(chat["policy"]["rules"][0]["action"], "deny");
    assert_eq!(
        chat["policyProblem"],
        "someone other than you may write this policy file"
    );
}

#[test]
fn the_files_access_lists_give_the_sandbox_read_and_the_handoff_delete() {
    assert_eq!(
        files::file_sddl("S-1-5-21-1-2-3-1001", "S-1-5-21-1-2-3-1002", "FRSD"),
        "D:P(A;;FA;;;S-1-5-21-1-2-3-1001)(A;;FRSD;;;S-1-5-21-1-2-3-1002)"
    );
}

#[test]
fn srt_is_refused_on_windows_only_while_another_chat_holds_the_lock() {
    // Off Windows nothing is held; on Windows CI no other chat runs.
    assert_eq!(refusal(), None);
}
