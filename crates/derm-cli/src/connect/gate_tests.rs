//! Tests for `derm connect <agent> --gate` and `--ungate` (`gate.rs`): each
//! writer shape against the entries lanes L and N published, the cases of
//! rules section 4 it touches (54, 55, 65, 70, 75, 78), and the checks on
//! the hook folder.

use std::collections::HashMap;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use super::gate::{self, Step, Vars};
use super::json::{self, Value};
use super::presets::Env;
use super::write::tests::{scratch, Answer};
use super::{run, Ctx};

struct MapEnv(HashMap<String, String>);
impl Env for MapEnv {
    fn var(&self, key: &str) -> Option<String> {
        self.0.get(key).cloned()
    }
}

fn env(pairs: &[(&str, &str)]) -> MapEnv {
    MapEnv(
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect(),
    )
}

struct Run {
    code: u8,
    out: String,
    err: String,
}

fn go_with(home: &Path, env: &MapEnv, answer: Answer, args: &[&str]) -> Run {
    let mut a = answer;
    let mut ctx = Ctx {
        home: home.to_path_buf(),
        cwd: home.join("proj"),
        macos: false,
        env,
        run_user: home.join("no-run-user"),
        confirm: &mut a,
        out: String::new(),
        err: String::new(),
        live: false,
    };
    let args: Vec<String> = args.iter().map(|s| s.to_string()).collect();
    let code = run(&args, &mut ctx);
    Run {
        code,
        out: ctx.out,
        err: ctx.err,
    }
}

fn go(home: &Path, args: &[&str]) -> Run {
    go_with(home, &env(&[]), Answer(true, None), args)
}

/// A package folder holding `package.json` with `name` and
/// `bin/derm-hook.mjs`, closed to others.
fn package(home: &Path, folder: &str, name: &str) -> String {
    let dir = home.join(folder);
    fs::create_dir_all(dir.join("bin")).unwrap();
    fs::write(
        dir.join("package.json"),
        format!("{{\"name\": \"{name}\", \"version\": \"0.0.0\"}}\n"),
    )
    .unwrap();
    fs::write(dir.join("bin/derm-hook.mjs"), "// gate\n").unwrap();
    for d in [&dir, &dir.join("bin")] {
        fs::set_permissions(d, fs::Permissions::from_mode(0o755)).unwrap();
    }
    dir.display().to_string()
}

fn parse(text: &str) -> Value {
    json::parse(text, true).unwrap().root.unwrap().to_value()
}

fn read(p: &Path) -> String {
    fs::read_to_string(p).unwrap_or_else(|e| panic!("{}: {e}", p.display()))
}

#[test]
fn the_table_reads_and_every_writing_row_finds_its_own_entry() {
    let rows = gate::table().unwrap();
    let mut ids: Vec<&str> = rows.iter().map(|a| a.agent.as_str()).collect();
    ids.sort_unstable();
    ids.dedup();
    assert_eq!(ids.len(), rows.len(), "an agent listed twice");
    let vars = Vars {
        command: Some("node --no-warnings \"/h/derm/bin/derm-hook.mjs\" x".into()),
        hook_dir: Some("/h/derm/packages/derm-opencode-plugin".into()),
        version: "0.1.3".into(),
    };
    for a in &rows {
        let writes = a.steps.iter().any(|s| !matches!(s, Step::Commands { .. }));
        if !writes {
            continue;
        }
        let marker = a
            .marker
            .as_deref()
            .unwrap_or_else(|| panic!("{}: no marker", a.agent));
        assert!(
            !a.installed_if.is_empty() || a.cli.is_some(),
            "{}: nothing tells whether it is installed",
            a.agent
        );
        if a.command.is_some() {
            assert!(a.hook_file.is_some(), "{}", a.agent);
        }
        for st in &a.steps {
            let v = match st {
                Step::JsonArrayEntry { entry, .. } | Step::JsonMember { entry, .. } => entry,
                Step::OwnedFile { content, .. } => content,
                _ => continue,
            };
            let mut vars = vars.clone();
            if a.agent == "kilo" {
                vars.hook_dir = Some("/h/derm/packages/derm-kilo-plugin".into());
            }
            let filled = gate::fill(v, &vars).unwrap();
            assert!(
                json::compact(&filled).contains(marker),
                "{}: its entry does not hold its marker",
                a.agent
            );
        }
    }
}

/// Lane N's `registration/mistral-vibe/hooks.toml` (85592cf), with the
/// folder filled: derm writes exactly that table beside the user's own.
#[test]
fn vibe_gets_lane_ns_table_beside_its_own_and_once() {
    let home = scratch("gate-vibe");
    let pkg = package(
        &home,
        "clone/packages/derm-hooks-native",
        "@aetiusgular/derm-hooks-native",
    );
    let cfg = home.join(".vibe/hooks.toml");
    fs::create_dir_all(cfg.parent().unwrap()).unwrap();
    let mine = "# my hooks\n[[hooks]]\nname = \"lint\"\ntype = \"post_tool\"\ncommand = \"lint\"\n";
    fs::write(&cfg, mine).unwrap();
    let r = go(
        &home,
        &["mistral-vibe", "--gate", "--hook", &pkg, "--write"],
    );
    assert_eq!(r.code, 0, "{}{}", r.out, r.err);
    // The user's text is kept as it was; derm's table holds exactly lane
    // N's keys and values (toml_edit may quote the command as a literal
    // string; the value Vibe reads is the same).
    let after = read(&cfg);
    assert!(after.starts_with(mine), "{after}");
    let doc: toml_edit::DocumentMut = after.parse().unwrap();
    let hooks = doc["hooks"].as_array_of_tables().unwrap();
    assert_eq!(hooks.len(), 2);
    let ours = hooks.get(1).unwrap();
    let keys: Vec<&str> = ours.iter().map(|(k, _)| k).collect();
    assert_eq!(
        keys,
        [
            "name",
            "type",
            "command",
            "timeout",
            "strict",
            "description"
        ]
    );
    assert_eq!(ours["name"].as_str(), Some("derm-gate"));
    assert_eq!(ours["type"].as_str(), Some("pre_tool"));
    assert_eq!(
        ours["command"].as_str().unwrap(),
        format!("node --no-warnings \"{pkg}/bin/derm-hook.mjs\" mistral-vibe")
    );
    assert_eq!(ours["timeout"].as_float(), Some(120.0));
    assert_eq!(ours["strict"].as_bool(), Some(true));
    let r = go(&home, &["mistral-vibe", "--gate", "--hook", &pkg]);
    assert!(r.out.contains("already registered"), "{}", r.out);
    let r = go(&home, &["mistral-vibe", "--ungate", "--write"]);
    assert_eq!(r.code, 0, "{}{}", r.out, r.err);
    assert_eq!(read(&cfg).trim_end(), mine.trim_end());
}

/// Case 75: the gate goes beside Orca's own entry in a Claude-format list,
/// a second run adds nothing, and --ungate takes out derm's alone.
#[test]
fn claude_format_list_beside_orcas_entry_and_out_again() {
    let home = scratch("gate-openclaude");
    let pkg = package(
        &home,
        "c/packages/derm-hooks-claude-compat",
        "@aetiusgular/derm-hooks-claude-compat",
    );
    let cfg = home.join(".openclaude/settings.json");
    fs::create_dir_all(cfg.parent().unwrap()).unwrap();
    let before = r#"{
  "model": "x",
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "*",
        "hooks": [
          {
            "type": "command",
            "command": "/Applications/Orca.app/hook.sh"
          }
        ]
      }
    ]
  }
}
"#;
    fs::write(&cfg, before).unwrap();
    let r = go(&home, &["openclaude", "--gate", "--hook", &pkg]);
    assert_eq!(r.code, 0, "{}", r.err);
    assert!(r.out.contains("dry run"), "{}", r.out);
    assert_eq!(read(&cfg), before, "a dry run writes nothing");
    let r = go(&home, &["openclaude", "--gate", "--hook", &pkg, "--write"]);
    assert_eq!(r.code, 0, "{}{}", r.out, r.err);
    let v = parse(&read(&cfg));
    let Some(Value::Array(groups)) = v.get_path(&["hooks", "PreToolUse"]) else {
        panic!()
    };
    assert_eq!(groups.len(), 2);
    assert!(json::compact(&groups[0]).contains("Orca.app"));
    let ours = json::compact(&groups[1]);
    assert!(
        ours.contains(&format!("{pkg}/bin/derm-hook.mjs\\\" openclaude pre")),
        "{ours}"
    );
    assert!(ours.contains("\"timeout\": 120"), "{ours}");
    assert_eq!(v.get("model"), Some(&Value::Str("x".into())));
    let r = go(&home, &["openclaude", "--gate", "--hook", &pkg, "--write"]);
    assert!(r.out.contains("already registered"), "{}", r.out);
    let r = go(&home, &["openclaude", "--ungate", "--write"]);
    assert_eq!(r.code, 0, "{}{}", r.out, r.err);
    assert_eq!(parse(&read(&cfg)), parse(before));
}

/// A hook folder moved since the last --gate: derm's entry is replaced,
/// never doubled.
#[test]
fn a_moved_package_replaces_derms_entry() {
    let home = scratch("gate-move");
    let one = package(
        &home,
        "a/derm-hooks-native",
        "@aetiusgular/derm-hooks-native",
    );
    let two = package(
        &home,
        "b/derm-hooks-native",
        "@aetiusgular/derm-hooks-native",
    );
    fs::create_dir_all(home.join(".config/crush")).unwrap();
    assert_eq!(
        go(&home, &["crush", "--gate", "--hook", &one, "--write"]).code,
        0
    );
    let r = go(&home, &["crush", "--gate", "--hook", &two, "--write"]);
    assert_eq!(r.code, 0, "{}{}", r.out, r.err);
    let v = parse(&read(&home.join(".config/crush/crush.json")));
    let Some(Value::Array(list)) = v.get_path(&["hooks", "PreToolUse"]) else {
        panic!()
    };
    assert_eq!(list.len(), 1);
    assert!(json::compact(&list[0]).contains(&two));
}

/// Cursor: two lists in one new file that starts with `version: 1`, as lane
/// N's `registration/cursor/hooks.json`.
#[test]
fn cursor_gets_both_events_in_a_new_file() {
    let home = scratch("gate-cursor");
    let pkg = package(
        &home,
        "n/derm-hooks-native",
        "@aetiusgular/derm-hooks-native",
    );
    fs::create_dir_all(home.join(".cursor")).unwrap();
    let r = go(&home, &["cursor", "--gate", "--hook", &pkg, "--write"]);
    assert_eq!(r.code, 0, "{}{}", r.out, r.err);
    let v = parse(&read(&home.join(".cursor/hooks.json")));
    assert_eq!(v.get("version"), Some(&Value::Number("1".into())));
    for ev in ["preToolUse", "beforeMCPExecution"] {
        let Some(Value::Array(l)) = v.get_path(&["hooks", ev]) else {
            panic!("{ev}")
        };
        assert_eq!(l.len(), 1, "{ev}");
        assert!(
            json::compact(&l[0]).contains("\"failClosed\": true"),
            "{ev}"
        );
    }
}

/// Antigravity: a named bundle beside others; a `derm` member that is not
/// derm's is refused.
#[test]
fn antigravity_named_bundle_and_a_stranger_under_the_name() {
    let home = scratch("gate-ag");
    let pkg = package(
        &home,
        "n/derm-hooks-native",
        "@aetiusgular/derm-hooks-native",
    );
    let cfg = home.join(".gemini/config/hooks.json");
    fs::create_dir_all(cfg.parent().unwrap()).unwrap();
    fs::write(&cfg, "{\"orca\": {\"enabled\": true}}\n").unwrap();
    let r = go(&home, &["antigravity", "--gate", "--hook", &pkg, "--write"]);
    assert_eq!(r.code, 0, "{}{}", r.out, r.err);
    let v = parse(&read(&cfg));
    assert!(v.get("orca").is_some());
    assert!(json::compact(v.get("derm").unwrap()).contains("derm-hook.mjs"));
    fs::write(
        &cfg,
        "{\"derm\": {\"enabled\": true, \"PreToolUse\": []}}\n",
    )
    .unwrap();
    let r = go(&home, &["antigravity", "--gate", "--hook", &pkg, "--write"]);
    assert_eq!(r.code, 1);
    assert!(r.err.contains("not derm's entry"), "{}", r.err);
}

/// goose: a plugin folder; --ungate never deletes it, it says to.
#[test]
fn goose_plugin_folder_written_and_left_for_you_to_remove() {
    let home = scratch("gate-goose");
    let pkg = package(
        &home,
        "n/derm-hooks-native",
        "@aetiusgular/derm-hooks-native",
    );
    fs::create_dir_all(home.join(".config/goose")).unwrap();
    let r = go(&home, &["goose", "--gate", "--hook", &pkg, "--write"]);
    assert_eq!(r.code, 0, "{}{}", r.out, r.err);
    let dir = home.join(".agents/plugins/derm");
    let plugin = parse(&read(&dir.join("plugin.json")));
    assert_eq!(plugin.get("name"), Some(&Value::Str("derm".into())));
    assert_eq!(
        plugin.get("version"),
        Some(&Value::Str(env!("CARGO_PKG_VERSION").into()))
    );
    assert!(read(&dir.join("hooks/hooks.json")).contains("\"on_failure\": \"block\""));
    let r = go(&home, &["goose", "--ungate", "--write"]);
    assert_eq!(r.code, 0);
    assert!(r.out.contains("remove the folder"), "{}", r.out);
    assert!(dir.join("hooks/hooks.json").exists());
    // A folder of that name that is not derm's is refused.
    let other = scratch("gate-goose2");
    let pkg2 = package(
        &other,
        "n/derm-hooks-native",
        "@aetiusgular/derm-hooks-native",
    );
    fs::create_dir_all(other.join(".agents/plugins/derm")).unwrap();
    fs::write(other.join(".agents/plugins/derm/plugin.json"), "{}").unwrap();
    fs::create_dir_all(other.join(".config/goose")).unwrap();
    let r = go(&other, &["goose", "--gate", "--hook", &pkg2, "--write"]);
    assert_eq!(r.code, 1);
    assert!(r.err.contains("is not derm's"), "{}", r.err);
}

/// Case 55 across files: Grok's gate is two files; one changes while the
/// question is open, and neither is written.
#[test]
fn a_file_that_changes_before_the_write_stops_every_file() {
    let home = scratch("gate-race");
    let pkg = package(
        &home,
        "c/derm-hooks-claude-compat",
        "@aetiusgular/derm-hooks-claude-compat",
    );
    let toml = home.join(".grok/config.toml");
    fs::create_dir_all(toml.parent().unwrap()).unwrap();
    fs::write(&toml, "model = \"grok\"\n").unwrap();
    let t2 = toml.clone();
    let answer = Answer(
        true,
        Some(Box::new(move || {
            fs::write(&t2, "model = \"other\"\n").unwrap()
        })),
    );
    let r = go_with(
        &home,
        &env(&[]),
        answer,
        &["grok", "--gate", "--hook", &pkg, "--write"],
    );
    assert_eq!(r.code, 1, "{}", r.out);
    assert!(r.err.contains("changed since the diff"), "{}", r.err);
    assert!(!home.join(".grok/hooks/derm.json").exists());
    assert_eq!(read(&toml), "model = \"other\"\n");
    // Without the race both are written, the compat switches off.
    fs::write(&toml, "model = \"grok\"\n").unwrap();
    let r = go(&home, &["grok", "--gate", "--hook", &pkg, "--write"]);
    assert_eq!(r.code, 0, "{}{}", r.out, r.err);
    let t = read(&toml);
    assert!(t.contains("[compat.claude]\nhooks = false"), "{t}");
    assert!(t.contains("[compat.cursor]\nhooks = false"), "{t}");
    assert!(read(&home.join(".grok/hooks/derm.json")).contains("\"failClosed\": true"));
}

/// Case 54: nothing for an agent that is not installed.
#[test]
fn an_agent_that_is_not_installed_gets_nothing_written() {
    let home = scratch("gate-absent");
    let pkg = package(
        &home,
        "c/derm-hooks-claude-compat",
        "@aetiusgular/derm-hooks-claude-compat",
    );
    let r = go(
        &home,
        &["command-code", "--gate", "--hook", &pkg, "--write"],
    );
    assert_eq!(r.code, 1, "{}", r.out);
    assert!(r.out.contains("does not look installed"), "{}", r.out);
    assert!(!home.join(".commandcode").exists());
}

/// The hook folder: absolute, no `..`, not a link, the right package, closed
/// to others, with its hook file.
#[test]
fn hook_folder_checks() {
    let home = scratch("gate-hook");
    fs::create_dir_all(home.join(".openclaude")).unwrap();
    let pkg = package(
        &home,
        "c/derm-hooks-claude-compat",
        "@aetiusgular/derm-hooks-claude-compat",
    );
    let bad = |hook: &str, why: &str| {
        let r = go(&home, &["openclaude", "--gate", "--hook", hook]);
        assert_eq!(r.code, 1, "{hook}: {}", r.out);
        assert!(r.err.contains(why), "{hook}: {}", r.err);
    };
    bad("relative/path", "absolute path");
    bad(&format!("{pkg}/../derm-hooks-claude-compat"), "no `..`");
    bad("/tmp/a\"b", "absolute path");
    let link = home.join("link");
    std::os::unix::fs::symlink(&pkg, &link).unwrap();
    bad(&link.display().to_string(), "a link is refused");
    let wrong = package(
        &home,
        "w/derm-hooks-native",
        "@aetiusgular/derm-hooks-native",
    );
    bad(&wrong, "not @aetiusgular/derm-hooks-claude-compat");
    fs::set_permissions(&pkg, fs::Permissions::from_mode(0o775)).unwrap();
    bad(&pkg, "writable by others");
    fs::set_permissions(&pkg, fs::Permissions::from_mode(0o755)).unwrap();
    fs::remove_file(format!("{pkg}/bin/derm-hook.mjs")).unwrap();
    bad(&pkg, "derm-hook.mjs");
    // --gate needs --hook for a writing row; --hook alone is refused.
    let r = go(&home, &["openclaude", "--gate"]);
    assert!(r.err.contains("needs --hook"), "{}", r.err);
    let r = go(&home, &["openclaude", "--hook", "/x"]);
    assert_eq!(r.code, 2);
    let r = go(&home, &["openclaude", "--ungate", "--hook", "/x"]);
    assert_eq!(r.code, 2);
}

/// Droid's hooks.json shadows settings.json: refused while it exists. And a
/// harness folder moved outside the home folder is refused (case 65's
/// neighbour: derm writes under your home only).
#[test]
fn shadowing_files_and_folders_outside_home_are_refused() {
    let home = scratch("gate-droid");
    let pkg = package(
        &home,
        "c/derm-hooks-claude-compat",
        "@aetiusgular/derm-hooks-claude-compat",
    );
    fs::create_dir_all(home.join(".factory")).unwrap();
    fs::write(home.join(".factory/hooks.json"), "{}").unwrap();
    let r = go(&home, &["droid", "--gate", "--hook", &pkg]);
    assert_eq!(r.code, 1);
    assert!(r.err.contains("hooks.json exists"), "{}", r.err);
    let r = go_with(
        &home,
        &env(&[("OPENCLAUDE_CONFIG_DIR", "/etc/openclaude")]),
        Answer(true, None),
        &["openclaude", "--gate", "--hook", &pkg],
    );
    assert_eq!(r.code, 1);
    assert!(r.err.contains("outside your home"), "{}", r.err);
}

/// OpenCode's `plugin` list in a JSONC file: comments elsewhere are kept; a
/// comment inside the list is refused rather than dropped.
#[test]
fn opencode_plugin_list_keeps_comments_and_refuses_one_inside_the_list() {
    let home = scratch("gate-oc");
    let pkg = package(
        &home,
        "clone/packages/derm-opencode-plugin",
        "@aetiusgular/derm-opencode-plugin",
    );
    let cfg = home.join(".config/opencode/opencode.json");
    fs::create_dir_all(cfg.parent().unwrap()).unwrap();
    fs::write(&cfg, "{\n  // mine\n  \"theme\": \"dark\"\n}\n").unwrap();
    let r = go(&home, &["opencode", "--gate", "--hook", &pkg, "--write"]);
    assert_eq!(r.code, 0, "{}{}", r.out, r.err);
    let t = read(&cfg);
    assert!(t.contains("// mine"), "{t}");
    assert!(t.contains(&format!("\"file://{pkg}\"")), "{t}");
    fs::write(
        &cfg,
        "{\n  \"plugin\": [\n    // pinned\n    \"file:///x/other\"\n  ]\n}\n",
    )
    .unwrap();
    let r = go(&home, &["opencode", "--gate", "--hook", &pkg, "--write"]);
    assert_eq!(r.code, 1);
    assert!(r.err.contains("holds comments"), "{}", r.err);
    // A package folder renamed so the entry would not carry the marker.
    let renamed = package(&home, "elsewhere/gate", "@aetiusgular/derm-opencode-plugin");
    fs::write(&cfg, "{}\n").unwrap();
    let r = go(&home, &["opencode", "--gate", "--hook", &renamed]);
    assert_eq!(r.code, 1);
    assert!(r.err.contains("finds its own entry"), "{}", r.err);
}

/// Agents whose gate installs through their own command, and Kimi until its
/// folder is settled: printed, never written.
#[test]
fn print_only_agents_print_and_write_nothing() {
    let home = scratch("gate-print");
    let r = go(&home, &["codex", "--gate"]);
    assert_eq!(r.code, 0, "{}", r.err);
    assert!(
        r.out.contains(&format!(
            "codex plugin marketplace add aetiusgular/derm --ref v{}",
            env!("CARGO_PKG_VERSION")
        )),
        "{}",
        r.out
    );
    let pkg = package(
        &home,
        "c/derm-hooks-claude-compat",
        "@aetiusgular/derm-hooks-claude-compat",
    );
    let r = go(&home, &["kimi", "--gate", "--hook", &pkg, "--write"]);
    assert_eq!(r.code, 1);
    assert!(
        r.out.contains(&format!(
            "command = 'node --no-warnings \"{pkg}/bin/derm-hook.mjs\" kimi pre'"
        )),
        "{}",
        r.out
    );
    assert!(!home.join(".kimi").exists() && !home.join(".kimi-code").exists());
    let r = go(&home, &["no-such-agent", "--gate"]);
    assert!(r.err.contains("no gate registration"), "{}", r.err);
}

/// `--node` pins Node by absolute path.
#[test]
fn node_can_be_pinned() {
    let home = scratch("gate-node");
    let pkg = package(
        &home,
        "n/derm-hooks-native",
        "@aetiusgular/derm-hooks-native",
    );
    fs::create_dir_all(home.join(".kiro")).unwrap();
    let r = go(
        &home,
        &[
            "kiro",
            "--gate",
            "--hook",
            &pkg,
            "--node",
            "/opt/node22/bin/node",
            "--write",
        ],
    );
    assert_eq!(r.code, 0, "{}{}", r.out, r.err);
    let t = read(&home.join(".kiro/hooks/derm.json"));
    assert!(
        t.contains("\"command\": \"/opt/node22/bin/node --no-warnings"),
        "{t}"
    );
    let r = go(&home, &["kiro", "--gate", "--hook", &pkg, "--node", "node"]);
    assert_eq!(r.code, 1);
    // A file of derm's own name that is not derm's is refused.
    fs::write(home.join(".kiro/hooks/derm.json"), "{\"hooks\": []}\n").unwrap();
    let r = go(&home, &["kiro", "--gate", "--hook", &pkg]);
    assert_eq!(r.code, 1);
    assert!(r.err.contains("not derm's"), "{}", r.err);
}

fn opencode_pkg(home: &Path) -> String {
    package(
        home,
        "clone/packages/derm-opencode-plugin",
        "@aetiusgular/derm-opencode-plugin",
    )
}

fn oc(home: &Path, file: &str) -> std::path::PathBuf {
    home.join(".config/opencode").join(file)
}

/// OpenCode 1.19.4 merges `config.json`, `opencode.json` and `opencode.jsonc`
/// in that order with remeda's `mergeDeep`, which replaces arrays
/// (`config.ts:272-274`): a `plugin` list in `opencode.jsonc` replaces the one
/// in `opencode.json`. derm writes the last of them that exists.
#[test]
fn opencode_gate_goes_in_the_file_opencode_reads_last() {
    let home = scratch("gate-oc-last");
    let pkg = opencode_pkg(&home);
    fs::create_dir_all(oc(&home, "")).unwrap();
    fs::write(oc(&home, "opencode.json"), "{}\n").unwrap();
    fs::write(
        oc(&home, "opencode.jsonc"),
        "{\n  \"plugin\": [\"file:///x/other\"]\n}\n",
    )
    .unwrap();
    let r = go(&home, &["opencode", "--gate", "--hook", &pkg, "--write"]);
    assert_eq!(r.code, 0, "{}{}", r.out, r.err);
    let t = read(&oc(&home, "opencode.jsonc"));
    assert!(t.contains("file:///x/other"), "{t}");
    assert!(t.contains(&format!("\"file://{pkg}\"")), "{t}");
    assert!(!read(&oc(&home, "opencode.json")).contains("derm"));
}

/// A list in a file OpenCode reads first would be replaced by a new list in
/// the file derm writes: refused, nothing written. With that file alone, the
/// entry goes beside the list there.
#[test]
fn a_plugin_list_in_a_file_read_earlier_is_never_replaced() {
    let home = scratch("gate-oc-shadow");
    let pkg = opencode_pkg(&home);
    fs::create_dir_all(oc(&home, "")).unwrap();
    let mine = "{\n  \"plugin\": [\"file:///x/other\"]\n}\n";
    fs::write(oc(&home, "config.json"), mine).unwrap();
    fs::write(oc(&home, "opencode.json"), "{\n  \"theme\": \"dark\"\n}\n").unwrap();
    let r = go(&home, &["opencode", "--gate", "--hook", &pkg, "--write"]);
    assert_eq!(r.code, 1, "{}{}", r.out, r.err);
    assert!(r.err.contains("config.json"), "{}", r.err);
    assert!(r.err.contains("replace"), "{}", r.err);
    assert_eq!(read(&oc(&home, "config.json")), mine);
    assert_eq!(
        read(&oc(&home, "opencode.json")),
        "{\n  \"theme\": \"dark\"\n}\n"
    );
    fs::remove_file(oc(&home, "opencode.json")).unwrap();
    let r = go(&home, &["opencode", "--gate", "--hook", &pkg, "--write"]);
    assert_eq!(r.code, 0, "{}{}", r.out, r.err);
    let t = read(&oc(&home, "config.json"));
    assert!(
        t.contains("file:///x/other") && t.contains("derm-opencode-plugin"),
        "{t}"
    );
}

/// Kilo 7.8.18's global folder is `$XDG_CONFIG_HOME/kilo` whatever
/// `KILO_CONFIG_DIR` says (`core/src/global.ts:24`; that variable adds a
/// folder to the project scan, `config.ts:818-836`), and Kilo reads
/// `opencode.jsonc` last of its five files (`config.ts:460-482`).
#[test]
fn kilo_writes_its_global_folder_and_the_file_it_reads_last() {
    let home = scratch("gate-kilo");
    let pkg = package(
        &home,
        "clone/packages/derm-kilo-plugin",
        "@aetiusgular/derm-kilo-plugin",
    );
    let dir = home.join(".config/kilo");
    fs::create_dir_all(&dir).unwrap();
    fs::create_dir_all(home.join("kc")).unwrap();
    let kc = home.join("kc").display().to_string();
    let r = go_with(
        &home,
        &env(&[("KILO_CONFIG_DIR", &kc)]),
        Answer(true, None),
        &["kilo", "--gate", "--hook", &pkg, "--write"],
    );
    assert_eq!(r.code, 0, "{}{}", r.out, r.err);
    assert!(read(&dir.join("kilo.json")).contains("derm-kilo-plugin"));
    assert!(fs::read_dir(home.join("kc")).unwrap().next().is_none());
    fs::write(dir.join("opencode.jsonc"), "{}\n").unwrap();
    let r = go(&home, &["kilo", "--gate", "--hook", &pkg, "--write"]);
    assert_eq!(r.code, 1, "{}{}", r.out, r.err);
    assert!(r.err.contains("kilo.json"), "{}", r.err);
}

fn permission(home: &Path, file: &str) -> Option<Value> {
    parse(&read(&oc(home, file))).get("permission").cloned()
}

fn keys(v: &Value) -> Vec<(String, String)> {
    match v {
        Value::Object(m) => m
            .iter()
            .map(|(k, v)| {
                (
                    k.clone(),
                    match v {
                        Value::Str(s) => s.clone(),
                        other => json::compact(other),
                    },
                )
            })
            .collect(),
        other => vec![("".into(), json::compact(other))],
    }
}

fn pairs(p: &[(&str, &str)]) -> Vec<(String, String)> {
    p.iter()
        .map(|(a, b)| (a.to_string(), b.to_string()))
        .collect()
}

/// The fragment's `permission` keys (OpenCode's own prompts as a second
/// layer). OpenCode 1.19.4 takes the last matching rule (`findLast`,
/// `permission/index.ts:28-32`) and keeps the file's key order
/// (`core/src/v1/config/permission.ts`), so a key added after a deny would
/// win over it: derm adds a key only beside allows and asks, turns an allow
/// into ask in place, and leaves every deny and pattern object.
#[test]
fn opencode_permission_block_only_ever_narrows() {
    let home = scratch("gate-oc-perm");
    let pkg = opencode_pkg(&home);
    fs::create_dir_all(oc(&home, "")).unwrap();
    let gate = |home: &Path| go(home, &["opencode", "--gate", "--hook", &pkg, "--write"]);
    let all_ask = pairs(&[
        ("bash", "ask"),
        ("edit", "ask"),
        ("webfetch", "ask"),
        ("external_directory", "ask"),
    ]);

    // Absent: the four keys.
    fs::write(oc(&home, "opencode.json"), "{}\n").unwrap();
    let r = gate(&home);
    assert_eq!(r.code, 0, "{}{}", r.out, r.err);
    assert_eq!(keys(&permission(&home, "opencode.json").unwrap()), all_ask);

    // A wildcard deny: nothing added after it.
    let deny = "{\n  \"permission\": {\n    \"*\": \"deny\"\n  }\n}\n";
    fs::write(oc(&home, "opencode.json"), deny).unwrap();
    let r = gate(&home);
    assert_eq!(r.code, 0, "{}{}", r.out, r.err);
    assert!(read(&oc(&home, "opencode.json")).contains("\"*\": \"deny\""));
    assert_eq!(
        keys(&permission(&home, "opencode.json").unwrap()),
        pairs(&[("*", "deny")])
    );
    assert!(
        r.out.contains("left:") && r.out.contains("deny"),
        "{}",
        r.out
    );

    // An allow narrowed in place; a pattern object and a matching deny left.
    fs::write(
        oc(&home, "opencode.json"),
        "{\n  \"permission\": {\n    \"bash\": \"allow\",\n    // mine\n    \"edit\": {\"*.md\": \"allow\", \"*\": \"deny\"},\n    \"web*\": \"deny\"\n  }\n}\n",
    )
    .unwrap();
    let r = gate(&home);
    assert_eq!(r.code, 0, "{}{}", r.out, r.err);
    let t = read(&oc(&home, "opencode.json"));
    assert!(t.contains("// mine"), "{t}");
    assert_eq!(
        keys(&permission(&home, "opencode.json").unwrap()),
        pairs(&[
            ("bash", "ask"),
            ("edit", "{\"*.md\": \"allow\", \"*\": \"deny\"}"),
            ("web*", "deny"),
            ("external_directory", "ask"),
        ])
    );

    // A whole-config action: allow keeps its meaning under `*`; deny stays.
    fs::write(oc(&home, "opencode.json"), "{\"permission\": \"allow\"}\n").unwrap();
    let r = gate(&home);
    assert_eq!(r.code, 0, "{}{}", r.out, r.err);
    let mut want = pairs(&[("*", "allow")]);
    want.extend(all_ask.clone());
    assert_eq!(keys(&permission(&home, "opencode.json").unwrap()), want);
    fs::write(oc(&home, "opencode.json"), "{\"permission\": \"deny\"}\n").unwrap();
    let r = gate(&home);
    assert_eq!(r.code, 0, "{}{}", r.out, r.err);
    assert_eq!(
        permission(&home, "opencode.json"),
        Some(Value::Str("deny".into()))
    );
}

/// A legacy `tools` switch set to false becomes a deny that any `permission`
/// key of the same name overrides (`config.ts:567-578`): derm adds none for
/// it. A `permission` block in another global file is merged key by key
/// (mergeDeep), so derm leaves the block alone and still writes the gate.
#[test]
fn opencode_permission_respects_tools_and_other_files() {
    let home = scratch("gate-oc-tools");
    let pkg = opencode_pkg(&home);
    fs::create_dir_all(oc(&home, "")).unwrap();
    fs::write(
        oc(&home, "config.json"),
        "{\"tools\": {\"bash\": false, \"write\": false}}\n",
    )
    .unwrap();
    fs::write(oc(&home, "opencode.json"), "{}\n").unwrap();
    let r = go(&home, &["opencode", "--gate", "--hook", &pkg, "--write"]);
    assert_eq!(r.code, 0, "{}{}", r.out, r.err);
    assert_eq!(
        keys(&permission(&home, "opencode.json").unwrap()),
        pairs(&[("webfetch", "ask"), ("external_directory", "ask")])
    );
    assert!(r.out.contains("tools"), "{}", r.out);

    fs::write(
        oc(&home, "config.json"),
        "{\"permission\": {\"*\": \"deny\"}}\n",
    )
    .unwrap();
    fs::write(oc(&home, "opencode.json"), "{}\n").unwrap();
    let r = go(&home, &["opencode", "--gate", "--hook", &pkg, "--write"]);
    assert_eq!(r.code, 0, "{}{}", r.out, r.err);
    assert_eq!(permission(&home, "opencode.json"), None);
    assert!(read(&oc(&home, "opencode.json")).contains("derm-opencode-plugin"));
    assert!(r.out.contains("config.json"), "{}", r.out);

    // --ungate takes the plugin entry out and leaves the block, saying so.
    fs::write(oc(&home, "config.json"), "{}\n").unwrap();
    fs::write(oc(&home, "opencode.json"), "{}\n").unwrap();
    go(&home, &["opencode", "--gate", "--hook", &pkg, "--write"]);
    let r = go(&home, &["opencode", "--ungate", "--write"]);
    assert_eq!(r.code, 0, "{}{}", r.out, r.err);
    assert!(!read(&oc(&home, "opencode.json")).contains("derm-opencode-plugin"));
    assert!(permission(&home, "opencode.json").is_some());
    assert!(r.out.contains("permission"), "{}", r.out);
}

#[test]
fn opencode_wildcard_matches_as_opencode_does() {
    use super::gate::wildcard;
    assert!(wildcard("bash", "*"));
    assert!(wildcard("bash", "b?sh"));
    assert!(wildcard("webfetch", "web*"));
    assert!(!wildcard("webfetch", "web"));
    assert!(!wildcard("bash", "Bash"));
    assert!(wildcard("ls", "ls *"));
    assert!(wildcard("ls -la", "ls *"));
    assert!(!wildcard("lsof", "ls *"));
    assert!(wildcard("a.b", "a.b"));
    assert!(!wildcard("axb", "a.b"));
    assert!(wildcard("a\\b", "a/b"));
}

/// Mac test w4, MW4-7: `--gate --hook <folder>` for Claude Code and Codex
/// printed the GitHub lines (Codex's pinned to the release's tag), so a tester
/// following them installed the release, not the folder named. With a folder,
/// the lines name the marketplace above it that lists that folder.
#[test]
fn plugin_agents_print_the_marketplace_of_the_folder_given() {
    let home = scratch("gate-folder");
    let clone = home.join("clone");
    let claude = package(
        &home,
        "clone/packages/derm-claude-plugin",
        "@aetiusgular/derm-claude-plugin",
    );
    let codex = package(
        &home,
        "clone/packages/derm-codex-plugin",
        "@aetiusgular/derm-codex-plugin",
    );
    // No marketplace file above the folder yet: said, and the release lines.
    let r = go(&home, &["claude-code", "--gate", "--hook", &claude]);
    assert_eq!(r.code, 0, "{}", r.err);
    assert!(
        r.out.contains("no .claude-plugin/marketplace.json above"),
        "{}",
        r.out
    );
    fs::create_dir_all(clone.join(".claude-plugin")).unwrap();
    fs::write(
        clone.join(".claude-plugin/marketplace.json"),
        r#"{"name":"derm","plugins":[{"name":"derm","source":"./packages/derm-claude-plugin"}]}"#,
    )
    .unwrap();
    fs::create_dir_all(clone.join(".agents/plugins")).unwrap();
    fs::write(
        clone.join(".agents/plugins/marketplace.json"),
        r#"{"name":"derm","plugins":[{"name":"derm","source":{"source":"local","path":"./packages/derm-codex-plugin"}}]}"#,
    )
    .unwrap();
    let r = go(&home, &["claude-code", "--gate", "--hook", &claude]);
    assert_eq!(r.code, 0, "{}", r.err);
    assert!(
        r.out.contains(&format!(
            "claude plugin marketplace add \"{}\"",
            clone.display()
        )),
        "{}",
        r.out
    );
    assert!(!r.out.contains("aetiusgular/derm\n"), "{}", r.out);
    let r = go(&home, &["codex", "--gate", "--hook", &codex]);
    assert_eq!(r.code, 0, "{}", r.err);
    assert!(
        r.out.contains(&format!(
            "codex plugin marketplace add \"{}\"",
            clone.display()
        )),
        "{}",
        r.out
    );
    assert!(!r.out.contains("--ref"), "{}", r.out);
    // A marketplace above that does not list this folder is not it.
    fs::write(
        clone.join(".claude-plugin/marketplace.json"),
        r#"{"name":"derm","plugins":[{"name":"derm","source":"./elsewhere"}]}"#,
    )
    .unwrap();
    let r = go(&home, &["claude-code", "--gate", "--hook", &claude]);
    assert!(
        r.out.contains("no .claude-plugin/marketplace.json above"),
        "{}",
        r.out
    );
    // Without --hook, the release lines, as before.
    let r = go(&home, &["claude-code", "--gate"]);
    assert!(
        r.out
            .contains("claude plugin marketplace add aetiusgular/derm"),
        "{}",
        r.out
    );
}
