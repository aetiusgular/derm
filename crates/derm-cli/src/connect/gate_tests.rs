//! Tests for `derm connect <agent> --gate` and `--ungate` (`gate.rs`): each
//! writer shape against the entries lanes L and N published, the cases of
//! rules section 4 it touches (54, 55, 65, 70, 75, 78), and the checks on
//! the hook folder.

use std::collections::HashMap;
use std::fs;
#[cfg(unix)]
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

#[cfg(unix)]
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

#[cfg(unix)]
/// Makes `path` the derm a registration names (`gate::TEST_SELF`).
fn set_self(path: &Path) {
    gate::TEST_SELF.with(|t| *t.borrow_mut() = Some(path.to_path_buf()));
}

#[cfg(unix)]
/// A derm in `<home>/<sub>/derm`, closed to others, made the derm this
/// test registers; its real path back.
fn fake_derm_in(home: &Path, sub: &str) -> String {
    let dir = home.join(sub);
    fs::create_dir_all(&dir).unwrap();
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o755)).unwrap();
    let f = dir.join("derm");
    fs::write(&f, "#!/bin/sh\nexit 2\n").unwrap();
    fs::set_permissions(&f, fs::Permissions::from_mode(0o755)).unwrap();
    set_self(&f);
    fs::canonicalize(&f).unwrap().display().to_string()
}

#[cfg(unix)]
fn fake_derm(home: &Path) -> String {
    fake_derm_in(home, "bin")
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
        command: None,
        hook_dir: Some("/h/derm/packages/derm-opencode-plugin".into()),
        version: "0.1.3".into(),
    };
    for a in &rows {
        let writes = a.steps.iter().any(|s| !matches!(s, Step::Commands { .. }));
        if !writes {
            continue;
        }
        assert!(!a.markers.is_empty(), "{}: no marker", a.agent);
        assert!(
            !a.installed_if.is_empty() || a.cli.is_some(),
            "{}: nothing tells whether it is installed",
            a.agent
        );
        let mut vars = vars.clone();
        if let Some(t) = &a.command {
            // Wave 5b lane 5bF: every command-hook row runs `derm hook`
            // by derm's own path, with no hook file and no node.
            assert!(t.starts_with("{derm} hook "), "{}: {t}", a.agent);
            assert!(a.hook_file.is_none(), "{}", a.agent);
            assert!(!t.contains("node") && !t.contains("{hook_file}"), "{t}");
            vars.command = Some(t.replace("{derm}", "/opt/x/derm"));
        }
        if a.agent == "kilo" {
            vars.hook_dir = Some("/h/derm/packages/derm-kilo-plugin".into());
        }
        for st in &a.steps {
            let v = match st {
                Step::JsonArrayEntry { entry, .. } | Step::JsonMember { entry, .. } => entry,
                Step::OwnedFile { content, .. } => content,
                _ => continue,
            };
            let filled = gate::fill(v, &vars).unwrap();
            assert!(
                json::compact(&filled).contains(a.markers[0].as_str()),
                "{}: its entry does not hold its first marker",
                a.agent
            );
        }
    }
}

#[cfg(unix)]
/// Lane N's `registration/mistral-vibe/hooks.toml` (85592cf), with the
/// command now `derm hook` by derm's path: derm writes exactly that table
/// beside the user's own.
#[test]
fn vibe_gets_lane_ns_table_beside_its_own_and_once() {
    let home = scratch("gate-vibe");
    let derm = fake_derm(&home);
    let cfg = home.join(".vibe/hooks.toml");
    fs::create_dir_all(cfg.parent().unwrap()).unwrap();
    let mine = "# my hooks\n[[hooks]]\nname = \"lint\"\ntype = \"post_tool\"\ncommand = \"lint\"\n";
    fs::write(&cfg, mine).unwrap();
    let r = go(&home, &["mistral-vibe", "--gate", "--write"]);
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
        format!("{derm} hook mistral-vibe pre")
    );
    assert_eq!(ours["timeout"].as_float(), Some(120.0));
    assert_eq!(ours["strict"].as_bool(), Some(true));
    let r = go(&home, &["mistral-vibe", "--gate"]);
    assert!(r.out.contains("already registered"), "{}", r.out);
    let r = go(&home, &["mistral-vibe", "--ungate", "--write"]);
    assert_eq!(r.code, 0, "{}{}", r.out, r.err);
    assert_eq!(read(&cfg).trim_end(), mine.trim_end());
}

#[cfg(unix)]
/// Case 75: the gate goes beside Orca's own entry in a Claude-format list,
/// a second run adds nothing, and --ungate takes out derm's alone.
#[test]
fn claude_format_list_beside_orcas_entry_and_out_again() {
    let home = scratch("gate-openclaude");
    let derm = fake_derm(&home);
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
    let r = go(&home, &["openclaude", "--gate"]);
    assert_eq!(r.code, 0, "{}", r.err);
    assert!(r.out.contains("dry run"), "{}", r.out);
    assert!(
        r.out.contains(&format!("gate:   {derm} hook openclaude")),
        "{}",
        r.out
    );
    assert_eq!(read(&cfg), before, "a dry run writes nothing");
    let r = go(&home, &["openclaude", "--gate", "--write"]);
    assert_eq!(r.code, 0, "{}{}", r.out, r.err);
    let v = parse(&read(&cfg));
    let Some(Value::Array(groups)) = v.get_path(&["hooks", "PreToolUse"]) else {
        panic!()
    };
    assert_eq!(groups.len(), 2);
    assert!(json::compact(&groups[0]).contains("Orca.app"));
    let ours = json::compact(&groups[1]);
    assert!(
        ours.contains(&format!("\"command\": \"{derm} hook openclaude pre\"")),
        "{ours}"
    );
    assert!(ours.contains("\"timeout\": 120"), "{ours}");
    assert_eq!(v.get("model"), Some(&Value::Str("x".into())));
    let r = go(&home, &["openclaude", "--gate", "--write"]);
    assert!(r.out.contains("already registered"), "{}", r.out);
    let r = go(&home, &["openclaude", "--ungate", "--write"]);
    assert_eq!(r.code, 0, "{}{}", r.out, r.err);
    assert_eq!(parse(&read(&cfg)), parse(before));
}

#[cfg(unix)]
/// derm moved since the last --gate: derm's entry is replaced, never
/// doubled. And a wave 4 entry (`node ... derm-hook.mjs`) is replaced by
/// `derm hook`, never left beside it to run a node from PATH (case 227).
#[test]
fn a_moved_derm_or_a_wave_4_node_entry_is_replaced() {
    let home = scratch("gate-move");
    let cfg = home.join(".config/crush/crush.json");
    fs::create_dir_all(cfg.parent().unwrap()).unwrap();
    fs::write(
        &cfg,
        "{\"hooks\": {\"PreToolUse\": [{\"name\": \"derm-gate\", \"command\": \"node --no-warnings \\\"/old/derm-hooks-native/bin/derm-hook.mjs\\\" crush\", \"timeout\": 120}, {\"name\": \"mine\", \"command\": \"lint\"}]}}\n",
    )
    .unwrap();
    let one = fake_derm_in(&home, "a");
    let r = go(&home, &["crush", "--gate", "--write"]);
    assert_eq!(r.code, 0, "{}{}", r.out, r.err);
    let two = fake_derm_in(&home, "b");
    assert_ne!(one, two);
    let r = go(&home, &["crush", "--gate", "--write"]);
    assert_eq!(r.code, 0, "{}{}", r.out, r.err);
    let v = parse(&read(&cfg));
    let Some(Value::Array(list)) = v.get_path(&["hooks", "PreToolUse"]) else {
        panic!()
    };
    assert_eq!(list.len(), 2, "{list:?}");
    let all = json::compact(&v);
    assert!(all.contains(&format!("{two} hook crush pre")), "{all}");
    assert!(
        !all.contains(&one) && !all.contains("derm-hook.mjs"),
        "{all}"
    );
    // derm's entry kept the place the old one had; the user's stays second.
    assert!(json::compact(&list[1]).contains("\"mine\""));
}

#[cfg(unix)]
/// Cursor: two lists in one new file that starts with `version: 1`, as lane
/// N's `registration/cursor/hooks.json`, each running `derm hook cursor pre`
/// (the dialect reads which event from the input).
#[test]
fn cursor_gets_both_events_in_a_new_file() {
    let home = scratch("gate-cursor");
    let derm = fake_derm(&home);
    fs::create_dir_all(home.join(".cursor")).unwrap();
    let r = go(&home, &["cursor", "--gate", "--write"]);
    assert_eq!(r.code, 0, "{}{}", r.out, r.err);
    let v = parse(&read(&home.join(".cursor/hooks.json")));
    assert_eq!(v.get("version"), Some(&Value::Number("1".into())));
    for ev in ["preToolUse", "beforeMCPExecution"] {
        let Some(Value::Array(l)) = v.get_path(&["hooks", ev]) else {
            panic!("{ev}")
        };
        assert_eq!(l.len(), 1, "{ev}");
        let e = json::compact(&l[0]);
        assert!(e.contains("\"failClosed\": true"), "{ev}");
        assert!(
            e.contains(&format!("\"command\": \"{derm} hook cursor pre\"")),
            "{e}"
        );
    }
}

#[cfg(unix)]
/// Antigravity: a named bundle beside others; a `derm` member that is not
/// derm's is refused.
#[test]
fn antigravity_named_bundle_and_a_stranger_under_the_name() {
    let home = scratch("gate-ag");
    let derm = fake_derm(&home);
    let cfg = home.join(".gemini/config/hooks.json");
    fs::create_dir_all(cfg.parent().unwrap()).unwrap();
    fs::write(&cfg, "{\"orca\": {\"enabled\": true}}\n").unwrap();
    let r = go(&home, &["antigravity", "--gate", "--write"]);
    assert_eq!(r.code, 0, "{}{}", r.out, r.err);
    let v = parse(&read(&cfg));
    assert!(v.get("orca").is_some());
    assert!(json::compact(v.get("derm").unwrap()).contains(&format!("{derm} hook antigravity pre")));
    fs::write(
        &cfg,
        "{\"derm\": {\"enabled\": true, \"PreToolUse\": []}}\n",
    )
    .unwrap();
    let r = go(&home, &["antigravity", "--gate", "--write"]);
    assert_eq!(r.code, 1);
    assert!(r.err.contains("not derm's entry"), "{}", r.err);
}

#[cfg(unix)]
/// goose: a plugin folder; --ungate never deletes it, it says to.
#[test]
fn goose_plugin_folder_written_and_left_for_you_to_remove() {
    let home = scratch("gate-goose");
    let derm = fake_derm(&home);
    fs::create_dir_all(home.join(".config/goose")).unwrap();
    let r = go(&home, &["goose", "--gate", "--write"]);
    assert_eq!(r.code, 0, "{}{}", r.out, r.err);
    let dir = home.join(".agents/plugins/derm");
    let plugin = parse(&read(&dir.join("plugin.json")));
    assert_eq!(plugin.get("name"), Some(&Value::Str("derm".into())));
    assert_eq!(
        plugin.get("version"),
        Some(&Value::Str(env!("CARGO_PKG_VERSION").into()))
    );
    let hooks = read(&dir.join("hooks/hooks.json"));
    assert!(hooks.contains("\"on_failure\": \"block\""), "{hooks}");
    assert!(hooks.contains(&format!("{derm} hook goose pre")), "{hooks}");
    let r = go(&home, &["goose", "--ungate", "--write"]);
    assert_eq!(r.code, 0);
    assert!(r.out.contains("remove the folder"), "{}", r.out);
    assert!(dir.join("hooks/hooks.json").exists());
    // A folder of that name that is not derm's is refused.
    let other = scratch("gate-goose2");
    fake_derm(&other);
    fs::create_dir_all(other.join(".agents/plugins/derm")).unwrap();
    fs::write(other.join(".agents/plugins/derm/plugin.json"), "{}").unwrap();
    fs::create_dir_all(other.join(".config/goose")).unwrap();
    let r = go(&other, &["goose", "--gate", "--write"]);
    assert_eq!(r.code, 1);
    assert!(r.err.contains("is not derm's"), "{}", r.err);
}

#[cfg(unix)]
/// Case 55 across files: Grok's gate is two files; one changes while the
/// question is open, and neither is written.
#[test]
fn a_file_that_changes_before_the_write_stops_every_file() {
    let home = scratch("gate-race");
    fake_derm(&home);
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
    let r = go_with(&home, &env(&[]), answer, &["grok", "--gate", "--write"]);
    assert_eq!(r.code, 1, "{}", r.out);
    assert!(r.err.contains("changed since the diff"), "{}", r.err);
    assert!(!home.join(".grok/hooks/derm.json").exists());
    assert_eq!(read(&toml), "model = \"other\"\n");
    // Without the race both are written, the compat switches off.
    fs::write(&toml, "model = \"grok\"\n").unwrap();
    let r = go(&home, &["grok", "--gate", "--write"]);
    assert_eq!(r.code, 0, "{}{}", r.out, r.err);
    let t = read(&toml);
    assert!(t.contains("[compat.claude]\nhooks = false"), "{t}");
    assert!(t.contains("[compat.cursor]\nhooks = false"), "{t}");
    assert!(read(&home.join(".grok/hooks/derm.json")).contains("\"failClosed\": true"));
}

#[cfg(unix)]
/// Case 54: nothing for an agent that is not installed.
#[test]
fn an_agent_that_is_not_installed_gets_nothing_written() {
    let home = scratch("gate-absent");
    fake_derm(&home);
    let r = go(&home, &["command-code", "--gate", "--write"]);
    assert_eq!(r.code, 1, "{}", r.out);
    assert!(r.out.contains("does not look installed"), "{}", r.out);
    assert!(!home.join(".commandcode").exists());
}

#[cfg(unix)]
/// Case 227: the derm a registration names. Its real path, links followed;
/// refused when a hook line would have to quote it, when someone else may
/// write it or its folder, or when it is not named `derm` (the markers that
/// find derm's entry again end in `/derm hook <agent> `).
#[test]
fn the_derm_a_registration_names_is_checked() {
    let home = scratch("gate-self");
    fs::create_dir_all(home.join(".openclaude")).unwrap();
    let derm = fake_derm(&home);
    // A link to derm is registered by the real path it leads to.
    let link_dir = home.join("links");
    fs::create_dir_all(&link_dir).unwrap();
    fs::set_permissions(&link_dir, fs::Permissions::from_mode(0o755)).unwrap();
    std::os::unix::fs::symlink(&derm, link_dir.join("derm")).unwrap();
    set_self(&link_dir.join("derm"));
    let r = go(&home, &["openclaude", "--gate"]);
    assert_eq!(r.code, 0, "{}{}", r.out, r.err);
    assert!(
        r.out.contains(&format!("{derm} hook openclaude pre")),
        "{}",
        r.out
    );
    let bad = |path: &Path, why: &str| {
        set_self(path);
        let r = go(&home, &["openclaude", "--gate"]);
        assert_eq!(r.code, 1, "{}: {}", path.display(), r.out);
        assert!(r.err.contains(why), "{}: {}", path.display(), r.err);
    };
    // A space: a hook line would have to quote it.
    let spaced = home.join("my tools");
    fs::create_dir_all(&spaced).unwrap();
    fs::set_permissions(&spaced, fs::Permissions::from_mode(0o755)).unwrap();
    fs::copy(&derm, spaced.join("derm")).unwrap();
    bad(&spaced.join("derm"), "would have to quote");
    // Writable by others, or in a folder others may write.
    let open = fake_derm_in(&home, "open");
    fs::set_permissions(&open, fs::Permissions::from_mode(0o777)).unwrap();
    bad(Path::new(&open), "writable by others");
    let open_dir = fake_derm_in(&home, "opendir");
    fs::set_permissions(
        Path::new(&open_dir).parent().unwrap(),
        fs::Permissions::from_mode(0o777),
    )
    .unwrap();
    bad(Path::new(&open_dir), "could be replaced");
    // Not named derm.
    let named = Path::new(&derm).with_file_name("derm-0.1.3");
    fs::copy(&derm, &named).unwrap();
    bad(&named, "named derm");
    // Not there.
    bad(&home.join("nowhere/derm"), "cannot read derm's own path");
}

#[cfg(unix)]
/// `--hook` is not used for a `derm hook` row: it says so and checks
/// nothing in it, so an old script still runs. In-process rows still need
/// it, and a bad one is still refused.
#[test]
fn hook_folder_is_ignored_for_derm_hook_rows_and_checked_for_the_others() {
    let home = scratch("gate-hook");
    fs::create_dir_all(home.join(".openclaude")).unwrap();
    fake_derm(&home);
    let r = go(
        &home,
        &["openclaude", "--gate", "--hook", "/nowhere/at/all"],
    );
    assert_eq!(r.code, 0, "{}{}", r.out, r.err);
    assert!(
        r.out.contains("--hook is not used for OpenClaude"),
        "{}",
        r.out
    );
    let pkg = package(
        &home,
        "c/derm-opencode-plugin",
        "@aetiusgular/derm-opencode-plugin",
    );
    let bad = |hook: &str, why: &str| {
        let r = go(&home, &["opencode", "--gate", "--hook", hook]);
        assert_eq!(r.code, 1, "{hook}: {}", r.out);
        assert!(r.err.contains(why), "{hook}: {}", r.err);
    };
    bad("relative/path", "absolute path");
    bad(&format!("{pkg}/../derm-opencode-plugin"), "no `..`");
    bad("/tmp/a\"b", "absolute path");
    let link = home.join("link");
    std::os::unix::fs::symlink(&pkg, &link).unwrap();
    bad(&link.display().to_string(), "a link is refused");
    let wrong = package(
        &home,
        "w/derm-hooks-native",
        "@aetiusgular/derm-hooks-native",
    );
    bad(&wrong, "not @aetiusgular/derm-opencode-plugin");
    fs::set_permissions(&pkg, fs::Permissions::from_mode(0o775)).unwrap();
    bad(&pkg, "writable by others");
    fs::set_permissions(&pkg, fs::Permissions::from_mode(0o755)).unwrap();
    // --gate needs --hook for an in-process row; --hook alone is refused.
    let r = go(&home, &["opencode", "--gate"]);
    assert!(r.err.contains("needs --hook"), "{}", r.err);
    let r = go(&home, &["openclaude", "--hook", "/x"]);
    assert_eq!(r.code, 2);
    let r = go(&home, &["openclaude", "--ungate", "--hook", "/x"]);
    assert_eq!(r.code, 2);
}

#[cfg(unix)]
/// Droid's hooks.json shadows settings.json: refused while it exists. And a
/// harness folder moved outside the home folder is refused (case 65's
/// neighbour: derm writes under your home only).
#[test]
fn shadowing_files_and_folders_outside_home_are_refused() {
    let home = scratch("gate-droid");
    fake_derm(&home);
    fs::create_dir_all(home.join(".factory")).unwrap();
    fs::write(home.join(".factory/hooks.json"), "{}").unwrap();
    let r = go(&home, &["droid", "--gate"]);
    assert_eq!(r.code, 1);
    assert!(r.err.contains("hooks.json exists"), "{}", r.err);
    let r = go_with(
        &home,
        &env(&[("OPENCLAUDE_CONFIG_DIR", "/etc/openclaude")]),
        Answer(true, None),
        &["openclaude", "--gate"],
    );
    assert_eq!(r.code, 1);
    assert!(r.err.contains("outside your home"), "{}", r.err);
}

#[cfg(unix)]
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

#[cfg(unix)]
/// Agents whose gate installs through their own command, and Kimi until its
/// folder is settled: printed, never written. Kimi's lines name `derm hook`
/// by derm's path.
#[test]
fn print_only_agents_print_and_write_nothing() {
    let home = scratch("gate-print");
    let derm = fake_derm(&home);
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
    let r = go(&home, &["kimi", "--gate", "--write"]);
    assert_eq!(r.code, 1);
    assert!(
        r.out.contains(&format!("command = '{derm} hook kimi pre'")),
        "{}",
        r.out
    );
    assert!(!home.join(".kimi").exists() && !home.join(".kimi-code").exists());
    let r = go(&home, &["no-such-agent", "--gate"]);
    assert!(r.err.contains("no gate registration"), "{}", r.err);
}

#[cfg(unix)]
/// `--node` is still checked (it fills the print-only lines that run a
/// node script, Gemini's policy writer), and changes nothing in a `derm
/// hook` row. A file of derm's own name that is not derm's is refused.
#[test]
fn node_is_checked_and_not_in_a_derm_hook_row() {
    let home = scratch("gate-node");
    let derm = fake_derm(&home);
    fs::create_dir_all(home.join(".kiro")).unwrap();
    let r = go(
        &home,
        &[
            "kiro",
            "--gate",
            "--node",
            "/opt/node22/bin/node",
            "--write",
        ],
    );
    assert_eq!(r.code, 0, "{}{}", r.out, r.err);
    let t = read(&home.join(".kiro/hooks/derm.json"));
    assert!(
        t.contains(&format!("\"command\": \"{derm} hook kiro pre\"")),
        "{t}"
    );
    assert!(!t.contains("--no-warnings"), "{t}");
    let r = go(&home, &["kiro", "--gate", "--node", "node"]);
    assert_eq!(r.code, 1);
    fs::write(home.join(".kiro/hooks/derm.json"), "{\"hooks\": []}\n").unwrap();
    let r = go(&home, &["kiro", "--gate"]);
    assert_eq!(r.code, 1);
    assert!(r.err.contains("not derm's"), "{}", r.err);
}

#[cfg(unix)]
/// Hermes (lane 5bB's plugin; case 227): the printed lines copy and enable
/// the plugin, and the write puts derm's absolute path in `derm-path` beside
/// `derm_gate.py`, which the plugin runs as `derm hook hermes <event>`.
/// Only into a plugin folder that exists, never over a file that is not
/// derm's, and `--ungate` leaves it for you to remove.
#[test]
fn hermes_gets_derm_path_beside_its_plugin() {
    let home = scratch("gate-hermes");
    let derm = fake_derm(&home);
    fs::create_dir_all(home.join(".hermes")).unwrap();
    // Not installed yet: the lines, and nothing written.
    let r = go(&home, &["hermes", "--gate", "--write"]);
    assert_eq!(r.code, 1, "{}{}", r.out, r.err);
    assert!(r.out.contains("hermes plugins enable derm"), "{}", r.out);
    assert!(r.out.contains("first, run these yourself"), "{}", r.out);
    let dir = home.join(".hermes/plugins/derm");
    assert!(!dir.exists());
    fs::create_dir_all(&dir).unwrap();
    let r = go(&home, &["hermes", "--gate"]);
    assert_eq!(r.code, 0, "{}{}", r.out, r.err);
    assert!(r.out.contains("dry run"), "{}", r.out);
    assert!(!dir.join("derm-path").exists());
    let r = go(&home, &["hermes", "--gate", "--write"]);
    assert_eq!(r.code, 0, "{}{}", r.out, r.err);
    let file = dir.join("derm-path");
    assert_eq!(read(&file), format!("{derm}\n"));
    let mode = fs::metadata(&file).unwrap().permissions().mode() & 0o777;
    assert_eq!(
        mode & 0o022,
        0,
        "derm_gate.py refuses a derm-path others may write: {mode:o}"
    );
    let r = go(&home, &["hermes", "--gate", "--write"]);
    assert!(r.out.contains("already registered"), "{}", r.out);
    let r = go(&home, &["hermes", "--ungate", "--write"]);
    assert_eq!(r.code, 0, "{}{}", r.out, r.err);
    assert!(r.out.contains("remove") && file.exists(), "{}", r.out);
    // A derm-path that is not derm's is never replaced.
    fs::write(&file, "#!/bin/sh\nexit 0\n").unwrap();
    let r = go(&home, &["hermes", "--gate", "--write"]);
    assert_eq!(r.code, 1, "{}", r.out);
    assert!(r.err.contains("not derm's"), "{}", r.err);
}

#[cfg(unix)]
/// The in-process plugins and the plugins' launcher find derm in its
/// install folders (lane 5bC's `installCandidates`, `derm-gate.sh`): the
/// output says which one answers, or that none does.
#[test]
fn route_says_where_a_plugin_finds_derm() {
    let home = scratch("gate-route");
    fake_derm(&home);
    let r = go(&home, &["pi", "--gate"]);
    assert_eq!(r.code, 0, "{}{}", r.out, r.err);
    assert!(r.out.contains("this derm is in none of them"), "{}", r.out);
    let bin = home.join(".local/bin");
    fs::create_dir_all(&bin).unwrap();
    fs::set_permissions(&bin, fs::Permissions::from_mode(0o755)).unwrap();
    let derm = fake_derm(&home);
    std::os::unix::fs::symlink(&derm, bin.join("derm")).unwrap();
    let r = go(&home, &["claude-code", "--gate"]);
    assert!(
        r.out
            .contains(&format!("runs derm from {}", bin.join("derm").display())),
        "{}",
        r.out
    );
}

#[cfg(unix)]
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

#[cfg(unix)]
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

#[cfg(unix)]
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

#[cfg(unix)]
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

#[cfg(unix)]
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

#[cfg(unix)]
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

#[cfg(unix)]
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
    // Fix pass 1's review, FP4-S5: the folder named only in a description,
    // a marketplace not named derm, or a file others can write is not it.
    for text in [
        r#"{"name":"derm","description":"see ./packages/derm-claude-plugin","plugins":[{"name":"derm","source":"./elsewhere"}]}"#,
        r#"{"name":"other","plugins":[{"name":"derm","source":"./packages/derm-claude-plugin"}]}"#,
        r#"{"name":"derm","plugins":[{"name":"evil","source":"./packages/derm-claude-plugin"}]}"#,
        // Re-review FP5-R7: two plugins named derm, one of them elsewhere.
        r#"{"name":"derm","plugins":[{"name":"derm","source":"./packages/derm-claude-plugin"},{"name":"derm","source":"./elsewhere"}]}"#,
    ] {
        fs::write(clone.join(".claude-plugin/marketplace.json"), text).unwrap();
        let r = go(&home, &["claude-code", "--gate", "--hook", &claude]);
        assert!(
            r.out.contains("no .claude-plugin/marketplace.json above"),
            "{text}: {}",
            r.out
        );
    }
    fs::write(
        clone.join(".claude-plugin/marketplace.json"),
        r#"{"name":"derm","plugins":[{"name":"derm","source":"./packages/derm-claude-plugin"}]}"#,
    )
    .unwrap();
    fs::set_permissions(
        clone.join(".claude-plugin/marketplace.json"),
        fs::Permissions::from_mode(0o666),
    )
    .unwrap();
    let r = go(&home, &["claude-code", "--gate", "--hook", &claude]);
    assert!(
        r.out.contains("no .claude-plugin/marketplace.json above"),
        "a marketplace others can write: {}",
        r.out
    );
    fs::set_permissions(
        clone.join(".claude-plugin/marketplace.json"),
        fs::Permissions::from_mode(0o644),
    )
    .unwrap();
    let r = go(&home, &["claude-code", "--gate", "--hook", &claude]);
    assert!(
        r.out.contains(&format!(
            "claude plugin marketplace add \"{}\"",
            clone.display()
        )),
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

// ---- Wave 5b lane 5bF: the plugins' launcher and hooks files ----
//
// Ports of `contracts/fixtures/hook-cases/manual.json`'s lane 5bF cases that
// test plugin files and launchers (`contracts/hook-dialects.md` 9.4); the
// status doc maps each TypeScript case to the test here that holds it.

#[cfg(unix)]
fn repo() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

#[cfg(unix)]
const PLUGINS: [&str; 3] = [
    "packages/derm-claude-plugin",
    "packages/derm-codex-plugin",
    "packages/derm-gemini-extension",
];

#[cfg(unix)]
fn plugin_hooks(pkg: &str) -> serde_json::Value {
    serde_json::from_str(&read(&repo().join(pkg).join("hooks/hooks.json"))).unwrap()
}

#[cfg(unix)]
/// One launcher, three copies: a fix in one is a fix in all.
#[test]
fn the_three_plugins_carry_one_launcher() {
    let one = read(&repo().join(PLUGINS[0]).join("hooks/derm-gate.sh"));
    for p in &PLUGINS[1..] {
        assert_eq!(read(&repo().join(p).join("hooks/derm-gate.sh")), one, "{p}");
    }
    assert!(one.starts_with("#!/bin/sh\n"));
}

#[cfg(unix)]
/// Case 112: the launcher, the in-process plugins (`installCandidates` in
/// each `src/serve/client.ts`) and `derm connect`'s route line try the same
/// folders in the same order.
#[test]
fn the_launcher_tries_the_folders_the_in_process_plugins_try() {
    let sh = read(&repo().join(PLUGINS[0]).join("hooks/derm-gate.sh"));
    let ts = read(&repo().join("packages/derm-pi/src/serve/client.ts"));
    for (macos, darwin_sh) in [(true, "Darwin) brew="), (false, "*) brew=")] {
        let want = gate::install_candidates(Path::new("/h"), macos);
        let want: Vec<String> = want.iter().map(|p| p.display().to_string()).collect();
        assert_eq!(want[0], "/h/.local/bin/derm");
        // The shell's list: ${HOME%/}/.local/bin/derm, then the brew line,
        // then /usr/bin/derm.
        let line = sh
            .lines()
            .find(|l| l.trim_start().starts_with(darwin_sh))
            .unwrap_or_else(|| panic!("{darwin_sh}"));
        let brew: Vec<&str> = line.split('"').nth(1).unwrap().split(' ').collect();
        assert_eq!(&want[1..3], brew.as_slice(), "{line}");
        assert!(sh.contains("local_bin=${HOME%/}/.local/bin/derm"));
        assert!(sh.contains("for c in $local_bin $brew /usr/bin/derm; do"));
        assert_eq!(want[3], "/usr/bin/derm");
        // The TypeScript's list, the same strings.
        for w in &want[1..] {
            assert!(ts.contains(&format!("\"{w}\"")), "{w} not in client.ts");
        }
        assert!(ts.contains("path.posix.join(home, \".local\", \"bin\", \"derm\")"));
        let order = if macos {
            "[\"/opt/homebrew/bin/derm\", \"/usr/local/bin/derm\"]"
        } else {
            "[\"/home/linuxbrew/.linuxbrew/bin/derm\", \"/usr/local/bin/derm\"]"
        };
        assert!(ts.contains(order), "{order}");
        assert!(ts.contains("return [local, ...brew, \"/usr/bin/derm\"];"));
    }
}

#[cfg(unix)]
/// Ports `derm-claude-plugin` "plugin files" and BC-3: the hooks run
/// /bin/sh by its absolute path in Claude Code's exec form (`command` plus
/// `args`, no shell, `${CLAUDE_PLUGIN_ROOT}` replaced in both; note BC
/// section 3, run), PreToolUse blocks on a failure, and nothing names
/// `node` or anything else found on PATH.
#[test]
fn claude_codes_plugin_hooks_run_the_launcher_in_exec_form() {
    let h = plugin_hooks(PLUGINS[0]);
    for (event, arg, timeout) in [("PreToolUse", "pre", 120), ("PostToolUse", "post", 30)] {
        let group = &h["hooks"][event][0];
        assert_eq!(group["matcher"], "*", "{event}");
        let hook = &group["hooks"][0];
        assert_eq!(hook["type"], "command");
        assert_eq!(hook["command"], "/bin/sh");
        assert_eq!(
            hook["args"],
            serde_json::json!([
                "${CLAUDE_PLUGIN_ROOT}/hooks/derm-gate.sh",
                "claude-code",
                arg
            ])
        );
        assert_eq!(hook["timeout"], timeout);
    }
    assert_eq!(
        h["hooks"]["PreToolUse"][0]["hooks"][0]["onFailure"],
        "block"
    );
    assert!(!h["hooks"].to_string().contains("node"));
}

#[cfg(unix)]
/// Ports `derm-codex-plugin` "plugin files > the launcher runs the hook":
/// Codex runs a hook line with its shell (`$SHELL -lc`), `PLUGIN_ROOT` in
/// the environment (`codex-rs/hooks/src/engine/command_runner.rs:444-517`
/// at rust-v0.167.1, read by the base): the line names /bin/sh by its
/// absolute path and the launcher by `$PLUGIN_ROOT`, which sh, bash, zsh
/// and fish all expand inside double quotes.
#[test]
fn codexs_plugin_hooks_run_the_launcher() {
    let h = plugin_hooks(PLUGINS[1]);
    for (event, arg) in [("PreToolUse", "pre"), ("PostToolUse", "post")] {
        let hook = &h["hooks"][event][0]["hooks"][0];
        assert_eq!(
            hook["command"],
            format!("/bin/sh \"$PLUGIN_ROOT/hooks/derm-gate.sh\" codex {arg}")
        );
    }
    assert_eq!(h["hooks"]["PreToolUse"][0]["hooks"][0]["timeout"], 120);
}

#[cfg(unix)]
/// Ports `derm-gemini-extension` "the extension's files": Gemini's shape,
/// a timeout above the ask cap (90 s), and the manifest's name. Gemini
/// 0.68.0 replaces `${extensionPath}` and `${/}` in every string of an
/// extension's hooks/hooks.json when it loads it (`loadExtensionHooks` and
/// `hydrateString`, bundle/chunk-ASDLQWJU.js:43548-43562 and 38340-38346 in
/// the published package, read here) and runs the line with `bash -c`.
#[test]
fn geminis_extension_hooks_run_the_launcher() {
    let h = plugin_hooks(PLUGINS[2]);
    let gate = &h["hooks"]["BeforeTool"][0];
    assert_eq!(gate["matcher"], ".*");
    assert_eq!(gate["hooks"][0]["type"], "command");
    assert_eq!(gate["hooks"][0]["name"], "derm-gate");
    assert!(gate["hooks"][0]["timeout"].as_u64().unwrap() > 90_000);
    assert_eq!(
        gate["hooks"][0]["command"],
        "/bin/sh \"${extensionPath}${/}hooks${/}derm-gate.sh\" gemini before"
    );
    assert_eq!(
        h["hooks"]["AfterTool"][0]["hooks"][0]["command"],
        "/bin/sh \"${extensionPath}${/}hooks${/}derm-gate.sh\" gemini after"
    );
    let manifest: serde_json::Value = serde_json::from_str(&read(
        &repo().join(PLUGINS[2]).join("gemini-extension.json"),
    ))
    .unwrap();
    assert_eq!(manifest["name"], "derm");
}

#[cfg(unix)]
struct Launched {
    code: Option<i32>,
    out: String,
    err: String,
}

#[cfg(unix)]
/// Runs the launcher as the hooks files do, `/bin/sh <file> <agent>
/// <event>`, from `cwd`, with only `env`.
fn launch(cwd: &Path, env: &[(&str, &str)], args: &[&str], input: &str) -> Launched {
    use std::io::Write;
    let file = repo().join(PLUGINS[0]).join("hooks/derm-gate.sh");
    let mut c = std::process::Command::new("/bin/sh");
    c.arg(&file)
        .args(args)
        .current_dir(cwd)
        .env_clear()
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    for (k, v) in env {
        c.env(k, v);
    }
    let mut child = c.spawn().unwrap();
    // The launcher may exit before it reads (a refusal): a closed pipe is
    // not the test's failure.
    let _ = child.stdin.take().unwrap().write_all(input.as_bytes());
    let o = child.wait_with_output().unwrap();
    Launched {
        code: o.status.code(),
        out: String::from_utf8_lossy(&o.stdout).into(),
        err: String::from_utf8_lossy(&o.stderr).into(),
    }
}

#[cfg(unix)]
/// A stand-in derm that prints its argv and its stdin, so a test sees what
/// the launcher ran it with.
fn echo_derm(dir: &Path) -> String {
    fs::create_dir_all(dir).unwrap();
    fs::set_permissions(dir, fs::Permissions::from_mode(0o755)).unwrap();
    let f = dir.join("derm");
    fs::write(
        &f,
        "#!/bin/sh\nprintf 'argv:%s\\n' \"$*\"\nprintf 'stdin:'\ncat\nexit 0\n",
    )
    .unwrap();
    fs::set_permissions(&f, fs::Permissions::from_mode(0o755)).unwrap();
    f.display().to_string()
}

#[cfg(unix)]
/// Ports "the launcher runs the hook" (Claude Code, Codex, Gemini, Hermes's
/// decider, the compat and native launchers): `derm hook <agent> <event>`
/// from `~/.local/bin`, the hook input passed on stdin untouched, a link
/// followed to the derm it names.
#[test]
fn the_launcher_runs_derm_hook_from_its_install_folder() {
    let home = scratch("launch-ok");
    let work = home.join("work");
    fs::create_dir_all(&work).unwrap();
    let real = echo_derm(&home.join("opt/derm-0.1.3"));
    let bin = home.join(".local/bin");
    fs::create_dir_all(&bin).unwrap();
    fs::set_permissions(&bin, fs::Permissions::from_mode(0o755)).unwrap();
    // A relative link, as Homebrew's.
    std::os::unix::fs::symlink("../../opt/derm-0.1.3/derm", bin.join("derm")).unwrap();
    let h = home.display().to_string();
    for (agent, event) in [
        ("claude-code", "pre"),
        ("claude-code", "post"),
        ("codex", "pre"),
        ("gemini", "before"),
        ("gemini", "after"),
    ] {
        let r = launch(&work, &[("HOME", &h)], &[agent, event], "{\"x\":1}");
        assert_eq!(r.code, Some(0), "{agent} {event}: {}", r.err);
        assert_eq!(
            r.out,
            format!("argv:hook {agent} {event}\nstdin:{{\"x\":1}}"),
            "{agent} {event}"
        );
    }
    let _ = real;
}

#[cfg(unix)]
/// Case 227 and case 109's rule: no derm found on PATH, none someone else
/// may write, none inside the session's folder. Each blocks in the agent's
/// own form (exit 2 and `derm: ` on stderr; Gemini's JSON deny on stdout
/// as well), and an unknown agent or event is refused before anything
/// runs. Ports "fails closed when the hook cannot load" (Claude Code,
/// Gemini, Hermes) and "an unknown agent exits 2 with the reason on stderr"
/// (the compat and native launchers).
#[test]
fn the_launcher_blocks_without_a_derm_it_can_trust() {
    let home = scratch("launch-no");
    let work = home.join("work");
    fs::create_dir_all(&work).unwrap();
    let h = home.display().to_string();
    // On PATH only: never run.
    let on_path = home.join("path-bin");
    echo_derm(&on_path);
    let p = on_path.display().to_string();
    let r = launch(
        &work,
        &[("HOME", &h), ("PATH", &p)],
        &["claude-code", "pre"],
        "{}",
    );
    assert_eq!(r.code, Some(2));
    assert!(r.out.is_empty(), "{}", r.out);
    assert!(
        r.err.starts_with("derm: no derm this hook can trust"),
        "{}",
        r.err
    );
    assert!(r.err.contains("never looked up on PATH"), "{}", r.err);
    // Gemini reads its JSON on stdout as well.
    let r = launch(&work, &[("HOME", &h)], &["gemini", "before"], "{}");
    assert_eq!(r.code, Some(2));
    let v: serde_json::Value = serde_json::from_str(r.out.trim()).unwrap();
    assert_eq!(v["decision"], "deny");
    assert!(v["reason"].as_str().unwrap().starts_with("derm: no derm"));
    // Writable by others: refused, and said.
    let bin = home.join(".local/bin");
    let f = echo_derm(&bin);
    fs::set_permissions(&f, fs::Permissions::from_mode(0o757)).unwrap();
    let r = launch(&work, &[("HOME", &h)], &["codex", "pre"], "{}");
    assert_eq!(r.code, Some(2));
    assert!(r.err.contains("others may write it"), "{}", r.err);
    fs::set_permissions(&f, fs::Permissions::from_mode(0o755)).unwrap();
    fs::set_permissions(&bin, fs::Permissions::from_mode(0o777)).unwrap();
    let r = launch(&work, &[("HOME", &h)], &["codex", "pre"], "{}");
    assert!(r.err.contains("others may write"), "{}", r.err);
    fs::set_permissions(&bin, fs::Permissions::from_mode(0o755)).unwrap();
    // Inside the session's folder (a HOME a project chose): refused.
    let r = launch(&home, &[("HOME", &h)], &["codex", "pre"], "{}");
    assert_eq!(r.code, Some(2), "{}", r.out);
    assert!(r.err.contains("inside the session's folder"), "{}", r.err);
    // A link that leads into a folder others may write.
    let open = home.join("open");
    echo_derm(&open);
    fs::set_permissions(&open, fs::Permissions::from_mode(0o777)).unwrap();
    fs::remove_file(&f).unwrap();
    std::os::unix::fs::symlink(open.join("derm"), &f).unwrap();
    let r = launch(&work, &[("HOME", &h)], &["claude-code", "pre"], "{}");
    assert_eq!(r.code, Some(2));
    assert!(r.err.contains("others may write"), "{}", r.err);
    // A relative or missing HOME is not used.
    let r = launch(&work, &[("HOME", "home")], &["claude-code", "pre"], "{}");
    assert!(r.err.contains("no derm this hook can trust"), "{}", r.err);
    // An agent or event it does not take: refused before anything runs,
    // the input never printed.
    for args in [&["frob", "pre"][..], &["claude-code", "before"], &[]] {
        let r = launch(&work, &[("HOME", &h)], args, "{\"secret\":\"sk-x\"}");
        assert_eq!(r.code, Some(2), "{args:?}");
        assert!(r.err.starts_with("derm: derm-gate.sh takes"), "{}", r.err);
        assert!(!r.err.contains("sk-x") && !r.out.contains("sk-x"));
    }
}

// ---- Wave 5b lane 5bF: registration ports ----
//
// `derm-hooks-claude-compat/src/registration.test.ts` and `security.test.ts`
// held the TypeScript's `registrationFor` and `hookCommand`; since wave 5b
// `gates.json` and `derm connect --gate` are the one registration.

#[cfg(unix)]
/// The rows that run `derm hook`, by agent.
fn derm_hook_rows() -> Vec<gate::Agent> {
    gate::table()
        .unwrap()
        .into_iter()
        .filter(|a| a.command.as_deref().is_some_and(|c| c.contains("{derm}")))
        .collect()
}

#[cfg(unix)]
/// Ports "covers every dialect": every command-hook agent `derm hook`
/// answers but Claude Code, Codex, Gemini and Hermes (whose gates install
/// through their own plugin files) has a row that runs `derm hook <agent>
/// pre`, and `derm hook` answers each row's agent and event.
#[test]
fn every_command_hook_agent_has_a_derm_hook_row() {
    let rows = derm_hook_rows();
    for (agent, _, events) in crate::hook::AGENTS {
        if ["claude-code", "codex", "gemini", "hermes"].contains(&agent) {
            assert!(!rows.iter().any(|r| r.agent == agent), "{agent}");
            continue;
        }
        let row = rows
            .iter()
            .find(|r| r.agent == agent)
            .unwrap_or_else(|| panic!("{agent} has no derm hook row"));
        assert_eq!(
            row.command.as_deref(),
            Some(format!("{{derm}} hook {agent} pre").as_str())
        );
        assert!(events.contains(&"pre"), "{agent}");
        assert_eq!(row.markers[0], format!("/derm hook {agent} "));
    }
    assert_eq!(rows.len(), crate::hook::AGENTS.len() - 4);
}

#[cfg(unix)]
/// Ports "waits longer than the gate's longest ask, so a slow ask is not a
/// timeout (case 70)": every written entry's timeout is above the hook's
/// ask cap plus 10 s, in the unit each agent reads.
#[test]
fn every_entry_waits_longer_than_the_longest_ask() {
    let cap = u64::from(crate::gate::core::HOOK_ASK_CAP_SECONDS) + 10;
    let text = include_str!("gates.json");
    let v: serde_json::Value = serde_json::from_str(text).unwrap();
    let mut seen = 0;
    for row in v["agents"].as_array().unwrap() {
        if !row["command"]
            .as_str()
            .is_some_and(|c| c.contains("{derm}"))
        {
            continue;
        }
        let s = row["steps"].to_string();
        for (key, scale) in [("\"timeout\":", 1), ("\"timeoutSec\":", 1)] {
            for part in s.split(key).skip(1) {
                let n: f64 = part
                    .trim_start()
                    .split(|c: char| !(c.is_ascii_digit() || c == '.'))
                    .next()
                    .unwrap()
                    .parse()
                    .unwrap();
                // Auggie's timeout is in milliseconds (its row's note).
                let secs = if row["agent"] == "auggie" {
                    n / 1000.0
                } else {
                    n
                } / f64::from(scale);
                assert!(secs > cap as f64, "{}: {secs} s", row["agent"]);
                seen += 1;
            }
        }
        if row["agent"] == "kimi" {
            assert!(s.contains("timeout = 120"), "{s}");
        }
    }
    assert!(seen >= 13, "{seen}");
}

#[cfg(unix)]
/// The keys of an object and of the first item of every array under it.
fn shape(v: &serde_json::Value, at: &str, out: &mut Vec<String>) {
    match v {
        serde_json::Value::Array(a) => match a.first() {
            Some(x) => shape(x, &format!("{at}[]"), out),
            None => out.push(format!("{at}[]")),
        },
        serde_json::Value::Object(m) => {
            for (k, x) in m {
                out.push(format!("{at}.{k}"));
                shape(x, &format!("{at}.{k}"), out);
            }
        }
        _ => {}
    }
}

#[cfg(unix)]
/// Ports "<agent>: the entry has the fixture's structure, with every tool
/// matched": the file derm writes holds every key of the vendor's own
/// example (`contracts/fixtures/hook-dialects/<agent>/register.json`), the
/// command names `derm hook <agent> pre` by derm's absolute path where the
/// example names `/ABSOLUTE/PATH/TO/derm-hook`, and no matcher narrows the
/// gate to one tool.
#[test]
fn each_written_entry_has_its_vendors_structure() {
    let skip = [
        "name",
        "description",
        "sequential",
        "matcher",
        "failClosed",
        "metadata",
    ];
    for (agent, file) in [
        ("openclaude", ".openclaude/settings.json"),
        ("qwen-code", ".qwen/settings.json"),
        ("droid", ".factory/settings.json"),
        ("command-code", ".commandcode/settings.json"),
        ("auggie", ".augment/settings.json"),
        ("copilot-cli", ".copilot/hooks/derm.json"),
        ("grok", ".grok/hooks/derm.json"),
    ] {
        let home = scratch(&format!("shape-{agent}"));
        let derm = fake_derm(&home);
        let f = home.join(file);
        fs::create_dir_all(f.parent().unwrap()).unwrap();
        if agent == "grok" {
            fs::write(home.join(".grok/config.toml"), "").unwrap();
        }
        let r = go(&home, &[agent, "--gate", "--write"]);
        assert_eq!(r.code, 0, "{agent}: {}{}", r.out, r.err);
        let got: serde_json::Value = serde_json::from_str(&read(&f)).unwrap();
        let fixture: serde_json::Value = serde_json::from_str(&read(&repo().join(format!(
            "contracts/fixtures/hook-dialects/{agent}/register.json"
        ))))
        .unwrap();
        let (mut want, mut have) = (Vec::new(), Vec::new());
        shape(&fixture, "", &mut want);
        shape(&got, "", &mut have);
        for p in want
            .iter()
            .filter(|p| !skip.iter().any(|k| p.contains(&format!(".{k}"))))
        {
            assert!(have.contains(p), "{agent}: {p} missing in {got}");
        }
        let text = got.to_string();
        assert!(
            text.contains(&format!("{derm} hook {agent} pre")),
            "{agent}: {text}"
        );
        for narrow in [
            "Bash",
            "Execute",
            "shell",
            "launch-process",
            "bash",
            "^run_shell_command$",
        ] {
            assert!(
                !text.contains(&format!("\"matcher\":\"{narrow}\"")),
                "{agent}: {text}"
            );
        }
    }
}

#[cfg(unix)]
/// Ports "Kimi: exactly the keys Kimi accepts, since a fifth makes it drop
/// the whole config": the printed table has only `event`, `matcher`,
/// `command` and `timeout` (its fixture's keys), as one `[[hooks]]` table.
#[test]
fn kimis_printed_table_has_only_the_keys_kimi_accepts() {
    let home = scratch("gate-kimi");
    let derm = fake_derm(&home);
    let r = go(&home, &["kimi", "--gate"]);
    assert_eq!(r.code, 0, "{}", r.err);
    let i = r.out.find("[[hooks]]").expect("the table");
    let table: Vec<&str> = r.out[i..]
        .lines()
        .skip(1)
        .take_while(|l| l.contains('='))
        .collect();
    let keys: Vec<&str> = table
        .iter()
        .map(|l| l.split('=').next().unwrap().trim())
        .collect();
    for k in &keys {
        assert!(
            ["event", "matcher", "command", "timeout"].contains(k),
            "{k}"
        );
    }
    assert!(
        table.contains(&format!("  command = '{derm} hook kimi pre'").as_str()),
        "{table:?}"
    );
    assert!(table.contains(&"  timeout = 120"), "{table:?}");
}

#[cfg(unix)]
/// Ports "sets the fail-closed switch where the agent has one" and "Droid:
/// never its hooks.json" (shown above in
/// `shadowing_files_and_folders_outside_home_are_refused`), and "Grok:
/// turns its Claude and Cursor hook imports off" (in
/// `a_file_that_changes_before_the_write_stops_every_file`): Command Code,
/// Grok and Cursor block on a failed gate; Droid's row writes settings.json
/// and refuses while its hooks.json exists.
#[test]
fn the_fail_closed_switch_is_set_where_the_agent_has_one() {
    for (agent, file, pre) in [
        ("command-code", ".commandcode/settings.json", ""),
        ("grok", ".grok/hooks/derm.json", ".grok/config.toml"),
        ("cursor", ".cursor/hooks.json", ""),
    ] {
        let home = scratch(&format!("fc-{agent}"));
        fake_derm(&home);
        fs::create_dir_all(home.join(file).parent().unwrap()).unwrap();
        if !pre.is_empty() {
            fs::write(home.join(pre), "").unwrap();
        }
        let r = go(&home, &[agent, "--gate", "--write"]);
        assert_eq!(r.code, 0, "{agent}: {}{}", r.out, r.err);
        assert!(
            read(&home.join(file)).contains("\"failClosed\": true"),
            "{agent}"
        );
    }
    let droid = derm_hook_rows()
        .into_iter()
        .find(|a| a.agent == "droid")
        .unwrap();
    assert_eq!(
        droid.refuse_if_exists,
        ["~/.factory/hooks.json", "~/.factory/hooks/hooks.json"]
    );
}

#[cfg(unix)]
/// Ports "the command line it gives runs the hook": each row's line, as an
/// agent's shell reads it (`/bin/sh -c`), runs `derm hook <agent> pre` with
/// the hook input on stdin, and as the exec forms split it (whitespace),
/// the same four words.
#[test]
fn each_registered_line_runs_derm_hook() {
    let home = scratch("lines-run");
    let derm = echo_derm(&home.join("bin"));
    for row in derm_hook_rows() {
        let line = row.command.as_deref().unwrap().replace("{derm}", &derm);
        let o = std::process::Command::new("/bin/sh")
            .args(["-c", &line])
            .env_clear()
            .stdin(std::process::Stdio::null())
            .output()
            .unwrap();
        assert_eq!(
            String::from_utf8_lossy(&o.stdout),
            format!("argv:hook {} pre\nstdin:", row.agent),
            "{}",
            row.agent
        );
        let words: Vec<&str> = line.split_whitespace().collect();
        assert_eq!(words, [derm.as_str(), "hook", row.agent.as_str(), "pre"]);
    }
}

#[cfg(unix)]
/// Ports "refuses a hook path a shell would read differently" and L-S8:
/// a derm path with a quote, a `$`, a backtick, a backslash, a space, a
/// control character or a line separator is never written into a line.
#[test]
fn a_derm_path_a_shell_would_read_differently_is_refused() {
    for bad in [
        "relative/derm",
        "/a\"b/derm",
        "/a$HOME/derm",
        "/a`id`/derm",
        "/a\\b/derm",
        "/a b/derm",
        "/a\nb/derm",
        "/a\u{2028}b/derm",
        "/a\u{7}b/derm",
        "/a/../derm",
        "/a/./derm",
    ] {
        assert!(!gate::plain_hook_path(bad), "{bad:?}");
    }
    for good in [
        "/usr/bin/derm",
        "/home/u/.local/bin/derm",
        "/opt/homebrew/Cellar/derm/0.1.3/bin/derm",
        "/x/a+b@c~d-e_f/derm",
    ] {
        assert!(gate::plain_hook_path(good), "{good}");
    }
}

#[cfg(unix)]
/// Ports L-S9 ("refuses an agent that is not one of the eight") and "an
/// unknown agent exits 2": `derm connect` registers only an agent in its
/// table, and the launcher only the three plugin agents
/// (`the_launcher_blocks_without_a_derm_it_can_trust`).
#[test]
fn an_agent_with_no_row_is_refused() {
    let home = scratch("no-row");
    fake_derm(&home);
    for bad in ["frob", "claude", "../crush", "crush;id"] {
        let r = go(&home, &[bad, "--gate"]);
        assert_ne!(r.code, 0, "{bad}");
    }
}

#[cfg(unix)]
/// Ports "a TOML basic string escapes control characters": the TOML rows
/// (Vibe's table, Grok's switches) write through toml_edit, and the only
/// text derm splices into them is a plain path; the written file parses
/// back to the very line.
#[test]
fn toml_rows_write_a_line_toml_reads_back() {
    let home = scratch("toml-line");
    let derm = fake_derm(&home);
    fs::create_dir_all(home.join(".vibe")).unwrap();
    let r = go(&home, &["mistral-vibe", "--gate", "--write"]);
    assert_eq!(r.code, 0, "{}{}", r.out, r.err);
    let doc: toml_edit::DocumentMut = read(&home.join(".vibe/hooks.toml")).parse().unwrap();
    assert_eq!(
        doc["hooks"][0]["command"].as_str(),
        Some(format!("{derm} hook mistral-vibe pre").as_str())
    );
}

#[cfg(unix)]
/// Ports Hermes's "plugin.yaml names the two hooks register() wires" and
/// "runs as derm_gate.py runs it": the plugin declares `pre_tool_call` and
/// `transform_tool_result`, and it reads derm's path from the very file
/// `derm connect hermes --gate` writes (`DERM_PATH_FILE = "derm-path"`,
/// beside derm_gate.py), running `[derm, "hook", "hermes", event]`.
#[test]
fn hermes_plugin_reads_the_file_derm_connect_writes() {
    let yaml = read(&repo().join("packages/derm-hermes-plugin/plugin.yaml"));
    assert!(yaml.contains("  - pre_tool_call\n") && yaml.contains("  - transform_tool_result\n"));
    let py = read(&repo().join("packages/derm-hermes-plugin/derm_gate.py"));
    assert!(py.contains("DERM_PATH_FILE = \"derm-path\""));
    assert!(py.contains("named = plugin_dir / DERM_PATH_FILE"));
    assert!(!py.contains("shutil.which"));
    let row = gate::table()
        .unwrap()
        .into_iter()
        .find(|a| a.agent == "hermes")
        .unwrap();
    let file = row.steps.iter().find_map(|s| match s {
        Step::TextFile { at, .. } => Some(at.path.clone()),
        _ => None,
    });
    assert_eq!(file.as_deref(), Some("~/.hermes/plugins/derm/derm-path"));
}
