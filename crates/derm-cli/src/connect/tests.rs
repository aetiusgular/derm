//! End-to-end tests for `derm connect`: byte comparisons against what each
//! harness's own `mcp add` wrote (recorded 27 Oct in a scratch HOME; how
//! each file was made is in `fixtures/recorded/README.md`), and the write
//! path through `run` with a scripted terminal.

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

use super::presets::{self, Env};
use super::spec::{EnvRef, Header, HeaderValue, HttpKind, Origin, Runner, ServerSpec, Transport};
use super::write::tests::{scratch, Answer};
use super::{compute, run, Change, Ctx};

const REC: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/src/connect/fixtures/recorded/"
);

fn rec(name: &str) -> String {
    fs::read_to_string(format!("{REC}{name}")).unwrap_or_else(|e| panic!("{name}: {e}"))
}

fn stdio(name: &str, command: &str, args: &[&str], env: &[&str]) -> ServerSpec {
    ServerSpec {
        name: name.into(),
        transport: Transport::Stdio {
            command: command.into(),
            args: args.iter().map(|a| a.to_string()).collect(),
        },
        env: env
            .iter()
            .map(|e| EnvRef {
                key: e.to_string(),
                var: e.to_string(),
            })
            .collect(),
        runner: Runner::Host,
        exposure: vec![],
        origin: Origin::Gateway {
            backend: "test".into(),
            id: "t".into(),
        },
        notes: vec![],
    }
}

fn http(name: &str, url: &str, headers: Vec<Header>) -> ServerSpec {
    let mut s = stdio(name, "x", &[], &[]);
    s.transport = Transport::Http {
        kind: HttpKind::Streamable,
        url: url.into(),
        headers,
    };
    s.runner = Runner::Remote;
    s
}

fn bearer(var: &str) -> Header {
    Header {
        name: "Authorization".into(),
        value: HeaderValue::Ref {
            prefix: "Bearer ".into(),
            var: var.into(),
        },
        optional: false,
    }
}

fn header(name: &str, var: &str) -> Header {
    Header {
        name: name.into(),
        value: HeaderValue::Ref {
            prefix: String::new(),
            var: var.into(),
        },
        optional: false,
    }
}

fn add(harness: &str, before: &str, spec: &ServerSpec) -> String {
    let p = presets::find(harness).unwrap();
    match compute(&p, before, Some(spec), None, false) {
        Ok(Change::Text(t)) => t,
        Ok(Change::Same(m)) => panic!("unexpected no-op: {m}"),
        Err(e) => panic!("{harness}: {e}"),
    }
}

fn fs_server() -> ServerSpec {
    stdio(
        "fs",
        "npx",
        &["-y", "@modelcontextprotocol/server-filesystem", "/tmp"],
        &["TOKEN"],
    )
}

// --- byte comparisons with each harness's own `mcp add` ---

#[test]
fn claude_code_matches_claude_mcp_add_json() {
    // `claude mcp add-json -s user fs '{"type":"stdio",...,"env":{"TOKEN":"${TOKEN}"}}'`
    assert_eq!(
        add("claude-code", &rec("claude-1-before.json"), &fs_server()),
        rec("claude-1-after.json")
    );
    // `claude mcp add-json -s user hdr '{"type":"http","url":...,"headers":{...}}'`
    let hdr = http(
        "hdr",
        "https://mcp.example.com/mcp",
        vec![bearer("EX_TOKEN")],
    );
    assert_eq!(
        add("claude-code", &rec("claude-2-after.json"), &hdr),
        rec("claude-3-after.json")
    );
}

#[test]
fn pi_matches_pi_mcp_add() {
    let mut fs_d = fs_server();
    fs_d.exposure = vec![("default".into(), "deferred".into())];
    let one = add("pi", "", &fs_d);
    assert_eq!(one, rec("pi-1-after.json"));
    let mut exa = http("exa", "https://mcp.exa.ai/mcp", vec![bearer("EXA_KEY")]);
    exa.exposure = vec![
        ("pi".into(), "deferred".into()),
        ("default".into(), "direct".into()),
    ];
    let two = add("pi", &one, &exa);
    assert_eq!(two, rec("pi-2-after.json"));
    let three = add(
        "pi",
        &two,
        &http("hdr", "https://x.example/mcp", vec![header("X-Key", "XK")]),
    );
    assert_eq!(three, rec("pi-3-after.json"));
    let four = add(
        "pi",
        &three,
        &stdio("plain", "uvx", &["mcp-server-time"], &[]),
    );
    assert_eq!(four, rec("pi-4-after.json"));
}

#[test]
fn codex_matches_codex_mcp_add_and_keeps_comments() {
    let exa = http("exa", "https://mcp.exa.ai/mcp", vec![bearer("EXA_KEY")]);
    let one = add("codex", &rec("codex-1-before.toml"), &exa);
    assert_eq!(one, rec("codex-1-after.toml"));
    let two = add(
        "codex",
        &one,
        &stdio("time", "uvx", &["mcp-server-time"], &[]),
    );
    assert_eq!(two, rec("codex-2-after.toml"));
}

#[test]
fn gemini_matches_gemini_mcp_add() {
    let one = add("gemini", "", &fs_server());
    let two = add(
        "gemini",
        &one,
        &http("exa", "https://mcp.exa.ai/mcp", vec![bearer("EXA_KEY")]),
    );
    assert_eq!(two, rec("gemini-2-after.json"));
}

#[test]
fn qwen_matches_qwen_mcp_add() {
    let one = add("qwen-code", "", &fs_server());
    let two = add(
        "qwen-code",
        &one,
        &http("exa", "https://mcp.exa.ai/mcp", vec![bearer("EXA_KEY")]),
    );
    // Qwen adds `"$version": 4` when it first writes the file; derm does not.
    let qwen = rec("qwen-2-after.json").replace("\n  },\n  \"$version\": 4\n}", "\n  }\n}");
    assert_eq!(two, qwen);
}

#[test]
fn copilot_matches_copilot_mcp_add() {
    let one = add("copilot-cli", "", &fs_server());
    let two = add(
        "copilot-cli",
        &one,
        &http("exa", "https://mcp.exa.ai/mcp", vec![header("X-Key", "XK")]),
    );
    assert_eq!(two, rec("copilot-2-after.json"));
}

#[test]
fn copilot_refuses_a_header_with_text_before_the_variable() {
    let p = presets::find("copilot-cli").unwrap();
    let spec = http("exa", "https://mcp.exa.ai/mcp", vec![bearer("EXA_KEY")]);
    let e = compute(&p, "", Some(&spec), None, false).err().unwrap();
    assert!(e.contains("whole value"), "{e}");
}

#[test]
fn opencode_refuses_sse_and_writes_env_references() {
    let p = presets::find("opencode").unwrap();
    let mut sse = http("s", "https://h.example/sse", vec![]);
    if let Transport::Http { kind, .. } = &mut sse.transport {
        *kind = HttpKind::Sse;
    }
    assert!(compute(&p, "", Some(&sse), None, false).is_err());
    match compute(&p, "", Some(&fs_server()), None, false) {
        Ok(Change::Text(t)) => {
            assert!(t.contains("\"TOKEN\": \"{env:TOKEN}\""), "{t}");
            assert!(t.contains("\"command\": [\n        \"npx\""), "{t}");
            assert!(!t.ends_with('\n'));
        }
        _ => panic!(),
    }
}

// --- the command line, end to end ---

struct MapEnv(HashMap<String, String>);
impl Env for MapEnv {
    fn var(&self, key: &str) -> Option<String> {
        self.0.get(key).cloned()
    }
}

struct Run {
    code: u8,
    out: String,
    err: String,
}

fn go(home: &Path, env: &MapEnv, answer: bool, args: &[&str]) -> Run {
    let mut a = Answer(answer, None);
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

fn no_env() -> MapEnv {
    MapEnv(HashMap::new())
}

fn entry_file(dir: &Path) -> PathBuf {
    let p = dir.join("exa.json");
    fs::write(
        &p,
        include_str!("../../../../contracts/fixtures/entry/server.json"),
    )
    .unwrap();
    p
}

fn sha_line(out: &str) -> String {
    out.lines()
        .find_map(|l| l.split("--expect-sha256 ").nth(1))
        .unwrap()
        .trim()
        .to_string()
}

#[test]
fn dry_run_writes_nothing_and_prints_the_diff_and_the_write_line() {
    let home = scratch("dry");
    fs::create_dir_all(home.join(".pi/agent")).unwrap();
    let e = entry_file(&home);
    let r = go(
        &home,
        &no_env(),
        true,
        &["pi", "--from", e.to_str().unwrap()],
    );
    assert_eq!(r.code, 0, "{}", r.err);
    assert!(r.out.contains("+    \"exa-fixture\": {"), "{}", r.out);
    assert!(r.out.contains("\"exposure\": \"deferred\""));
    assert!(r.out.contains("runs:   remote endpoint"));
    assert!(r.out.contains("dry run: nothing written"));
    assert!(!home.join(".pi/agent/mcp.json").exists());
}

#[test]
fn write_then_same_again_is_a_no_op_and_the_log_records_it() {
    let home = scratch("write");
    fs::create_dir_all(home.join(".pi/agent")).unwrap();
    let e = entry_file(&home);
    let ef = e.to_str().unwrap();
    let dry = go(&home, &no_env(), true, &["pi", "--from", ef]);
    let sha = sha_line(&dry.out);
    let w = go(
        &home,
        &no_env(),
        true,
        &["pi", "--from", ef, "--write", "--expect-sha256", &sha],
    );
    assert_eq!(w.code, 0, "{}", w.err);
    let file = fs::read_to_string(home.join(".pi/agent/mcp.json")).unwrap();
    assert!(file.contains("\"url\": \"https://mcp.exa.ai/mcp\""));
    let log = fs::read_to_string(home.join(".derm/connect.log")).unwrap();
    assert!(log.contains("\"action\":\"add\""), "{log}");
    assert!(
        !log.contains("mcp.exa.ai/mcp\""),
        "the log holds no config values"
    );
    let again = go(&home, &no_env(), true, &["pi", "--from", ef]);
    assert_eq!(again.code, 0);
    assert!(again.out.contains("already connected"), "{}", again.out);
}

#[test]
fn a_stale_expect_hash_is_refused() {
    // Case 55, across two invocations.
    let home = scratch("stale");
    fs::create_dir_all(home.join(".pi/agent")).unwrap();
    let e = entry_file(&home);
    let ef = e.to_str().unwrap();
    let sha = sha_line(&go(&home, &no_env(), true, &["pi", "--from", ef]).out);
    fs::write(home.join(".pi/agent/mcp.json"), "{\"mcpServers\": {}}\n").unwrap();
    let w = go(
        &home,
        &no_env(),
        true,
        &["pi", "--from", ef, "--write", "--expect-sha256", &sha],
    );
    assert_eq!(w.code, 1);
    assert!(w.err.contains("changed since the dry run"), "{}", w.err);
    assert_eq!(
        fs::read_to_string(home.join(".pi/agent/mcp.json")).unwrap(),
        "{\"mcpServers\": {}}\n"
    );
}

#[test]
fn not_confirmed_means_nothing_written() {
    let home = scratch("no");
    fs::create_dir_all(home.join(".pi/agent")).unwrap();
    let e = entry_file(&home);
    let w = go(
        &home,
        &no_env(),
        false,
        &["pi", "--from", e.to_str().unwrap(), "--write"],
    );
    assert_eq!(w.code, 1);
    assert!(w.err.contains("not confirmed"));
    assert!(!home.join(".pi/agent/mcp.json").exists());
}

#[test]
fn a_harness_that_is_not_installed_gets_the_entry_and_no_write() {
    // Case 54.
    let home = scratch("absent");
    let e = entry_file(&home);
    let r = go(
        &home,
        &no_env(),
        true,
        &["codex", "--from", e.to_str().unwrap(), "--write"],
    );
    assert_eq!(r.code, 1);
    assert!(r.out.contains("does not look installed"), "{}", r.out);
    assert!(r.out.contains("[mcp_servers.exa-fixture]"));
    assert!(!home.join(".codex/config.toml").exists());
}

#[test]
fn a_cli_on_path_counts_as_installed() {
    let home = scratch("onpath");
    let bin = home.join("bin");
    fs::create_dir_all(&bin).unwrap();
    fs::write(bin.join("codex"), "").unwrap();
    let env = MapEnv(HashMap::from([(
        "PATH".to_string(),
        bin.display().to_string(),
    )]));
    let e = entry_file(&home);
    let r = go(
        &home,
        &env,
        true,
        &["codex", "--from", e.to_str().unwrap(), "--write"],
    );
    assert_eq!(r.code, 0, "{}", r.err);
    let t = fs::read_to_string(home.join(".codex/config.toml")).unwrap();
    assert_eq!(
        t,
        "[mcp_servers.exa-fixture]\nurl = \"https://mcp.exa.ai/mcp\"\n"
    );
}

#[test]
fn a_different_entry_under_the_same_name_needs_replace() {
    let home = scratch("replace");
    fs::create_dir_all(home.join(".pi/agent")).unwrap();
    fs::write(
        home.join(".pi/agent/mcp.json"),
        "{\n  \"mcpServers\": {\n    \"exa-fixture\": {\n      \"command\": \"evil\"\n    }\n  }\n}\n",
    )
    .unwrap();
    let e = entry_file(&home);
    let ef = e.to_str().unwrap();
    let r = go(&home, &no_env(), true, &["pi", "--from", ef, "--write"]);
    assert_eq!(r.code, 1);
    assert!(r.err.contains("--replace"), "{}", r.err);
    let r = go(
        &home,
        &no_env(),
        true,
        &["pi", "--from", ef, "--replace", "--write"],
    );
    assert_eq!(r.code, 0, "{}", r.err);
    assert!(!fs::read_to_string(home.join(".pi/agent/mcp.json"))
        .unwrap()
        .contains("evil"));
    let log = fs::read_to_string(home.join(".derm/connect.log")).unwrap();
    assert!(log.contains("\"action\":\"replace\""));
    // The old file was backed up.
    let backups: Vec<_> = fs::read_dir(home.join(".derm/backups")).unwrap().collect();
    assert_eq!(backups.len(), 1);
}

#[test]
fn remove_takes_the_entry_out() {
    let home = scratch("remove");
    fs::create_dir_all(home.join(".codex")).unwrap();
    fs::write(home.join(".codex/config.toml"), rec("codex-2-after.toml")).unwrap();
    let r = go(
        &home,
        &no_env(),
        true,
        &["codex", "--remove", "exa", "--write"],
    );
    assert_eq!(r.code, 0, "{}", r.err);
    let t = fs::read_to_string(home.join(".codex/config.toml")).unwrap();
    assert!(!t.contains("mcp_servers.exa"));
    assert!(t.contains("[mcp_servers.time]"));
    assert!(t.starts_with("# my settings\n"));
    let r = go(&home, &no_env(), true, &["codex", "--remove", "exa"]);
    assert!(r.out.contains("nothing to remove"));
}

#[test]
fn project_scope_yes_flags_and_unknown_harnesses_are_usage_errors() {
    let home = scratch("usage");
    for args in [
        vec!["pi", "--scope", "project"],
        vec!["pi", "--yes"],
        vec!["pi", "-y"],
        vec!["nope", "--from", "x"],
        vec![],
        vec!["pi", "--expect-sha256", "abc"],
    ] {
        assert_eq!(go(&home, &no_env(), true, &args).code, 2, "{args:?}");
    }
}

#[test]
fn a_managed_path_is_never_written() {
    // Case 65: CODEX_HOME pointed at the folder of the managed file.
    let home = scratch("managed");
    let env = MapEnv(HashMap::from([(
        "CODEX_HOME".to_string(),
        "/etc/codex".to_string(),
    )]));
    let e = entry_file(&home);
    let r = go(
        &home,
        &env,
        true,
        &["codex", "--from", e.to_str().unwrap(), "--write"],
    );
    assert_eq!(r.code, 1);
    assert!(
        r.err.contains("managed file") || r.err.contains("outside your home folder"),
        "{}",
        r.err
    );
    assert!(!Path::new("/etc/codex/config.toml").exists() || r.out.is_empty());
}

#[test]
fn a_file_with_comments_in_a_strict_json_harness_is_refused() {
    let home = scratch("comments");
    fs::create_dir_all(home.join(".pi/agent")).unwrap();
    fs::write(
        home.join(".pi/agent/mcp.json"),
        "{\n  // mine\n  \"mcpServers\": {}\n}\n",
    )
    .unwrap();
    let e = entry_file(&home);
    let r = go(
        &home,
        &no_env(),
        true,
        &["pi", "--from", e.to_str().unwrap()],
    );
    assert_eq!(r.code, 1);
    assert!(r.err.contains("cannot parse"), "{}", r.err);
}

#[test]
fn zed_keeps_comments() {
    let home = scratch("zed");
    let dir = home.join(".config/zed");
    fs::create_dir_all(&dir).unwrap();
    fs::write(
        dir.join("settings.json"),
        "// Zed settings\n{\n  \"theme\": \"One Dark\", // mine\n}\n",
    )
    .unwrap();
    let r = go(
        &home,
        &no_env(),
        true,
        &[
            "zed",
            "--gateway",
            "docker",
            "--profile",
            "derm_github",
            "--write",
        ],
    );
    assert_eq!(r.code, 0, "{}", r.err);
    let t = fs::read_to_string(dir.join("settings.json")).unwrap();
    assert!(
        t.starts_with("// Zed settings\n{\n  \"theme\": \"One Dark\", // mine\n"),
        "{t}"
    );
    assert!(
        t.contains("\"context_servers\": {\n    \"github\": {\n      \"command\": \"docker\""),
        "{t}"
    );
}

#[test]
fn print_only_harnesses_print_and_refuse_write() {
    let home = scratch("print");
    for h in ["hermes", "goose", "openclaw"] {
        let r = go(
            &home,
            &no_env(),
            true,
            &[h, "--gateway", "docker", "--profile", "derm_github"],
        );
        assert_eq!(r.code, 0, "{h}: {}", r.err);
        assert!(r.out.contains("print only"), "{h}");
        assert!(r.out.contains("docker"), "{h}: {}", r.out);
        let w = go(
            &home,
            &no_env(),
            true,
            &[
                h,
                "--gateway",
                "docker",
                "--profile",
                "derm_github",
                "--write",
            ],
        );
        assert_eq!(w.code, 1, "{h}");
    }
}

#[test]
fn host_runner_needs_accept_host_to_write() {
    let home = scratch("host");
    fs::create_dir_all(home.join(".pi/agent")).unwrap();
    let e = home.join("host.json");
    fs::write(
        &e,
        r#"{"name": "io.github.x/time", "version": "1.0.0",
          "packages": [{"registryType": "pypi", "identifier": "mcp-server-time", "version": "1.2.0", "transport": {"type": "stdio"}}],
          "_meta": {"io.modelcontextprotocol.registry/publisher-provided": {"io.github.aetiusgular.derm": {
            "kind": "server", "tier": "own", "status": "active", "runner": {"kind": "host", "note": "runs as you"},
            "exposure": {"default": "direct"}, "trust": {}}}}}"#,
    )
    .unwrap();
    let ef = e.to_str().unwrap();
    let dry = go(&home, &no_env(), true, &["pi", "--from", ef]);
    assert!(dry.out.contains("runs as you"), "{}", dry.out);
    assert!(dry.out.contains("--accept-host"));
    let w = go(&home, &no_env(), true, &["pi", "--from", ef, "--write"]);
    assert_eq!(w.code, 1);
    let w = go(
        &home,
        &no_env(),
        true,
        &["pi", "--from", ef, "--write", "--accept-host"],
    );
    assert_eq!(w.code, 0, "{}", w.err);
    assert!(fs::read_to_string(home.join(".pi/agent/mcp.json"))
        .unwrap()
        .contains("mcp-server-time==1.2.0"));
}

#[test]
fn toolhive_prints_and_refuses_write() {
    let home = scratch("thv");
    fs::create_dir_all(home.join(".pi/agent")).unwrap();
    let r = go(
        &home,
        &no_env(),
        true,
        &["pi", "--gateway", "toolhive", "--workload", "fetch"],
    );
    assert_eq!(r.code, 0, "{}", r.err);
    assert!(r.out.contains("\"thv\""));
    let w = go(
        &home,
        &no_env(),
        true,
        &[
            "pi",
            "--gateway",
            "toolhive",
            "--workload",
            "fetch",
            "--write",
        ],
    );
    assert_eq!(w.code, 1);
    assert!(!home.join(".pi/agent/mcp.json").exists());
}

#[test]
fn allowlist_fragments_print_and_write_nothing() {
    let home = scratch("allow");
    let r = go(
        &home,
        &no_env(),
        true,
        &[
            "claude-code",
            "--allowlist",
            "--gateway",
            "docker",
            "--profile",
            "derm_github",
        ],
    );
    assert_eq!(r.code, 0, "{}", r.err);
    assert!(
        r.out.contains("\"serverCommand\": [\n        \"docker\""),
        "{}",
        r.out
    );
    let e = entry_file(&home);
    let r = go(
        &home,
        &no_env(),
        true,
        &["codex", "--allowlist", "--from", e.to_str().unwrap()],
    );
    assert_eq!(r.code, 0, "{}", r.err);
    assert!(
        r.out.contains("[mcp_servers.exa-fixture.identity]"),
        "{}",
        r.out
    );
    assert!(r.out.contains("url = \"https://mcp.exa.ai/mcp\""));
    let r = go(
        &home,
        &no_env(),
        true,
        &["pi", "--allowlist", "--from", e.to_str().unwrap()],
    );
    assert_eq!(r.code, 1);
    assert_eq!(
        fs::read_dir(&home).unwrap().count(),
        1,
        "only the entry file"
    );
}

#[test]
fn list_and_path() {
    let home = scratch("list");
    let r = go(&home, &no_env(), true, &["--list"]);
    assert_eq!(r.code, 0);
    // A header line and one per row of `harnesses` (fourteen, and the four
    // lane Q verified in wave 4).
    assert_eq!(r.out.lines().count(), 19, "{}", r.out);
    let r = go(&home, &no_env(), true, &["claude-code", "--path"]);
    assert_eq!(
        r.out.trim(),
        home.join(".claude.json").display().to_string()
    );
}

#[test]
fn a_symlinked_config_is_refused() {
    let home = scratch("symlink");
    fs::create_dir_all(home.join(".pi/agent")).unwrap();
    let real = home.join("real.json");
    fs::write(&real, "{}").unwrap();
    std::os::unix::fs::symlink(&real, home.join(".pi/agent/mcp.json")).unwrap();
    let e = entry_file(&home);
    let r = go(
        &home,
        &no_env(),
        true,
        &["pi", "--from", e.to_str().unwrap(), "--write"],
    );
    assert_eq!(r.code, 1);
    assert!(r.err.contains("symlink"));
    assert_eq!(fs::read_to_string(&real).unwrap(), "{}");
}

#[test]
fn a_reserved_claude_code_name_is_refused() {
    let home = scratch("reserved");
    let r = go(
        &home,
        &no_env(),
        true,
        &[
            "claude-code",
            "--gateway",
            "docker",
            "--profile",
            "derm_x",
            "--name",
            "computer-use",
        ],
    );
    assert_eq!(r.code, 1);
    assert!(r.err.contains("keeps for itself"), "{}", r.err);
}

#[test]
fn a_custom_codex_home_outside_home_is_refused() {
    let home = scratch("codexhome");
    let env = MapEnv(HashMap::from([(
        "CODEX_HOME".to_string(),
        "/srv/codex".to_string(),
    )]));
    let e = entry_file(&home);
    let r = go(
        &home,
        &env,
        true,
        &["codex", "--from", e.to_str().unwrap(), "--write"],
    );
    assert_eq!(r.code, 1);
    assert!(r.err.contains("outside your home folder"), "{}", r.err);
}

#[test]
fn an_entry_that_expands_a_variable_into_its_url_is_refused() {
    let home = scratch("exfil");
    let e = home.join("x.json");
    let text = include_str!("../../../../contracts/fixtures/entry/server.json").replace(
        "https://mcp.exa.ai/mcp",
        "https://mcp.exa.ai/mcp?k=$GITHUB_TOKEN",
    );
    fs::write(&e, text).unwrap();
    let r = go(
        &home,
        &no_env(),
        true,
        &["pi", "--from", e.to_str().unwrap()],
    );
    assert_eq!(r.code, 1);
    assert!(
        r.err.contains("expanded from your environment"),
        "{}",
        r.err
    );
}

// Mac test w1, finding M3: the dry run printed unchanged context lines of
// `~/.codex/config.toml` verbatim, and two of them were API keys. Every
// printed line (context, removed, added) goes through the redactor.
// Visibly fake, still in the shapes the redactor knows (review R8).
const FAKE_OPENAI: &str = "sk-proj-FAKEFAKEFAKE0000000000000000000000";
const FAKE_ANTHROPIC: &str = "sk-ant-api03-FAKEFAKEFAKE00000000000000000";
const FAKE_OPAQUE: &str = "FAKE0FAKE1FAKE2FAKE3FAKE4FAKE5FAKE6";

#[test]
fn the_dry_run_prints_no_secret_from_the_lines_around_the_change() {
    let home = scratch("m3-context");
    fs::create_dir_all(home.join(".codex")).unwrap();
    fs::write(
        home.join(".codex/config.toml"),
        format!(
            "model = \"gpt-5\"\n\n[shell_environment_policy.set]\nOPENAI_API_KEY = \"{FAKE_OPENAI}\"\nANTHROPIC_API_KEY = \"{FAKE_ANTHROPIC}\"\nSERVICE_SECRET = '{FAKE_OPAQUE}'\n"
        ),
    )
    .unwrap();
    let r = go(
        &home,
        &no_env(),
        true,
        &["codex", "--gateway", "docker", "--profile", "derm_exa"],
    );
    assert_eq!(r.code, 0, "{}", r.err);
    assert!(r.out.contains("+[mcp_servers.exa]"), "{}", r.out);
    for s in [FAKE_OPENAI, FAKE_ANTHROPIC, FAKE_OPAQUE] {
        assert!(!r.out.contains(s), "{}", r.out);
    }
    // The context is still there, with its keys.
    assert!(
        r.out.contains(" OPENAI_API_KEY = \"[redacted]\""),
        "{}",
        r.out
    );
}

#[test]
fn removing_an_entry_prints_no_secret_from_its_lines() {
    let home = scratch("m3-remove");
    fs::write(
        home.join(".claude.json"),
        format!(
            "{{\n  \"mcpServers\": {{\n    \"supabase\": {{\n      \"command\": \"npx\",\n      \"args\": [\"-y\", \"@supabase/mcp-server-supabase\", \"--access-token\", \"sbp_{FAKE_OPAQUE}\"],\n      \"env\": {{\n        \"SUPABASE_ACCESS_TOKEN\": \"plain-but-named-{FAKE_OPAQUE}\",\n        \"DATABASE_URL\": \"postgresql://postgres:hunter2pass@db.example.supabase.co:5432/postgres\",\n        \"X_CUSTOM\": \"{FAKE_OPAQUE}\"\n      }},\n      \"headers\": {{\"Authorization\": \"Bearer opaqueBearerValue\"}}\n    }}\n  }}\n}}\n"
        ),
    )
    .unwrap();
    let r = go(
        &home,
        &no_env(),
        true,
        &["claude-code", "--remove", "supabase"],
    );
    assert_eq!(r.code, 0, "{}", r.err);
    assert!(r.out.contains("-    \"supabase\": {"), "{}", r.out);
    for s in [FAKE_OPAQUE, "hunter2pass", "opaqueBearerValue"] {
        assert!(!r.out.contains(s), "{s} in {}", r.out);
    }
}

// Box test w1, BX11: the allowlist for the T0.1 HTTP gateway named the
// stdio command. C10 ran without `--url`; with the same flags as the write
// the fragment names the URL the entry uses.
#[test]
fn the_allowlist_for_an_http_gateway_names_its_url() {
    let home = scratch("bx11");
    let r = go(
        &home,
        &no_env(),
        true,
        &[
            "claude-code",
            "--allowlist",
            "--gateway",
            "docker",
            "--profile",
            "derm_box",
            "--url",
            "http://127.0.0.1:8811/mcp",
            "--bearer-env",
            "DERM_GATEWAY_TOKEN",
        ],
    );
    assert_eq!(r.code, 0, "{}", r.err);
    assert!(
        r.out
            .contains("\"serverUrl\": \"http://127.0.0.1:8811/mcp\""),
        "{}",
        r.out
    );
    assert!(!r.out.contains("serverCommand"), "{}", r.out);
    let r = go(
        &home,
        &no_env(),
        true,
        &[
            "codex",
            "--allowlist",
            "--gateway",
            "docker",
            "--profile",
            "derm_box",
            "--url",
            "http://127.0.0.1:8811/mcp",
        ],
    );
    assert!(
        r.out.contains("url = \"http://127.0.0.1:8811/mcp\""),
        "{}",
        r.out
    );
}

// Mac test w1, M5: `identity.command = "docker"` matches any server named
// `exa` that docker starts (Codex's configuration reference: "The string
// form doesn't inspect arguments"). The fragment pins the executable and
// every argument with the matcher table (openai/codex#29648).
#[test]
fn the_codex_allowlist_pins_the_arguments_of_a_stdio_server() {
    let home = scratch("m5");
    let r = go(
        &home,
        &no_env(),
        true,
        &[
            "codex",
            "--allowlist",
            "--gateway",
            "docker",
            "--profile",
            "derm_exa",
        ],
    );
    assert_eq!(r.code, 0, "{}", r.err);
    assert!(
        r.out
            .contains("[mcp_servers.exa.identity.command]\nexecutable = \"docker\"\n"),
        "{}",
        r.out
    );
    for a in ["mcp", "gateway", "run", "--profile", "derm_exa"] {
        assert!(
            r.out
                .contains(&format!("  {{ match = \"exact\", value = \"{a}\" }},\n")),
            "{a}: {}",
            r.out
        );
    }
    assert!(!r.out.contains("command = \"docker\""), "{}", r.out);
    // The fragment is TOML a parser takes, with the shape Codex documents.
    let body: String = r
        .out
        .lines()
        .filter(|l| !l.starts_with('#'))
        .collect::<Vec<_>>()
        .join("\n");
    let v: toml_edit::DocumentMut = body.parse().unwrap();
    let cmd = &v["mcp_servers"]["exa"]["identity"]["command"];
    assert_eq!(cmd["executable"].as_str(), Some("docker"));
    assert_eq!(cmd["args"].as_array().unwrap().len(), 5);
}

// Box test w1, BX6: Pi 1.4.0 refuses a server whose header variable is
// unset or empty ("Failed to resolve MCP server ... from environment
// variable", run on the box and in the cloud). Context7's key is optional
// (`isRequired: false`), so for Pi derm leaves an optional header out while
// its variable is unset, and says so; with the variable set it is kept.
#[test]
fn pi_leaves_out_an_optional_header_whose_variable_is_unset() {
    let home = scratch("bx6");
    fs::create_dir_all(home.join(".pi/agent")).unwrap();
    let e = home.join("context7.json");
    fs::write(
        &e,
        include_str!("../../../../library/catalog/context7/server.json"),
    )
    .unwrap();
    let ef = e.to_str().unwrap();
    let r = go(&home, &no_env(), true, &["pi", "--from", ef]);
    assert_eq!(r.code, 0, "{}", r.err);
    assert!(
        !r.out.contains("+        \"CONTEXT7_API_KEY\""),
        "{}",
        r.out
    );
    assert!(r.out.contains("CONTEXT7_API_KEY is optional"), "{}", r.out);
    // The header's variable is namespaced to the server (S12).
    let set = MapEnv(HashMap::from([(
        "DERM_CONTEXT7__CONTEXT7_API_KEY".to_string(),
        "k".to_string(),
    )]));
    let r = go(&home, &set, true, &["pi", "--from", ef]);
    assert!(
        r.out
            .contains("\"CONTEXT7_API_KEY\": \"${DERM_CONTEXT7__CONTEXT7_API_KEY}\""),
        "{}",
        r.out
    );
    // Another harness keeps the header: only Pi refuses an unset variable.
    fs::create_dir_all(home.join(".config/opencode")).unwrap();
    let r = go(&home, &no_env(), true, &["opencode", "--from", ef]);
    assert!(r.out.contains("CONTEXT7_API_KEY"), "{}", r.out);
    assert!(!r.out.contains("is optional"), "{}", r.out);
}

// Fix pass review R5: a TOML parse error quoted the broken line, key and
// all. The error keeps the line and column only.
#[test]
fn a_toml_parse_error_does_not_quote_the_file() {
    let home = scratch("r5");
    fs::create_dir_all(home.join(".codex")).unwrap();
    fs::write(
        home.join(".codex/config.toml"),
        "OPENAI_API_KEY = \"FAKE-not-a-key-0000000000000000\" oops\n",
    )
    .unwrap();
    let r = go(
        &home,
        &no_env(),
        true,
        &["codex", "--gateway", "docker", "--profile", "derm_exa"],
    );
    assert_eq!(r.code, 1);
    assert!(!r.err.contains("FAKE-not-a-key"), "{}", r.err);
    assert!(r.err.contains("line 1"), "{}", r.err);
}

// Re-review W2-R1's residue (integration w2): in the single-underscore
// forms (OpenCode's and Kilo's `s_t`, Gemini's and Crush's `mcp_s_t`,
// oh-my-pi's `mcp__s_t`) a server `exa-evil` reaches the gate as
// `exa_evil_<tool>`, which a listed `exa` takes (`contracts/policy.md`
// section 4, step 3a, the open note). derm connect refuses to write such a
// pair; the person picks another name with --name.
#[test]
fn a_name_one_underscore_away_from_a_configured_server_is_refused() {
    let home = scratch("w2r1");
    let cfg = home.join(".config/opencode/opencode.json");
    fs::create_dir_all(cfg.parent().unwrap()).unwrap();
    let before = "{\n  \"mcp\": {\n    \"exa\": {\n      \"type\": \"remote\",\n      \"url\": \"https://mcp.exa.ai/mcp\"\n    }\n  }\n}\n";
    fs::write(&cfg, before).unwrap();
    let e = entry_file(&home);
    let ef = e.to_str().unwrap();
    for name in ["exa-evil", "exa-", "EXA"] {
        if !super::spec::valid_server_name(name) {
            continue;
        }
        let r = go(
            &home,
            &no_env(),
            true,
            &["opencode", "--from", ef, "--name", name, "--write"],
        );
        assert_eq!(r.code, 1, "{name}: {}", r.out);
        assert!(r.err.contains("one `_`"), "{name}: {}", r.err);
        assert_eq!(fs::read_to_string(&cfg).unwrap(), before, "{name}");
    }
    // The reverse: `exa` next to a configured `exa-evil`.
    let other = home.join("other");
    let cfg2 = other.join(".config/opencode/opencode.json");
    fs::create_dir_all(cfg2.parent().unwrap()).unwrap();
    fs::write(&cfg2, before.replace("\"exa\"", "\"exa-evil\"")).unwrap();
    let r = go(
        &other,
        &no_env(),
        true,
        &["opencode", "--from", ef, "--name", "exa"],
    );
    assert_eq!(r.code, 1, "{}", r.out);
    // A name in the policy's `servers` counts, with nothing in the file.
    let third = home.join("third");
    fs::create_dir_all(third.join(".config/opencode")).unwrap();
    fs::create_dir_all(third.join(".derm")).unwrap();
    fs::write(
        third.join(".derm/policy.json"),
        "{\"version\": 1, \"servers\": [\"exa\"], \"rules\": []}",
    )
    .unwrap();
    let r = go(
        &third,
        &no_env(),
        true,
        &["opencode", "--from", ef, "--name", "exa-evil"],
    );
    assert_eq!(r.code, 1, "{}", r.out);
    // A double-underscore agent splits `mcp__exa-evil__t` plainly: allowed.
    fs::create_dir_all(third.join(".claude")).unwrap();
    let r = go(
        &third,
        &no_env(),
        true,
        &["claude-code", "--from", ef, "--name", "exa-evil"],
    );
    assert_eq!(r.code, 0, "{}", r.err);
    // An unrelated name is fine on OpenCode too.
    let r = go(
        &home,
        &no_env(),
        true,
        &["opencode", "--from", ef, "--name", "search"],
    );
    assert_eq!(r.code, 0, "{}", r.err);
}

// `--check-names` lists W2-R1's pairs that derm connect did not write: a
// project's own `opencode.json` can bring `exa_evil` beside the user's `exa`.
// It reads the project file and never writes it.
#[test]
fn check_names_lists_the_pairs_in_the_user_project_and_policy_files() {
    let home = scratch("checknames");
    let user = home.join(".config/opencode/opencode.json");
    fs::create_dir_all(user.parent().unwrap()).unwrap();
    fs::write(
        &user,
        "{\"mcp\": {\"exa\": {\"type\": \"remote\", \"url\": \"https://mcp.exa.ai/mcp\"}}}\n",
    )
    .unwrap();
    let r = go(&home, &no_env(), true, &["opencode", "--check-names"]);
    assert_eq!(r.code, 0, "{}{}", r.out, r.err);
    assert!(r.out.contains("no two server names"), "{}", r.out);
    let proj = home.join("proj");
    fs::create_dir_all(&proj).unwrap();
    let project_text = "{\n  // a project's own servers\n  \"mcp\": {\"exa_evil\": {\"type\": \"local\", \"command\": [\"x\"]}}\n}\n";
    fs::write(proj.join("opencode.json"), project_text).unwrap();
    let r = go(&home, &no_env(), true, &["opencode", "--check-names"]);
    assert_eq!(r.code, 1, "{}{}", r.out, r.err);
    assert!(r.out.contains("pair: `exa` (user file"), "{}", r.out);
    assert!(r.out.contains("`exa_evil` (project file"), "{}", r.out);
    assert_eq!(
        fs::read_to_string(proj.join("opencode.json")).unwrap(),
        project_text
    );
    // The policy's servers are read too, through DERM_POLICY when absolute.
    let pol = home.join("p.json");
    fs::write(
        &pol,
        "{\"version\": 1, \"servers\": [\"search\"], \"rules\": []}",
    )
    .unwrap();
    fs::write(
        &user,
        "{\"mcp\": {\"search-x\": {\"type\": \"remote\", \"url\": \"https://h.example/mcp\"}}}\n",
    )
    .unwrap();
    fs::remove_file(proj.join("opencode.json")).unwrap();
    let env = MapEnv(HashMap::from([(
        "DERM_POLICY".to_string(),
        pol.display().to_string(),
    )]));
    let r = go(&home, &env, true, &["opencode", "--check-names"]);
    assert_eq!(r.code, 1, "{}{}", r.out, r.err);
    assert!(r.out.contains("`search` (policy"), "{}", r.out);
    // A double-underscore agent has nothing to check.
    let r = go(&home, &no_env(), true, &["claude-code", "--check-names"]);
    assert_eq!(r.code, 0);
    assert!(r.out.contains("nothing to check"), "{}", r.out);
    // It takes the harness alone.
    let r = go(
        &home,
        &no_env(),
        true,
        &["opencode", "--check-names", "--write"],
    );
    assert_eq!(r.code, 1);
}

// Integration w1, lane F's request: `--allowlist` with no server prints the
// gate plugin's own managed fragment, as the fragments' comments say.
#[test]
fn allowlist_alone_prints_the_plugins_managed_fragment() {
    let home = scratch("allowfrag");
    let r = go(&home, &no_env(), true, &["claude-code", "--allowlist"]);
    assert_eq!(r.code, 0, "{}", r.err);
    assert!(
        r.out.contains(include_str!(
            "../../../../packages/derm-claude-plugin/managed-settings.fragment.json"
        )),
        "{}",
        r.out
    );
    let r = go(&home, &no_env(), true, &["codex", "--allowlist"]);
    assert_eq!(r.code, 0, "{}", r.err);
    assert!(
        r.out.contains(include_str!(
            "../../../../packages/derm-codex-plugin/requirements.fragment.toml"
        )),
        "{}",
        r.out
    );
    // Other agents have no plugin fragment; a server is still needed.
    let r = go(&home, &no_env(), true, &["pi", "--allowlist"]);
    assert_eq!(r.code, 1);
}

/// Rows wave 4 lane Q verified and staged in `connect/promoted/`, which
/// integration w4 folded into their `presets/` rows beside `coverage` and
/// moved from `planned` to `harnesses` (lane Q's request 9).
const PROMOTED: &[&str] = &["kilo", "codebuff", "oh-my-pi", "continue"];

fn promoted(id: &str) -> presets::Preset {
    presets::find(id).unwrap_or_else(|| panic!("presets/{id}.json"))
}

#[test]
fn promoted_rows_are_verified_and_in_harnesses() {
    let table: serde_json::Value = serde_json::from_str(presets::table_json()).unwrap();
    let harnesses = table["harnesses"].as_array().unwrap();
    let planned = table["planned"].as_array().unwrap();
    for id in PROMOTED {
        let row = harnesses
            .iter()
            .find(|r| r["id"] == *id)
            .unwrap_or_else(|| panic!("{id} is not in `harnesses`"));
        assert!(!planned.iter().any(|r| r["id"] == *id), "{id}");
        assert!(row.get("mcpFile").is_none(), "{id}: mcpFile was the planned row's");
        assert!(row.get("coverage").is_some(), "{id}: keeps its coverage");
        assert!(!row.to_string().contains("\"TODO\""), "{id}");
        let p = promoted(id);
        assert_eq!(p.id, *id);
        assert!(p.verified.starts_with("2026-"), "{id}");
        assert!(!p.sources.is_empty(), "{id}");
        assert!(p.write == "write" || p.write_note.is_some(), "{id}");
        assert!(p.cli.is_some(), "{id}");
    }
}

/// Kilo 7.8.18 keeps OpenCode 1.19.4's entry schema: the same render, in
/// ~/.config/kilo/kilo.json, whatever KILO_CONFIG_DIR says (it does not
/// move the global folder, `core/src/global.ts:24`).
#[test]
fn kilo_gets_opencodes_entry_in_its_global_folder() {
    let p = promoted("kilo");
    let oc = presets::find("opencode").unwrap();
    let render = |p: &presets::Preset| match compute(p, "", Some(&fs_server()), None, false) {
        Ok(Change::Text(t)) => t,
        _ => panic!("{}", p.id),
    };
    let t = render(&p);
    assert_eq!(t, render(&oc));
    assert!(t.contains("\"TOKEN\": \"{env:TOKEN}\""), "{t}");
    let home = Path::new("/home/u");
    let env = MapEnv(HashMap::from([(
        "KILO_CONFIG_DIR".to_string(),
        "/home/u/kc".to_string(),
    )]));
    assert_eq!(
        p.user_path(home, false, &env).unwrap(),
        home.join(".config/kilo/kilo.json")
    );
    let xdg = MapEnv(HashMap::from([(
        "XDG_CONFIG_HOME".to_string(),
        "/home/u/x".to_string(),
    )]));
    assert_eq!(
        p.user_path(home, false, &xdg).unwrap(),
        Path::new("/home/u/x/kilo/kilo.json")
    );
}

/// Codebuff 1.0.688 (read at v1.0.679 and main, which agree): strict
/// entries, a whole-value `$VAR` in a stdio `env`, no expansion in headers,
/// and an unset variable drops every server in the file.
#[test]
fn codebuff_writes_only_what_its_strict_schema_and_loader_read() {
    let p = promoted("codebuff");
    match compute(&p, "", Some(&fs_server()), None, false) {
        Ok(Change::Text(t)) => {
            let v = super::json::parse(&t, false)
                .unwrap()
                .root
                .unwrap()
                .to_value();
            let e = v.get_path(&["mcpServers"]).unwrap();
            let (_, entry) = match e {
                super::json::Value::Object(m) => m[0].clone(),
                _ => panic!("{t}"),
            };
            let keys: Vec<String> = match &entry {
                super::json::Value::Object(m) => m.iter().map(|(k, _)| k.clone()).collect(),
                _ => panic!(),
            };
            assert_eq!(keys, ["type", "command", "args", "env"], "{t}");
            assert!(t.contains("\"TOKEN\": \"$TOKEN\""), "{t}");
            assert!(t.ends_with('\n'));
        }
        _ => panic!(),
    }
    let e = compute(
        &p,
        "",
        Some(&http(
            "exa",
            "https://mcp.exa.ai/mcp",
            vec![bearer("EXA_KEY")],
        )),
        None,
        false,
    )
    .err()
    .unwrap();
    assert!(e.contains("never expands a header"), "{e}");
    match compute(
        &p,
        "",
        Some(&http("open", "https://h.example/mcp", vec![])),
        None,
        false,
    ) {
        Ok(Change::Text(t)) => {
            assert!(t.contains("\"type\": \"http\""), "{t}");
            assert!(t.contains("\"url\": \"https://h.example/mcp\""), "{t}");
        }
        _ => panic!(),
    }
    let none = no_env();
    let e = super::codebuff_env_is_set(&p, &fs_server(), &none).unwrap_err();
    assert!(
        e.contains("drops every server") && e.contains("TOKEN"),
        "{e}"
    );
    let set = MapEnv(HashMap::from([("TOKEN".to_string(), "x".to_string())]));
    assert!(super::codebuff_env_is_set(&p, &fs_server(), &set).is_ok());
    let oc = presets::find("opencode").unwrap();
    assert!(super::codebuff_env_is_set(&oc, &fs_server(), &none).is_ok());
}

/// oh-my-pi 18.16.0: Claude Code's entry shape with `${VAR}`, the agent
/// folder moved by PI_CODING_AGENT_DIR, and a literal header that names a
/// set variable refused (oh-my-pi would send the variable's value).
#[test]
fn oh_my_pi_reads_a_literal_that_names_a_variable_as_the_variable() {
    let p = promoted("oh-my-pi");
    match compute(&p, "", Some(&fs_server()), None, false) {
        Ok(Change::Text(t)) => {
            assert!(t.contains("\"TOKEN\": \"${TOKEN}\""), "{t}");
            assert!(t.contains("\"type\": \"stdio\""), "{t}");
            assert!(!t.ends_with('\n'));
        }
        _ => panic!(),
    }
    let home = Path::new("/home/u");
    let env = MapEnv(HashMap::from([(
        "PI_CODING_AGENT_DIR".to_string(),
        "/srv/omp".to_string(),
    )]));
    assert_eq!(
        p.user_path(home, false, &env).unwrap(),
        Path::new("/srv/omp/mcp.json")
    );
    assert_eq!(
        p.user_path(home, false, &no_env()).unwrap(),
        home.join(".omp/agent/mcp.json")
    );
    let lit = |v: &str| Header {
        name: "X-Where".into(),
        value: HeaderValue::Literal(v.into()),
        optional: false,
    };
    let set = MapEnv(HashMap::from([("HOME".to_string(), "/home/u".to_string())]));
    let e = super::omp_literal_names_no_variable(
        &p,
        &http("h", "https://h.example/mcp", vec![lit("HOME")]),
        &set,
    )
    .unwrap_err();
    assert!(e.contains("names a set variable"), "{e}");
    assert!(super::omp_literal_names_no_variable(
        &p,
        &http("h", "https://h.example/mcp", vec![lit("v1")]),
        &set
    )
    .is_ok());
    let claude = presets::find("claude-code").unwrap();
    assert!(super::omp_literal_names_no_variable(
        &claude,
        &http("h", "https://h.example/mcp", vec![lit("HOME")]),
        &set
    )
    .is_ok());
}

/// Continue CLI 1.5.47: printed as a YAML list item, with
/// `${{ secrets.VAR }}` references, `streamable-http` for HTTP and headers
/// under `requestOptions`.
#[test]
fn continue_prints_a_list_item_with_secret_templates() {
    let p = promoted("continue");
    assert!(!p.writes());
    let r = super::render::render(&p, &fs_server()).unwrap();
    let y = match r {
        super::render::Rendered::Yaml(y) => y,
        _ => panic!(),
    };
    assert!(
        y.starts_with("mcpServers:\n  - name: \"fs\"\n    type: stdio\n"),
        "{y}"
    );
    assert!(y.contains("TOKEN: \"${{ secrets.TOKEN }}\""), "{y}");
    let h = super::render::render(
        &p,
        &http("exa", "https://mcp.exa.ai/mcp", vec![bearer("EXA_KEY")]),
    )
    .unwrap();
    let y = match h {
        super::render::Rendered::Yaml(y) => y,
        _ => panic!(),
    };
    assert!(y.contains("type: streamable-http"), "{y}");
    assert!(y.contains("requestOptions:\n      headers:\n"), "{y}");
    assert!(y.contains("\"Bearer ${{ secrets.EXA_KEY }}\""), "{y}");
    let home = Path::new("/home/u");
    let env = MapEnv(HashMap::from([(
        "CONTINUE_GLOBAL_DIR".to_string(),
        "/srv/cn".to_string(),
    )]));
    assert_eq!(
        p.user_path(home, false, &env).unwrap(),
        Path::new("/srv/cn/config.yaml")
    );
}
