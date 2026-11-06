use super::*;

const CHAT: &str = "chat-j";
const ROOT: u32 = 1000;

fn ev(source: Source, kind: &str, at: i64, pid: Option<u32>, detail: Value) -> Event {
    Event {
        id: format!("{kind}-{at}-{}", pid.unwrap_or(0)),
        at,
        chat_id: CHAT.into(),
        harness: "claude-code".into(),
        source,
        kind: kind.into(),
        summary: String::new(),
        detail,
        pid,
        approval_id: None,
    }
}

fn start(j: &mut Join) {
    j.observe(&ev(
        Source::Run,
        "run.start",
        0,
        Some(ROOT),
        json!({"cwd": "/w"}),
    ));
}

/// `run.start` under a boundary, with the harness's executable as `derm run`
/// resolved it (or none, as for a harness `derm run` could not resolve).
fn start_under(j: &mut Join, boundary: &str, exe: Option<&str>) {
    j.observe(&ev(
        Source::Run,
        "run.start",
        0,
        Some(ROOT),
        json!({"cwd": "/w", "boundary": boundary, "harnessExe": exe}),
    ));
}

/// A tool call: the tap sees it at `t`, the gate allows it at `t + 10`, the
/// hook reports it ran at `end`.
fn call(j: &mut Join, id: &str, tool: &str, paths: &[&str], t: i64, end: Option<i64>) {
    let mut e = ev(
        Source::Tap,
        "tap.call",
        t,
        None,
        json!({"callId": id, "toolNormalized": tool, "paths": paths, "resultSha256": null}),
    );
    e.id = format!("tap-{CHAT}-{id}");
    j.observe(&e);
    j.observe(&ev(
        Source::Adapter,
        "approval",
        t + 10,
        None,
        json!({"toolUseId": id, "decision": "allow"}),
    ));
    if let Some(end) = end {
        j.observe(&ev(
            Source::Adapter,
            "tool.call",
            end,
            None,
            json!({"toolUseId": id}),
        ));
    }
}

fn effect(j: &mut Join, kind: &str, at: i64, pid: u32, ppid: u32, extra: Value) -> Vec<Event> {
    let mut d = json!({"ppid": ppid, "auditAt": at});
    if let Value::Object(m) = extra {
        for (k, v) in m {
            d[k] = v;
        }
    }
    j.observe(&ev(Source::Auditd, kind, at + 50, Some(pid), d))
}

#[test]
fn a_process_a_call_starts_and_its_children_are_that_calls() {
    let mut j = Join::new();
    start(&mut j);
    call(&mut j, "toolu_A", "bash", &[], 1_000, Some(5_000));
    // The harness forks a shell while only A runs; the shell forks again.
    assert!(effect(&mut j, "fork", 1_100, ROOT, 1, json!({"child": 2001})).is_empty());
    // The program is known at the exec: a shell for a shell call (case 43).
    let r = effect(
        &mut j,
        "exec",
        1_110,
        2001,
        ROOT,
        json!({"exe": "/usr/bin/bash"}),
    );
    assert_eq!(r[0].detail["chosen"], "tap-chat-j-toolu_A");
    effect(&mut j, "fork", 1_200, 2001, ROOT, json!({"child": 2002}));
    let r = effect(
        &mut j,
        "write",
        1_300,
        2002,
        2001,
        json!({"path": "/w/out.txt"}),
    );
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].kind, "join.candidates");
    assert_eq!(r[0].source, Source::Derm);
    assert_eq!(r[0].detail["candidates"][0]["by"], "tree");
    assert_eq!(r[0].detail["chosen"], "tap-chat-j-toolu_A");
    assert_eq!(r[0].detail["effect"], "write-1350-2002");
    assert_eq!(r[0].id, "join-write-1350-2002");
}

#[test]
fn case_123_two_overlapping_calls_make_a_candidate_set_with_no_choice() {
    let mut j = Join::new();
    start(&mut j);
    call(&mut j, "toolu_A", "bash", &[], 1_000, Some(9_000));
    call(&mut j, "toolu_B", "bash", &[], 1_500, Some(9_000));
    // A child of the harness while both run belongs to neither.
    effect(&mut j, "fork", 2_000, ROOT, 1, json!({"child": 3001}));
    let r = effect(&mut j, "write", 2_100, 3001, ROOT, json!({"path": "/w/x"}));
    let c = r[0].detail["candidates"].as_array().unwrap();
    assert_eq!(c.len(), 2);
    assert!(c.iter().all(|x| x["by"] == "window"));
    assert_eq!(r[0].detail["chosen"], Value::Null);
    assert_eq!(r[0].summary, "write fits 2 calls");
}

#[test]
fn a_path_one_running_call_names_picks_it_and_two_names_make_a_set() {
    let mut j = Join::new();
    start(&mut j);
    call(&mut j, "toolu_E", "edit", &["src/a.rs"], 1_000, Some(9_000));
    call(
        &mut j,
        "toolu_F",
        "edit",
        &["/w/src/b.rs"],
        1_000,
        Some(9_000),
    );
    // The harness writes in-process: the tree says nothing, the path does.
    let r = effect(
        &mut j,
        "write",
        2_000,
        ROOT,
        1,
        json!({"path": "/w/src/a.rs"}),
    );
    assert_eq!(r[0].detail["chosen"], "tap-chat-j-toolu_E");
    assert_eq!(r[0].detail["candidates"][0]["by"], "path");
    call(
        &mut j,
        "toolu_G",
        "edit",
        &["./src/b.rs"],
        1_200,
        Some(9_000),
    );
    let r = effect(
        &mut j,
        "rename",
        2_500,
        ROOT,
        1,
        json!({"path": "/w/tmp", "dest": "/w/src/b.rs"}),
    );
    assert_eq!(r[0].detail["candidates"].as_array().unwrap().len(), 2);
    assert_eq!(r[0].detail["chosen"], Value::Null);
}

#[test]
fn an_mcp_servers_writes_are_credited_to_the_mcp_calls_it_served() {
    let mut j = Join::new();
    start(&mut j);
    // The server starts with the session, before any call.
    effect(&mut j, "fork", 100, ROOT, 1, json!({"child": 4001}));
    effect(&mut j, "exec", 110, 4001, ROOT, json!({}));
    call(&mut j, "toolu_M", "files/write", &[], 1_000, Some(3_000));
    call(&mut j, "toolu_N", "bash", &[], 1_000, Some(3_000));
    let r = effect(
        &mut j,
        "write",
        1_500,
        4001,
        ROOT,
        json!({"path": "/w/data.json"}),
    );
    let c = r[0].detail["candidates"].as_array().unwrap();
    assert_eq!(c.len(), 1);
    assert_eq!(c[0]["by"], "mcp-server");
    assert_eq!(c[0]["call"], "tap-chat-j-toolu_M");
    assert_eq!(r[0].detail["chosen"], Value::Null);
    // Between calls, the server's writes fit nothing and get no record.
    assert!(effect(
        &mut j,
        "write",
        60_000_000,
        4001,
        ROOT,
        json!({"path": "/w/data.json"})
    )
    .is_empty());
}

#[test]
fn a_denied_call_owns_nothing_and_an_ended_call_stops_owning_new_children() {
    let mut j = Join::new();
    start(&mut j);
    let mut e = ev(
        Source::Tap,
        "tap.call",
        1_000,
        None,
        json!({"callId": "toolu_D", "toolNormalized": "bash", "paths": []}),
    );
    e.id = "tap-chat-j-toolu_D".into();
    j.observe(&e);
    j.observe(&ev(
        Source::Adapter,
        "approval",
        1_010,
        None,
        json!({"toolUseId": "toolu_D", "decision": "deny"}),
    ));
    assert!(effect(&mut j, "write", 4_000, ROOT, 1, json!({"path": "/w/y"})).is_empty());
    call(&mut j, "toolu_A", "bash", &[], 10_000, Some(11_000));
    effect(&mut j, "fork", 20_000, ROOT, 1, json!({"child": 5001}));
    assert!(effect(&mut j, "write", 20_100, 5001, ROOT, json!({"path": "/w/z"})).is_empty());
}

#[test]
fn a_result_from_the_tap_ends_a_call_the_hook_never_reported() {
    let mut j = Join::new();
    start(&mut j);
    call(&mut j, "toolu_R", "bash", &[], 1_000, None);
    let mut done = ev(
        Source::Tap,
        "tap.call",
        2_000,
        None,
        json!({"callId": "toolu_R", "toolNormalized": "bash", "paths": [], "resultSha256": "00"}),
    );
    done.id = "tap-chat-j-toolu_R".into();
    j.observe(&done);
    assert!(effect(&mut j, "write", 100_000, ROOT, 1, json!({"path": "/w/q"})).is_empty());
    assert_eq!(
        effect(&mut j, "write", 1_900, ROOT, 1, json!({"path": "/w/q"})).len(),
        1
    );
}

#[test]
fn records_follow_the_wave5_schema_shape_and_other_chats_never_mix() {
    let mut j = Join::new();
    start(&mut j);
    call(&mut j, "toolu_A", "bash", &[], 1_000, Some(9_000));
    let mut other = ev(
        Source::Auditd,
        "write",
        2_050,
        Some(ROOT),
        json!({"ppid": 1, "auditAt": 2_000, "path": "/w/x"}),
    );
    other.chat_id = "chat-other".into();
    assert!(j.observe(&other).is_empty());
    let r = effect(
        &mut j,
        "net.connect",
        2_000,
        ROOT,
        1,
        json!({"host": "example.com:443"}),
    );
    let d = &r[0].detail;
    assert_eq!(d["trust"], "daemon");
    assert_eq!(d["effectKind"], "net.connect");
    for c in d["candidates"].as_array().unwrap() {
        let keys: Vec<&String> = c.as_object().unwrap().keys().collect();
        assert_eq!(keys, vec!["by", "call", "why"]);
    }
    let keys: Vec<&String> = d.as_object().unwrap().keys().collect();
    assert_eq!(
        keys,
        vec!["candidates", "chosen", "effect", "effectKind", "trust"]
    );
    // After the stop and past the keep for late effects (MW5-17; before,
    // the chat was dropped at the stop itself), the chat records nothing.
    j.observe(&ev(Source::Run, "run.stop", 99_000, Some(ROOT), json!({})));
    let mut late = ev(
        Source::Auditd,
        "write",
        99_000 + STOPPED_KEEP_MS + 1,
        Some(ROOT),
        json!({"ppid": 1, "auditAt": 2_000, "path": "/w/x"}),
    );
    late.id = "late".into();
    assert!(j.observe(&late).is_empty());
}

/// Box test w5, BW5-11: Claude Code started its MCP servers (`uv`, `npm
/// exec`) while one Bash call ran, and the join credited every write they
/// made to that call "by tree". A harness child is the call's only when it is
/// a shell started for a shell call; anything else is no call's for certain.
#[test]
fn a_helper_the_harness_starts_during_a_shell_call_is_not_that_calls() {
    let mut j = Join::new();
    start(&mut j);
    call(&mut j, "toolu_B", "bash", &[], 1_000, Some(60_000));
    effect(&mut j, "fork", 1_100, ROOT, 1, json!({"child": 3001}));
    effect(
        &mut j,
        "exec",
        1_110,
        3001,
        ROOT,
        json!({"exe": "/home/u/.local/bin/uv"}),
    );
    let r = effect(
        &mut j,
        "write",
        1_300,
        3001,
        ROOT,
        json!({"path": "/home/u/.cache/uv/x"}),
    );
    assert_eq!(r.len(), 1, "{r:?}");
    assert!(r[0].detail["chosen"].is_null(), "{}", r[0].detail);
    assert!(
        r[0].detail["candidates"]
            .as_array()
            .unwrap()
            .iter()
            .all(|c| c["by"] != "tree"),
        "{}",
        r[0].detail
    );
    // A shell for a non-shell call is not placed either.
    call(&mut j, "toolu_C", "read", &[], 70_000, Some(71_000));
    effect(&mut j, "fork", 70_100, ROOT, 1, json!({"child": 3002}));
    effect(
        &mut j,
        "exec",
        70_110,
        3002,
        ROOT,
        json!({"exe": "/bin/sh"}),
    );
    let r = effect(&mut j, "write", 70_200, 3002, ROOT, json!({"path": "/w/y"}));
    assert!(r[0].detail["chosen"].is_null(), "{}", r[0].detail);
}

/// Fix pass 1's review, F1: one more call open (a parallel call, or one
/// approval a chat token posted with no call after it) made the install's
/// shell no call's, so its writes reached no install flag. A shell started
/// while several shell calls run is theirs together: its writes are each
/// call's by tree, none chosen; a non-shell call running beside one shell
/// call does not take the shell from it.
#[test]
fn a_shell_started_while_shell_calls_run_is_theirs_together() {
    let mut j = Join::new();
    start(&mut j);
    call(&mut j, "toolu_I", "bash", &[], 1_000, Some(60_000));
    call(&mut j, "toolu_R", "read", &[], 1_000, Some(60_000));
    effect(&mut j, "fork", 1_100, ROOT, 1, json!({"child": 3101}));
    effect(
        &mut j,
        "exec",
        1_110,
        3101,
        ROOT,
        json!({"exe": "/bin/bash"}),
    );
    let r = effect(&mut j, "write", 1_200, 3101, ROOT, json!({"path": "/w/a"}));
    assert!(!r[0].detail["chosen"].is_null(), "{}", r[0].detail);
    call(&mut j, "toolu_F", "bash", &[], 2_000, Some(60_000));
    effect(&mut j, "fork", 2_100, ROOT, 1, json!({"child": 3102}));
    effect(
        &mut j,
        "exec",
        2_110,
        3102,
        ROOT,
        json!({"exe": "/bin/bash"}),
    );
    let r = effect(
        &mut j,
        "write",
        2_300,
        3102,
        ROOT,
        json!({"path": "/w/.git/hooks/pre-commit"}),
    );
    assert!(r[0].detail["chosen"].is_null(), "{}", r[0].detail);
    let by_tree: Vec<&Value> = r[0].detail["candidates"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|c| c["by"] == "tree")
        .collect();
    assert_eq!(by_tree.len(), 2, "{}", r[0].detail);
}

/// Fix pass 1's re-review, N1: a shell placed among a forged open call and
/// the real install call wrote after the real call ended (a postinstall's
/// background child), and only the forged call was left to choose. A
/// shell's calls stay its candidates after they end, and none is chosen.
#[test]
fn a_shells_calls_stay_its_candidates_after_they_end() {
    let mut j = Join::new();
    start(&mut j);
    j.observe(&ev(
        Source::Adapter,
        "approval",
        900,
        None,
        json!({"toolUseId": "toolu_FORGED", "tool": "bash", "decision": "allow"}),
    ));
    call(&mut j, "toolu_I", "bash", &[], 1_000, Some(5_000));
    effect(&mut j, "fork", 1_100, ROOT, 1, json!({"child": 3201}));
    effect(&mut j, "exec", 1_110, 3201, ROOT, json!({"exe": "/bin/sh"}));
    let r = effect(
        &mut j,
        "write",
        8_000,
        3201,
        ROOT,
        json!({"path": "/w/.git/hooks/pre-commit"}),
    );
    assert_eq!(r.len(), 1, "{r:?}");
    assert!(r[0].detail["chosen"].is_null(), "{}", r[0].detail);
    let tree: Vec<&str> = r[0].detail["candidates"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|c| c["by"] == "tree")
        .filter_map(|c| c["call"].as_str())
        .collect();
    assert_eq!(tree.len(), 2, "{}", r[0].detail);
    assert!(tree.iter().any(|c| c.ends_with("toolu_I")), "{tree:?}");
}

/// An untapped chat (Pi) names its call's tool only in the gate's record.
#[test]
fn an_untapped_shell_call_still_owns_its_shell() {
    let mut j = Join::new();
    start(&mut j);
    j.observe(&ev(
        Source::Adapter,
        "approval",
        1_000,
        None,
        json!({"toolUseId": "toolu_P", "tool": "bash", "decision": "allow"}),
    ));
    effect(&mut j, "fork", 1_100, ROOT, 1, json!({"child": 4001}));
    effect(
        &mut j,
        "exec",
        1_110,
        4001,
        ROOT,
        json!({"exe": "/bin/bash"}),
    );
    let r = effect(&mut j, "write", 1_200, 4001, ROOT, json!({"path": "/w/z"}));
    assert_eq!(
        r[0].detail["candidates"][0]["by"], "tree",
        "{}",
        r[0].detail
    );
}

/// Mac test w5 retest 2, MW5-16: under srt, `run.start`'s pid is srt's own
/// node, and the harness runs under its wrappers (`sandbox-exec`, a shell's
/// `-c`, `env`). Every child of the root started before a call was the
/// session's, so the harness and every shell it started for a call were the
/// session's too, and a real Claude Code turn under srt got no join record.
#[test]
fn under_a_boundarys_wrappers_the_harness_shells_are_still_its_calls() {
    let mut j = Join::new();
    start_under(&mut j, "srt", Some("/opt/claude/claude")); // ROOT is srt's node.
                                                            // srt -> sandbox-exec -> sh -c -> env -> claude, all before any call.
    effect(&mut j, "fork", 100, ROOT, 1, json!({"child": 1100}));
    effect(
        &mut j,
        "exec",
        101,
        1100,
        ROOT,
        json!({"exe": "/usr/bin/sandbox-exec"}),
    );
    effect(&mut j, "exec", 102, 1100, ROOT, json!({"exe": "/bin/sh"}));
    effect(&mut j, "fork", 103, 1100, ROOT, json!({"child": 1101}));
    effect(
        &mut j,
        "exec",
        104,
        1101,
        1100,
        json!({"exe": "/usr/bin/env"}),
    );
    effect(
        &mut j,
        "exec",
        105,
        1101,
        1100,
        json!({"exe": "/opt/claude/claude"}),
    );
    // An MCP server the harness starts with the session.
    effect(&mut j, "fork", 200, 1101, 1100, json!({"child": 1200}));
    effect(
        &mut j,
        "exec",
        201,
        1200,
        1101,
        json!({"exe": "/usr/bin/node"}),
    );
    call(&mut j, "toolu_S", "bash", &[], 1_000, Some(5_000));
    // The harness's shell for the Bash call, and what it runs.
    effect(&mut j, "fork", 1_100, 1101, 1100, json!({"child": 1300}));
    let r = effect(
        &mut j,
        "exec",
        1_110,
        1300,
        1101,
        json!({"exe": "/bin/zsh"}),
    );
    assert_eq!(r[0].detail["chosen"], "tap-chat-j-toolu_S", "{r:?}");
    effect(&mut j, "fork", 1_200, 1300, 1101, json!({"child": 1301}));
    let r = effect(
        &mut j,
        "write",
        1_300,
        1301,
        1300,
        json!({"path": "/w/.github/workflows/x.yml"}),
    );
    assert_eq!(r[0].detail["chosen"], "tap-chat-j-toolu_S", "{r:?}");
    assert_eq!(r[0].detail["candidates"][0]["by"], "tree");
    // The MCP server stays the session's: a shell it starts during the Bash
    // call is not that call's (BW5-11).
    effect(&mut j, "fork", 2_000, 1200, 1101, json!({"child": 1400}));
    effect(&mut j, "exec", 2_010, 1400, 1200, json!({"exe": "/bin/sh"}));
    let r = effect(
        &mut j,
        "write",
        2_100,
        1400,
        1200,
        json!({"path": "/w/cache"}),
    );
    assert!(
        r.iter().all(|e| e.detail["chosen"].is_null()
            && e.detail["candidates"]
                .as_array()
                .unwrap()
                .iter()
                .all(|c| c["by"] != "tree")),
        "{r:?}"
    );
    // A wrapper (srt's own node) starting a process during a call does not
    // place it once the harness is known.
    effect(&mut j, "fork", 3_000, ROOT, 1, json!({"child": 1500}));
    effect(&mut j, "exec", 3_010, 1500, ROOT, json!({"exe": "/bin/sh"}));
    let r = effect(&mut j, "write", 3_100, 1500, ROOT, json!({"path": "/w/z"}));
    // The root still places, as it always has: under none it is the harness.
    assert_eq!(r[0].detail["chosen"], "tap-chat-j-toolu_S", "{r:?}");
}

/// Review FP3-S2: an MCP server started with the session is a process under
/// the wrappers too. A shell it starts during a Bash call, before the
/// harness's own, must not be chosen for that call, and must not make it the
/// placer: the harness is the process that execs `harnessExe`.
#[test]
fn an_mcp_servers_shell_under_a_boundary_is_never_chosen_for_a_call() {
    let mut j = Join::new();
    start_under(&mut j, "srt", Some("/opt/claude/claude"));
    effect(&mut j, "fork", 100, ROOT, 1, json!({"child": 1100}));
    effect(
        &mut j,
        "exec",
        101,
        1100,
        ROOT,
        json!({"exe": "/usr/bin/sandbox-exec"}),
    );
    effect(&mut j, "fork", 103, 1100, ROOT, json!({"child": 1101}));
    effect(
        &mut j,
        "exec",
        105,
        1101,
        1100,
        json!({"exe": "/opt/claude/claude"}),
    );
    effect(&mut j, "fork", 200, 1101, 1100, json!({"child": 1200}));
    effect(
        &mut j,
        "exec",
        201,
        1200,
        1101,
        json!({"exe": "/usr/bin/node"}),
    );
    call(&mut j, "toolu_S", "bash", &[], 1_000, Some(5_000));
    // The MCP server's shell, 40 ms before the harness's.
    effect(&mut j, "fork", 1_050, 1200, 1101, json!({"child": 1400}));
    effect(&mut j, "exec", 1_060, 1400, 1200, json!({"exe": "/bin/sh"}));
    let mcp = effect(
        &mut j,
        "write",
        1_070,
        1400,
        1200,
        json!({"path": "/w/.git/hooks/pre-commit"}),
    );
    effect(&mut j, "fork", 1_100, 1101, 1100, json!({"child": 1300}));
    effect(
        &mut j,
        "exec",
        1_110,
        1300,
        1101,
        json!({"exe": "/bin/zsh"}),
    );
    let real = effect(
        &mut j,
        "write",
        1_300,
        1300,
        1101,
        json!({"path": "/w/out.txt"}),
    );
    assert!(
        mcp.iter().all(|e| e.detail["chosen"].is_null()),
        "mcp write chosen: {mcp:?}"
    );
    assert_eq!(
        real.first().map(|e| e.detail["chosen"].clone()),
        Some(json!("tap-chat-j-toolu_S")),
        "real write: {real:?}"
    );
}

/// Review FP3-S2b: a chat token can post an approval for a Bash call that
/// never ran, so a shell started then must not take the harness's place for
/// the rest of the chat.
#[test]
fn a_forged_call_cannot_take_the_harness_place() {
    let mut j = Join::new();
    start_under(&mut j, "srt", Some("/opt/claude/claude"));
    effect(&mut j, "fork", 100, ROOT, 1, json!({"child": 1101}));
    effect(
        &mut j,
        "exec",
        105,
        1101,
        ROOT,
        json!({"exe": "/opt/claude/claude"}),
    );
    effect(&mut j, "fork", 200, 1101, ROOT, json!({"child": 1200}));
    effect(
        &mut j,
        "exec",
        201,
        1200,
        1101,
        json!({"exe": "/usr/bin/node"}),
    );
    j.observe(&ev(
        Source::Adapter,
        "approval",
        500,
        None,
        json!({"toolUseId": "toolu_FORGED", "tool": "Bash", "decision": "allow"}),
    ));
    effect(&mut j, "fork", 510, 1200, 1101, json!({"child": 1400}));
    effect(&mut j, "exec", 520, 1400, 1200, json!({"exe": "/bin/sh"}));
    let t = 20 * 60 * 1000;
    call(&mut j, "toolu_R", "bash", &[], t, Some(t + 4_000));
    effect(&mut j, "fork", t + 100, 1101, ROOT, json!({"child": 1300}));
    effect(
        &mut j,
        "exec",
        t + 110,
        1300,
        1101,
        json!({"exe": "/bin/zsh"}),
    );
    let real = effect(
        &mut j,
        "write",
        t + 300,
        1300,
        1101,
        json!({"path": "/w/out.txt"}),
    );
    assert_eq!(
        real.first().map(|e| e.detail["chosen"].clone()),
        Some(json!("tap-chat-j-toolu_R")),
        "real write: {real:?}"
    );
}

/// Where `derm run` could not name the harness's executable (a script run by
/// its interpreter, a shim), no process under the wrappers is taken for the
/// harness: their shells are candidates of the running shell calls, none
/// chosen (case 123's rule), so the writes are still seen.
#[test]
fn with_no_harness_exe_shells_under_a_boundary_are_candidates_only() {
    let mut j = Join::new();
    start_under(&mut j, "srt", None);
    effect(&mut j, "fork", 100, ROOT, 1, json!({"child": 1101}));
    effect(
        &mut j,
        "exec",
        105,
        1101,
        ROOT,
        json!({"exe": "/usr/bin/node"}),
    );
    effect(&mut j, "fork", 200, 1101, ROOT, json!({"child": 1200}));
    effect(
        &mut j,
        "exec",
        201,
        1200,
        1101,
        json!({"exe": "/usr/bin/node"}),
    );
    call(&mut j, "toolu_S", "bash", &[], 1_000, Some(5_000));
    for (shell, parent) in [(1400, 1200), (1300, 1101)] {
        effect(&mut j, "fork", 1_050, parent, ROOT, json!({"child": shell}));
        effect(
            &mut j,
            "exec",
            1_060,
            shell,
            parent,
            json!({"exe": "/bin/sh"}),
        );
        let r = effect(
            &mut j,
            "write",
            1_070,
            shell,
            parent,
            json!({"path": "/w/x"}),
        );
        assert_eq!(r.len(), 1, "{r:?}");
        assert!(r[0].detail["chosen"].is_null(), "{r:?}");
        assert_eq!(
            r[0].detail["candidates"][0]["call"], "tap-chat-j-toolu_S",
            "{r:?}"
        );
        assert_eq!(r[0].detail["candidates"][0]["by"], "tree", "{r:?}");
    }
}

/// With no boundary the root is the harness, and a helper it started with
/// the session (an MCP server) places nothing (BW5-11, as before MW5-16).
#[test]
fn with_no_boundary_only_the_root_places() {
    let mut j = Join::new();
    start_under(&mut j, "none", Some("/opt/claude/claude"));
    effect(&mut j, "fork", 200, ROOT, 1, json!({"child": 1200}));
    effect(
        &mut j,
        "exec",
        201,
        1200,
        ROOT,
        json!({"exe": "/usr/bin/node"}),
    );
    call(&mut j, "toolu_S", "bash", &[], 1_000, Some(5_000));
    effect(&mut j, "fork", 1_050, 1200, ROOT, json!({"child": 1400}));
    effect(&mut j, "exec", 1_060, 1400, 1200, json!({"exe": "/bin/sh"}));
    let r = effect(&mut j, "write", 1_070, 1400, 1200, json!({"path": "/w/x"}));
    assert!(
        r.iter().all(|e| e.detail["candidates"]
            .as_array()
            .unwrap()
            .iter()
            .all(|c| c["by"] != "tree")),
        "{r:?}"
    );
}

/// Re-review R1: a harness that is a `#!/usr/bin/env node` script execs as
/// `env`, then `node`; `derm run` names the interpreter (`harnessExe`), and
/// the process that execs it is the harness, so its shell is chosen.
#[test]
fn a_script_harness_is_found_by_its_interpreter() {
    let mut j = Join::new();
    start_under(&mut j, "srt", Some("/usr/bin/node"));
    effect(&mut j, "fork", 100, ROOT, 1, json!({"child": 1101}));
    effect(
        &mut j,
        "exec",
        104,
        1101,
        ROOT,
        json!({"exe": "/usr/bin/env"}),
    );
    effect(
        &mut j,
        "exec",
        105,
        1101,
        ROOT,
        json!({"exe": "/usr/bin/node"}),
    );
    call(&mut j, "toolu_I", "bash", &[], 1_000, Some(5_000));
    effect(&mut j, "fork", 1_100, 1101, ROOT, json!({"child": 1300}));
    effect(&mut j, "exec", 1_110, 1300, 1101, json!({"exe": "/bin/sh"}));
    let r = effect(
        &mut j,
        "write",
        1_300,
        1300,
        1101,
        json!({"path": "/w/.git/hooks/pre-commit"}),
    );
    assert_eq!(
        r.first().map(|e| e.detail["chosen"].clone()),
        Some(json!("tap-chat-j-toolu_I")),
        "{r:?}"
    );
    assert!(r[0].detail.get("harnessFound").is_none(), "{r:?}");
}

/// Re-review R3: srt itself is node, so when the harness is node too the
/// root's own exec must not name the root the harness.
#[test]
fn the_roots_own_exec_never_names_the_harness() {
    let mut j = Join::new();
    start_under(&mut j, "srt", Some("/usr/bin/node"));
    effect(&mut j, "exec", 50, ROOT, 1, json!({"exe": "/usr/bin/node"}));
    effect(&mut j, "fork", 100, ROOT, 1, json!({"child": 1100}));
    effect(
        &mut j,
        "exec",
        101,
        1100,
        ROOT,
        json!({"exe": "/usr/bin/bwrap"}),
    );
    effect(&mut j, "fork", 103, 1100, ROOT, json!({"child": 1101}));
    effect(
        &mut j,
        "exec",
        105,
        1101,
        1100,
        json!({"exe": "/usr/bin/node"}),
    );
    call(&mut j, "toolu_S", "bash", &[], 1_000, Some(5_000));
    effect(&mut j, "fork", 1_100, 1101, 1100, json!({"child": 1300}));
    effect(&mut j, "exec", 1_110, 1300, 1101, json!({"exe": "/bin/sh"}));
    let r = effect(&mut j, "write", 1_300, 1300, 1101, json!({"path": "/w/x"}));
    assert_eq!(
        r.first().map(|e| e.detail["chosen"].clone()),
        Some(json!("tap-chat-j-toolu_S")),
        "{r:?}"
    );
}

/// With the harness not found, a shell under the boundary names its call as
/// a tree candidate, none chosen, and the record says the harness was not
/// found, so the flagger can still flag an install's shell (re-review R1).
#[test]
fn an_unplaced_shell_says_the_harness_was_not_found() {
    let mut j = Join::new();
    start_under(&mut j, "srt", Some("/opt/never/seen"));
    effect(&mut j, "fork", 100, ROOT, 1, json!({"child": 1101}));
    effect(
        &mut j,
        "exec",
        105,
        1101,
        ROOT,
        json!({"exe": "/usr/bin/node"}),
    );
    call(&mut j, "toolu_I", "bash", &[], 1_000, Some(5_000));
    effect(&mut j, "fork", 1_100, 1101, ROOT, json!({"child": 1300}));
    effect(&mut j, "exec", 1_110, 1300, 1101, json!({"exe": "/bin/sh"}));
    let r = effect(&mut j, "write", 1_300, 1300, 1101, json!({"path": "/w/x"}));
    assert_eq!(r.len(), 1, "{r:?}");
    assert!(r[0].detail["chosen"].is_null());
    assert_eq!(r[0].detail["harnessFound"], false);
    assert_eq!(r[0].detail["candidates"][0]["by"], "tree");
}

/// Second re-review S1: a harness launched by a shell script (an asdf shim,
/// a bash launcher) resolves to the shell, and srt's own `bash -c` wrappers
/// exec that shell first; a shell or wrapper names no harness, so the real
/// harness's shells stay candidates instead of vanishing.
#[test]
fn a_shell_as_the_harness_exe_names_no_harness() {
    let mut j = Join::new();
    start_under(&mut j, "srt", Some("/usr/bin/bash"));
    effect(&mut j, "fork", 100, ROOT, 1, json!({"child": 1100}));
    effect(
        &mut j,
        "exec",
        101,
        1100,
        ROOT,
        json!({"exe": "/usr/bin/bash"}),
    );
    effect(&mut j, "fork", 102, 1100, ROOT, json!({"child": 1101}));
    effect(
        &mut j,
        "exec",
        103,
        1101,
        1100,
        json!({"exe": "/usr/bin/bwrap"}),
    );
    effect(&mut j, "fork", 104, 1101, 1100, json!({"child": 1102}));
    effect(
        &mut j,
        "exec",
        105,
        1102,
        1101,
        json!({"exe": "/usr/bin/bash"}),
    );
    effect(&mut j, "fork", 106, 1102, 1101, json!({"child": 1103}));
    effect(
        &mut j,
        "exec",
        107,
        1103,
        1102,
        json!({"exe": "/usr/bin/bash"}),
    );
    effect(
        &mut j,
        "exec",
        108,
        1103,
        1102,
        json!({"exe": "/usr/bin/node"}),
    );
    call(&mut j, "toolu_S", "bash", &[], 1_000, Some(5_000));
    effect(&mut j, "fork", 1_100, 1103, 1102, json!({"child": 1300}));
    effect(&mut j, "exec", 1_110, 1300, 1103, json!({"exe": "/bin/sh"}));
    let r = effect(
        &mut j,
        "write",
        1_300,
        1300,
        1103,
        json!({"path": "/w/.git/hooks/pre-commit"}),
    );
    assert_eq!(
        r.len(),
        1,
        "the real call's write has no join record: {r:?}"
    );
    assert_eq!(
        r[0].detail["candidates"][0]["call"], "tap-chat-j-toolu_S",
        "{r:?}"
    );
    assert_eq!(r[0].detail["harnessFound"], false, "{r:?}");
}

/// Second re-review S2: a call the model runs beside a shell call, naming
/// the path the shell writes, joins the tree candidates and is not chosen.
#[test]
fn a_path_naming_call_does_not_take_a_tree_candidates_write() {
    let mut j = Join::new();
    start_under(&mut j, "srt", None);
    effect(&mut j, "fork", 100, ROOT, 1, json!({"child": 1101}));
    effect(
        &mut j,
        "exec",
        105,
        1101,
        ROOT,
        json!({"exe": "/usr/bin/node"}),
    );
    call(&mut j, "toolu_I", "bash", &[], 1_000, Some(9_000));
    call(
        &mut j,
        "toolu_R",
        "read",
        &["/w/.git/hooks/pre-commit"],
        1_020,
        Some(9_000),
    );
    effect(&mut j, "fork", 1_100, 1101, ROOT, json!({"child": 1300}));
    effect(&mut j, "exec", 1_110, 1300, 1101, json!({"exe": "/bin/sh"}));
    let r = effect(
        &mut j,
        "write",
        1_300,
        1300,
        1101,
        json!({"path": "/w/.git/hooks/pre-commit"}),
    );
    assert!(r[0].detail["chosen"].is_null(), "{r:?}");
    let by: Vec<_> = r[0].detail["candidates"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| (c["call"].clone(), c["by"].clone()))
        .collect();
    assert!(
        by.contains(&(json!("tap-chat-j-toolu_I"), json!("tree"))),
        "{r:?}"
    );
    assert!(
        by.contains(&(json!("tap-chat-j-toolu_R"), json!("path"))),
        "{r:?}"
    );
}

/// Second re-review S3: a chat token's "it ran" for a running install ends
/// its window early; a later write of the install's own shell is still
/// that call's.
#[test]
fn an_early_end_does_not_drop_a_calls_own_writes() {
    let mut j = Join::new();
    start_under(&mut j, "none", None);
    call(&mut j, "toolu_I", "bash", &[], 1_000, None);
    effect(&mut j, "fork", 1_100, ROOT, 1, json!({"child": 1300}));
    effect(&mut j, "exec", 1_110, 1300, ROOT, json!({"exe": "/bin/sh"}));
    j.observe(&ev(
        Source::Adapter,
        "tool.call",
        1_200,
        None,
        json!({"toolUseId": "toolu_I"}),
    ));
    let r = effect(
        &mut j,
        "write",
        60_000,
        1300,
        ROOT,
        json!({"path": "/w/.git/hooks/pre-commit"}),
    );
    assert_eq!(r.len(), 1, "the shell's own write has no record: {r:?}");
    assert_eq!(r[0].detail["chosen"], "tap-chat-j-toolu_I", "{r:?}");
}

/// Third re-review T1: a pid the OS hands out again is a new process, not
/// the old one; its writes are not the old call's.
#[test]
fn a_reused_pid_does_not_keep_an_old_calls_owner() {
    let mut j = Join::new();
    start(&mut j);
    call(&mut j, "toolu_A", "bash", &[], 1_000, Some(2_000));
    effect(&mut j, "fork", 1_100, ROOT, 1, json!({"child": 1300}));
    effect(&mut j, "exec", 1_110, 1300, ROOT, json!({"exe": "/bin/sh"}));
    call(&mut j, "toolu_B", "bash", &[], 900_000, Some(905_000));
    effect(&mut j, "fork", 900_100, ROOT, 1, json!({"child": 1300}));
    effect(
        &mut j,
        "exec",
        900_110,
        1300,
        ROOT,
        json!({"exe": "/usr/bin/node"}),
    );
    let r = effect(
        &mut j,
        "write",
        900_200,
        1300,
        ROOT,
        json!({"path": "/w/.git/hooks/pre-commit"}),
    );
    assert!(
        r.iter()
            .all(|e| e.detail["chosen"] != json!("tap-chat-j-toolu_A")),
        "{r:?}"
    );
    // The owners map's order holds each pid once, so eviction stays exact.
    let st = j.chats.get(CHAT).unwrap();
    assert_eq!(
        st.owner_order.iter().filter(|p| **p == 1300).count(),
        st.owners.contains_key(&1300) as usize
    );
}

/// T1's clearing holds the feed's order: a child's exec that arrives
/// before its parent's fork record keeps the exec's placement.
#[test]
fn a_fork_that_arrives_after_its_childs_exec_keeps_the_childs_owner() {
    let mut j = Join::new();
    start(&mut j);
    call(&mut j, "toolu_A", "bash", &[], 1_000, Some(5_000));
    effect(&mut j, "exec", 1_110, 1300, ROOT, json!({"exe": "/bin/sh"}));
    effect(&mut j, "fork", 1_100, ROOT, 1, json!({"child": 1300}));
    let r = effect(&mut j, "write", 1_300, 1300, ROOT, json!({"path": "/w/x"}));
    assert_eq!(r[0].detail["chosen"], "tap-chat-j-toolu_A", "{r:?}");
}

/// Review FP3-S4: the line is bounded like the owners map.
#[test]
fn the_line_is_bounded() {
    let mut j = Join::new();
    start_under(&mut j, "srt", None);
    for n in 0..(MAX_PIDS as u32 + 1_000) {
        effect(&mut j, "fork", 100, ROOT, 1, json!({"child": 100_000 + n}));
    }
    let len = j.chats.get(CHAT).unwrap().line.len();
    assert!(
        len <= MAX_PIDS,
        "line holds {len} pids, MAX_PIDS {MAX_PIDS}"
    );
}

/// Mac test w5 retest 2, MW5-17: the Mac's OS events reach the daemon
/// seconds after they happen, and the join forgot a chat at its `run.stop`,
/// so the end of every short chat (its Bash call's own `ls` exec among them)
/// fit no call. A stopped chat is kept `STOPPED_KEEP_MS` for them.
#[test]
fn effects_that_arrive_after_the_stop_are_still_joined_for_a_while() {
    let mut j = Join::new();
    start(&mut j);
    call(&mut j, "toolu_L", "bash", &[], 1_000, Some(2_000));
    effect(&mut j, "fork", 1_100, ROOT, 1, json!({"child": 6001}));
    effect(
        &mut j,
        "exec",
        1_110,
        6001,
        ROOT,
        json!({"exe": "/bin/zsh"}),
    );
    j.observe(&ev(Source::Run, "run.stop", 2_500, Some(ROOT), json!({})));
    // The exec of `ls` happened at 1,200 and reached the daemon 6 s later.
    let mut late = ev(
        Source::Eslogger,
        "exec",
        8_500,
        Some(6002),
        json!({"ppid": 6001, "osAt": 1_200, "exe": "/bin/ls"}),
    );
    late.id = "es-late-1".into();
    effect(&mut j, "fork", 1_150, 6001, ROOT, json!({"child": 6002}));
    let r = j.observe(&late);
    assert_eq!(r.len(), 1, "{r:?}");
    assert_eq!(r[0].detail["chosen"], "tap-chat-j-toolu_L");
    // Past the keep, the chat is gone.
    let mut later = late.clone();
    later.id = "es-late-2".into();
    later.at = 2_500 + STOPPED_KEEP_MS + 1;
    assert!(j.observe(&later).is_empty());
    // A chat id started again begins afresh: an old call does not carry over.
    start(&mut j);
    assert!(effect(&mut j, "write", 1_300, 6002, 6001, json!({"path": "/w/x"})).is_empty());
}
