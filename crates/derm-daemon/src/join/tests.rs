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
    // the chat was dropped at the stop itself), the chat records nothing,
    // once the feed has passed the stop (MW5-34: the OS stamped this write
    // after it).
    j.observe(&ev(Source::Run, "run.stop", 99_000, Some(ROOT), json!({})));
    let mut late = ev(
        Source::Auditd,
        "write",
        99_000 + STOPPED_KEEP_MS + 1,
        Some(ROOT),
        json!({"ppid": 1, "auditAt": 99_000 + SLACK_AFTER_MS + 1, "path": "/w/x"}),
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
    // Past the keep, once the feed has delivered an event the OS stamped
    // after the stop, the chat is gone, and its later events are counted
    // (MW5-34; before it, the keep went by the daemon's clock alone).
    let mut passed = ev(
        Source::Eslogger,
        "exec",
        2_500 + STOPPED_KEEP_MS + 1,
        Some(9_999),
        json!({"osAt": 2_500 + SLACK_AFTER_MS + 1, "exe": "/bin/ls"}),
    );
    passed.chat_id = String::new();
    passed.id = "es-other".into();
    j.observe(&passed);
    let mut later = late.clone();
    later.id = "es-late-2".into();
    later.at = 2_500 + STOPPED_KEEP_MS + 2;
    assert!(j.observe(&later).is_empty());
    // Counted as done after the stop, not as feed lag (FP11-S2).
    assert_eq!(j.after_for(CHAT), Some(1));
    assert_eq!(j.late_for(CHAT), None);
    // A chat id started again begins afresh: an old call does not carry over.
    start(&mut j);
    assert!(effect(&mut j, "write", 1_300, 6002, 6001, json!({"path": "/w/x"})).is_empty());
}

/// A call as the tap alone records it (no gate registered), for a harness:
/// the call at `t`, its result at `end`.
fn tap_only(j: &mut Join, harness: &str, id: &str, tool: &str, t: i64, end: i64) {
    let mut e = ev(
        Source::Tap,
        "tap.call",
        t,
        None,
        json!({"callId": id, "toolNormalized": tool, "paths": [], "resultSha256": null}),
    );
    e.id = format!("tap-{CHAT}-{id}");
    e.harness = harness.into();
    j.observe(&e);
    let mut r = ev(
        Source::Tap,
        "tap.call",
        end,
        None,
        json!({"callId": id, "toolNormalized": tool, "paths": [], "resultSha256": "ab"}),
    );
    r.id = format!("tap-{CHAT}-{id}");
    r.harness = harness.into();
    j.observe(&r);
}

/// A Codex Code Mode call as the tap records it since fix pass 6: its cell
/// (`cellId`: `wait`'s argument on both records, an `exec`'s from its
/// result) and its result's header (`codeStatus`).
fn tap_code(
    j: &mut Join,
    id: &str,
    tool: &str,
    t: i64,
    end: i64,
    cell: Option<&str>,
    status: Option<&str>,
) {
    let first_cell = if tool == "wait" { cell } else { None };
    let mut e = ev(
        Source::Tap,
        "tap.call",
        t,
        None,
        json!({"callId": id, "toolNormalized": tool, "paths": [], "resultSha256": null, "cellId": first_cell}),
    );
    e.id = format!("tap-{CHAT}-{id}");
    e.harness = "codex".into();
    j.observe(&e);
    let mut r = ev(
        Source::Tap,
        "tap.call",
        end,
        None,
        json!({"callId": id, "toolNormalized": tool, "paths": [], "resultSha256": "ab", "cellId": cell, "codeStatus": status}),
    );
    r.id = format!("tap-{CHAT}-{id}");
    r.harness = "codex".into();
    j.observe(&r);
}

/// The harness forks and execs a shell, which forks and execs `sleep`, which
/// writes: the write's join record.
fn shell_writes(j: &mut Join, at: i64, sh: u32, path: &str) -> Vec<Event> {
    effect(j, "fork", at, ROOT, 1, json!({"child": sh}));
    effect(j, "exec", at + 5, sh, ROOT, json!({"exe": "/bin/zsh"}));
    effect(j, "fork", at + 10, sh, ROOT, json!({"child": sh + 1}));
    effect(j, "exec", at + 15, sh + 1, sh, json!({"exe": "/bin/sleep"}));
    effect(j, "write", at + 20, sh + 1, sh, json!({"path": path}))
}

/// Mac test w5 retest 5, MW5-27: Codex 0.163.0 in Code Mode offers the model
/// one tool, `exec` (JavaScript that calls nested tools such as
/// `exec_command`; `codex-rs/code-mode-protocol/src/lib.rs:54`), and its
/// shells start during that call as children of Codex itself. The tap
/// records `exec`, which is no shell tool, so the join placed none of them.
/// A Code Mode call owns the shells Codex starts while it runs, as a shell
/// call does; the same names in another harness are not code tools.
#[test]
fn mw5_27_a_codex_code_mode_call_owns_the_shells_it_starts() {
    let mut j = Join::new();
    start(&mut j);
    tap_only(&mut j, "codex", "call_E1", "exec", 1_000, 30_000);
    let r = shell_writes(&mut j, 1_100, 7001, "/w/a");
    assert_eq!(r.len(), 1, "{r:?}");
    assert_eq!(
        r[0].detail["chosen"], "tap-chat-j-call_E1",
        "{}",
        r[0].detail
    );
    assert_eq!(
        r[0].detail["candidates"][0]["by"], "tree",
        "{}",
        r[0].detail
    );
    // `wait` resumes a running cell: its shells are its. (Since fix pass 6
    // the tap reads each result's header: E1 yielded cell 1, and the wait
    // names cell 1 and reports it ended, so the cell is one and the running
    // wait is chosen; with no header read, the two may be different cells
    // and none is chosen, `fp6_*` below.)
    let mut j = Join::new();
    start(&mut j);
    tap_code(
        &mut j,
        "call_E1",
        "exec",
        1_000,
        30_000,
        Some("1"),
        Some("running"),
    );
    tap_code(
        &mut j,
        "call_W1",
        "wait",
        40_000,
        60_000,
        Some("1"),
        Some("ended"),
    );
    let r = shell_writes(&mut j, 40_100, 7011, "/w/b");
    assert_eq!(
        r[0].detail["chosen"], "tap-chat-j-call_W1",
        "{}",
        r[0].detail
    );
    // A tool named `exec` in another harness is not Codex's Code Mode.
    tap_only(&mut j, "claude-code", "call_X1", "exec", 70_000, 90_000);
    let r = shell_writes(&mut j, 70_100, 7021, "/w/c");
    assert!(r[0].detail["chosen"].is_null(), "{}", r[0].detail);
}

/// With the gate registered, Code Mode's nested `exec_command` reaches it as
/// `Bash` with its own call id while the outer `exec` runs (Codex 0.163.0,
/// `core/src/tools/handlers/unified_exec/exec_command.rs:514`). The nested
/// shell call is the more precise owner: a shell call running wins over the
/// Code Mode call around it.
#[test]
fn mw5_27_a_nested_shell_call_wins_over_the_code_mode_call_around_it() {
    let mut j = Join::new();
    start(&mut j);
    tap_only(&mut j, "codex", "call_E2", "exec", 1_000, 30_000);
    let mut a = ev(
        Source::Adapter,
        "approval",
        1_050,
        None,
        json!({"toolUseId": "call_N2", "decision": "allow", "tool": "bash"}),
    );
    a.harness = "codex".into();
    j.observe(&a);
    let r = shell_writes(&mut j, 1_100, 7101, "/w/d");
    assert_eq!(r[0].detail["chosen"], "approval-1050-0", "{}", r[0].detail);
}

/// Codex 0.163.0 runs no PreToolUse hook for Code Mode's `exec` (its default
/// hook payload is for a `Function` payload only, and `exec` is `Custom`:
/// `core/src/tools/registry.rs:150-159`), so a gate record naming `exec` in a
/// Codex chat is never Codex's own. A chat token can post one; it must not
/// take the shells no call owns.
#[test]
fn mw5_27_a_gate_record_naming_exec_owns_no_shells() {
    let mut j = Join::new();
    start(&mut j);
    let mut a = ev(
        Source::Adapter,
        "approval",
        1_000,
        None,
        json!({"toolUseId": "forged_E", "decision": "allow", "tool": "exec"}),
    );
    a.harness = "codex".into();
    j.observe(&a);
    let r = shell_writes(&mut j, 1_100, 7201, "/w/e");
    assert!(r[0].detail["chosen"].is_null(), "{}", r[0].detail);
}

// ---- Separate review of fix pass 5 (FP5R): its probes, each failing on
// `429a0f2` but the two guards, kept as fix pass 6's reproducing tests. ----

/// FP5R-1 probe. Codex 0.163.0's `exec` yields while its cell keeps running
/// (`yield_time_ms`, `yield_control()`: `code-mode-protocol/src/description.rs`
/// lines 30-31 and 46; `core/src/tools/code_mode/execute_handler.rs:144-160`
/// closes the cell's dispatch only when the first response is not `Yielded`),
/// so cell A's nested shell can start while a later, unrelated `exec` B runs.
/// The join cannot tell the cells apart, yet it now chooses B by tree. At
/// `8551bed` the same shell was a `window` candidate of B with none chosen.
#[test]
fn fp5r_1_a_yielded_cells_shell_is_not_chosen_for_a_later_exec() {
    let mut j = Join::new();
    start(&mut j);
    // exec A yields at once ("Script running with cell ID ..."): its result
    // reaches the tap at 1_200, and cell A keeps running.
    tap_only(&mut j, "codex", "call_A", "exec", 1_000, 1_200);
    // exec B, a different cell, runs from 10_000 to 30_000.
    tap_only(&mut j, "codex", "call_B", "exec", 10_000, 30_000);
    // Cell A's nested exec_command starts a shell at 12_000.
    let r = shell_writes(&mut j, 12_000, 7301, "/w/from-cell-a");
    assert_eq!(r.len(), 1, "{r:?}");
    assert!(
        r[0].detail["chosen"].is_null(),
        "a shell that may be a yielded cell's was credited to the running exec: {}",
        r[0].detail
    );
}

/// FP5R-2 probe. The same yielded cell's shell when no call runs (the model
/// is writing its next reply): the join writes nothing for it or its writes,
/// as for a session helper. MW5-27 says a Code Mode call owns its shells.
#[test]
fn fp5r_2_a_yielded_cells_shell_with_no_call_running_gets_a_record() {
    let mut j = Join::new();
    start(&mut j);
    tap_only(&mut j, "codex", "call_A", "exec", 1_000, 1_200);
    // `await new Promise(r => setTimeout(r, 5000)); await tools.exec_command(...)`
    let r = shell_writes(&mut j, 6_200, 7401, "/w/hidden");
    assert_eq!(
        r.len(),
        1,
        "the yielded cell's write has no join record: {r:?}"
    );
}

/// FP5R-3 probe (code call). A chat token tails its own chat
/// (`daemon.rs:1744-1754`), so the agent learns the running `exec` call's id
/// and posts an `approval` for it after its shell started but before the OS
/// feed delivers that shell (2 to 8 s late on the Mac, MW5-17). The approval
/// moves the call's start (`join/mod.rs`, `c.start = Some(e.at)`), the
/// shell's exec falls outside the call's window, and the shell is the
/// session's: no record for it or anything under it.
#[test]
fn fp5r_3_a_late_chat_token_approval_does_not_unplace_a_code_calls_shell() {
    let mut j = Join::new();
    start(&mut j);
    tap_only(&mut j, "codex", "call_E9", "exec", 1_000, 30_000);
    let mut a = ev(
        Source::Adapter,
        "approval",
        1_700,
        None,
        json!({"toolUseId": "call_E9", "decision": "allow", "tool": "exec"}),
    );
    a.harness = "codex".into();
    j.observe(&a);
    let r = shell_writes(&mut j, 1_100, 7501, "/w/f");
    assert_eq!(r.len(), 1, "{r:?}");
    assert_eq!(
        r[0].detail["chosen"], "tap-chat-j-call_E9",
        "{}",
        r[0].detail
    );
}

/// FP5R-3 probe (shell call, a deny; the class is older than fix pass 5).
#[test]
fn fp5r_3_a_late_chat_token_deny_does_not_unplace_a_shell_calls_shell() {
    let mut j = Join::new();
    start(&mut j);
    tap_only(&mut j, "claude-code", "toolu_S9", "bash", 1_000, 30_000);
    j.observe(&ev(
        Source::Adapter,
        "approval",
        1_700,
        None,
        json!({"toolUseId": "toolu_S9", "decision": "deny"}),
    ));
    let r = shell_writes(&mut j, 1_100, 7601, "/w/g");
    assert_eq!(r.len(), 1, "{r:?}");
    assert_eq!(
        r[0].detail["chosen"], "tap-chat-j-toolu_S9",
        "{}",
        r[0].detail
    );
}

/// FP5-S1 check: an adapter record for the tap's own `exec` call id, naming
/// `bash`, does not turn the code call into a shell call, before or after
/// the tap's record.
#[test]
fn fp5r_guard_a_gate_record_cannot_rename_the_taps_exec_call() {
    for gate_first in [true, false] {
        let mut j = Join::new();
        start(&mut j);
        let mut a = ev(
            Source::Adapter,
            "approval",
            1_005,
            None,
            json!({"toolUseId": "call_E7", "decision": "allow", "tool": "bash"}),
        );
        a.harness = "codex".into();
        if gate_first {
            j.observe(&a);
        }
        tap_only(&mut j, "codex", "call_E7", "exec", 1_000, 30_000);
        if !gate_first {
            j.observe(&a);
        }
        let st = j.chats.get(CHAT).unwrap();
        let c = st.calls.get("call_E7").unwrap();
        assert!(c.code && !c.shell(), "gate_first={gate_first}: {c:?}");
    }
}

/// Case and spacing: the tap's normalized name is lowercased and trimmed
/// (`derm_core::policy::lower_name`), and `mcp_exec` normalizes to `exec`.
#[test]
fn fp5r_guard_which_tap_names_count_as_code_tools() {
    for raw in ["exec", "Exec", " EXEC ", "mcp_exec", "mcp__wait"] {
        let n = derm_core::policy::normalize_tool_name_for(raw, &[], "codex");
        assert!(code_tool("codex", &n), "{raw:?} -> {n:?}");
    }
    assert!(!code_tool("Codex", "exec"));
    assert!(!code_tool("codex", "exec_command"));
}

/// FP5R-4 probe. No race needed: a code call's nested shells are each a new
/// child of the harness, placed by what runs when it starts, and a chat
/// token's `tool.call` for the `exec` call id (never a gate decision, so the
/// daemon keeps no conflict for it, `activity/store.rs:253-256`) ends the call
/// early (`c.end = min`). Every later nested shell of the same cell is then
/// the session's, and its writes get no record.
#[test]
fn fp5r_4_a_chat_token_tool_call_does_not_end_a_code_call_early() {
    let mut j = Join::new();
    start(&mut j);
    tap_only(&mut j, "codex", "call_E8", "exec", 1_000, 30_000);
    let mut t = ev(
        Source::Adapter,
        "tool.call",
        2_000,
        None,
        json!({"toolUseId": "call_E8"}),
    );
    t.harness = "codex".into();
    j.observe(&t);
    let r = shell_writes(&mut j, 10_000, 7701, "/w/h");
    assert_eq!(
        r.len(),
        1,
        "the cell's later shell has no join record: {r:?}"
    );
    assert_eq!(
        r[0].detail["chosen"], "tap-chat-j-call_E8",
        "{}",
        r[0].detail
    );
}

// ---- Fix pass 6: the cell rule's other edges. ----

/// With no header read for either result, an `exec` and a later `wait` may
/// be different cells: a shell during the wait is a candidate of both, none
/// chosen (fails safe toward more candidates, never toward none).
#[test]
fn fp6_with_no_header_a_wait_and_an_earlier_exec_choose_none() {
    let mut j = Join::new();
    start(&mut j);
    tap_only(&mut j, "codex", "call_E1", "exec", 1_000, 30_000);
    tap_only(&mut j, "codex", "call_W1", "wait", 40_000, 60_000);
    let r = shell_writes(&mut j, 40_100, 7811, "/w/b");
    assert!(r[0].detail["chosen"].is_null(), "{}", r[0].detail);
    let c = r[0].detail["candidates"].as_array().unwrap();
    assert_eq!(c.len(), 2, "{}", r[0].detail);
    assert!(c.iter().all(|x| x["by"] == "tree"), "{}", r[0].detail);
}

/// A yielded cell is the only one that may run: its later shell, with no
/// call running, is that `exec`'s, chosen; once a `wait` on the cell says it
/// ended, a later shell with nothing running is the session's again.
#[test]
fn fp6_a_yielded_cell_owns_its_later_shells_until_a_wait_says_it_ended() {
    let mut j = Join::new();
    start(&mut j);
    tap_code(
        &mut j,
        "call_E1",
        "exec",
        1_000,
        1_200,
        Some("4"),
        Some("running"),
    );
    let r = shell_writes(&mut j, 6_200, 7821, "/w/late");
    assert_eq!(
        r[0].detail["chosen"], "tap-chat-j-call_E1",
        "{}",
        r[0].detail
    );
    tap_code(
        &mut j,
        "call_W1",
        "wait",
        10_000,
        12_000,
        Some("4"),
        Some("ended"),
    );
    assert!(shell_writes(&mut j, 20_000, 7831, "/w/after").is_empty());
    // An exec whose cell completed in its first response leaves nothing open.
    tap_code(
        &mut j,
        "call_E2",
        "exec",
        30_000,
        31_000,
        None,
        Some("ended"),
    );
    assert!(shell_writes(&mut j, 40_000, 7841, "/w/none").is_empty());
}

/// Two cells that both yielded: a shell with no call running is a candidate
/// of both, none chosen.
#[test]
fn fp6_two_yielded_cells_share_a_shell_and_none_is_chosen() {
    let mut j = Join::new();
    start(&mut j);
    tap_code(
        &mut j,
        "call_E1",
        "exec",
        1_000,
        1_200,
        Some("1"),
        Some("running"),
    );
    tap_code(
        &mut j,
        "call_E2",
        "exec",
        2_000,
        2_200,
        Some("2"),
        Some("running"),
    );
    let r = shell_writes(&mut j, 9_000, 7851, "/w/x");
    assert!(r[0].detail["chosen"].is_null(), "{}", r[0].detail);
    assert_eq!(
        r[0].detail["candidates"].as_array().unwrap().len(),
        2,
        "{}",
        r[0].detail
    );
}

/// A helper the harness starts while only a yielded cell may run (an MCP
/// server, no shell) is the session's, as with no call at all.
#[test]
fn fp6_a_non_shell_helper_while_a_cell_runs_is_the_sessions() {
    let mut j = Join::new();
    start(&mut j);
    tap_code(
        &mut j,
        "call_E1",
        "exec",
        1_000,
        1_200,
        Some("1"),
        Some("running"),
    );
    effect(&mut j, "fork", 5_000, ROOT, 1, json!({"child": 7861}));
    effect(
        &mut j,
        "exec",
        5_005,
        7861,
        ROOT,
        json!({"exe": "/usr/bin/node"}),
    );
    assert!(effect(&mut j, "write", 5_020, 7861, ROOT, json!({"path": "/w/m"})).is_empty());
}

/// FP5R-4's other order: a chat token's `tool.call` (or a deny) for an id
/// before the tap's record names it is undone when the tap marks it a code
/// call, so the cell's nested shells still find it.
#[test]
fn fp6_an_adapter_end_before_the_taps_record_does_not_end_a_code_call() {
    let mut j = Join::new();
    start(&mut j);
    let mut t = ev(
        Source::Adapter,
        "tool.call",
        900,
        None,
        json!({"toolUseId": "call_E5"}),
    );
    t.harness = "codex".into();
    j.observe(&t);
    tap_only(&mut j, "codex", "call_E5", "exec", 1_000, 30_000);
    let r = shell_writes(&mut j, 10_000, 7871, "/w/n");
    assert_eq!(
        r[0].detail["chosen"], "tap-chat-j-call_E5",
        "{}",
        r[0].detail
    );
}

/// FP5R-3 in an untapped chat: a second approval for a call, later than the
/// first, does not move its start past a shell the call already started.
#[test]
fn fp6_a_later_approval_does_not_move_an_untapped_calls_start() {
    let mut j = Join::new();
    start(&mut j);
    j.observe(&ev(
        Source::Adapter,
        "approval",
        1_000,
        None,
        json!({"toolUseId": "toolu_U1", "decision": "allow", "tool": "bash"}),
    ));
    j.observe(&ev(
        Source::Adapter,
        "approval",
        5_000,
        None,
        json!({"toolUseId": "toolu_U1", "decision": "allow", "tool": "bash"}),
    ));
    let r = shell_writes(&mut j, 1_100, 7881, "/w/u");
    assert_eq!(r[0].detail["chosen"], "approval-1000-0", "{}", r[0].detail);
}

// ---- Separate review of fix pass 6: probes. ----

/// FP6-S1 probe, the join's half: a `wait` on a padded id (Codex answered
/// for a missing cell, "Script terminated") must not close the still-running
/// cell 3, so cell 3's later shell keeps a record. The review's probe fed the
/// tap's old record (cellId "3", trimmed from " 3"); since the fix the tap
/// keeps `wait`'s id as Codex reads it, and " 3" is no id `cell_id_ok`
/// takes, so the record names no cell (`record::tests::fp6_s1_...`). This
/// feeds that record; the assertion is the probe's.
#[test]
fn fp6_s1_a_wait_on_another_cell_does_not_close_a_running_cell() {
    let mut j = Join::new();
    start(&mut j);
    tap_code(
        &mut j,
        "call_E1",
        "exec",
        1_000,
        1_200,
        Some("3"),
        Some("running"),
    );
    // What the tap records for `wait` on " 3" since FP6-S1: no cellId.
    tap_code(&mut j, "call_W1", "wait", 5_000, 5_100, None, Some("ended"));
    let r = shell_writes(&mut j, 20_000, 7901, "/w/after-pad");
    assert_eq!(r.len(), 1, "the running cell's shell has no record: {r:?}");
}

/// FP6-S2 probe. A chat token's `tool.call` for a tapped shell call, posted
/// as soon as the tap's record shows in its tail and before the gate lets the
/// shell start (an ask the person answers after a few seconds), ends the
/// call before its shell exists: the shell is the session's, no record.
/// The code-call half of FP5R-4 is fixed; this shell-call half is not.
#[test]
fn fp6_s2_a_chat_token_tool_call_before_a_tapped_shell_starts_drops_it() {
    let mut j = Join::new();
    start(&mut j);
    let mut e = ev(
        Source::Tap,
        "tap.call",
        1_000,
        None,
        json!({"callId": "toolu_S2", "toolNormalized": "bash", "paths": [], "resultSha256": null}),
    );
    e.id = format!("tap-{CHAT}-toolu_S2");
    j.observe(&e);
    j.observe(&ev(
        Source::Adapter,
        "tool.call",
        1_100,
        None,
        json!({"toolUseId": "toolu_S2"}),
    ));
    // The gate's real approval after the person answers, then the shell.
    j.observe(&ev(
        Source::Adapter,
        "approval",
        6_000,
        None,
        json!({"toolUseId": "toolu_S2", "decision": "allow", "tool": "bash"}),
    ));
    let r = shell_writes(&mut j, 6_100, 7911, "/w/s2");
    assert_eq!(r.len(), 1, "the call's own shell has no record: {r:?}");
}

/// FP6-S3 probe. `code_owners` calls `cell_closed` (a scan of every call)
/// for every open code call, on each harness fork and exec: 4,096 yielded
/// cells (MAX_CALLS) cost 4,096 x 4,096 checks per event, under the join's
/// lock. The bound here is generous for a 2-core box.
#[test]
fn fp6_s3_many_open_cells_keep_a_harness_fork_cheap() {
    let mut j = Join::new();
    start(&mut j);
    for i in 0..MAX_CALLS as i64 {
        let id = format!("call_C{i}");
        let cell = format!("{i}");
        tap_code(
            &mut j,
            &id,
            "exec",
            1_000 + i,
            1_001 + i,
            Some(&cell),
            Some("running"),
        );
    }
    let t0 = std::time::Instant::now();
    for k in 0..10u32 {
        effect(
            &mut j,
            "fork",
            100_000 + k as i64,
            ROOT,
            1,
            json!({"child": 8000 + k}),
        );
    }
    let took = t0.elapsed();
    // 1 s, not the probe's 50 ms: the probe failed once under the full
    // suite's load on a 2-core box (re-review FP6R2-4), and the quadratic
    // scan it guards against took 5.99 s for these 10 forks.
    assert!(
        took < std::time::Duration::from_secs(1),
        "10 forks took {took:?}"
    );
}

/// FP6-S2: only a call's first allow re-opens an end posted before it, so a
/// chat token's late allow after the call's real end does not make the
/// finished call own a later harness shell.
#[test]
fn fp6r_a_late_allow_does_not_re_open_a_finished_call() {
    let mut j = Join::new();
    start(&mut j);
    call(&mut j, "toolu_L", "bash", &[], 1_000, Some(2_000));
    j.observe(&ev(
        Source::Adapter,
        "approval",
        30_000,
        None,
        json!({"toolUseId": "toolu_L", "decision": "allow", "tool": "bash"}),
    ));
    let r = shell_writes(&mut j, 30_100, 7921, "/w/late");
    assert!(r.is_empty(), "{r:?}");
}

/// FP6-S2, a deny: a chat token's `deny` for an untapped call, posted before
/// the gate's real allow, ends nothing once the allow comes.
#[test]
fn fp6r_a_deny_before_the_allow_does_not_end_an_untapped_call() {
    let mut j = Join::new();
    start(&mut j);
    j.observe(&ev(
        Source::Adapter,
        "approval",
        1_000,
        None,
        json!({"toolUseId": "toolu_U", "decision": "deny", "tool": "bash"}),
    ));
    j.observe(&ev(
        Source::Adapter,
        "approval",
        6_000,
        None,
        json!({"toolUseId": "toolu_U", "decision": "allow", "tool": "bash"}),
    ));
    let r = shell_writes(&mut j, 6_100, 7931, "/w/u2");
    assert_eq!(r.len(), 1, "{r:?}");
}

// ---- Re-review of d0c8a07: probes. ----

fn tap_open(j: &mut Join, id: &str, tool: &str, t: i64) {
    let mut e = ev(
        Source::Tap,
        "tap.call",
        t,
        None,
        json!({"callId": id, "toolNormalized": tool, "paths": [], "resultSha256": null}),
    );
    e.id = format!("tap-{CHAT}-{id}");
    j.observe(&e);
}

/// FP6R-1 probe. The gate's honest decision is `ask` (no approver answered,
/// so the harness asks the person in its own prompt, `derm-claude-plugin`
/// `hook.ts:76-99`): no later derm record says when the person allowed it.
/// A chat token's `tool.call` posted while the person reads the prompt is
/// not flagged (a gate decision is in the ring) and nothing re-opens the
/// call, so the shell that starts on the person's yes has no record.
#[test]
fn fp6r_1_an_early_tool_call_during_a_native_ask_does_not_drop_the_shell() {
    let mut j = Join::new();
    start(&mut j);
    tap_open(&mut j, "toolu_R1", "bash", 1_000);
    j.observe(&ev(
        Source::Adapter,
        "approval",
        1_010,
        None,
        json!({"toolUseId": "toolu_R1", "decision": "ask", "tool": "bash"}),
    ));
    j.observe(&ev(
        Source::Adapter,
        "tool.call",
        1_100,
        None,
        json!({"toolUseId": "toolu_R1"}),
    ));
    let r = shell_writes(&mut j, 8_000, 7951, "/w/r1");
    assert_eq!(r.len(), 1, "the call's own shell has no record: {r:?}");
}

/// FP6R-2 probe. The agent posts a decision of its own first (any decision
/// other than `deny` or `deferred` counts as the first allow), then a
/// `tool.call`; the gate's real allow arrives as a conflict copy, which the
/// join still reads but which no longer re-opens the call. The daemon flags
/// the gate's copy (`gate.conflict`), yet the shell has no join record.
#[test]
fn fp6r_2_an_agent_decision_first_disarms_the_re_open() {
    let mut j = Join::new();
    start(&mut j);
    tap_open(&mut j, "toolu_R2", "bash", 1_000);
    j.observe(&ev(
        Source::Adapter,
        "approval",
        1_050,
        None,
        json!({"toolUseId": "toolu_R2", "decision": "allow", "tool": "bash"}),
    ));
    j.observe(&ev(
        Source::Adapter,
        "tool.call",
        1_100,
        None,
        json!({"toolUseId": "toolu_R2"}),
    ));
    // The gate's real allow, after the person answered (a conflict copy).
    let mut real = ev(
        Source::Adapter,
        "approval",
        6_000,
        None,
        json!({"toolUseId": "toolu_R2", "decision": "allow", "tool": "bash", "conflictsWith": "x"}),
    );
    real.id = "claude-code-toolu_R2-decision-conflict-1".into();
    j.observe(&real);
    let r = shell_writes(&mut j, 6_100, 7961, "/w/r2");
    assert_eq!(r.len(), 1, "the call's own shell has no record: {r:?}");
}

/// FP6R-1, the honest flow: after a gate `ask` the person answers in the
/// harness's own prompt; the call's own shell, started before the gate's
/// real `tool.call`, is chosen for it, and a shell the harness starts after
/// that end and before the tap's result (a post-tool hook) lists the call
/// and is not chosen; after the tap's result it is the session's.
#[test]
fn fp6r_after_a_native_ask_the_calls_own_shell_is_chosen_and_a_later_one_is_not() {
    let mut j = Join::new();
    start(&mut j);
    tap_open(&mut j, "toolu_H", "bash", 1_000);
    j.observe(&ev(
        Source::Adapter,
        "approval",
        1_010,
        None,
        json!({"toolUseId": "toolu_H", "decision": "ask", "tool": "bash"}),
    ));
    let own = shell_writes(&mut j, 5_000, 7971, "/w/own");
    assert_eq!(
        own[0].detail["chosen"], "tap-chat-j-toolu_H",
        "{}",
        own[0].detail
    );
    j.observe(&ev(
        Source::Adapter,
        "tool.call",
        6_000,
        None,
        json!({"toolUseId": "toolu_H"}),
    ));
    let after = shell_writes(&mut j, 6_500, 7981, "/w/hook");
    assert_eq!(after.len(), 1, "{after:?}");
    assert!(after[0].detail["chosen"].is_null(), "{}", after[0].detail);
    assert_eq!(
        after[0].detail["candidates"][0]["call"],
        "tap-chat-j-toolu_H"
    );
    let mut result = ev(
        Source::Tap,
        "tap.call",
        7_000,
        None,
        json!({"callId": "toolu_H", "toolNormalized": "bash", "paths": [], "resultSha256": "ab"}),
    );
    result.id = format!("tap-{CHAT}-toolu_H");
    j.observe(&result);
    let later = shell_writes(&mut j, 20_000, 7991, "/w/later");
    assert!(later.is_empty(), "{later:?}");
}

// ---- Re-review of 7508cb1: probe. ----

/// FP6R2-1 probe. derm's Codex gate posts `allow` and says nothing to Codex,
/// so Codex's own approval prompt still runs after it (`packages/
/// derm-codex-plugin/src/hook.ts:110-111`, "Allow: say nothing, so Codex's
/// own approval flow runs as configured"). The person answers that prompt
/// after seconds, and no derm record marks the answer. A chat token's
/// `tool.call` posted while the prompt waits is not flagged (the call is in
/// `Decided`), the call is not contested (the decision is `allow`), and the
/// shell that starts on the person's yes has no record.
#[test]
fn fp6r2_1_an_early_tool_call_during_codexs_own_prompt_does_not_drop_the_shell() {
    let mut j = Join::new();
    start(&mut j);
    let mut e = ev(
        Source::Tap,
        "tap.call",
        1_000,
        None,
        json!({"callId": "call_X1", "toolNormalized": "exec_command", "paths": [], "resultSha256": null}),
    );
    e.id = format!("tap-{CHAT}-call_X1");
    e.harness = "codex".into();
    j.observe(&e);
    let mut allow = ev(
        Source::Adapter,
        "approval",
        1_010,
        None,
        json!({"toolUseId": "call_X1", "decision": "allow", "tool": "exec_command"}),
    );
    allow.harness = "codex".into();
    j.observe(&allow);
    let mut forged = ev(
        Source::Adapter,
        "tool.call",
        1_100,
        None,
        json!({"toolUseId": "call_X1"}),
    );
    forged.harness = "codex".into();
    j.observe(&forged);
    let r = shell_writes(&mut j, 9_000, 7971, "/w/x1");
    assert_eq!(r.len(), 1, "the call's own shell has no record: {r:?}");
}

// Fix pass 7: the Mac test w5's retest 6 (MW5-28, MW5-29).

/// Codex 0.163.0's npm launcher (`@openai/codex@0.163.0` `bin/codex.js:241`).
const CODEX_NODE: &str = "/opt/homebrew/Cellar/node@22/22.22.3/bin/node";
const CODEX_NATIVE: &str = "/opt/homebrew/lib/node_modules/@openai/codex/node_modules/@openai/codex-darwin-arm64/vendor/aarch64-apple-darwin/bin/codex";

/// `run.start` for `derm run codex` from npm: `harnessExe` is the launcher's
/// interpreter, `harnessChildExe` the native binary the launcher starts.
fn start_codex(j: &mut Join, boundary: &str, child: Option<&str>) {
    let mut e = ev(
        Source::Run,
        "run.start",
        0,
        Some(ROOT),
        json!({"cwd": "/w", "boundary": boundary, "harnessExe": CODEX_NODE, "harnessChildExe": child}),
    );
    e.harness = "codex".into();
    j.observe(&e);
}

/// Mac test w5 retest 6, MW5-28: Codex 0.163.0's npm launcher (node, the
/// run's root under `--boundary none`) spawns the native binary as a child
/// before any call, so the join gave that child, and every shell it starts,
/// to the session: a tapped Codex chat got no join record at all. `derm run`
/// names the native binary (`harnessChildExe`), and the launcher's child that
/// execs it while no call runs is the harness too.
#[test]
fn mw5_28_a_launchers_child_that_execs_the_named_binary_is_the_harness() {
    let mut j = Join::new();
    start_codex(&mut j, "none", Some(CODEX_NATIVE));
    effect(&mut j, "exec", 10, ROOT, 1, json!({"exe": "/usr/bin/env"}));
    effect(&mut j, "exec", 11, ROOT, 1, json!({"exe": CODEX_NODE}));
    effect(&mut j, "fork", 20, ROOT, 1, json!({"child": 2000}));
    effect(&mut j, "exec", 21, 2000, ROOT, json!({"exe": CODEX_NATIVE}));
    tap_only(&mut j, "codex", "call_L1", "exec", 1_000, 30_000);
    effect(&mut j, "fork", 1_100, 2000, ROOT, json!({"child": 2001}));
    effect(
        &mut j,
        "exec",
        1_105,
        2001,
        2000,
        json!({"exe": "/bin/zsh"}),
    );
    effect(&mut j, "fork", 1_110, 2001, 2000, json!({"child": 2002}));
    effect(
        &mut j,
        "exec",
        1_115,
        2002,
        2001,
        json!({"exe": "/bin/sleep"}),
    );
    let r = effect(&mut j, "write", 1_120, 2002, 2001, json!({"path": "/w/a"}));
    assert_eq!(r.len(), 1, "{r:?}");
    assert_eq!(
        r[0].detail["chosen"], "tap-chat-j-call_L1",
        "{}",
        r[0].detail
    );
    assert_eq!(
        r[0].detail["candidates"][0]["by"], "tree",
        "{}",
        r[0].detail
    );
}

/// MW5-28 under srt (inferred by the retest, not run there): the harness
/// found under the wrappers is the launcher's node, and its child that execs
/// the native binary places the shells.
#[test]
fn mw5_28_under_a_boundary_the_launchers_child_is_the_harness_too() {
    let mut j = Join::new();
    start_codex(&mut j, "srt", Some(CODEX_NATIVE));
    effect(&mut j, "exec", 5, ROOT, 1, json!({"exe": CODEX_NODE}));
    effect(&mut j, "fork", 10, ROOT, 1, json!({"child": 1100}));
    effect(
        &mut j,
        "exec",
        11,
        1100,
        ROOT,
        json!({"exe": "/usr/bin/sandbox-exec"}),
    );
    effect(&mut j, "exec", 12, 1100, ROOT, json!({"exe": CODEX_NODE}));
    effect(&mut j, "fork", 20, 1100, ROOT, json!({"child": 1200}));
    effect(&mut j, "exec", 21, 1200, 1100, json!({"exe": CODEX_NATIVE}));
    tap_only(&mut j, "codex", "call_L2", "exec", 1_000, 30_000);
    effect(&mut j, "fork", 1_100, 1200, 1100, json!({"child": 1201}));
    effect(
        &mut j,
        "exec",
        1_105,
        1201,
        1200,
        json!({"exe": "/bin/zsh"}),
    );
    let r = effect(&mut j, "write", 1_120, 1201, 1200, json!({"path": "/w/b"}));
    assert_eq!(r.len(), 1, "{r:?}");
    assert_eq!(
        r[0].detail["chosen"], "tap-chat-j-call_L2",
        "{}",
        r[0].detail
    );
    assert!(r[0].detail.get("harnessFound").is_none(), "{}", r[0].detail);
}

/// Codex 0.167.0's launcher replaces node with the native binary
/// (`bin/codex.js:236-243`, `process.execve`): the root is the harness, as
/// before. The handoff is spent there, so a later child the harness starts
/// while no call runs that execs the same binary stays the session's and its
/// shells are no call's.
#[test]
fn mw5_28_a_second_native_binary_is_not_the_harness() {
    let mut j = Join::new();
    start_codex(&mut j, "none", Some(CODEX_NATIVE));
    effect(&mut j, "exec", 10, ROOT, 1, json!({"exe": "/usr/bin/env"}));
    effect(&mut j, "exec", 11, ROOT, 1, json!({"exe": CODEX_NODE}));
    effect(&mut j, "exec", 12, ROOT, 1, json!({"exe": CODEX_NATIVE}));
    effect(&mut j, "fork", 20, ROOT, 1, json!({"child": 2100}));
    effect(&mut j, "exec", 21, 2100, ROOT, json!({"exe": CODEX_NATIVE}));
    tap_only(&mut j, "codex", "call_L3", "exec", 1_000, 30_000);
    // The root's own shell is the call's, as it was.
    let r = shell_writes(&mut j, 1_100, 2200, "/w/c");
    assert_eq!(
        r[0].detail["chosen"], "tap-chat-j-call_L3",
        "{}",
        r[0].detail
    );
    // The second native binary's shell is not.
    effect(&mut j, "fork", 1_300, 2100, ROOT, json!({"child": 2101}));
    effect(
        &mut j,
        "exec",
        1_305,
        2101,
        2100,
        json!({"exe": "/bin/zsh"}),
    );
    let r = effect(&mut j, "write", 1_310, 2101, 2100, json!({"path": "/w/d"}));
    assert!(r.is_empty(), "{r:?}");
}

/// The handoff needs a child started while no call ran: a shell a call
/// started that execs the native binary (`codex exec` run by the agent) is
/// that call's, not a second harness.
#[test]
fn mw5_28_a_calls_own_child_never_becomes_the_harness() {
    let mut j = Join::new();
    start_codex(&mut j, "none", Some(CODEX_NATIVE));
    effect(&mut j, "exec", 11, ROOT, 1, json!({"exe": CODEX_NODE}));
    call(&mut j, "toolu_L4", "bash", &[], 1_000, Some(5_000));
    effect(&mut j, "fork", 1_100, ROOT, 1, json!({"child": 2300}));
    effect(&mut j, "exec", 1_105, 2300, ROOT, json!({"exe": "/bin/sh"}));
    effect(
        &mut j,
        "exec",
        1_110,
        2300,
        ROOT,
        json!({"exe": CODEX_NATIVE}),
    );
    call(&mut j, "toolu_L5", "bash", &[], 6_000, Some(9_000));
    // The agent's codex starts a shell during a later call: by inheritance it
    // stays L4's, never placed as the harness's for L5.
    effect(&mut j, "fork", 6_100, 2300, ROOT, json!({"child": 2301}));
    effect(
        &mut j,
        "exec",
        6_105,
        2301,
        2300,
        json!({"exe": "/bin/zsh"}),
    );
    let r = effect(&mut j, "write", 6_110, 2301, 2300, json!({"path": "/w/e"}));
    assert_eq!(
        r[0].detail["chosen"], "tap-chat-j-toolu_L4",
        "{}",
        r[0].detail
    );
}

/// Mac test w5 retest 6, MW5-29: Codex runs each command as
/// `/usr/bin/sandbox-exec -p <profile> -- zsh -c ...` (its
/// `MACOS_PATH_TO_SEATBELT_EXECUTABLE`, `sandboxing/src/seatbelt.rs:62` at
/// 0.163.0), then `zsh` and the program in the same pid. The join decided
/// the child's owner at its first exec, `sandbox-exec`, no shell, so the
/// command was no call's. A sandbox wrapper the harness starts defers the
/// decision to the program it runs.
#[test]
fn mw5_29_a_command_in_the_harnesss_sandbox_is_its_calls() {
    let mut j = Join::new();
    start_under(&mut j, "none", Some(CODEX_NATIVE));
    tap_only(&mut j, "codex", "call_S1", "exec", 1_000, 30_000);
    effect(&mut j, "fork", 1_100, ROOT, 1, json!({"child": 3000}));
    effect(
        &mut j,
        "exec",
        1_101,
        3000,
        ROOT,
        json!({"exe": "/usr/bin/sandbox-exec"}),
    );
    effect(
        &mut j,
        "exec",
        1_102,
        3000,
        ROOT,
        json!({"exe": "/bin/zsh"}),
    );
    effect(
        &mut j,
        "exec",
        1_103,
        3000,
        ROOT,
        json!({"exe": "/bin/sleep"}),
    );
    let r = effect(&mut j, "write", 1_110, 3000, ROOT, json!({"path": "/w/f"}));
    assert_eq!(r.len(), 1, "{r:?}");
    assert_eq!(
        r[0].detail["chosen"], "tap-chat-j-call_S1",
        "{}",
        r[0].detail
    );
    assert_eq!(
        r[0].detail["candidates"][0]["by"], "tree",
        "{}",
        r[0].detail
    );
}

/// MW5-29 on Linux, read in Codex 0.163.0 and bubblewrap, not run (review
/// FP7-S4 corrected the sequence): the harness runs its own binary through
/// the `codex-linux-sandbox` alias (`arg0/src/lib.rs:360-410`, a link to
/// itself, so the OS feed names Codex's own binary). With protected-create
/// targets, which a workspace missing `.git`, `.agents`, `.codex` or `.aws`
/// has (`protocol/src/permissions.rs:46-50`, `linux-sandbox/src/bwrap.rs:831-853`),
/// that outer stage forks `bwrap` (`linux_run_main.rs:576-610`). `bwrap
/// --unshare-pid` clones its pid 1, which forks the command
/// (`bubblewrap.c:3057-3061`, `3479-3490`): Codex's binary again, the inner
/// stage, which forks the shell (`linux_run_main.rs:247-256`).
#[test]
fn mw5_29_through_the_harnesss_own_helper_and_bwrap_on_linux() {
    let mut j = Join::new();
    start_under(&mut j, "none", Some(CODEX_NATIVE));
    call(&mut j, "toolu_S2", "exec_command", &[], 1_000, Some(9_000));
    let steps: &[(&str, u32, u32, serde_json::Value)] = &[
        ("fork", ROOT, 1, json!({"child": 4000})),
        ("exec", 4000, ROOT, json!({"exe": CODEX_NATIVE})),
        ("fork", 4000, ROOT, json!({"child": 4001})),
        ("exec", 4001, 4000, json!({"exe": "/usr/bin/bwrap"})),
        ("fork", 4001, 4000, json!({"child": 4002})),
        ("fork", 4002, 4001, json!({"child": 4003})),
        ("exec", 4003, 4002, json!({"exe": CODEX_NATIVE})),
        ("fork", 4003, 4002, json!({"child": 4004})),
        ("exec", 4004, 4003, json!({"exe": "/bin/bash"})),
        ("fork", 4004, 4003, json!({"child": 4005})),
        ("exec", 4005, 4004, json!({"exe": "/usr/bin/npm"})),
    ];
    for (i, (kind, pid, ppid, d)) in steps.iter().enumerate() {
        effect(&mut j, kind, 1_100 + i as i64, *pid, *ppid, d.clone());
    }
    let r = effect(&mut j, "write", 1_150, 4005, 4004, json!({"path": "/w/g"}));
    assert_eq!(r.len(), 1, "{r:?}");
    assert_eq!(
        r[0].detail["chosen"], "tap-chat-j-toolu_S2",
        "{}",
        r[0].detail
    );
}

/// The narrowing that FP7-S4's fix keeps: a child the harness's own binary
/// forks while a call runs is placed only through a sandbox wrapper. One that
/// runs a shell itself, or an MCP server the npm harness starts as node (an
/// interpreter, never the harness's own binary) that runs `bwrap` and a
/// shell, is not chosen.
#[test]
fn fp7_s4_only_a_sandbox_wrapper_passes_a_call_through_the_harnesss_own_binary() {
    let mut j = Join::new();
    start_under(&mut j, "none", Some(CODEX_NATIVE));
    call(&mut j, "toolu_X1", "exec_command", &[], 1_000, Some(9_000));
    effect(&mut j, "fork", 1_100, ROOT, 1, json!({"child": 4100}));
    effect(
        &mut j,
        "exec",
        1_101,
        4100,
        ROOT,
        json!({"exe": CODEX_NATIVE}),
    );
    effect(&mut j, "fork", 1_102, 4100, ROOT, json!({"child": 4101}));
    effect(&mut j, "exec", 1_103, 4101, 4100, json!({"exe": "/bin/sh"}));
    let r = effect(&mut j, "write", 1_110, 4101, 4100, json!({"path": "/w/x"}));
    assert!(r[0].detail["chosen"].is_null(), "{}", r[0].detail);

    let mut j = Join::new();
    start_codex(&mut j, "none", None);
    call(&mut j, "toolu_X2", "bash", &[], 1_000, Some(9_000));
    effect(&mut j, "fork", 1_100, ROOT, 1, json!({"child": 4200}));
    effect(
        &mut j,
        "exec",
        1_101,
        4200,
        ROOT,
        json!({"exe": CODEX_NODE}),
    );
    effect(&mut j, "fork", 1_102, 4200, ROOT, json!({"child": 4201}));
    effect(
        &mut j,
        "exec",
        1_103,
        4201,
        4200,
        json!({"exe": "/usr/bin/bwrap"}),
    );
    effect(&mut j, "fork", 1_104, 4201, 4200, json!({"child": 4202}));
    effect(&mut j, "exec", 1_105, 4202, 4201, json!({"exe": "/bin/sh"}));
    let r = effect(&mut j, "write", 1_110, 4202, 4201, json!({"path": "/w/y"}));
    assert!(r[0].detail["chosen"].is_null(), "{}", r[0].detail);
}

/// FP7-S1 for a wrapper: a process forked under a harness's sandbox wrapper
/// that execs more than `WRAP_MS` after the harness started the wrapper is
/// no launch, so the call that ran then is not chosen.
#[test]
fn fp7_s1_a_wrappers_late_descendant_is_not_chosen_for_an_old_call() {
    let mut j = Join::new();
    start_under(&mut j, "none", Some(CODEX_NATIVE));
    call(&mut j, "toolu_Q3", "bash", &[], 1_000, Some(3_000));
    effect(&mut j, "fork", 1_100, ROOT, 1, json!({"child": 7100}));
    effect(
        &mut j,
        "exec",
        1_101,
        7100,
        ROOT,
        json!({"exe": "/usr/bin/bwrap"}),
    );
    effect(&mut j, "fork", 1_102, 7100, ROOT, json!({"child": 7101}));
    effect(&mut j, "fork", 30_000, 7101, 7100, json!({"child": 7102}));
    effect(
        &mut j,
        "exec",
        30_001,
        7102,
        7101,
        json!({"exe": "/bin/sh"}),
    );
    let r = effect(&mut j, "write", 30_010, 7102, 7101, json!({"path": "/w/z"}));
    assert!(r.iter().all(|e| e.detail["chosen"].is_null()), "{r:?}");
}

/// What a sandbox wrapper defers to keeps the shell rule's limits: two shell
/// calls running share it, none chosen; a program that is no shell is no
/// call's choice; a wrapper started while no call runs is the session's; and
/// the harness's own binary that execs nothing more (Claude Code's ripgrep)
/// is never chosen for a shell call running beside it.
#[test]
fn mw5_29_a_wrapper_keeps_the_shell_rules_limits() {
    let mut j = Join::new();
    start_under(&mut j, "none", Some("/opt/claude/claude"));
    // Idle: the session's.
    effect(&mut j, "fork", 100, ROOT, 1, json!({"child": 5000}));
    effect(
        &mut j,
        "exec",
        101,
        5000,
        ROOT,
        json!({"exe": "/usr/bin/sandbox-exec"}),
    );
    effect(&mut j, "exec", 102, 5000, ROOT, json!({"exe": "/bin/zsh"}));
    call(&mut j, "toolu_W1", "bash", &[], 1_000, Some(9_000));
    let r = effect(&mut j, "write", 1_050, 5000, ROOT, json!({"path": "/w/h"}));
    assert!(r.is_empty(), "{r:?}");
    // The harness's own binary, then nothing: not chosen.
    effect(&mut j, "fork", 1_100, ROOT, 1, json!({"child": 5100}));
    effect(
        &mut j,
        "exec",
        1_101,
        5100,
        ROOT,
        json!({"exe": "/opt/claude/claude"}),
    );
    let r = effect(&mut j, "write", 1_110, 5100, ROOT, json!({"path": "/w/i"}));
    assert!(r[0].detail["chosen"].is_null(), "{}", r[0].detail);
    // A wrapper that runs a program that is no shell: not chosen.
    effect(&mut j, "fork", 1_200, ROOT, 1, json!({"child": 5200}));
    effect(
        &mut j,
        "exec",
        1_201,
        5200,
        ROOT,
        json!({"exe": "/usr/bin/sandbox-exec"}),
    );
    effect(
        &mut j,
        "exec",
        1_202,
        5200,
        ROOT,
        json!({"exe": "/usr/bin/python3"}),
    );
    let r = effect(&mut j, "write", 1_210, 5200, ROOT, json!({"path": "/w/j"}));
    assert!(r[0].detail["chosen"].is_null(), "{}", r[0].detail);
    // Two shell calls: both candidates, none chosen.
    call(&mut j, "toolu_W2", "bash", &[], 1_300, Some(9_000));
    effect(&mut j, "fork", 1_400, ROOT, 1, json!({"child": 5300}));
    effect(
        &mut j,
        "exec",
        1_401,
        5300,
        ROOT,
        json!({"exe": "/usr/bin/sandbox-exec"}),
    );
    effect(
        &mut j,
        "exec",
        1_402,
        5300,
        ROOT,
        json!({"exe": "/bin/zsh"}),
    );
    let r = effect(&mut j, "write", 1_410, 5300, ROOT, json!({"path": "/w/k"}));
    assert!(r[0].detail["chosen"].is_null(), "{}", r[0].detail);
    let c = r[0].detail["candidates"].as_array().unwrap();
    assert_eq!(c.len(), 2, "{}", r[0].detail);
    assert!(c.iter().all(|x| x["by"] == "tree"), "{}", r[0].detail);
}

/// A wrapper decides at the time the harness started it: the call that ran
/// then, even when the shell's exec arrives after the call's window.
#[test]
fn mw5_29_a_wrapper_is_decided_by_when_the_harness_started_it() {
    let mut j = Join::new();
    start_under(&mut j, "none", Some(CODEX_NATIVE));
    call(&mut j, "toolu_W3", "bash", &[], 1_000, Some(2_000));
    effect(&mut j, "fork", 1_500, ROOT, 1, json!({"child": 5400}));
    effect(
        &mut j,
        "exec",
        1_501,
        5400,
        ROOT,
        json!({"exe": "/usr/bin/bwrap"}),
    );
    effect(&mut j, "fork", 1_502, 5400, ROOT, json!({"child": 5401}));
    // After the call's window (2_000 + `SLACK_AFTER_MS`), within `WRAP_MS`
    // of the wrapper's start (review FP7-S1).
    effect(&mut j, "exec", 6_000, 5401, 5400, json!({"exe": "/bin/sh"}));
    let r = effect(&mut j, "write", 6_010, 5401, 5400, json!({"path": "/w/l"}));
    assert_eq!(
        r[0].detail["chosen"], "tap-chat-j-toolu_W3",
        "{}",
        r[0].detail
    );
}

/// The harness's own executable run again counts only for the process's own
/// next exec: an npm harness's `harnessExe` is node, so an MCP server it
/// starts as node during a shell call, which then starts a shell, never gives
/// that shell to the call (BW5-11's class).
#[test]
fn mw5_29_a_helper_run_as_the_harnesss_own_program_does_not_pass_a_call_to_its_children() {
    let mut j = Join::new();
    start_under(&mut j, "none", Some(CODEX_NODE));
    call(&mut j, "toolu_P1", "bash", &[], 1_000, Some(9_000));
    effect(&mut j, "fork", 1_100, ROOT, 1, json!({"child": 6000}));
    effect(
        &mut j,
        "exec",
        1_101,
        6000,
        ROOT,
        json!({"exe": CODEX_NODE}),
    );
    effect(&mut j, "fork", 1_200, 6000, ROOT, json!({"child": 6001}));
    effect(&mut j, "exec", 1_201, 6001, 6000, json!({"exe": "/bin/sh"}));
    let r = effect(&mut j, "write", 1_210, 6001, 6000, json!({"path": "/w/m"}));
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
}

// Review of fix pass 7 (FP7-S*): probes. Each fails on 5112623.

/// FP7-S1: a helper the harness starts as its own executable while a shell
/// call runs (`Owner::Pending`) is re-decided at its next exec with no time
/// bound, as of the call that ran at its start: an exec into a shell long
/// after that call ended makes the call chosen (case 43: a helper is never
/// a call's with certainty).
#[test]
fn fp7_s1_a_pending_helpers_late_exec_is_not_chosen_for_an_old_call() {
    let mut j = Join::new();
    start_under(&mut j, "none", Some(CODEX_NODE));
    call(&mut j, "toolu_Q1", "bash", &[], 1_000, Some(9_000));
    effect(&mut j, "fork", 1_100, ROOT, 1, json!({"child": 7000}));
    effect(
        &mut j,
        "exec",
        1_101,
        7000,
        ROOT,
        json!({"exe": CODEX_NODE}),
    );
    // A minute later, no call running: the same pid execs a shell.
    effect(
        &mut j,
        "exec",
        60_000,
        7000,
        ROOT,
        json!({"exe": "/bin/sh"}),
    );
    call(&mut j, "toolu_Q2", "read", &[], 60_005, Some(70_000));
    let r = effect(&mut j, "write", 60_010, 7000, ROOT, json!({"path": "/w/q"}));
    assert!(
        r.iter()
            .all(|e| e.detail["chosen"] != json!("tap-chat-j-toolu_Q1")),
        "{r:?}"
    );
}

/// FP7-S2: `launched` is a pid kept for the chat; a fork that names it again
/// (the pid reused) clears its owner but not its role, so a process of a
/// call's tree that gets that pid places its children by time: a shell it
/// starts during a later call is chosen for that call, not its own.
#[test]
fn fp7_s2_a_reused_launched_pid_does_not_place_children() {
    let mut j = Join::new();
    start_codex(&mut j, "none", Some(CODEX_NATIVE));
    effect(&mut j, "exec", 11, ROOT, 1, json!({"exe": CODEX_NODE}));
    effect(&mut j, "fork", 20, ROOT, 1, json!({"child": 2000}));
    effect(&mut j, "exec", 21, 2000, ROOT, json!({"exe": CODEX_NATIVE}));
    call(&mut j, "toolu_R1", "bash", &[], 1_000, Some(5_000));
    effect(&mut j, "fork", 1_100, 2000, ROOT, json!({"child": 2001}));
    effect(
        &mut j,
        "exec",
        1_105,
        2001,
        2000,
        json!({"exe": "/bin/zsh"}),
    );
    // The call's shell starts a process that the OS gives pid 2000 again.
    effect(&mut j, "fork", 3_000, 2001, 2000, json!({"child": 2000}));
    effect(
        &mut j,
        "exec",
        3_005,
        2000,
        2001,
        json!({"exe": "/usr/bin/python3"}),
    );
    call(&mut j, "toolu_R2", "bash", &[], 20_000, Some(29_000));
    effect(&mut j, "fork", 20_100, 2000, 2001, json!({"child": 2005}));
    effect(
        &mut j,
        "exec",
        20_105,
        2005,
        2000,
        json!({"exe": "/bin/zsh"}),
    );
    let r = effect(&mut j, "write", 20_110, 2005, 2000, json!({"path": "/w/r"}));
    assert_eq!(
        r[0].detail["chosen"], "tap-chat-j-toolu_R1",
        "{}",
        r[0].detail
    );
}

/// FP7-S3: the feed can deliver a child's exec before its fork (T1). When
/// the launcher's child's exec comes first, the handoff forgets nothing yet,
/// and the late fork then gives the harness itself `Session`: its own write
/// during a call that is no MCP call gets no record, where in feed order it
/// gets one.
#[test]
fn fp7_s3_a_late_fork_record_does_not_make_the_launched_harness_the_sessions() {
    let mut j = Join::new();
    start_codex(&mut j, "none", Some(CODEX_NATIVE));
    effect(&mut j, "exec", 11, ROOT, 1, json!({"exe": CODEX_NODE}));
    effect(&mut j, "exec", 21, 2000, ROOT, json!({"exe": CODEX_NATIVE}));
    effect(&mut j, "fork", 20, ROOT, 1, json!({"child": 2000}));
    call(&mut j, "toolu_T1", "read", &[], 1_000, Some(5_000));
    let r = effect(&mut j, "write", 1_500, 2000, ROOT, json!({"path": "/w/t"}));
    assert_eq!(r.len(), 1, "{r:?}");
}

/// FP7-S4 (Codex 0.163.0 `linux-sandbox/src/linux_run_main.rs:247-256`):
/// the inner stage (`--apply-seccomp-then-exec`) forks and its child execs
/// the command; it does not exec the shell in its own pid as
/// `mw5_29_through_the_harnesss_own_helper_and_bwrap_on_linux` models. The
/// fork's child inherits `Ambiguous` from `Pending`, so the shell is never
/// chosen on Linux.
#[test]
fn fp7_s4_codexs_linux_inner_stage_forks_the_command() {
    let mut j = Join::new();
    start_under(&mut j, "none", Some(CODEX_NATIVE));
    call(&mut j, "toolu_U1", "exec_command", &[], 1_000, Some(9_000));
    effect(&mut j, "fork", 1_100, ROOT, 1, json!({"child": 4000}));
    effect(
        &mut j,
        "exec",
        1_101,
        4000,
        ROOT,
        json!({"exe": CODEX_NATIVE}),
    );
    effect(
        &mut j,
        "exec",
        1_102,
        4000,
        ROOT,
        json!({"exe": "/usr/bin/bwrap"}),
    );
    effect(&mut j, "fork", 1_103, 4000, ROOT, json!({"child": 4001}));
    effect(
        &mut j,
        "exec",
        1_104,
        4001,
        4000,
        json!({"exe": CODEX_NATIVE}),
    );
    effect(&mut j, "fork", 1_105, 4001, 4000, json!({"child": 4002}));
    effect(
        &mut j,
        "exec",
        1_106,
        4002,
        4001,
        json!({"exe": "/bin/bash"}),
    );
    let r = effect(&mut j, "write", 1_110, 4002, 4001, json!({"path": "/w/u"}));
    assert_eq!(
        r[0].detail["chosen"], "tap-chat-j-toolu_U1",
        "{}",
        r[0].detail
    );
}

/// FP7-S5: T1's feed order (a child's exec before its fork). A wrapper's
/// child whose shell exec arrives first is placed on the call, then the late
/// fork overwrites that with the parent's `Wrapped`, which no later exec
/// re-decides: the call's shell is not chosen.
#[test]
fn fp7_s5_a_wrapped_childs_late_fork_keeps_the_exec_placement() {
    let mut j = Join::new();
    start_under(&mut j, "none", Some(CODEX_NATIVE));
    call(&mut j, "toolu_V1", "bash", &[], 1_000, Some(9_000));
    effect(&mut j, "fork", 1_100, ROOT, 1, json!({"child": 5400}));
    effect(
        &mut j,
        "exec",
        1_101,
        5400,
        ROOT,
        json!({"exe": "/usr/bin/bwrap"}),
    );
    effect(&mut j, "exec", 1_110, 5401, 5400, json!({"exe": "/bin/sh"}));
    effect(&mut j, "fork", 1_105, 5400, ROOT, json!({"child": 5401}));
    let r = effect(&mut j, "write", 1_200, 5401, 5400, json!({"path": "/w/v"}));
    assert_eq!(
        r[0].detail["chosen"], "tap-chat-j-toolu_V1",
        "{}",
        r[0].detail
    );
}

/// Box test w5 retest, BW5R-7: Codex's Stop hook shell started 1.5 s after
/// the tap's result for the `exec` call (its cell ended) was chosen for that
/// call by tree, with no call running: the shell was inside the window's
/// 2 s slack. A tool's result reaches the tap only after its command ended,
/// so a shell the harness starts after a tapped call's result is not that
/// call's (beyond a small clock slack); its writes fit no call by tree.
#[test]
fn bw5r_7_a_shell_started_after_a_tapped_results_end_is_not_that_calls() {
    let mut j = Join::new();
    start(&mut j);
    tap_code(
        &mut j,
        "call_S1",
        "exec",
        1_000,
        37_000,
        Some("1"),
        Some("ended"),
    );
    let r = shell_writes(&mut j, 38_500, 7101, "/w/hook");
    assert!(
        r.iter().all(|e| e.detail["chosen"].is_null()),
        "the Stop hook's shell is no call's: {r:?}"
    );
    // A shell call ended by the tap: a shell after its result is not its,
    // one before it is, and one inside the clock slack still is.
    tap_only(&mut j, "claude-code", "toolu_S2", "bash", 50_000, 52_000);
    let before = shell_writes(&mut j, 51_000, 7201, "/w/a");
    assert_eq!(
        before[0].detail["chosen"], "tap-chat-j-toolu_S2",
        "{before:?}"
    );
    let skew = shell_writes(&mut j, 52_100, 7301, "/w/b");
    assert_eq!(skew[0].detail["chosen"], "tap-chat-j-toolu_S2", "{skew:?}");
    let after = shell_writes(&mut j, 53_000, 7401, "/w/c");
    assert!(
        after.iter().all(|e| e.detail["chosen"].is_null()),
        "{after:?}"
    );
    // A yielded cell still owns its later shells (fix pass 6, FP5R-1).
    tap_code(
        &mut j,
        "call_S3",
        "exec",
        60_000,
        61_000,
        Some("2"),
        Some("running"),
    );
    let cell = shell_writes(&mut j, 63_000, 7501, "/w/d");
    assert_eq!(cell[0].detail["chosen"], "tap-chat-j-call_S3", "{cell:?}");
}

/// Box test w5 retest, BW5R-2: Claude Code writes its shell snapshot
/// (`~/.claude/shell-snapshots/snapshot-bash-*.sh`) from a shell it starts
/// itself, a direct child of the harness, at its first Bash call. The join
/// says so (`harnessChild`), so the install flagger can tell it from a write
/// an install's script makes further down the call's tree.
#[test]
fn bw5r_2_a_write_by_the_harnesss_own_child_is_marked() {
    let mut j = Join::new();
    start(&mut j);
    tap_only(&mut j, "claude-code", "toolu_I1", "bash", 1_000, 9_000);
    let snap = "/home/u/.claude/shell-snapshots/snapshot-bash-1-x.sh";
    effect(&mut j, "fork", 1_100, ROOT, 1, json!({"child": 8001}));
    effect(
        &mut j,
        "exec",
        1_105,
        8001,
        ROOT,
        json!({"exe": "/bin/bash"}),
    );
    let own = effect(&mut j, "write", 1_110, 8001, ROOT, json!({"path": snap}));
    assert_eq!(own[0].detail["chosen"], "tap-chat-j-toolu_I1", "{own:?}");
    assert_eq!(own[0].detail["harnessChild"], true, "{own:?}");
    // The install's script, a grandchild of the call's shell: not marked.
    let deep = shell_writes(&mut j, 1_200, 8101, snap);
    assert_eq!(deep[0].detail["chosen"], "tap-chat-j-toolu_I1", "{deep:?}");
    assert!(deep[0].detail.get("harnessChild").is_none(), "{deep:?}");
    // A reused pid is a new process: no longer the harness's child.
    effect(&mut j, "fork", 1_300, 8101, ROOT, json!({"child": 8001}));
    effect(&mut j, "exec", 1_305, 8001, 8101, json!({"exe": "/bin/sh"}));
    let reused = effect(&mut j, "write", 1_310, 8001, 8101, json!({"path": snap}));
    assert!(reused[0].detail.get("harnessChild").is_none(), "{reused:?}");
}

/// Box test w5 retest, BW5R-6: Codex 0.166.0 starts every child through its
/// own binary first (`/proc/self/exe --codex-run-as-process-setup ...`, which
/// execs the target in the same pid: `utils/pty/src/spawn_helper.rs:31-35,
/// 74-140` at `rust-v0.166.0`), so the sandboxed chain is: that helper, then
/// `codex-linux-sandbox` (Codex's binary again, by its arg0 link), which
/// starts `bwrap`, whose pid 1 starts the inner stage, which runs the shell.
/// The command's shell is chosen for its call; the stages' own exec records
/// are window candidates, as `sandbox-exec`'s are on macOS. A helper that
/// starts an MCP server while no call runs leaves it the session's.
#[test]
fn bw5r_6_codex_0_166s_spawn_helper_chain_places_the_command() {
    let mut j = Join::new();
    start_under(&mut j, "none", Some(CODEX_NATIVE));
    // An MCP server through the helper, at the session's start.
    effect(&mut j, "fork", 100, ROOT, 1, json!({"child": 9900}));
    effect(
        &mut j,
        "exec",
        101,
        9900,
        ROOT,
        json!({"exe": CODEX_NATIVE}),
    );
    effect(
        &mut j,
        "exec",
        102,
        9900,
        ROOT,
        json!({"exe": "/usr/bin/node"}),
    );
    call(&mut j, "toolu_W1", "exec_command", &[], 1_000, Some(9_000));
    let mcp = effect(&mut j, "write", 1_050, 9900, ROOT, json!({"path": "/w/m"}));
    assert!(
        mcp.is_empty() || mcp[0].detail["chosen"].is_null(),
        "{mcp:?}"
    );
    // The command: helper, then the sandbox launcher, bwrap, its pid 1, the
    // inner stage, the shell.
    effect(&mut j, "fork", 1_100, ROOT, 1, json!({"child": 9001}));
    effect(
        &mut j,
        "exec",
        1_101,
        9001,
        ROOT,
        json!({"exe": CODEX_NATIVE}),
    );
    effect(
        &mut j,
        "exec",
        1_102,
        9001,
        ROOT,
        json!({"exe": CODEX_NATIVE}),
    );
    effect(&mut j, "fork", 1_103, 9001, ROOT, json!({"child": 9002}));
    effect(
        &mut j,
        "exec",
        1_104,
        9002,
        9001,
        json!({"exe": "/usr/bin/bwrap"}),
    );
    effect(&mut j, "fork", 1_105, 9002, 9001, json!({"child": 9003}));
    effect(
        &mut j,
        "exec",
        1_106,
        9003,
        9002,
        json!({"exe": CODEX_NATIVE}),
    );
    effect(&mut j, "fork", 1_107, 9003, 9002, json!({"child": 9004}));
    effect(
        &mut j,
        "exec",
        1_108,
        9004,
        9003,
        json!({"exe": "/bin/bash"}),
    );
    let r = effect(&mut j, "write", 1_110, 9004, 9003, json!({"path": "/w/x"}));
    assert_eq!(r[0].detail["chosen"], "tap-chat-j-toolu_W1", "{r:?}");
}

/// Review FP9-S1 (its probe, which passed on `c491b97`, inverted): bash runs
/// a lone command in its own pid (`bash -lc "pip install x"` execs pip there;
/// run with bash 5.2), so the install program kept the harness's-child mark
/// and its writes read as the harness's own shell's. A second exec, or a
/// first exec that is no shell, drops the mark; an exec record that names
/// no parent drops it too (FP9-S8).
#[test]
fn fp9_s1_a_command_bash_runs_in_its_own_pid_is_not_the_harnesss_shell() {
    let mut j = Join::new();
    start(&mut j);
    tap_only(&mut j, "claude-code", "toolu_P1", "bash", 1_000, 9_000);
    let snap = "/home/u/.claude/shell-snapshots/snapshot-bash-1-x.sh";
    effect(&mut j, "fork", 1_100, ROOT, 1, json!({"child": 8001}));
    effect(
        &mut j,
        "exec",
        1_105,
        8001,
        ROOT,
        json!({"exe": "/usr/bin/bash"}),
    );
    effect(
        &mut j,
        "exec",
        1_110,
        8001,
        ROOT,
        json!({"exe": "/usr/bin/python3"}),
    );
    let r = effect(&mut j, "write", 1_200, 8001, ROOT, json!({"path": snap}));
    assert_eq!(r[0].detail["chosen"], "tap-chat-j-toolu_P1", "{r:?}");
    assert!(r[0].detail.get("harnessChild").is_none(), "{r:?}");
    // A first exec that is no shell.
    effect(&mut j, "fork", 1_300, ROOT, 1, json!({"child": 8002}));
    effect(
        &mut j,
        "exec",
        1_305,
        8002,
        ROOT,
        json!({"exe": "/usr/bin/node"}),
    );
    let r = effect(&mut j, "write", 1_310, 8002, ROOT, json!({"path": snap}));
    assert!(r[0].detail.get("harnessChild").is_none(), "{r:?}");
    // The harness's shell, one exec: still marked, never more than marked.
    effect(&mut j, "fork", 1_400, ROOT, 1, json!({"child": 8003}));
    effect(
        &mut j,
        "exec",
        1_405,
        8003,
        ROOT,
        json!({"exe": "/bin/bash"}),
    );
    let r = effect(&mut j, "write", 1_410, 8003, ROOT, json!({"path": snap}));
    assert_eq!(r[0].detail["harnessChild"], true, "{r:?}");
}

/// Review FP9-S3 (its probe, which passed on `c491b97`, inverted): BW5R-7's
/// cut-off read `Call::end`, which a chat token's `tool.call` can move
/// earlier, so with the OS feed behind the tap (MW5-17) a shell started
/// 400 ms after a posted end, and 3.6 s before the tap's own result, was no
/// longer placed on the install. The cut-off is the tap's own result time.
#[test]
fn fp9_s3_a_posted_end_does_not_move_the_taps_cut_off() {
    let run = |forge: bool| {
        let mut j = Join::new();
        start(&mut j);
        let mut e = ev(
            Source::Tap,
            "tap.call",
            1_000,
            None,
            json!({"callId": "toolu_F1", "toolNormalized": "bash", "paths": [], "resultSha256": null}),
        );
        e.id = format!("tap-{CHAT}-toolu_F1");
        j.observe(&e);
        j.observe(&ev(
            Source::Adapter,
            "approval",
            1_010,
            None,
            json!({"toolUseId": "toolu_F1", "decision": "allow"}),
        ));
        if forge {
            j.observe(&ev(
                Source::Adapter,
                "tool.call",
                1_020,
                None,
                json!({"toolUseId": "toolu_F1"}),
            ));
        }
        let mut r = ev(
            Source::Tap,
            "tap.call",
            5_000,
            None,
            json!({"callId": "toolu_F1", "toolNormalized": "bash", "paths": [], "resultSha256": "ab"}),
        );
        r.id = format!("tap-{CHAT}-toolu_F1");
        j.observe(&r);
        shell_writes(&mut j, 1_400, 7701, "/home/u/p/.git/hooks/pre-commit")
    };
    for forge in [false, true] {
        let out = run(forge);
        assert_eq!(
            out[0].detail["chosen"], "tap-chat-j-toolu_F1",
            "forge={forge}: {out:?}"
        );
    }
}

// Re-review of fix pass 9 (FP9R-1 to FP9R-3): its probes, each failing on `6a9e0be`.

/// FP9R-1: the "one exec" rule drops the mark on the second exec, but a
/// third exec of a shell in the same pid gets it back: the guard only asks
/// that the pid is not already marked. `bash -lc "python setup.py"` where
/// setup.py does `os.execv("/bin/sh", ...)`, or `bash -c "exec sh -c 'exec
/// sh -c ...'"`.
#[test]
fn fp9r_1_a_shell_after_a_non_shell_exec_regains_the_mark() {
    let mut j = Join::new();
    start(&mut j);
    tap_only(&mut j, "claude-code", "toolu_R1", "bash", 1_000, 9_000);
    let snap = "/home/u/.claude/shell-snapshots/snapshot-bash-1-x.sh";
    effect(&mut j, "fork", 1_100, ROOT, 1, json!({"child": 8101}));
    effect(
        &mut j,
        "exec",
        1_105,
        8101,
        ROOT,
        json!({"exe": "/usr/bin/bash"}),
    );
    effect(
        &mut j,
        "exec",
        1_110,
        8101,
        ROOT,
        json!({"exe": "/usr/bin/python3"}),
    );
    effect(&mut j, "exec", 1_120, 8101, ROOT, json!({"exe": "/bin/sh"}));
    let r = effect(&mut j, "write", 1_200, 8101, ROOT, json!({"path": snap}));
    assert!(
        r[0].detail.get("harnessChild").is_none(),
        "an install program's own exec of sh is marked the harness's shell: {r:?}"
    );
}

/// FP9R-2: `direct` is never cleared when a marked shell exits, and the
/// write record's own `ppid` is not checked. A process the install's tree
/// forks that gets the pid again writes before the feed delivers its fork
/// record (T1: the parent's clone record comes at its syscall exit) and is
/// marked as the harness's own shell.
#[test]
fn fp9r_2_a_reused_pid_writing_before_its_fork_record_keeps_the_mark() {
    let mut j = Join::new();
    start(&mut j);
    tap_only(&mut j, "claude-code", "toolu_R2", "bash", 1_000, 9_000);
    let snap = "/home/u/.claude/shell-snapshots/snapshot-bash-1-x.sh";
    // The harness's shell, one exec: marked.
    effect(&mut j, "fork", 1_100, ROOT, 1, json!({"child": 8201}));
    effect(
        &mut j,
        "exec",
        1_105,
        8201,
        ROOT,
        json!({"exe": "/bin/bash"}),
    );
    // It exits (no record); the install's process 7300 (not the harness)
    // forks a subshell that gets pid 8201 and writes before its fork record.
    let r = effect(&mut j, "write", 2_000, 8201, 7300, json!({"path": snap}));
    assert!(
        r.first()
            .is_none_or(|x| x.detail.get("harnessChild").is_none()),
        "a write whose ppid is not the harness is marked the harness's shell: {r:?}"
    );
}

/// FP9R-3 (info, safe direction): an exec delivered before its fork (T1)
/// sets the mark, then the late fork resets it to "no exec yet", so the
/// harness's real snapshot shell loses the label (flagged plain).
#[test]
fn fp9r_3_a_fork_delivered_after_its_exec_drops_the_mark() {
    let mut j = Join::new();
    start(&mut j);
    tap_only(&mut j, "claude-code", "toolu_R3", "bash", 1_000, 9_000);
    let snap = "/home/u/.claude/shell-snapshots/snapshot-bash-1-x.sh";
    effect(
        &mut j,
        "exec",
        1_105,
        8301,
        ROOT,
        json!({"exe": "/bin/bash"}),
    );
    effect(&mut j, "fork", 1_100, ROOT, 1, json!({"child": 8301}));
    let r = effect(&mut j, "write", 1_200, 8301, ROOT, json!({"path": snap}));
    assert_eq!(r[0].detail["harnessChild"], true, "{r:?}");
}

/// Mac test w5 retest 9, MW5-34: on a loaded Mac the OS feed fell 40 s
/// behind, and a chat's effects reached the daemon after the join's 30 s
/// keep, so they were never joined and nothing said so. A stopped chat is
/// kept while the feed has not delivered an event the OS stamped after the
/// stop.
#[test]
fn mw5_34_a_chat_is_kept_while_the_feed_is_behind_its_stop() {
    let mut j = Join::new();
    start(&mut j);
    call(&mut j, "toolu_K", "bash", &[], 1_000, Some(2_000));
    effect(&mut j, "fork", 1_100, ROOT, 1, json!({"child": 6101}));
    effect(
        &mut j,
        "exec",
        1_110,
        6101,
        ROOT,
        json!({"exe": "/bin/zsh"}),
    );
    j.observe(&ev(Source::Run, "run.stop", 2_500, Some(ROOT), json!({})));
    // The feed is 40 s behind: the `ls` the shell ran at 1,200 arrives now.
    effect(&mut j, "fork", 1_150, 6101, ROOT, json!({"child": 6102}));
    let mut late = ev(
        Source::Eslogger,
        "exec",
        2_500 + 40_000,
        Some(6102),
        json!({"ppid": 6101, "osAt": 1_200, "exe": "/bin/ls"}),
    );
    late.id = "es-behind-1".into();
    let r = j.observe(&late);
    assert_eq!(r.len(), 1, "{r:?}");
    assert_eq!(r[0].detail["chosen"], "tap-chat-j-toolu_K");
    assert_eq!(j.late_for(CHAT), None, "nothing came too late");
}

/// MW5-34: the wait for a feed that is behind has a cap; what comes after it
/// is counted, never joined, and never makes the chat again.
#[test]
fn mw5_34_past_the_cap_a_chats_effects_are_counted_as_late() {
    let mut j = Join::new();
    start(&mut j);
    call(&mut j, "toolu_C", "bash", &[], 1_000, Some(2_000));
    j.observe(&ev(Source::Run, "run.stop", 2_500, Some(ROOT), json!({})));
    let mut late = ev(
        Source::Eslogger,
        "write",
        2_500 + STOPPED_FEED_CAP_MS + 1,
        Some(6201),
        json!({"osAt": 1_300, "path": "/w/.github/workflows/x.yml"}),
    );
    late.id = "es-cap-1".into();
    assert!(j.observe(&late).is_empty());
    late.id = "es-cap-2".into();
    assert!(j.observe(&late).is_empty());
    assert_eq!(j.late_for(CHAT), Some(2));
    assert!(keep_stopped(0, STOPPED_KEEP_MS, i64::MAX));
    assert!(keep_stopped(0, STOPPED_FEED_CAP_MS, SLACK_AFTER_MS));
    assert!(!keep_stopped(0, STOPPED_FEED_CAP_MS + 1, 0));
    assert!(!keep_stopped(0, STOPPED_KEEP_MS + 1, SLACK_AFTER_MS + 1));
}

// ---- Fix pass 11's review, FP11-S1 to S4: its probes, which failed on
// f95d8fd (FP11-S1's and the helper's count read `after_for` since FP11-S2
// split the two kinds of late) ----

fn fp11_dropped_chat(j: &mut Join) {
    start(j);
    call(j, "toolu_P", "bash", &[], 1_000, Some(2_000));
    j.observe(&ev(Source::Run, "run.stop", 2_500, Some(ROOT), json!({})));
    // The feed passes the stop (an event of no chat stamped after it).
    let mut passed = ev(
        Source::Eslogger,
        "exec",
        2_500 + STOPPED_KEEP_MS + 1,
        Some(9_999),
        json!({"osAt": 2_500 + SLACK_AFTER_MS + 1, "exe": "/bin/ls"}),
    );
    passed.chat_id = String::new();
    passed.id = "es-pass".into();
    j.observe(&passed);
    // A chat event after the keep sweeps the chat.
    let mut w = ev(
        Source::Eslogger,
        "write",
        2_500 + STOPPED_KEEP_MS + 2,
        Some(6301),
        json!({"osAt": 2_500 + SLACK_AFTER_MS + 2, "path": "/w/.github/workflows/a.yml"}),
    );
    w.id = "es-late-a".into();
    j.observe(&w);
    assert_eq!(j.after_for(CHAT), Some(1));
}

/// FP11-S1: an adapter record the agent posts after the chat was let go
/// (a greeted socket keeps chat scope past run.stop, daemon.rs:1741-1743)
/// makes the chat again with no stop; its later OS events are then neither
/// joined nor counted late, and the chat is never swept.
#[test]
fn fp11_s1_an_adapter_record_after_the_drop_hides_late_os_events() {
    let mut j = Join::new();
    fp11_dropped_chat(&mut j);
    j.observe(&ev(
        Source::Adapter,
        "tool.call",
        2_500 + STOPPED_KEEP_MS + 3,
        None,
        json!({"toolUseId": "toolu_forged"}),
    ));
    let mut w = ev(
        Source::Eslogger,
        "write",
        2_500 + STOPPED_KEEP_MS + 4,
        Some(6301),
        json!({"osAt": 2_500 + SLACK_AFTER_MS + 4, "path": "/w/.github/workflows/b.yml"}),
    );
    w.id = "es-late-b".into();
    let r = j.observe(&w);
    assert!(r.is_empty(), "{r:?}");
    let far = 2_500 + STOPPED_FEED_CAP_MS * 10;
    let mut w2 = w.clone();
    w2.id = "es-late-c".into();
    w2.at = far;
    j.observe(&w2);
    assert_eq!(
        j.after_for(CHAT),
        Some(3),
        "late OS events of the stopped chat are counted"
    );
    assert!(
        !j.chats.contains_key(CHAT),
        "the stopped chat is never kept forever"
    );
    // Its run's next start makes it again, with nothing late (FP11-S3).
    start(&mut j);
    assert!(j.chats.contains_key(CHAT));
    assert_eq!(j.after_for(CHAT), None);
}

/// FP11-S3: a chat id started again keeps the late count of its last run.
#[test]
fn fp11_s3_a_restarted_chat_reports_the_old_runs_late_count() {
    let mut j = Join::new();
    fp11_dropped_chat(&mut j);
    start(&mut j);
    assert_eq!(j.late_for(CHAT), None, "a new run starts with nothing late");
}

/// FP11-S2: the report says late events came "more than 10 min after it
/// stopped, while the OS feed was behind"; here one 30 s after the stop with
/// the feed not behind is counted.
#[test]
fn fp11_s2_late_count_only_past_the_cap() {
    let mut j = Join::new();
    fp11_dropped_chat(&mut j);
    // fp11_dropped_chat already asserted Some(1) at stop + 30 s; the probe
    // states the report's claim.
    assert!(
        j.late_for(CHAT).is_none(),
        "counted late only past STOPPED_FEED_CAP_MS"
    );
}

/// FP11-S4: one OS event stamped in the future (a clock step) moves
/// os_seen for good, so the MW5-34 wait is off for every later chat.
#[test]
fn fp11_s4_a_future_os_stamp_disables_the_wait_for_later_chats() {
    let mut j = Join::new();
    let mut fut = ev(
        Source::Auditd,
        "exec",
        10,
        Some(1),
        json!({"auditAt": i64::MAX / 2, "exe": "/bin/true"}),
    );
    fut.chat_id = String::new();
    j.observe(&fut);
    start(&mut j);
    call(&mut j, "toolu_F", "bash", &[], 1_000, Some(2_000));
    effect(&mut j, "fork", 1_100, ROOT, 1, json!({"child": 6401}));
    j.observe(&ev(Source::Run, "run.stop", 2_500, Some(ROOT), json!({})));
    // The feed is 40 s behind: an effect stamped before the stop arrives.
    let mut late = ev(
        Source::Auditd,
        "write",
        2_500 + 40_000,
        Some(6401),
        json!({"ppid": ROOT, "auditAt": 1_200, "path": "/w/x"}),
    );
    late.id = "au-behind".into();
    let r = j.observe(&late);
    assert_eq!(
        r.len(),
        1,
        "the chat is still kept while the feed is behind: {r:?}"
    );
}

#[test]
fn fp11_s4_control_without_the_future_stamp() {
    let mut j = Join::new();
    start(&mut j);
    call(&mut j, "toolu_F", "bash", &[], 1_000, Some(2_000));
    effect(&mut j, "fork", 1_100, ROOT, 1, json!({"child": 6401}));
    j.observe(&ev(Source::Run, "run.stop", 2_500, Some(ROOT), json!({})));
    let mut late = ev(
        Source::Auditd,
        "write",
        2_500 + 40_000,
        Some(6401),
        json!({"ppid": ROOT, "auditAt": 1_200, "path": "/w/x"}),
    );
    late.id = "au-behind".into();
    assert_eq!(j.observe(&late).len(), 1);
}

/// FP13R-5 (fp13 review): the Linux feed posts `feed.gap` (source auditd,
/// no `auditAt`) when it starts and is about to read a log it is behind on.
/// `feed_progress` takes the daemon's own `at` for it, so the join takes the
/// feed as past every stop and lets kept chats go; the resumed lines then
/// count as done after the stop instead of being joined.
#[test]
fn fp13r_5_a_feed_gap_does_not_tell_the_join_the_feed_is_current() {
    let mut j = Join::new();
    start(&mut j);
    call(&mut j, "toolu_G", "bash", &[], 1_000, Some(2_000));
    effect(&mut j, "fork", 1_100, ROOT, 1, json!({"child": 6301}));
    j.observe(&ev(Source::Run, "run.stop", 2_500, Some(ROOT), json!({})));
    let mut gap = ev(
        Source::Auditd,
        "feed.gap",
        2_500 + 40_000,
        None,
        json!({"fromMs": 1_000, "toMs": 2_500 + 40_000, "reason": "rotated"}),
    );
    gap.chat_id = String::new();
    gap.id = "auditd-gap-42500".into();
    j.observe(&gap);
    // The feed reads on: the shell's exec, stamped 1,150, arrives now.
    let mut late = ev(
        Source::Auditd,
        "exec",
        2_500 + 40_001,
        Some(6301),
        json!({"ppid": ROOT, "auditAt": 1_150, "exe": "/bin/sh"}),
    );
    late.id = "auditd-1150-1".into();
    let r = j.observe(&late);
    assert_eq!(j.after_for(CHAT), None, "counted as after the stop: {r:?}");
}

/// Box retest of fix pass 13r, BW5R5-4: a real Claude Code 2.1.319 chat under
/// srt 0.0.81 on Linux, its records as the daemon logged them on the box
/// (`fixtures/README.md`). Inside bubblewrap's PID namespace a fork's
/// `child` is the namespace's pid (`exit=2`, `exit=8`), so `apply-seccomp`'s
/// inner process (host pid 21759) was never placed and the harness under it
/// (21760, which execs the binary `harnessExe` names) was never found; the
/// shell that wrote `a.txt` during the Bash call got no join record. Every
/// record still names its own host pid and its parent's (`pid=`, `ppid=`;
/// Linux 7.0 `kernel/auditsc.c:1635-1638`), which places it.
#[test]
fn bw5r5_4_under_srt_on_linux_the_harnesss_shell_is_its_calls() {
    let mut j = Join::new();
    let text = include_str!("fixtures/srt-linux-claude-2.1.319-auditd.jsonl");
    let mut events: Vec<Event> = text
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str(l).expect("a recorded event"))
        .collect();
    events.sort_by_key(|e| {
        e.detail
            .get("auditAt")
            .and_then(Value::as_i64)
            .unwrap_or(e.at)
    });
    let mut out = Vec::new();
    for e in &events {
        out.extend(j.observe(e));
    }
    let write = out
        .iter()
        .find(|r| {
            r.detail.get("effect").and_then(Value::as_str) == Some("auditd-1794193636470-27520")
        })
        .unwrap_or_else(|| panic!("no join record for the a.txt write: {} records", out.len()));
    assert_eq!(
        write.detail["chosen"], "tap-b510bs3-toolu_01FNX7QFrjAdjXwub46HBPA5",
        "{}",
        write.detail
    );
    assert_eq!(
        write.detail["candidates"][0]["by"], "tree",
        "{}",
        write.detail
    );
}
