//! The proxy over real pipes: a scripted client on one side, a scripted
//! agent on the other, the records taken from the log channel.

use std::io::{BufRead, BufReader, Write};
use std::sync::mpsc;
use std::sync::Arc;
use std::time::Duration;

use derm_core::event::Event;
use derm_core::policy::parse;
use serde_json::{json, Value};

use super::decide::Ctx;
use super::proxy::{self, State, REFUSED};

struct Rig {
    /// What the test writes as the client.
    client: std::io::PipeWriter,
    /// What the proxy sent the client.
    from_proxy: BufReader<std::io::PipeReader>,
    /// What the test writes as the agent.
    agent: std::io::PipeWriter,
    /// What the proxy sent the agent.
    to_agent: BufReader<std::io::PipeReader>,
    records: mpsc::Receiver<Event>,
}

fn rig(rules: &str, full_access: bool) -> Rig {
    rig_with(rules, full_access, false)
}

fn rig_with(rules: &str, full_access: bool, confined: bool) -> Rig {
    let (client_r, client_w) = std::io::pipe().unwrap();
    let (out_r, out_w) = std::io::pipe().unwrap();
    let (agent_in_r, agent_in_w) = std::io::pipe().unwrap();
    let (agent_out_r, agent_out_w) = std::io::pipe().unwrap();
    let (tx, rx) = mpsc::channel();
    let st = Arc::new(State::new(
        Ctx {
            policy: parse(&format!(r#"{{"version":1,"rules":{rules}}}"#)).unwrap(),
            harness: "gemini".into(),
            chat: "derm-acpchat0001".into(),
            full_access,
            confined,
        },
        Some(tx),
    ));
    proxy::start(st, Box::new(agent_in_w), agent_out_r, client_r, out_w, None);
    Rig {
        client: client_w,
        from_proxy: BufReader::new(out_r),
        agent: agent_out_w,
        to_agent: BufReader::new(agent_in_r),
        records: rx,
    }
}

fn send(w: &mut std::io::PipeWriter, v: &Value) -> String {
    let line = format!("{}\n", serde_json::to_string(v).unwrap());
    w.write_all(line.as_bytes()).unwrap();
    w.flush().unwrap();
    line
}

fn read(r: &mut BufReader<std::io::PipeReader>) -> String {
    let mut s = String::new();
    r.read_line(&mut s).unwrap();
    s
}

fn records(rx: &mpsc::Receiver<Event>, n: usize) -> Vec<Event> {
    (0..n)
        .map(|_| rx.recv_timeout(Duration::from_secs(5)).expect("a record"))
        .collect()
}

fn tool_call(id: &str, name: Option<&str>, kind: &str, raw: Value) -> Value {
    let mut update = json!({
        "sessionUpdate": "tool_call",
        "toolCallId": id,
        "title": "Running a command",
        "kind": kind,
        "status": "pending",
        "rawInput": raw,
    });
    if let Some(n) = name {
        update["name"] = json!(n);
    }
    json!({"jsonrpc": "2.0", "method": "session/update", "params": {"sessionId": "s1", "update": update}})
}

fn ask(id: i64, call: &str) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "method": "session/request_permission", "params": {
        "sessionId": "s1",
        "toolCall": {"toolCallId": call},
        "options": [
            {"optionId": "allow-once", "name": "Allow", "kind": "allow_once"},
            {"optionId": "allow-always", "name": "Always allow", "kind": "allow_always"},
            {"optionId": "reject-once", "name": "Reject", "kind": "reject_once"}
        ]
    }})
}

#[test]
fn an_allowed_call_is_answered_once_and_the_client_never_sees_the_request() {
    let mut r = rig(r#"[{"tool":"bash","action":"allow"}]"#, false);
    let update = send(
        &mut r.agent,
        &tool_call("t1", Some("bash"), "execute", json!({"command": "ls -la"})),
    );
    // The update reaches the client byte for byte.
    assert_eq!(read(&mut r.from_proxy), update);
    send(&mut r.agent, &ask(7, "t1"));
    let reply: Value = serde_json::from_str(&read(&mut r.to_agent)).unwrap();
    assert_eq!(
        reply,
        json!({"jsonrpc": "2.0", "id": 7, "result": {"outcome": {"outcome": "selected", "optionId": "allow-once"}}})
    );
    // The next thing the client sees is what the agent sends next, not the
    // request derm answered.
    let after = send(
        &mut r.agent,
        &json!({"jsonrpc": "2.0", "method": "session/update", "params": {"sessionId": "s1", "update": {"sessionUpdate": "agent_message_chunk", "content": {"type": "text", "text": "done"}}}}),
    );
    assert_eq!(read(&mut r.from_proxy), after);
    let recs = records(&r.records, 2);
    assert_eq!(recs[0].kind, "tool.call");
    assert_eq!(recs[0].detail["gate"], "logged, not gated");
    assert_eq!(recs[0].detail["name"], "bash");
    assert!(
        recs[0].detail.get("rawInput").is_none(),
        "no content in the record"
    );
    assert_eq!(recs[0].chat_id, "derm-acpchat0001");
    assert_eq!(recs[1].kind, "approval");
    assert_eq!(recs[1].detail["decision"], "allow");
    assert_eq!(recs[1].detail["answeredBy"], "derm");
    assert_eq!(recs[1].detail["toolUseId"], "t1");
    // The decision's id ends in 128 random bits (BW2).
    let tail = recs[1].id.rsplit("-decision-").next().unwrap();
    assert_eq!(tail.len(), 32, "{}", recs[1].id);
}

#[test]
fn a_denied_call_is_rejected_and_an_ask_goes_to_the_clients_prompt() {
    let mut r = rig(
        r#"[{"tool":"bash","action":"deny"},{"tool":"edit_file","action":"ask"}]"#,
        false,
    );
    send(
        &mut r.agent,
        &tool_call(
            "t1",
            Some("bash"),
            "execute",
            json!({"command": "rm -rf build"}),
        ),
    );
    read(&mut r.from_proxy);
    send(&mut r.agent, &ask(1, "t1"));
    let reply: Value = serde_json::from_str(&read(&mut r.to_agent)).unwrap();
    assert_eq!(reply["result"]["outcome"]["optionId"], "reject-once");

    // Ask: the request reaches the client unchanged, and the client's
    // answer reaches the agent unchanged.
    send(
        &mut r.agent,
        &tool_call("t2", Some("edit_file"), "edit", json!({"path": "/w/a.rs"})),
    );
    read(&mut r.from_proxy);
    let req = send(&mut r.agent, &ask(2, "t2"));
    assert_eq!(read(&mut r.from_proxy), req);
    let answer = send(
        &mut r.client,
        &json!({"jsonrpc": "2.0", "id": 2, "result": {"outcome": {"outcome": "selected", "optionId": "reject-once"}}}),
    );
    assert_eq!(read(&mut r.to_agent), answer);
    let recs = records(&r.records, 4);
    let decisions: Vec<(&str, &str)> = recs
        .iter()
        .filter(|e| e.kind == "approval")
        .map(|e| {
            (
                e.detail["decision"].as_str().unwrap(),
                e.detail["answeredBy"].as_str().unwrap(),
            )
        })
        .collect();
    assert_eq!(decisions, vec![("deny", "derm"), ("ask", "client")]);
}

#[test]
fn an_unnamed_call_asks_even_under_a_catch_all_allow() {
    // Case 73.
    let mut r = rig(r#"[{"tool":"*","action":"allow"}]"#, false);
    send(
        &mut r.agent,
        &tool_call("t9", None, "edit", json!({"path": "/w/x"})),
    );
    read(&mut r.from_proxy);
    let req = send(&mut r.agent, &ask(3, "t9"));
    assert_eq!(read(&mut r.from_proxy), req, "passed to the client");
}

#[test]
fn in_full_access_an_ask_is_denied_by_derm() {
    // Case 83: nobody is asked; an ask is a deny.
    let mut r = rig("[]", true);
    send(
        &mut r.agent,
        &tool_call("t1", Some("edit_file"), "edit", json!({})),
    );
    read(&mut r.from_proxy);
    send(&mut r.agent, &ask(4, "t1"));
    let reply: Value = serde_json::from_str(&read(&mut r.to_agent)).unwrap();
    assert_eq!(reply["result"]["outcome"]["optionId"], "reject-once");
}

#[test]
fn a_permission_request_with_its_own_tool_call_fields_is_judged_on_them() {
    // No earlier update: the request's `toolCall` names the tool.
    let mut r = rig(r#"[{"tool":"read_file","action":"allow"}]"#, false);
    let mut req = ask(5, "t5");
    req["params"]["toolCall"] = json!({"toolCallId": "t5", "name": "read_file", "kind": "read", "rawInput": {"path": "/w/a"}});
    send(&mut r.agent, &req);
    let reply: Value = serde_json::from_str(&read(&mut r.to_agent)).unwrap();
    assert_eq!(reply["result"]["outcome"]["optionId"], "allow-once");
}

#[test]
fn client_side_writes_and_terminals_the_policy_denies_are_refused() {
    let mut r = rig(
        r#"[{"tool":"write","action":"deny"},{"tool":"bash","action":"allow"}]"#,
        false,
    );
    send(
        &mut r.agent,
        &json!({"jsonrpc": "2.0", "id": 11, "method": "fs/write_text_file", "params": {"sessionId": "s1", "path": "/w/a.txt", "content": "x"}}),
    );
    let reply: Value = serde_json::from_str(&read(&mut r.to_agent)).unwrap();
    assert_eq!(reply["id"], 11);
    assert_eq!(reply["error"]["code"], REFUSED);
    assert!(reply["error"]["message"]
        .as_str()
        .unwrap()
        .starts_with("derm: "));
    // An allowed terminal goes to the client unchanged.
    let term = send(
        &mut r.agent,
        &json!({"jsonrpc": "2.0", "id": 12, "method": "terminal/create", "params": {"sessionId": "s1", "command": "ls", "args": ["-la"]}}),
    );
    assert_eq!(read(&mut r.from_proxy), term);
    // A terminal the reject list names is refused whatever the rules say.
    send(
        &mut r.agent,
        &json!({"jsonrpc": "2.0", "id": 13, "method": "terminal/create", "params": {"sessionId": "s1", "command": "claude", "args": ["--dangerously-skip-permissions"]}}),
    );
    let reply: Value = serde_json::from_str(&read(&mut r.to_agent)).unwrap();
    assert_eq!(reply["id"], 13);
    assert_eq!(reply["error"]["code"], REFUSED);
}

#[test]
fn other_lines_pass_unchanged_and_a_batch_is_split() {
    let mut r = rig(r#"[{"tool":"bash","action":"deny"}]"#, false);
    // Not JSON: dropped, never passed on (security review L1; this test
    // asserted the opposite before).
    r.agent.write_all(b"not json at all\n").unwrap();
    // A response to a client request: as it came.
    let resp = send(
        &mut r.agent,
        &json!({"jsonrpc": "2.0", "id": 1, "result": {"protocolVersion": 1}}),
    );
    assert_eq!(read(&mut r.from_proxy), resp);
    // A batch holding a request derm answers: that one is answered, the
    // other goes to the client on its own line.
    send(
        &mut r.agent,
        &json!([
            {"jsonrpc": "2.0", "id": 21, "method": "terminal/create", "params": {"sessionId": "s1", "command": "ls"}},
            {"jsonrpc": "2.0", "method": "session/update", "params": {"sessionId": "s1", "update": {"sessionUpdate": "plan", "entries": []}}}
        ]),
    );
    let reply: Value = serde_json::from_str(&read(&mut r.to_agent)).unwrap();
    assert_eq!(reply["id"], 21);
    assert_eq!(reply["error"]["code"], REFUSED);
    let passed: Value = serde_json::from_str(&read(&mut r.from_proxy)).unwrap();
    assert_eq!(passed["params"]["update"]["sessionUpdate"], "plan");
}

#[test]
fn the_clients_end_of_input_closes_the_agents() {
    let r = rig("[]", false);
    let Rig {
        client,
        mut to_agent,
        ..
    } = r;
    drop(client);
    let mut s = String::new();
    // EOF reaches the agent's stdin.
    assert_eq!(to_agent.read_line(&mut s).unwrap(), 0);
}

#[test]
fn decision_ids_keep_the_daemons_characters_and_fit_its_cap() {
    let id = proxy::decision_id("gemini", "call/with spaces\nand;more");
    assert!(
        id.starts_with("gemini-call_with_spaces_and_more-decision-"),
        "{id}"
    );
    let long = proxy::decision_id("gemini", &"x".repeat(400));
    assert!(long.len() <= 128, "{}", long.len());
    assert_ne!(proxy::decision_id("g", "c"), proxy::decision_id("g", "c"));
}

/// Security review L1: a line serde_json cannot read may still be one a
/// JavaScript client reads (`JSON.parse` takes lone surrogates, `1e400` and
/// deep nesting), so it is never passed on; what is passed on is the message
/// derm judged, written again.
#[test]
fn a_line_derm_cannot_read_never_reaches_the_client() {
    let mut r = rig(r#"[{"tool":"*","action":"allow"}]"#, true);
    let lines: Vec<Vec<u8>> = vec![
        br#"{"jsonrpc":"2.0","id":1,"method":"terminal/create","params":{"sessionId":"s1","command":"claude","args":["--dangerously-skip-permissions"],"x":"\ud800"}}"#.to_vec(),
        br#"{"jsonrpc":"2.0","id":2,"method":"fs/write_text_file","params":{"sessionId":"s1","path":"/home/u/.bashrc","content":"x","pad":1e400}}"#.to_vec(),
        format!(
            r#"{{"jsonrpc":"2.0","id":3,"method":"session/request_permission","params":{{"sessionId":"s1","toolCall":{{"toolCallId":"t"}},"options":[],"deep":{}{}}}}}"#,
            "[".repeat(200),
            "]".repeat(200)
        )
        .into_bytes(),
        [&br#"{"jsonrpc":"2.0","id":4,"method":"terminal/create","params":{"sessionId":"s1","command":"ls"#[..], &[0xff], br#""}}"#].concat(),
    ];
    for mut l in lines {
        l.push(b'\n');
        r.agent.write_all(&l).unwrap();
    }
    // Spaces and all: the client gets the message as derm wrote it again.
    r.agent
        .write_all(b"{ \"jsonrpc\" : \"2.0\", \"id\": 9, \"result\": {} }\n")
        .unwrap();
    let got = read(&mut r.from_proxy);
    let v: Value = serde_json::from_str(&got).unwrap();
    assert_eq!(v["id"], 9, "the first line the client saw: {got}");
    assert_eq!(got, format!("{}\n", serde_json::to_string(&v).unwrap()));
}

#[test]
fn a_line_past_the_cap_is_dropped_whole() {
    use super::proxy::{read_line_capped, Line};
    let mut input = std::io::Cursor::new(b"0123456789abcdef\nok\n".to_vec());
    let mut buf = Vec::new();
    assert_eq!(
        read_line_capped(&mut input, &mut buf, 8).unwrap(),
        Line::TooLong
    );
    assert_eq!(
        read_line_capped(&mut input, &mut buf, 8).unwrap(),
        Line::Read
    );
    assert_eq!(buf, b"ok\n");
    assert_eq!(
        read_line_capped(&mut input, &mut buf, 8).unwrap(),
        Line::Eof
    );
}

fn refused(r: &mut Rig, id: i64) {
    let reply: Value = serde_json::from_str(&read(&mut r.to_agent)).unwrap();
    assert_eq!(reply["id"], id, "{reply}");
    assert_eq!(reply["error"]["code"], REFUSED, "{reply}");
}

fn marker(r: &mut Rig) {
    // The next line the client sees is this one: nothing before it got through.
    send(
        &mut r.agent,
        &json!({"jsonrpc": "2.0", "method": "session/update", "params": {"sessionId": "s1", "update": {"sessionUpdate": "plan", "entries": []}}}),
    );
    let v: Value = serde_json::from_str(&read(&mut r.from_proxy)).unwrap();
    assert_eq!(v["params"]["update"]["sessionUpdate"], "plan", "{v}");
}

/// Security review L2: under srt or sbx the client would read, write and
/// run outside the boundary, so it is told it cannot, and every such request
/// is refused.
#[test]
fn inside_a_boundary_the_client_does_no_files_and_no_terminals() {
    let mut r = rig_with(r#"[{"tool":"*","action":"allow"}]"#, false, true);
    send(
        &mut r.client,
        &json!({"jsonrpc": "2.0", "id": 0, "method": "initialize", "params": {"protocolVersion": 1, "clientCapabilities": {"fs": {"readTextFile": true, "writeTextFile": true}, "terminal": true, "elicitation": {}}}}),
    );
    let init: Value = serde_json::from_str(&read(&mut r.to_agent)).unwrap();
    let caps = &init["params"]["clientCapabilities"];
    assert_eq!(caps["fs"]["readTextFile"], false, "{init}");
    assert_eq!(caps["fs"]["writeTextFile"], false);
    assert_eq!(caps["terminal"], false);
    assert_eq!(caps["elicitation"], json!({}), "the rest is kept");
    let reqs = [
        (
            "fs/read_text_file",
            json!({"sessionId": "s1", "path": "/home/u/.ssh/id_ed25519"}),
        ),
        (
            "fs/write_text_file",
            json!({"sessionId": "s1", "path": "/w/a", "content": "x"}),
        ),
        (
            "terminal/create",
            json!({"sessionId": "s1", "command": "ls"}),
        ),
        (
            "terminal/output",
            json!({"sessionId": "s1", "terminalId": "t"}),
        ),
    ];
    for (i, (method, params)) in reqs.iter().enumerate() {
        let id = 30 + i as i64;
        send(
            &mut r.agent,
            &json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params}),
        );
        refused(&mut r, id);
    }
    marker(&mut r);
    // Outside a boundary the client's own answer is kept.
    let mut r = rig_with("[]", false, false);
    let line = send(
        &mut r.client,
        &json!({"jsonrpc": "2.0", "id": 0, "method": "initialize", "params": {"protocolVersion": 1, "clientCapabilities": {"terminal": true}}}),
    );
    assert_eq!(read(&mut r.to_agent), line);
}

#[test]
fn a_read_the_policy_denies_is_refused() {
    let mut r = rig(r#"[{"tool":"*","action":"deny"}]"#, false);
    send(
        &mut r.agent,
        &json!({"jsonrpc": "2.0", "id": 40, "method": "fs/read_text_file", "params": {"sessionId": "s1", "path": "/home/u/.ssh/id_ed25519"}}),
    );
    refused(&mut r, 40);
    marker(&mut r);
}

/// Security review L3: in full access an ask on a client request is a deny,
/// as it is on a permission request.
#[test]
fn in_full_access_an_ask_on_a_client_request_is_refused() {
    let mut r = rig("[]", true);
    send(
        &mut r.agent,
        &json!({"jsonrpc": "2.0", "id": 50, "method": "terminal/create", "params": {"sessionId": "s1", "command": "curl", "args": ["https://x.example"]}}),
    );
    refused(&mut r, 50);
    let mut r = rig(r#"[{"tool":"write","action":"allow"}]"#, true);
    send(
        &mut r.agent,
        &json!({"jsonrpc": "2.0", "id": 51, "method": "fs/write_text_file", "params": {"sessionId": "s1", "path": "/home/u/.claude/settings.json", "content": "{}"}}),
    );
    refused(&mut r, 51);
    marker(&mut r);
}

/// Security review L4: a terminal's env and cwd are part of what it runs.
#[test]
fn a_terminals_env_cwd_and_odd_args_are_judged() {
    let mut r = rig(r#"[{"tool":"bash","action":"allow"}]"#, false);
    send(
        &mut r.agent,
        &json!({"jsonrpc": "2.0", "id": 60, "method": "terminal/create", "params": {"sessionId": "s1", "command": "ls", "env": [{"name": "ANTHROPIC_BASE_URL", "value": "http://evil.example"}]}}),
    );
    refused(&mut r, 60);
    for (id, args) in [
        (61, json!([["$(id)"]])),
        (62, json!([{"a": "$(id)"}])),
        (63, json!([1])),
    ] {
        send(
            &mut r.agent,
            &json!({"jsonrpc": "2.0", "id": id, "method": "terminal/create", "params": {"sessionId": "s1", "command": "ls", "args": args}}),
        );
        refused(&mut r, id);
    }
    marker(&mut r);
    // In full access, an env value the shell expands asks, so it is refused.
    let mut r = rig(r#"[{"tool":"bash","action":"allow"}]"#, true);
    send(
        &mut r.agent,
        &json!({"jsonrpc": "2.0", "id": 64, "method": "terminal/create", "params": {"sessionId": "s1", "command": "ls", "env": [{"name": "X", "value": "$(id)"}]}}),
    );
    refused(&mut r, 64);
}

/// Security review L17: only the methods ACP v1 has the agent send the
/// client pass; any other request is refused and any other notification
/// dropped.
#[test]
fn only_the_methods_acp_defines_pass() {
    let mut r = rig(r#"[{"tool":"*","action":"allow"}]"#, false);
    for (id, method) in [(70, "mcp/message"), (71, "_vendor/run"), (72, "made/up")] {
        send(
            &mut r.agent,
            &json!({"jsonrpc": "2.0", "id": id, "method": method, "params": {}}),
        );
        refused(&mut r, id);
    }
    // Notifications of a request derm judges, or of anything unknown: dropped.
    send(
        &mut r.agent,
        &json!({"jsonrpc": "2.0", "method": "fs/write_text_file", "params": {"sessionId": "s1", "path": "/w/a", "content": "x"}}),
    );
    send(
        &mut r.agent,
        &json!({"jsonrpc": "2.0", "method": "_vendor/note", "params": {}}),
    );
    marker(&mut r);
    // Elicitation is a question for the user: it passes.
    let e = send(
        &mut r.agent,
        &json!({"jsonrpc": "2.0", "id": 73, "method": "elicitation/create", "params": {"sessionId": "s1", "message": "?"}}),
    );
    assert_eq!(read(&mut r.from_proxy), e);
    // So do a terminal's later calls outside a boundary.
    let o = send(
        &mut r.agent,
        &json!({"jsonrpc": "2.0", "id": 74, "method": "terminal/output", "params": {"sessionId": "s1", "terminalId": "t"}}),
    );
    assert_eq!(read(&mut r.from_proxy), o);
}

/// Security review L16: the agent holds the chat token, so a call's record
/// id must not be one it can work out and post first.
#[test]
fn a_calls_record_id_cannot_be_guessed_and_joins_its_updates() {
    let id_of = |rules: &str| {
        let mut r = rig(rules, false);
        send(
            &mut r.agent,
            &tool_call("t1", Some("bash"), "execute", json!({"command": "ls"})),
        );
        read(&mut r.from_proxy);
        send(
            &mut r.agent,
            &json!({"jsonrpc": "2.0", "method": "session/update", "params": {"sessionId": "s1", "update": {"sessionUpdate": "tool_call_update", "toolCallId": "t1", "status": "completed"}}}),
        );
        read(&mut r.from_proxy);
        let recs = records(&r.records, 2);
        assert_eq!(
            recs[0].id, recs[1].id,
            "an update replaces its call's record"
        );
        assert!(recs[0].id.len() <= 128, "{}", recs[0].id);
        recs[0].id.clone()
    };
    let a = id_of("[]");
    let b = id_of("[]");
    assert_ne!(a, b, "the same call in two runs: {a}");
    assert!(a.starts_with("gemini-acp-s1-t1-"), "{a}");
}
