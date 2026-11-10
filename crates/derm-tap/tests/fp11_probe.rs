// Fix pass 11 review probes, kept as tests (FP11-S5, FP11R-2).
use derm_tap::apis::ResponseParser;
use derm_tap::record::Api;
use derm_tap::record::CallRecord;
use serde_json::json;

fn sse(events: &[serde_json::Value]) -> Vec<u8> {
    let mut out = Vec::new();
    for e in events {
        out.extend(format!("event: {}\ndata: {}\n\n", e["type"].as_str().unwrap(), e).into_bytes());
    }
    out
}

/// Sound check: the early record follows the content rule (hashes and
/// paths only, never the argument text).
#[test]
fn fp11_early_record_keeps_no_argument_text() {
    let mut p = ResponseParser::new(Api::AnthropicMessages, false, "g");
    p.feed_at(&sse(&[
        json!({"type":"message_start","message":{"model":"m"}}),
        json!({"type":"content_block_start","index":0,"content_block":{"type":"tool_use","id":"toolu_S","name":"Bash","input":{}}}),
        json!({"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":"{\"command\":\"echo SECRET-EARLY\"}"}}),
        json!({"type":"content_block_stop","index":0}),
    ]), 5_000);
    let done = p.take_done();
    assert_eq!(done.len(), 1);
    let rec = CallRecord::new(Api::AnthropicMessages, "m", None, "claude-code", &done[0]);
    let e = rec.event("c", "claude-code", done[0].done_at.unwrap());
    let text = serde_json::to_string(&e).unwrap();
    assert!(!text.contains("SECRET-EARLY"), "{text}");
}

/// FP11-S5: a second tool_use under an index already ended is posted early
/// too, with its own end time.
#[test]
fn fp11_s5_a_reused_index_is_posted_early_with_its_own_time() {
    let mut p = ResponseParser::new(Api::AnthropicMessages, false, "g");
    p.feed_at(&sse(&[
        json!({"type":"message_start","message":{"model":"m"}}),
        json!({"type":"content_block_start","index":0,"content_block":{"type":"tool_use","id":"toolu_A","name":"Bash","input":{}}}),
        json!({"type":"content_block_stop","index":0}),
    ]), 1_000);
    assert_eq!(p.take_done().len(), 1);
    p.feed_at(&sse(&[
        json!({"type":"content_block_start","index":0,"content_block":{"type":"tool_use","id":"toolu_B","name":"Bash","input":{}}}),
        json!({"type":"content_block_stop","index":0}),
    ]), 9_000);
    let second = p.take_done();
    assert_eq!(second.len(), 1, "toolu_B posted early");
    assert_eq!(second[0].done_at, Some(9_000));
}

/// FP11R-2: an upstream that names a moved call's key (1<<62 + order) does
/// not rewrite that finished, already-posted call's arguments.
#[test]
fn fp11r_2_an_upstream_cannot_name_a_moved_calls_key() {
    let mut p = ResponseParser::new(Api::AnthropicMessages, false, "g");
    let k: u64 = (1u64 << 62) + 1;
    p.feed_at(&sse(&[
        json!({"type":"message_start","message":{"model":"m"}}),
        json!({"type":"content_block_start","index":0,"content_block":{"type":"tool_use","id":"toolu_A","name":"Bash","input":{}}}),
        json!({"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":"{\"command\":\"ls\"}"}}),
        json!({"type":"content_block_stop","index":0}),
        json!({"type":"content_block_start","index":0,"content_block":{"type":"tool_use","id":"toolu_B","name":"Bash","input":{}}}),
        json!({"type":"content_block_stop","index":0}),
        json!({"type":"content_block_delta","index":k,"delta":{"type":"input_json_delta","partial_json":"X"}}),
        json!({"type":"message_stop"}),
    ]), 1_000);
    let info = p.finish();
    let a = info
        .calls
        .iter()
        .find(|c| c.call_id == "toolu_A")
        .expect("A kept");
    let args = format!("{:?}", a.args);
    assert!(
        !args.contains('X'),
        "A's args were rewritten through the moved key: {args}"
    );
}

/// FP11R's note: an `output_index` of u64::MAX overflowed `+ 1` (a panic in
/// a debug build). It is read as no index now.
#[test]
fn fp11r_an_output_index_at_u64_max_does_not_overflow() {
    let mut p = ResponseParser::new(Api::OpenAiResponses, false, "g");
    p.feed_at(&sse(&[
        json!({"type":"response.output_item.added","output_index":u64::MAX,"item":{"type":"function_call","id":"fc_1","call_id":"call_1","name":"shell","arguments":""}}),
        json!({"type":"response.output_item.done","output_index":u64::MAX,"item":{"type":"function_call","id":"fc_1","call_id":"call_1","name":"shell","arguments":"{}"}}),
    ]), 1_000);
    let info = p.finish();
    assert_eq!(info.calls.len(), 1, "the call is kept under its item id");
}
