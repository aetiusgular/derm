// FP11 review probes (uncommitted).
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

/// FP11-S5: a second tool_use under an index already ended is never posted
/// early, and keeps the first call's end time.
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
