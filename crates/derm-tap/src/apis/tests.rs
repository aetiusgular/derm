use super::*;
use serde_json::json;

fn sse(events: &[(&str, Value)]) -> Vec<u8> {
    let mut out = Vec::new();
    for (name, data) in events {
        out.extend_from_slice(format!("event: {name}\ndata: {data}\n\n").as_bytes());
    }
    out
}

/// Feeds `bytes` in pieces of every size from 1 to 7, so no parse depends on
/// where the network cut the stream.
fn parse_split(api: Api, stream: bool, bytes: &[u8]) -> ResponseInfo {
    let mut first: Option<ResponseInfo> = None;
    for step in 1..=7 {
        let mut p = ResponseParser::new(api, stream, "gem");
        for chunk in bytes.chunks(step) {
            p.feed(chunk);
        }
        let info = p.finish();
        if let Some(f) = &first {
            assert_eq!(&info, f, "step {step}");
        } else {
            first = Some(info);
        }
    }
    first.unwrap()
}

fn anthropic_stream(cut_after: Option<usize>) -> Vec<u8> {
    let events = vec![
        (
            "message_start",
            json!({"type":"message_start","message":{"model":"claude-x","usage":{"input_tokens":100,"cache_read_input_tokens":20,"output_tokens":1}}}),
        ),
        (
            "content_block_start",
            json!({"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}),
        ),
        ("ping", json!({"type":"ping"})),
        (
            "content_block_delta",
            json!({"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"ok"}}),
        ),
        (
            "content_block_stop",
            json!({"type":"content_block_stop","index":0}),
        ),
        (
            "content_block_start",
            json!({"type":"content_block_start","index":1,"content_block":{"type":"tool_use","id":"toolu_A","name":"Bash","input":{}}}),
        ),
        (
            "content_block_delta",
            json!({"type":"content_block_delta","index":1,"delta":{"type":"input_json_delta","partial_json":"{\"comm"}}),
        ),
        (
            "content_block_delta",
            json!({"type":"content_block_delta","index":1,"delta":{"type":"input_json_delta","partial_json":"and\":\"ls\"}"}}),
        ),
        (
            "content_block_stop",
            json!({"type":"content_block_stop","index":1}),
        ),
        (
            "content_block_start",
            json!({"type":"content_block_start","index":2,"content_block":{"type":"tool_use","id":"toolu_B","name":"Read","input":{}}}),
        ),
        (
            "content_block_stop",
            json!({"type":"content_block_stop","index":2}),
        ),
        (
            "message_delta",
            json!({"type":"message_delta","delta":{"stop_reason":"tool_use"},"usage":{"output_tokens":42}}),
        ),
        ("message_stop", json!({"type":"message_stop"})),
    ];
    let n = cut_after.unwrap_or(events.len());
    sse(&events[..n])
}

#[test]
fn anthropic_streamed_calls_tokens_and_completion() {
    let info = parse_split(Api::AnthropicMessages, true, &anthropic_stream(None));
    assert!(info.complete);
    assert_eq!(info.model.as_deref(), Some("claude-x"));
    assert_eq!(info.input_tokens, Some(120));
    assert_eq!(info.output_tokens, Some(42));
    assert_eq!(info.calls.len(), 2);
    assert_eq!(info.calls[0].call_id, "toolu_A");
    assert_eq!(info.calls[0].tool, "Bash");
    assert_eq!(
        info.calls[0].args,
        ArgsText::Text("{\"command\":\"ls\"}".into())
    );
    assert!(!info.calls[0].incomplete);
    assert_eq!(info.calls[1].args, ArgsText::Json(json!({})));
}

#[test]
fn a_stream_cut_mid_call_marks_the_call_and_the_response_incomplete() {
    // Case 115: cut after the first argument delta of toolu_A.
    let info = parse_split(Api::AnthropicMessages, true, &anthropic_stream(Some(7)));
    assert!(!info.complete);
    assert_eq!(info.calls.len(), 1);
    assert_eq!(info.calls[0].call_id, "toolu_A");
    assert!(info.calls[0].incomplete);
    assert_eq!(info.calls[0].args, ArgsText::Text("{\"comm".into()));
    // Cut after toolu_A closed but before message_stop: A is whole, the
    // response is not.
    let info = parse_split(Api::AnthropicMessages, true, &anthropic_stream(Some(9)));
    assert!(!info.complete);
    assert!(!info.calls[0].incomplete);
}

#[test]
fn anthropic_whole_body_and_request_results() {
    let root = concat!(env!("CARGO_MANIFEST_DIR"), "/../../contracts/fixtures/tap/");
    let body = std::fs::read(format!("{root}anthropic.response.json")).unwrap();
    let info = parse_split(Api::AnthropicMessages, false, &body);
    assert!(info.complete);
    assert_eq!(info.calls.len(), 1);
    assert_eq!(info.calls[0].call_id, "toolu_01FIXTURE0000000000000001");
    let req: Value = serde_json::from_slice(
        &std::fs::read(format!("{root}anthropic.next-request.json")).unwrap(),
    )
    .unwrap();
    let r = inspect_request(Api::AnthropicMessages, "/v1/messages", &req);
    assert_eq!(r.model, "claude-fixture");
    assert_eq!(r.results.len(), 1);
    assert_eq!(
        r.results[0].call_id.as_deref(),
        Some("toolu_01FIXTURE0000000000000001")
    );
    assert_eq!(r.results[0].value, json!("# Project\n"));
}

#[test]
fn responses_streamed_function_and_custom_calls() {
    let events = vec![
        (
            "response.created",
            json!({"type":"response.created","response":{"model":"gpt-x"}}),
        ),
        (
            "response.output_item.added",
            json!({"type":"response.output_item.added","output_index":0,"item":{"type":"reasoning","id":"rs_1"}}),
        ),
        (
            "response.output_item.done",
            json!({"type":"response.output_item.done","output_index":0,"item":{"type":"reasoning","id":"rs_1"}}),
        ),
        (
            "response.output_item.added",
            json!({"type":"response.output_item.added","output_index":1,"item":{"type":"function_call","call_id":"call_1","name":"shell","arguments":""}}),
        ),
        (
            "response.function_call_arguments.delta",
            json!({"type":"response.function_call_arguments.delta","output_index":1,"delta":"{\"command\":"}),
        ),
        (
            "response.function_call_arguments.delta",
            json!({"type":"response.function_call_arguments.delta","output_index":1,"delta":"[\"ls\"]}"}),
        ),
        (
            "response.output_item.done",
            json!({"type":"response.output_item.done","output_index":1,"item":{"type":"function_call","call_id":"call_1","name":"shell","arguments":"{\"command\":[\"ls\"]}"}}),
        ),
        (
            "response.output_item.added",
            json!({"type":"response.output_item.added","output_index":2,"item":{"type":"custom_tool_call","call_id":"call_2","name":"apply_patch","input":""}}),
        ),
        (
            "response.output_item.done",
            json!({"type":"response.output_item.done","output_index":2,"item":{"type":"custom_tool_call","call_id":"call_2","name":"apply_patch","input":"*** Begin Patch\n*** Add File: a.txt\n+hi\n*** End Patch"}}),
        ),
        (
            "response.completed",
            json!({"type":"response.completed","response":{"model":"gpt-x","usage":{"input_tokens":900,"output_tokens":20}}}),
        ),
    ];
    let info = parse_split(Api::OpenAiResponses, true, &sse(&events));
    assert!(info.complete);
    assert_eq!(info.model.as_deref(), Some("gpt-x"));
    assert_eq!(
        (info.input_tokens, info.output_tokens),
        (Some(900), Some(20))
    );
    let ids: Vec<&str> = info.calls.iter().map(|c| c.call_id.as_str()).collect();
    assert_eq!(ids, vec!["call_1", "call_2"]);
    assert_eq!(
        info.calls[0].args,
        ArgsText::Text("{\"command\":[\"ls\"]}".into())
    );
    assert_eq!(
        crate::record::paths_named(&info.calls[1].args),
        vec!["a.txt"]
    );

    // Cut after the first delta: the call is there, incomplete.
    let info = parse_split(Api::OpenAiResponses, true, &sse(&events[..5]));
    assert!(!info.complete);
    assert_eq!(info.calls.len(), 1);
    assert!(info.calls[0].incomplete);
}

#[test]
fn responses_request_results_of_each_kind() {
    let req = json!({"model":"gpt-x","tools":[{},{}],"input":[
        {"type":"message","role":"user","content":"hi"},
        {"type":"function_call_output","call_id":"call_1","output":"a.rs\n"},
        {"type":"custom_tool_call_output","call_id":"call_2","output":"Done"}
    ]});
    let r = inspect_request(Api::OpenAiResponses, "/responses", &req);
    assert_eq!(r.tools_offered, 2);
    let ids: Vec<_> = r
        .results
        .iter()
        .map(|x| x.call_id.clone().unwrap())
        .collect();
    assert_eq!(ids, vec!["call_1", "call_2"]);
}

#[test]
fn chat_streamed_tool_calls_by_index() {
    let chunks = [
        json!({"model":"qwen","choices":[{"index":0,"delta":{"role":"assistant","tool_calls":[{"index":0,"id":"call_9","type":"function","function":{"name":"bash","arguments":""}}]}}]}),
        json!({"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"arguments":"{\"cmd\":"}}]}}]}),
        json!({"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"arguments":"\"pwd\"}"}}]}}]}),
        json!({"choices":[{"index":0,"delta":{},"finish_reason":"tool_calls"}],"usage":{"prompt_tokens":50,"completion_tokens":7}}),
    ];
    let mut bytes = Vec::new();
    for c in &chunks {
        bytes.extend_from_slice(format!("data: {c}\n\n").as_bytes());
    }
    bytes.extend_from_slice(b"data: [DONE]\n\n");
    let info = parse_split(Api::OpenAiChat, true, &bytes);
    assert!(info.complete);
    assert_eq!(info.calls.len(), 1);
    assert_eq!(info.calls[0].call_id, "call_9");
    assert_eq!(
        info.calls[0].args,
        ArgsText::Text("{\"cmd\":\"pwd\"}".into())
    );
    assert_eq!((info.input_tokens, info.output_tokens), (Some(50), Some(7)));
    let req = json!({"model":"qwen","messages":[{"role":"tool","tool_call_id":"call_9","content":"/home"}]});
    let r = inspect_request(Api::OpenAiChat, "/v1/chat/completions", &req);
    assert_eq!(r.results[0].call_id.as_deref(), Some("call_9"));
}

#[test]
fn gemini_calls_without_ids_get_the_requests_prefix() {
    let chunk = json!({"candidates":[{"content":{"role":"model","parts":[{"functionCall":{"name":"run_shell_command","args":{"command":"ls"}}},{"functionCall":{"id":"own-id","name":"read_file","args":{"absolute_path":"/x"}}}]},"finishReason":"STOP"}],"usageMetadata":{"promptTokenCount":11,"candidatesTokenCount":3},"modelVersion":"gemini-x"});
    let info = parse_split(
        Api::Gemini,
        true,
        format!("data: {chunk}\r\n\r\n").as_bytes(),
    );
    assert!(info.complete);
    let ids: Vec<&str> = info.calls.iter().map(|c| c.call_id.as_str()).collect();
    assert_eq!(ids, vec!["gem-1", "own-id"]);
    let req = json!({"contents":[{"role":"user","parts":[{"functionResponse":{"name":"run_shell_command","response":{"output":"a"}}}]}],"tools":[{"functionDeclarations":[{},{},{}]}]});
    let r = inspect_request(
        Api::Gemini,
        "/v1beta/models/gemini-x:streamGenerateContent?alt=sse",
        &req,
    );
    assert_eq!(r.model, "gemini-x");
    assert_eq!(r.tools_offered, 3);
    assert_eq!(r.results[0].name.as_deref(), Some("run_shell_command"));
    assert_eq!(r.results[0].call_id, None);
}

#[test]
fn api_by_method_and_path() {
    assert_eq!(
        api_of("POST", "/v1/messages?beta=true"),
        Some(Api::AnthropicMessages)
    );
    assert_eq!(api_of("POST", "/v1/messages/count_tokens"), None);
    assert_eq!(api_of("GET", "/v1/messages"), None);
    assert_eq!(api_of("POST", "/responses"), Some(Api::OpenAiResponses));
    assert_eq!(api_of("POST", "/v1/responses"), Some(Api::OpenAiResponses));
    assert_eq!(api_of("POST", "/responses/compact"), None);
    assert_eq!(
        api_of("POST", "/v1/chat/completions"),
        Some(Api::OpenAiChat)
    );
    assert_eq!(
        api_of("POST", "/v1beta/models/g:streamGenerateContent?alt=sse"),
        Some(Api::Gemini)
    );
    assert_eq!(api_of("POST", "/v1beta/models/g:countTokens"), None);
    assert_eq!(api_of("HEAD", "/api/hello"), None);
}

#[test]
fn bytes_that_are_not_json_are_unparsed_not_calls() {
    let info = parse_split(Api::AnthropicMessages, false, b"<html>bad gateway</html>");
    assert!(info.unparsed);
    assert!(info.calls.is_empty());
}
