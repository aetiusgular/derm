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

/// Mac test w5 retest 2, MW5-20: a Codex chat through the tap to
/// chatgpt.com gave `tap.request` records and no `tap.call`. The parser keyed
/// every item on `output_index`, which Codex's own parser never reads and its
/// test streams leave out; a stream without it gave no call (the cause on
/// chatgpt.com is inferred, not seen).
#[test]
fn responses_items_without_an_output_index_are_still_calls() {
    let events = vec![
        (
            "response.output_item.added",
            json!({"type":"response.output_item.added","item":{"type":"function_call","id":"fc_1","call_id":"call_9","name":"shell","arguments":""}}),
        ),
        (
            "response.function_call_arguments.delta",
            json!({"type":"response.function_call_arguments.delta","item_id":"fc_1","delta":"{\"command\":[\"sleep\",\"20\"]}"}),
        ),
        (
            "response.output_item.done",
            json!({"type":"response.output_item.done","item":{"type":"function_call","id":"fc_1","call_id":"call_9","name":"shell","arguments":"{\"command\":[\"sleep\",\"20\"]}"}}),
        ),
        // Only a done item, as Codex's own test fixtures send it.
        (
            "response.output_item.done",
            json!({"type":"response.output_item.done","item":{"type":"function_call","call_id":"call_10","name":"shell","arguments":"{\"command\":[\"ls\"]}"}}),
        ),
        (
            "response.output_item.done",
            json!({"type":"response.output_item.done","item":{"type":"message","id":"msg_1","content":[]}}),
        ),
        (
            "response.completed",
            json!({"type":"response.completed","response":{"model":"gpt-5.6-luna"}}),
        ),
    ];
    let info = parse_split(Api::OpenAiResponses, true, &sse(&events));
    let ids: Vec<&str> = info.calls.iter().map(|c| c.call_id.as_str()).collect();
    assert_eq!(ids, vec!["call_9", "call_10"]);
    assert_eq!(
        info.calls[0].args,
        ArgsText::Text("{\"command\":[\"sleep\",\"20\"]}".into())
    );
    assert!(info.calls.iter().all(|c| !c.incomplete));
}

/// The stream Codex 0.163.0 reads from chatgpt.com, by shape (Mac test w5
/// retest 4, the tap's content files read for keys and types only): a
/// `custom_tool_call` item with `output_index`, its input deltas, and usage
/// in `response.completed`.
fn codex_chatgpt_stream() -> Vec<u8> {
    sse(&[
        (
            "response.created",
            json!({"type":"response.created","response":{"model":"gpt-5.6-luna"}}),
        ),
        (
            "response.output_item.added",
            json!({"type":"response.output_item.added","output_index":0,"item":{"type":"custom_tool_call","id":"ctc_1","call_id":"call_s1","name":"exec","input":""}}),
        ),
        (
            "response.custom_tool_call_input.delta",
            json!({"type":"response.custom_tool_call_input.delta","output_index":0,"item_id":"ctc_1","delta":"sleep "}),
        ),
        (
            "response.custom_tool_call_input.delta",
            json!({"type":"response.custom_tool_call_input.delta","output_index":0,"item_id":"ctc_1","delta":"5"}),
        ),
        (
            "response.output_item.done",
            json!({"type":"response.output_item.done","output_index":0,"item":{"type":"custom_tool_call","id":"ctc_1","call_id":"call_s1","name":"exec","input":"sleep 5"}}),
        ),
        (
            "response.completed",
            json!({"type":"response.completed","response":{"model":"gpt-5.6-luna","usage":{"input_tokens":7000,"output_tokens":30}}}),
        ),
    ])
}

/// Mac test w5 retest 4, MW5-20: every `tap.request` of a Codex chat on
/// chatgpt.com said no tokens, no calls and `incomplete: false`, which only
/// a parser started for a whole JSON body gives; so the reply was not typed
/// `text/event-stream` (inferred: the tap keeps no header). Codex itself
/// reads the body as a stream whatever its type (`codex-rs/codex-api/src/sse/responses.rs:525-548`
/// at `rust-v0.163.0`, `eventsource_stream`, no content-type check), so the
/// parser reads it by its shape.
#[test]
fn a_stream_not_typed_as_one_is_read_as_a_stream() {
    let bytes = codex_chatgpt_stream();
    for lead in [
        &b""[..],
        b"\n",
        b"\r\n",
        b"\xEF\xBB\xBF",
        b": keepalive\n\n",
    ] {
        let body = [lead, &bytes[..]].concat();
        let info = parse_split(Api::OpenAiResponses, false, &body);
        assert!(info.complete, "lead {lead:?}");
        assert!(!info.unparsed, "lead {lead:?}");
        assert_eq!(
            (info.input_tokens, info.output_tokens),
            (Some(7000), Some(30))
        );
        let ids: Vec<&str> = info.calls.iter().map(|c| c.call_id.as_str()).collect();
        assert_eq!(ids, vec!["call_s1"], "lead {lead:?}");
        assert_eq!(info.calls[0].args, ArgsText::Text("sleep 5".into()));
    }
    // Cut before its end: the call is there and incomplete, and so is the
    // response.
    let cut = &bytes[..bytes.len() / 2];
    let info = parse_split(Api::OpenAiResponses, false, cut);
    assert!(!info.complete);
    assert!(info.calls.iter().all(|c| c.incomplete));
    // A whole JSON body untyped is still a body, and HTML is still unparsed.
    let whole = json!({"model":"gpt-x","output":[{"type":"function_call","call_id":"c","name":"shell","arguments":"{}"}],"usage":{"input_tokens":3,"output_tokens":1}});
    let info = parse_split(Api::OpenAiResponses, false, format!("  {whole}").as_bytes());
    assert!(info.complete && !info.unparsed);
    assert_eq!(info.calls.len(), 1);
    assert!(parse_split(Api::OpenAiResponses, false, b"<html>x</html>").unparsed);
    // Which form the parser read.
    let mut p = ResponseParser::new(Api::OpenAiResponses, false, "g");
    p.feed(&bytes);
    assert_eq!(p.form(), Some(ResponseForm::StreamUntyped));
    let mut p = ResponseParser::new(Api::OpenAiResponses, true, "g");
    p.feed(&bytes);
    assert_eq!(p.form(), Some(ResponseForm::Stream));
    let mut p = ResponseParser::new(Api::OpenAiResponses, false, "g");
    p.feed(whole.to_string().as_bytes());
    assert_eq!(p.form(), Some(ResponseForm::Json));
    assert_eq!(
        ResponseParser::new(Api::OpenAiResponses, false, "g").form(),
        None
    );
}

/// MW5-20: Codex 0.163.0 with `use_responses_lite` sends no `tools` and puts
/// them in an `additional_tools` input item instead
/// (`codex-rs/core/src/client.rs:980-993`, `protocol/src/models.rs:1028-1035`
/// at `rust-v0.163.0`), so `toolsOffered` was 0.
#[test]
fn tools_in_an_additional_tools_item_are_counted() {
    let body = json!({
        "model": "gpt-5.6-luna",
        "input": [
            {"type":"additional_tools","role":"developer","tools":[{"type":"custom","name":"exec"},{"type":"function","name":"view_image"}]},
            {"type":"message","role":"user","content":[]},
            {"type":"additional_tools","role":"developer","tools":[{"type":"function","name":"mcp"}]},
            {"type":"additional_tools","role":"developer","tools":"not a list"}
        ]
    });
    let info = inspect_request(Api::OpenAiResponses, "/responses", &body);
    assert_eq!(info.tools_offered, 3);
    let both = json!({"tools":[{"name":"a"}],"input":[{"type":"additional_tools","tools":[{"name":"b"}]}]});
    assert_eq!(
        inspect_request(Api::OpenAiResponses, "/responses", &both).tools_offered,
        2
    );
}
