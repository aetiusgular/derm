//! What a request offers and returns, per API: the tools it offers, the
//! results it carries back, and the calls its response asks for, from a
//! whole JSON body or a stream read as it passes.
//!
//! Shapes: the Anthropic Messages API and its SSE events (Claude Code's
//! gateway guide, https://code.claude.com/docs/en/llm-gateway-protocol, and
//! `tests/cli-contract/lib/fakeMessages.mjs`); the OpenAI Responses API
//! (`function_call`, `custom_tool_call`, `local_shell_call` items and their
//! `*_output` answers; `fakeResponses.mjs`, the base's fixtures); Chat
//! Completions (`tool_calls` and `role: "tool"`; `fakeChat.mjs`); the Gemini
//! API (`functionCall` and `functionResponse` parts; `fakeGemini.mjs`).
//!
//! Server-run tools (Anthropic's `server_tool_use` and `mcp_tool_use`, the
//! Responses API's `web_search_call` and the like) are not recorded as calls:
//! the harness never runs them, so no gate or OS event can join them.

use std::collections::BTreeMap;

use serde_json::Value;

use crate::record::{Api, ArgsText, Call};
use crate::sse::SseReader;

/// The largest SSE event or JSON body the parser reads (the bytes still pass
/// through; past this the response counts as unparsed).
pub const MAX_PARSE: usize = 32 * 1024 * 1024;

/// Which API, from the method and the path after the upstream key.
pub fn api_of(method: &str, path: &str) -> Option<Api> {
    if method != "POST" {
        return None;
    }
    let path = path.split('?').next().unwrap_or("");
    if path.ends_with("/v1/messages") || path == "/messages" {
        return Some(Api::AnthropicMessages);
    }
    if path.ends_with("/responses") {
        return Some(Api::OpenAiResponses);
    }
    if path.ends_with("/chat/completions") {
        return Some(Api::OpenAiChat);
    }
    let last = path.rsplit('/').next().unwrap_or("");
    if last.ends_with(":generateContent") || last.ends_with(":streamGenerateContent") {
        return Some(Api::Gemini);
    }
    None
}

/// A tool result the harness sent back in a request.
#[derive(Clone, Debug, PartialEq)]
pub struct ResultSeen {
    pub call_id: Option<String>,
    /// The tool's name, where the API gives one (Gemini).
    pub name: Option<String>,
    pub value: Value,
    pub is_error: Option<bool>,
}

/// What the request says.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct RequestInfo {
    pub model: String,
    pub tools_offered: u64,
    pub results: Vec<ResultSeen>,
}

/// Reads a request body. A body that is not JSON gives an empty info.
pub fn inspect_request(api: Api, path: &str, body: &Value) -> RequestInfo {
    let mut info = RequestInfo {
        model: body
            .get("model")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string(),
        ..Default::default()
    };
    let count = |v: Option<&Value>| v.and_then(Value::as_array).map_or(0, |a| a.len() as u64);
    match api {
        Api::AnthropicMessages => {
            info.tools_offered = count(body.get("tools"));
            for m in body
                .get("messages")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
            {
                for b in m
                    .get("content")
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten()
                {
                    if b.get("type").and_then(Value::as_str) == Some("tool_result") {
                        info.results.push(ResultSeen {
                            call_id: b
                                .get("tool_use_id")
                                .and_then(Value::as_str)
                                .map(str::to_string),
                            name: None,
                            value: b
                                .get("content")
                                .cloned()
                                .unwrap_or(Value::String(String::new())),
                            is_error: b.get("is_error").and_then(Value::as_bool),
                        });
                    }
                }
            }
        }
        Api::OpenAiResponses => {
            info.tools_offered = count(body.get("tools"));
            for item in body
                .get("input")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
            {
                let kind = item.get("type").and_then(Value::as_str).unwrap_or("");
                if matches!(
                    kind,
                    "function_call_output" | "custom_tool_call_output" | "local_shell_call_output"
                ) {
                    info.results.push(ResultSeen {
                        call_id: item
                            .get("call_id")
                            .or_else(|| item.get("id"))
                            .and_then(Value::as_str)
                            .map(str::to_string),
                        name: None,
                        value: item
                            .get("output")
                            .cloned()
                            .unwrap_or(Value::String(String::new())),
                        is_error: None,
                    });
                }
            }
        }
        Api::OpenAiChat => {
            info.tools_offered = count(body.get("tools"));
            for m in body
                .get("messages")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
            {
                if m.get("role").and_then(Value::as_str) == Some("tool") {
                    info.results.push(ResultSeen {
                        call_id: m
                            .get("tool_call_id")
                            .and_then(Value::as_str)
                            .map(str::to_string),
                        name: None,
                        value: m
                            .get("content")
                            .cloned()
                            .unwrap_or(Value::String(String::new())),
                        is_error: None,
                    });
                }
            }
        }
        Api::Gemini => {
            if info.model.is_empty() {
                info.model = gemini_model(path);
            }
            info.tools_offered = body
                .get("tools")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .map(|t| {
                    count(
                        t.get("functionDeclarations")
                            .or_else(|| t.get("function_declarations")),
                    )
                })
                .sum();
            for c in body
                .get("contents")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
            {
                for p in c
                    .get("parts")
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten()
                {
                    if let Some(fr) = p
                        .get("functionResponse")
                        .or_else(|| p.get("function_response"))
                    {
                        info.results.push(ResultSeen {
                            call_id: fr.get("id").and_then(Value::as_str).map(str::to_string),
                            name: fr.get("name").and_then(Value::as_str).map(str::to_string),
                            value: fr.get("response").cloned().unwrap_or(Value::Null),
                            is_error: None,
                        });
                    }
                }
            }
        }
    }
    info
}

fn gemini_model(path: &str) -> String {
    let path = path.split('?').next().unwrap_or("");
    let last = path.rsplit('/').next().unwrap_or("");
    last.split(':').next().unwrap_or("").to_string()
}

/// What the response says.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct ResponseInfo {
    pub model: Option<String>,
    pub calls: Vec<Call>,
    pub input_tokens: Option<u64>,
    pub output_tokens: Option<u64>,
    /// The response reached its last event, or was a whole JSON body.
    pub complete: bool,
    /// The body could not be read (too big, not JSON, an event too long).
    pub unparsed: bool,
}

/// One call while its stream is still open.
#[derive(Clone, Debug, Default)]
struct Pending {
    id: String,
    name: String,
    args: String,
    json_args: Option<Value>,
    done: bool,
    freeform: bool,
}

/// Reads a response as it passes. Feed it every byte the upstream sends,
/// then `finish`.
#[derive(Debug)]
pub struct ResponseParser {
    api: Api,
    sse: Option<SseReader>,
    body: Vec<u8>,
    too_big: bool,
    calls: BTreeMap<u64, Pending>,
    order: u64,
    /// A Responses item's own id (or `call_id`) to its slot, for a stream
    /// whose events carry no `output_index` (MW5-20; Codex's own parser
    /// never reads it, `codex-rs/codex-api/src/sse/responses.rs` at
    /// `rust-v0.163.0`, and its test streams leave it out).
    by_item: std::collections::HashMap<String, u64>,
    info: ResponseInfo,
    gemini_seq: u64,
    gemini_prefix: String,
}

impl ResponseParser {
    /// `event_stream`: the response's `content-type` is `text/event-stream`.
    /// `gemini_prefix` names Gemini calls that carry no id of their own.
    pub fn new(api: Api, event_stream: bool, gemini_prefix: &str) -> Self {
        ResponseParser {
            api,
            sse: event_stream.then(|| SseReader::new(MAX_PARSE)),
            body: Vec::new(),
            too_big: false,
            calls: BTreeMap::new(),
            order: 0,
            by_item: Default::default(),
            info: ResponseInfo::default(),
            gemini_seq: 0,
            gemini_prefix: gemini_prefix.to_string(),
        }
    }

    pub fn feed(&mut self, bytes: &[u8]) {
        if let Some(sse) = self.sse.as_mut() {
            let events = sse.feed(bytes);
            for e in events {
                if e.data == "[DONE]" {
                    self.info.complete = true;
                    continue;
                }
                if let Ok(v) = serde_json::from_str::<Value>(&e.data) {
                    self.on_event(&e.event, &v);
                }
            }
        } else if !self.too_big {
            if self.body.len() + bytes.len() > MAX_PARSE {
                self.too_big = true;
                self.body = Vec::new();
            } else {
                self.body.extend_from_slice(bytes);
            }
        }
    }

    pub fn finish(mut self) -> ResponseInfo {
        if let Some(sse) = &self.sse {
            if sse.overflowed {
                self.info.unparsed = true;
            }
        } else if self.too_big {
            self.info.unparsed = true;
        } else {
            match serde_json::from_slice::<Value>(&self.body) {
                Ok(Value::Array(parts)) if self.api == Api::Gemini => {
                    for p in &parts {
                        self.on_whole(p);
                    }
                    self.info.complete = true;
                }
                Ok(v) => {
                    self.on_whole(&v);
                    self.info.complete = true;
                }
                Err(_) => self.info.unparsed = !self.body.is_empty(),
            }
        }
        let complete = self.info.complete;
        let pending = std::mem::take(&mut self.calls);
        for (_, p) in pending {
            if p.id.is_empty() && p.name.is_empty() {
                continue;
            }
            let args = match p.json_args {
                Some(v) => ArgsText::Json(v),
                None => ArgsText::Text(p.args),
            };
            let _ = p.freeform;
            self.info.calls.push(Call {
                call_id: p.id,
                tool: p.name,
                args,
                incomplete: !(p.done || complete),
            });
        }
        self.info.calls.retain(|c| !c.call_id.is_empty());
        self.info
    }

    fn slot(&mut self, key: u64) -> &mut Pending {
        self.calls.entry(key).or_default()
    }

    fn next_key(&mut self) -> u64 {
        self.order += 1;
        self.order
    }

    fn on_event(&mut self, name: &str, v: &Value) {
        let kind = v.get("type").and_then(Value::as_str).unwrap_or(name);
        match self.api {
            Api::AnthropicMessages => self.anthropic_event(kind, v),
            Api::OpenAiResponses => self.responses_event(kind, v),
            Api::OpenAiChat => self.chat_chunk(v),
            Api::Gemini => self.gemini_part(v),
        }
    }

    fn on_whole(&mut self, v: &Value) {
        match self.api {
            Api::AnthropicMessages => {
                self.model_from(v.get("model"));
                self.usage_anthropic(v.get("usage"));
                for b in v
                    .get("content")
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten()
                {
                    if b.get("type").and_then(Value::as_str) == Some("tool_use") {
                        let k = self.next_key();
                        let p = self.slot(k);
                        p.id = str_of(b.get("id"));
                        p.name = str_of(b.get("name"));
                        p.json_args = b.get("input").cloned();
                        p.done = true;
                    }
                }
            }
            Api::OpenAiResponses => {
                self.model_from(v.get("model"));
                self.usage_openai(v.get("usage"));
                for item in v
                    .get("output")
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten()
                {
                    let k = self.next_key();
                    self.responses_item(k, item, true);
                }
            }
            Api::OpenAiChat => {
                self.model_from(v.get("model"));
                self.usage_openai(v.get("usage"));
                for choice in v
                    .get("choices")
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten()
                {
                    let msg = choice.get("message");
                    for tc in msg
                        .and_then(|m| m.get("tool_calls"))
                        .and_then(Value::as_array)
                        .into_iter()
                        .flatten()
                    {
                        let k = self.next_key();
                        let p = self.slot(k);
                        p.id = str_of(tc.get("id"));
                        p.name = str_of(tc.pointer("/function/name"));
                        p.args = str_of(tc.pointer("/function/arguments"));
                        p.done = true;
                    }
                }
            }
            Api::Gemini => self.gemini_part(v),
        }
    }

    fn model_from(&mut self, v: Option<&Value>) {
        if let Some(m) = v.and_then(Value::as_str).filter(|m| !m.is_empty()) {
            self.info.model = Some(m.to_string());
        }
    }

    fn usage_anthropic(&mut self, u: Option<&Value>) {
        let Some(u) = u else { return };
        let get = |k: &str| u.get(k).and_then(Value::as_u64);
        if let Some(i) = get("input_tokens") {
            let cached = get("cache_creation_input_tokens").unwrap_or(0)
                + get("cache_read_input_tokens").unwrap_or(0);
            self.info.input_tokens = Some(i + cached);
        }
        if let Some(o) = get("output_tokens") {
            self.info.output_tokens = Some(o);
        }
    }

    fn usage_openai(&mut self, u: Option<&Value>) {
        let Some(u) = u else { return };
        let get = |a: &str, b: &str| u.get(a).or_else(|| u.get(b)).and_then(Value::as_u64);
        if let Some(i) = get("input_tokens", "prompt_tokens") {
            self.info.input_tokens = Some(i);
        }
        if let Some(o) = get("output_tokens", "completion_tokens") {
            self.info.output_tokens = Some(o);
        }
    }

    fn anthropic_event(&mut self, kind: &str, v: &Value) {
        match kind {
            "message_start" => {
                let m = v.get("message");
                self.model_from(m.and_then(|m| m.get("model")));
                self.usage_anthropic(m.and_then(|m| m.get("usage")));
            }
            "content_block_start" => {
                let b = v.get("content_block");
                if b.and_then(|b| b.get("type")).and_then(Value::as_str) == Some("tool_use") {
                    let idx = v.get("index").and_then(Value::as_u64).unwrap_or(u64::MAX);
                    let p = self.slot(idx);
                    p.id = str_of(b.and_then(|b| b.get("id")));
                    p.name = str_of(b.and_then(|b| b.get("name")));
                    // An input given whole at the start (rare); deltas replace it.
                    if let Some(i) = b
                        .and_then(|b| b.get("input"))
                        .filter(|i| i.as_object().is_some_and(|o| !o.is_empty()))
                    {
                        p.json_args = Some(i.clone());
                    }
                }
            }
            "content_block_delta" => {
                let idx = v.get("index").and_then(Value::as_u64).unwrap_or(u64::MAX);
                if let Some(part) = v.pointer("/delta/partial_json").and_then(Value::as_str) {
                    if let Some(p) = self.calls.get_mut(&idx) {
                        p.json_args = None;
                        p.args.push_str(part);
                    }
                }
            }
            "content_block_stop" => {
                let idx = v.get("index").and_then(Value::as_u64).unwrap_or(u64::MAX);
                if let Some(p) = self.calls.get_mut(&idx) {
                    if p.args.is_empty() && p.json_args.is_none() {
                        p.json_args = Some(Value::Object(Default::default()));
                    }
                    p.done = true;
                }
            }
            "message_delta" => self.usage_anthropic(v.get("usage")),
            "message_stop" => self.info.complete = true,
            _ => {}
        }
    }

    fn responses_item(&mut self, key: u64, item: &Value, done: bool) {
        let kind = item.get("type").and_then(Value::as_str).unwrap_or("");
        let p = self.slot(key);
        match kind {
            "function_call" => {
                p.id = str_of(item.get("call_id"));
                p.name = str_of(item.get("name"));
                let a = str_of(item.get("arguments"));
                if !a.is_empty() || done {
                    p.args = a;
                }
            }
            "custom_tool_call" => {
                p.id = str_of(item.get("call_id"));
                p.name = str_of(item.get("name"));
                p.freeform = true;
                let a = str_of(item.get("input"));
                if !a.is_empty() || done {
                    p.args = a;
                }
            }
            "local_shell_call" => {
                p.id = str_of(item.get("call_id").or_else(|| item.get("id")));
                p.name = "local_shell".into();
                p.json_args = item.get("action").cloned();
            }
            _ => {
                self.calls.remove(&key);
                return;
            }
        }
        if done {
            p.done = true;
        }
    }

    /// The slot for an item with no `output_index`: by its id, else its
    /// `call_id`, a new one the first time either is seen.
    fn item_key(&mut self, item: &Value) -> Option<u64> {
        let names: Vec<String> = ["id", "call_id"]
            .iter()
            .filter_map(|k| item.get(*k).and_then(Value::as_str))
            .filter(|s| !s.is_empty())
            .map(|s| format!("noidx:{s}"))
            .collect();
        if names.is_empty() {
            return None;
        }
        if let Some(k) = names.iter().find_map(|n| self.by_item.get(n).copied()) {
            for n in names {
                self.by_item.insert(n, k);
            }
            return Some(k);
        }
        // Past the indexes a well-formed stream gives (a hostile upstream can
        // send any `output_index`, and at worst merges two of its own calls;
        // review FP3-S7).
        let k = (1u64 << 32) + self.next_key();
        if self.by_item.len() < 4_096 {
            for n in names {
                self.by_item.insert(n, k);
            }
        }
        Some(k)
    }

    fn responses_event(&mut self, kind: &str, v: &Value) {
        let mut key = v.get("output_index").and_then(Value::as_u64).map(|i| i + 1);
        if key.is_none() {
            key = match kind {
                "response.output_item.added" | "response.output_item.done" => {
                    v.get("item").and_then(|item| self.item_key(item))
                }
                _ => v
                    .get("item_id")
                    .and_then(Value::as_str)
                    .and_then(|id| self.by_item.get(&format!("noidx:{id}")).copied()),
            };
        }
        match kind {
            "response.created" | "response.in_progress" => {
                self.model_from(v.pointer("/response/model"));
            }
            "response.output_item.added" | "response.output_item.done" => {
                if let (Some(k), Some(item)) = (key, v.get("item")) {
                    self.responses_item(k, item, kind.ends_with(".done"));
                }
            }
            "response.function_call_arguments.delta" | "response.custom_tool_call_input.delta" => {
                if let (Some(k), Some(d)) = (key, v.get("delta").and_then(Value::as_str)) {
                    if let Some(p) = self.calls.get_mut(&k) {
                        p.args.push_str(d);
                    }
                }
            }
            "response.function_call_arguments.done" | "response.custom_tool_call_input.done" => {
                let whole = v
                    .get("arguments")
                    .or_else(|| v.get("input"))
                    .and_then(Value::as_str);
                if let (Some(k), Some(a)) = (key, whole) {
                    if let Some(p) = self.calls.get_mut(&k) {
                        p.args = a.to_string();
                    }
                }
            }
            "response.completed" | "response.done" | "response.incomplete" | "response.failed" => {
                let r = v.get("response");
                self.model_from(r.and_then(|r| r.get("model")));
                self.usage_openai(r.and_then(|r| r.get("usage")));
                self.info.complete = true;
            }
            _ => {}
        }
    }

    fn chat_chunk(&mut self, v: &Value) {
        self.model_from(v.get("model"));
        self.usage_openai(v.get("usage"));
        for choice in v
            .get("choices")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            for tc in choice
                .pointer("/delta/tool_calls")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
            {
                let idx = tc.get("index").and_then(Value::as_u64).unwrap_or(0);
                let p = self.slot(idx);
                if let Some(id) = tc
                    .get("id")
                    .and_then(Value::as_str)
                    .filter(|s| !s.is_empty())
                {
                    p.id = id.to_string();
                }
                if let Some(n) = tc
                    .pointer("/function/name")
                    .and_then(Value::as_str)
                    .filter(|s| !s.is_empty())
                {
                    p.name = n.to_string();
                }
                if let Some(a) = tc.pointer("/function/arguments").and_then(Value::as_str) {
                    p.args.push_str(a);
                }
            }
            if choice.get("finish_reason").is_some_and(|f| !f.is_null()) {
                self.info.complete = true;
                for p in self.calls.values_mut() {
                    p.done = true;
                }
            }
        }
    }

    fn gemini_part(&mut self, v: &Value) {
        self.model_from(v.get("modelVersion"));
        if let Some(u) = v.get("usageMetadata") {
            if let Some(i) = u.get("promptTokenCount").and_then(Value::as_u64) {
                self.info.input_tokens = Some(i);
            }
            if let Some(o) = u.get("candidatesTokenCount").and_then(Value::as_u64) {
                self.info.output_tokens = Some(o);
            }
        }
        for cand in v
            .get("candidates")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            for part in cand
                .pointer("/content/parts")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
            {
                if let Some(fc) = part.get("functionCall") {
                    self.gemini_seq += 1;
                    let id = fc
                        .get("id")
                        .and_then(Value::as_str)
                        .filter(|s| !s.is_empty())
                        .map(str::to_string)
                        .unwrap_or_else(|| format!("{}-{}", self.gemini_prefix, self.gemini_seq));
                    let k = self.next_key();
                    let p = self.slot(k);
                    p.id = id;
                    p.name = str_of(fc.get("name"));
                    p.json_args = Some(
                        fc.get("args")
                            .cloned()
                            .unwrap_or(Value::Object(Default::default())),
                    );
                    p.done = true;
                }
            }
            if cand.get("finishReason").is_some_and(|f| !f.is_null()) {
                self.info.complete = true;
            }
        }
    }
}

fn str_of(v: Option<&Value>) -> String {
    v.and_then(Value::as_str).unwrap_or("").to_string()
}

#[cfg(test)]
mod tests;
