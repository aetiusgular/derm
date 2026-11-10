//! What a tap record keeps: hashes, sizes and the paths a call names, never
//! content (`contracts/events.md` section 5; the base's hash rules in
//! `contracts/fixtures/tap/README.md`).

use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

use derm_core::event::{Event, Source};

/// Most paths one call's record keeps (the schema's `maxItems`).
pub const MAX_PATHS: usize = 64;
/// Longest path kept, in bytes (the schema's `maxLength`).
pub const MAX_PATH_LEN: usize = 4096;

/// Which API a request speaks (`wave5-records.schema.json`, `$defs.api`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Api {
    AnthropicMessages,
    OpenAiResponses,
    OpenAiChat,
    Gemini,
}

impl Api {
    pub fn name(self) -> &'static str {
        match self {
            Api::AnthropicMessages => "anthropic-messages",
            Api::OpenAiResponses => "openai-responses",
            Api::OpenAiChat => "openai-chat",
            Api::Gemini => "gemini",
        }
    }
}

/// `value` as canonical JSON: object keys sorted by their UTF-8 bytes, no
/// whitespace. A streamed and a whole response hash alike.
pub fn canonical(value: &Value) -> String {
    let mut out = String::new();
    write_canonical(value, &mut out);
    out
}

fn write_canonical(value: &Value, out: &mut String) {
    match value {
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            out.push('{');
            for (i, k) in keys.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push_str(&serde_json::to_string(k).unwrap_or_default());
                out.push(':');
                write_canonical(&map[*k], out);
            }
            out.push('}');
        }
        Value::Array(items) => {
            out.push('[');
            for (i, v) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_canonical(v, out);
            }
            out.push(']');
        }
        other => out.push_str(&serde_json::to_string(other).unwrap_or_default()),
    }
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// A hash and a size.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Digested {
    pub sha256: String,
    pub bytes: u64,
}

impl Digested {
    fn of(text: &str) -> Self {
        Digested {
            sha256: sha256_hex(text.as_bytes()),
            bytes: text.len() as u64,
        }
    }
}

/// Arguments as the model sent them: parsed JSON hashes canonically; text
/// that does not parse (a cut stream, a freeform tool such as Codex's
/// `apply_patch`) hashes as written.
pub fn digest_args(raw: &ArgsText) -> Digested {
    match raw {
        ArgsText::Json(v) => Digested::of(&canonical(v)),
        ArgsText::Text(t) => match serde_json::from_str::<Value>(t) {
            Ok(v) if v.is_object() => Digested::of(&canonical(&v)),
            _ => Digested::of(t),
        },
    }
}

/// A result as the harness sent it back: a string hashes as its text,
/// anything else as canonical JSON.
pub fn digest_result(result: &Value) -> Digested {
    match result {
        Value::String(s) => Digested::of(s),
        other => Digested::of(&canonical(other)),
    }
}

/// A call's arguments before they are hashed.
#[derive(Clone, Debug, PartialEq)]
pub enum ArgsText {
    Json(Value),
    Text(String),
}

impl ArgsText {
    fn parsed(&self) -> Option<Value> {
        match self {
            ArgsText::Json(v) => Some(v.clone()),
            ArgsText::Text(t) => serde_json::from_str(t).ok(),
        }
    }
}

/// The file paths a call's arguments name: string values of the top-level
/// keys `path`, `file_path`, `filePath`, `notebook_path` and the strings in
/// `paths`; and, for a freeform patch (Codex's `apply_patch`), each
/// `*** Add File:`, `*** Update File:`, `*** Delete File:` and
/// `*** Move to:` line. Command text is not read for paths (Decisions).
pub fn paths_named(args: &ArgsText) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut push = |p: &str| {
        let p = p.trim();
        if !p.is_empty()
            && p.len() <= MAX_PATH_LEN
            && out.len() < MAX_PATHS
            && !out.iter().any(|x| x == p)
        {
            out.push(p.to_string());
        }
    };
    if let Some(Value::Object(map)) = args.parsed() {
        for key in ["path", "file_path", "filePath", "notebook_path"] {
            if let Some(Value::String(s)) = map.get(key) {
                push(s);
            }
        }
        if let Some(Value::Array(items)) = map.get("paths") {
            for v in items {
                if let Value::String(s) = v {
                    push(s);
                }
            }
        }
        for key in ["input", "patch"] {
            if let Some(Value::String(s)) = map.get(key) {
                patch_paths(s, &mut push);
            }
        }
    } else if let ArgsText::Text(t) = args {
        patch_paths(t, &mut push);
    }
    out
}

fn patch_paths(text: &str, push: &mut impl FnMut(&str)) {
    if !text.contains("*** Begin Patch") {
        return;
    }
    for line in text.lines() {
        for head in [
            "*** Add File:",
            "*** Update File:",
            "*** Delete File:",
            "*** Move to:",
        ] {
            if let Some(p) = line.strip_prefix(head) {
                push(p);
            }
        }
    }
}

/// One tool call the model asked for, as the tap saw it.
#[derive(Clone, Debug, PartialEq)]
pub struct Call {
    pub call_id: String,
    pub tool: String,
    pub args: ArgsText,
    /// The stream ended before this call's arguments did.
    pub incomplete: bool,
    /// When a streamed reply finished this call's item (MW5-33), if the
    /// tap read it as it came; the record is stamped with it.
    pub done_at: Option<i64>,
}

/// What the tap knows of a call when it writes its record.
#[derive(Clone, Debug)]
pub struct CallRecord {
    pub api: Api,
    pub model: String,
    pub request: Option<String>,
    pub call_id: String,
    pub tool: String,
    pub tool_normalized: String,
    pub args: Digested,
    pub paths: Vec<String>,
    pub result: Option<(Digested, Option<bool>)>,
    pub incomplete: bool,
    pub content_kept: bool,
    /// For a harness's code tool (`derm_core::policy::CODE_TOOLS`): the cell
    /// the call works on, from Codex's `wait` arguments (`cell_id`) or its
    /// result's header (fix pass 6, FP5R-1 and FP5R-2).
    pub cell_id: Option<String>,
    /// For a code tool's result: whether its header says the cell keeps
    /// running (`derm_core::policy::cell_status`); `None` when no header was
    /// read.
    pub code_status: Option<derm_core::policy::CellStatus>,
}

impl CallRecord {
    pub fn new(api: Api, model: &str, request: Option<String>, harness: &str, call: &Call) -> Self {
        CallRecord {
            api,
            model: clip(model, 200),
            request,
            call_id: clip(&call.call_id, 128),
            tool: clip(&call.tool, 200),
            tool_normalized: clip(
                &derm_core::policy::normalize_tool_name_for(&call.tool, &[], harness),
                200,
            ),
            args: digest_args(&call.args),
            paths: paths_named(&call.args),
            result: None,
            incomplete: call.incomplete,
            content_kept: false,
            cell_id: None,
            code_status: None,
        }
        .with_wait_cell(harness, call)
    }

    /// Codex's `wait` names the cell it resumes in its `cell_id` argument
    /// (`core/src/tools/code_mode/wait_spec.rs:12`, 0.163.0).
    fn with_wait_cell(mut self, harness: &str, call: &Call) -> Self {
        if derm_core::policy::code_tool(harness, &self.tool_normalized)
            && self.tool_normalized.eq_ignore_ascii_case("wait")
        {
            self.cell_id = call
                .args
                .parsed()
                // As Codex 0.163.0 reads it: `ExecWaitArgs.cell_id` is a
                // `String` taken as given (`CellId::new(args.cell_id)`,
                // `core/src/tools/code_mode/wait_handler.rs:28-29, 126`), so
                // a padded id names another cell, never the trimmed one, and
                // a number fails Codex's parse and names no cell (fix pass
                // 6's review, FP6-S1).
                .and_then(|v| match v.get("cell_id") {
                    Some(Value::String(s)) => Some(s.clone()),
                    _ => None,
                })
                .filter(|c| derm_core::policy::cell_id_ok(c));
        }
        self
    }

    /// Reads a code tool's result header (`derm_core::policy::cell_status`)
    /// from every output the request carries for this call: a cell can add
    /// outputs of its own (`notify()`, `code-mode-protocol/src/description.rs`
    /// line 40), so a header that says the cell runs wins over one that says
    /// it ended, and a cell's own text cannot close it early.
    pub fn read_cell_status<'a>(
        &mut self,
        harness: &str,
        outputs: impl Iterator<Item = &'a Value>,
    ) {
        if !derm_core::policy::code_tool(harness, &self.tool_normalized) {
            return;
        }
        for v in outputs {
            let text = match v {
                Value::String(s) => Some(s.as_str()),
                Value::Array(items) => items
                    .first()
                    .and_then(|i| i.get("text"))
                    .and_then(Value::as_str),
                _ => None,
            };
            match text.and_then(derm_core::policy::cell_status) {
                Some(derm_core::policy::CellStatus::Running(id)) => {
                    if let Some(id) = id {
                        self.cell_id = Some(id.clone());
                        self.code_status = Some(derm_core::policy::CellStatus::Running(Some(id)));
                    } else if !matches!(
                        self.code_status,
                        Some(derm_core::policy::CellStatus::Running(Some(_)))
                    ) {
                        self.code_status = Some(derm_core::policy::CellStatus::Running(None));
                    }
                }
                Some(derm_core::policy::CellStatus::Ended) if self.code_status.is_none() => {
                    self.code_status = Some(derm_core::policy::CellStatus::Ended);
                }
                _ => {}
            }
        }
    }

    /// The record's id: one per call per chat, so the copy with the result
    /// replaces the first (case 35).
    pub fn id(&self, chat: &str) -> String {
        format!("tap-{chat}-{}", self.call_id)
    }

    pub fn event(&self, chat: &str, harness: &str, at: i64) -> Event {
        let mut d = Map::new();
        d.insert("trust".into(), json!("daemon"));
        d.insert("api".into(), json!(self.api.name()));
        d.insert("model".into(), json!(self.model));
        if let Some(r) = &self.request {
            d.insert("request".into(), json!(r));
        }
        d.insert("callId".into(), json!(self.call_id));
        d.insert("tool".into(), json!(self.tool));
        d.insert("toolNormalized".into(), json!(self.tool_normalized));
        d.insert("argsSha256".into(), json!(self.args.sha256));
        d.insert("argsBytes".into(), json!(self.args.bytes));
        d.insert("paths".into(), json!(self.paths));
        match &self.result {
            Some((r, is_error)) => {
                d.insert("resultSha256".into(), json!(r.sha256));
                d.insert("resultBytes".into(), json!(r.bytes));
                if let Some(e) = is_error {
                    d.insert("resultIsError".into(), json!(e));
                }
            }
            None => {
                d.insert("resultSha256".into(), Value::Null);
                d.insert("resultBytes".into(), Value::Null);
            }
        }
        d.insert("incomplete".into(), json!(self.incomplete));
        if let Some(c) = &self.cell_id {
            d.insert("cellId".into(), json!(c));
        }
        match &self.code_status {
            Some(derm_core::policy::CellStatus::Running(_)) => {
                d.insert("codeStatus".into(), json!("running"));
            }
            Some(derm_core::policy::CellStatus::Ended) => {
                d.insert("codeStatus".into(), json!("ended"));
            }
            None => {}
        }
        if self.content_kept {
            d.insert("contentKept".into(), json!(true));
        }
        let summary = if self.incomplete {
            format!("{} (cut)", self.tool)
        } else {
            self.tool.clone()
        };
        Event {
            id: self.id(chat),
            at,
            chat_id: chat.to_string(),
            harness: harness.to_string(),
            source: Source::Tap,
            kind: "tap.call".into(),
            summary: clip(&summary, 200),
            detail: Value::Object(d),
            pid: None,
            approval_id: None,
        }
    }
}

/// One model round trip.
#[derive(Clone, Debug, Default)]
pub struct RequestRecord {
    pub id: String,
    pub api: Option<Api>,
    pub upstream: String,
    pub model: String,
    pub status: Option<u16>,
    pub input_tokens: Option<u64>,
    pub output_tokens: Option<u64>,
    pub duration_ms: u64,
    pub tools_offered: u64,
    pub tool_calls: u64,
    pub incomplete: bool,
    pub content_kept: bool,
    /// How the tap read the response body (`apis::ResponseForm::name`): the
    /// form, never a header's value (case 114).
    pub response_form: Option<&'static str>,
}

impl RequestRecord {
    pub fn event(&self, chat: &str, harness: &str, at: i64) -> Event {
        let api = self.api.unwrap_or(Api::AnthropicMessages);
        let mut d = Map::new();
        d.insert("trust".into(), json!("daemon"));
        d.insert("api".into(), json!(api.name()));
        d.insert("upstream".into(), json!(clip(&self.upstream, 255)));
        d.insert("model".into(), json!(clip(&self.model, 200)));
        d.insert("status".into(), json!(self.status));
        d.insert("inputTokens".into(), json!(self.input_tokens));
        d.insert("outputTokens".into(), json!(self.output_tokens));
        d.insert("durationMs".into(), json!(self.duration_ms));
        d.insert("toolsOffered".into(), json!(self.tools_offered));
        d.insert("toolCalls".into(), json!(self.tool_calls));
        d.insert("incomplete".into(), json!(self.incomplete));
        if let Some(f) = self.response_form {
            d.insert("responseForm".into(), json!(f));
        }
        if self.content_kept {
            d.insert("contentKept".into(), json!(true));
        }
        let calls = match self.tool_calls {
            1 => "1 tool call".to_string(),
            n => format!("{n} tool calls"),
        };
        let mut summary = format!(
            "{}, {calls}",
            if self.model.is_empty() {
                "model"
            } else {
                &self.model
            }
        );
        if self.incomplete {
            summary.push_str(", cut");
        }
        Event {
            id: self.id.clone(),
            at,
            chat_id: chat.to_string(),
            harness: harness.to_string(),
            source: Source::Tap,
            kind: "tap.request".into(),
            summary: clip(&summary, 200),
            detail: Value::Object(d),
            pid: None,
            approval_id: None,
        }
    }
}

/// `text` cut to at most `max` bytes on a character boundary.
pub fn clip(text: &str, max: usize) -> String {
    if text.len() <= max {
        return text.to_string();
    }
    let mut end = max;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    text[..end].to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// FP6-S1 probe (review of fix pass 6). Codex 0.163.0 builds the cell id
    /// from `wait`'s argument as given (`core/src/tools/code_mode/
    /// wait_handler.rs:126`, `CellId::new(args.cell_id)`, no trim), so a
    /// padded id names a different cell than the trimmed one. The tap must
    /// not record the padded id as the live cell's.
    #[test]
    fn fp6_s1_a_padded_wait_cell_id_is_not_taken_as_the_trimmed_cell() {
        let call = Call {
            call_id: "call_W".into(),
            tool: "wait".into(),
            args: ArgsText::Json(json!({"cell_id": " 3"})),
            incomplete: false,
            done_at: None,
        };
        let rec = CallRecord::new(Api::OpenAiResponses, "m", None, "codex", &call);
        assert_ne!(rec.cell_id.as_deref(), Some("3"), "{:?}", rec.cell_id);
    }

    #[test]
    fn canonical_json_sorts_keys_and_drops_spaces() {
        let v: Value =
            serde_json::from_str(r#"{ "b": [1, {"y": 2, "x": "é"}], "a": null }"#).unwrap();
        assert_eq!(canonical(&v), r#"{"a":null,"b":[1,{"x":"é","y":2}]}"#);
    }

    #[test]
    fn a_streamed_and_a_whole_argument_hash_alike() {
        let whole = ArgsText::Json(json!({"command": "ls -la src"}));
        let streamed = ArgsText::Text("{\"command\":  \"ls -la src\"}".into());
        assert_eq!(digest_args(&whole), digest_args(&streamed));
        let cut = ArgsText::Text("{\"command\": \"ls -".into());
        assert_eq!(
            digest_args(&cut).sha256,
            sha256_hex(b"{\"command\": \"ls -")
        );
    }

    #[test]
    fn paths_come_from_named_keys_and_patch_headers_only() {
        let a = ArgsText::Json(
            json!({"file_path": "/p/a.rs", "content": "path: /etc/passwd", "paths": ["/p/b", 3, "/p/a.rs"]}),
        );
        assert_eq!(paths_named(&a), vec!["/p/a.rs", "/p/b"]);
        let cmd = ArgsText::Json(json!({"command": "cat /etc/shadow"}));
        assert!(paths_named(&cmd).is_empty());
        let patch = ArgsText::Text(
            "*** Begin Patch\n*** Update File: src/a.rs\n@@\n-x\n+y\n*** Add File: src/b.rs\n+z\n*** Delete File: old.rs\n*** End Patch\n".into(),
        );
        assert_eq!(paths_named(&patch), vec!["src/a.rs", "src/b.rs", "old.rs"]);
        let not_a_patch = ArgsText::Text("*** Update File: x".into());
        assert!(paths_named(&not_a_patch).is_empty());
    }

    #[test]
    fn records_match_the_bases_fixtures() {
        let root = concat!(env!("CARGO_MANIFEST_DIR"), "/../../contracts/fixtures/tap/");
        let read = |f: &str| -> Value {
            serde_json::from_str(&std::fs::read_to_string(format!("{root}{f}")).unwrap()).unwrap()
        };
        // Anthropic: the call from the response, the result from the next request.
        let resp = read("anthropic.response.json");
        let block = &resp["content"][1];
        let call = Call {
            call_id: block["id"].as_str().unwrap().into(),
            tool: block["name"].as_str().unwrap().into(),
            args: ArgsText::Json(block["input"].clone()),
            incomplete: false,
            done_at: None,
        };
        let mut rec = CallRecord::new(
            Api::AnthropicMessages,
            "claude-fixture",
            None,
            "claude-code",
            &call,
        );
        let next = read("anthropic.next-request.json");
        let result = &next["messages"][2]["content"][0]["content"];
        rec.result = Some((digest_result(result), None));
        let got = serde_json::to_value(rec.event("chat-fixture", "claude-code", 1_793_000_000_000))
            .unwrap();
        assert_eq!(got, read("anthropic.expected.json")[0]);

        let resp = read("openai-responses.response.json");
        let item = &resp["output"][0];
        let call = Call {
            call_id: item["call_id"].as_str().unwrap().into(),
            tool: item["name"].as_str().unwrap().into(),
            args: ArgsText::Text(item["arguments"].as_str().unwrap().into()),
            incomplete: false,
            done_at: None,
        };
        let mut rec = CallRecord::new(Api::OpenAiResponses, "gpt-fixture", None, "codex", &call);
        let next = read("openai-responses.next-request.json");
        rec.result = Some((digest_result(&next["input"][0]["output"]), None));
        let got =
            serde_json::to_value(rec.event("chat-fixture", "codex", 1_793_000_000_000)).unwrap();
        assert_eq!(got, read("openai-responses.expected.json")[0]);
    }

    #[test]
    fn a_record_holds_no_argument_or_result_text() {
        let call = Call {
            call_id: "toolu_1".into(),
            tool: "Bash".into(),
            args: ArgsText::Json(json!({"command": "echo SECRET-ARG-VALUE"})),
            incomplete: false,
            done_at: None,
        };
        let mut rec = CallRecord::new(Api::AnthropicMessages, "m", None, "claude-code", &call);
        rec.result = Some((digest_result(&json!("SECRET-RESULT-VALUE")), Some(false)));
        let text = serde_json::to_string(&rec.event("c", "claude-code", 0)).unwrap();
        assert!(!text.contains("SECRET"), "{text}");
    }
}
