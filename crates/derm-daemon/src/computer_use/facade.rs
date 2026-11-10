//! The MCP server a chat's harness talks to for computer use (C3).
//!
//! derm answers the harness itself and keeps its own MCP session with the
//! chat's Cua runtime behind it, so the runtime can start, stop and restart
//! with a new manifest without the harness noticing.
//!
//! Since wave 5 (lane U) the harness sees one tool, `computer_use`, in
//! Hermes Agent's shape (`tool.rs`, `contracts/cu-tool.schema.json`). It
//! replaces lane K's surface, `request_app_access`, `computer_use_status`
//! and Cua's own tools: an app is asked for from inside the tool, when a
//! `capture` or `focus_app` names one the chat does not hold, and the
//! runtime's tools are called only by `tool.rs`, never by name from the
//! model.
//!
//! Every reply is built here from typed data. Text from the runtime is passed
//! through as MCP content and never parsed for instructions.

use std::time::Duration;

use serde_json::{json, Value};

pub use super::bridge_cli::OFF_TEXT;
use super::grants::Grant;
use super::tool;

/// The protocol versions this server speaks, newest first.
const PROTOCOL_VERSIONS: &[&str] = &["2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05"];
/// How long one `computer_use` call waits for a card. Short enough for
/// every harness's own tool timeout (Codex's default is 60 seconds); the
/// model calls again to keep waiting.
pub const ACCESS_WAIT: Duration = Duration::from_secs(45);

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccessRequest {
    /// What the model named: a bundle id or an app name, as given.
    pub app: String,
    pub reason: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AccessAnswer {
    Granted {
        bundle_id: String,
    },
    Denied,
    /// The card is still open after the wait.
    Pending,
    /// No card could be shown: the window is closed, or the request was bad.
    Refused(String),
}

/// How one runtime call ended (lane U). A call that timed out or lost its
/// transport is never sent again (`tool.rs`, rules case 120).
#[derive(Clone, Debug, PartialEq)]
pub enum CallOutcome {
    /// The runtime's MCP result.
    Done(Value),
    /// No answer in time: the call may still have taken effect.
    TimedOut,
    /// The runtime or the helper went away during the call.
    Lost(String),
    /// Refused before it reached the runtime, or the runtime refused it.
    Failed(String),
}

/// What the facade needs from the rest of derm.
pub trait Backend {
    /// The grants that hold for the chat now.
    fn grants(&self, chat: &str) -> Vec<Grant>;
    /// Shows the approval card and waits up to `wait` for the answer.
    fn request_access(&self, chat: &str, request: AccessRequest, wait: Duration) -> AccessAnswer;
    /// The runtime's tool list for the chat's current grants, starting or
    /// restarting the runtime as needed.
    fn runtime_tools(&self, chat: &str) -> Result<Vec<Value>, String>;
    /// One `tools/call` on the runtime; the result as the runtime sent it.
    fn runtime_call(&self, chat: &str, name: &str, arguments: Value) -> Result<Value, String>;
    /// Whether the chat's current turn is a plan turn. Then only look-only
    /// tools run, on every harness (security review S6).
    fn plan_turn(&self, _chat: &str) -> bool {
        false
    }
    /// Whether computer use is switched on for the chat. While off, the
    /// connection stays and offers no tools (Mac test 4.7).
    fn enabled(&self, _chat: &str) -> bool {
        true
    }
    /// One runtime call with how it ended (lane U). The default reads every
    /// error as a refusal; `Core` tells a timeout and a lost helper apart.
    fn call(&self, chat: &str, name: &str, arguments: Value) -> CallOutcome {
        match self.runtime_call(chat, name, arguments) {
            Ok(result) => CallOutcome::Done(result),
            Err(message) => CallOutcome::Failed(message),
        }
    }
    /// Ends the chat's runtime, so the next call starts a fresh one (after
    /// a call whose outcome is unknown).
    fn reset_runtime(&self, _chat: &str) {}
    /// Asks the person for a scope beyond an app grant (foreground input in
    /// one app), once per chat and scope. No asker: refused, never allowed.
    fn ask_scope(
        &self,
        _chat: &str,
        _scope: &str,
        _summary: &str,
        _wait: Duration,
    ) -> AccessAnswer {
        AccessAnswer::Refused("No one can be asked for that here.".into())
    }
    /// One `cu.action` record's detail, for the chat's log.
    fn record(&self, _chat: &str, _detail: Value) {}
}

/// One harness connection's MCP session.
pub struct Facade {
    chat: String,
    initialized: bool,
    /// The `computer_use` tool's sticky target and element tokens.
    cu: tool::State,
    /// The switch the last `tools/list` answered for, to know when to tell
    /// the harness the list changed. Grants no longer change the list: the
    /// one tool is offered whenever computer use is on.
    listed_for: Option<bool>,
}

impl Facade {
    pub fn new(chat: impl Into<String>) -> Self {
        Self {
            chat: chat.into(),
            initialized: false,
            cu: tool::State::default(),
            listed_for: None,
        }
    }

    /// A `notifications/tools/list_changed` when the switch differs from the
    /// one the harness last listed tools for.
    pub fn list_changed(&mut self, backend: &dyn Backend) -> Option<Value> {
        let listed = self.listed_for?;
        let now = backend.enabled(&self.chat);
        if now == listed {
            return None;
        }
        // Answered once: the next tools/list sets it again.
        self.listed_for = None;
        Some(json!({"jsonrpc": "2.0", "method": "notifications/tools/list_changed"}))
    }

    /// Handles one message from the harness. Returns the reply for a request,
    /// None for a notification or a response.
    pub fn handle(&mut self, backend: &dyn Backend, message: &Value) -> Option<Value> {
        let object = message.as_object()?;
        let method = object.get("method").and_then(Value::as_str);
        let id = object.get("id").cloned();
        let (Some(method), Some(id)) = (method, id) else {
            // A notification (initialized, cancelled) or a stray response.
            return None;
        };
        if !(id.is_string() || id.is_number()) {
            return Some(error(Value::Null, -32600, "Invalid request id"));
        }
        let params = object.get("params").cloned().unwrap_or(Value::Null);
        Some(match method {
            "initialize" => {
                self.initialized = true;
                result(id, initialize_result(&params))
            }
            "ping" => result(id, json!({})),
            "tools/list" if self.initialized => {
                let on = backend.enabled(&self.chat);
                let tools = if on {
                    vec![tool::definition()]
                } else {
                    Vec::new()
                };
                self.listed_for = Some(on);
                result(id, json!({ "tools": tools }))
            }
            "tools/call" if self.initialized && !backend.enabled(&self.chat) => {
                result(id, tool_error(OFF_TEXT))
            }
            "tools/call" if self.initialized => result(id, self.call(backend, &params)),
            "tools/list" | "tools/call" => error(id, -32002, "Server not initialized"),
            "resources/list" => result(id, json!({ "resources": [] })),
            "prompts/list" => result(id, json!({ "prompts": [] })),
            _ => error(id, -32601, "Method not found"),
        })
    }

    fn call(&mut self, backend: &dyn Backend, params: &Value) -> Value {
        let name = params.get("name").and_then(Value::as_str).unwrap_or("");
        let arguments = params
            .get("arguments")
            .cloned()
            .unwrap_or_else(|| json!({}));
        if name != tool::TOOL_NAME {
            return tool_error(&format!(
                "{} is not offered in derm's computer use; the one tool is computer_use.",
                printable(name, 64)
            ));
        }
        tool::handle(backend, &self.chat, &mut self.cu, &arguments)
    }
}

/// Tools that only look. Every other tool acts on an app.
const LOOK_ONLY: &[&str] = &[
    "list_apps",
    "list_windows",
    "get_window_state",
    "get_accessibility_tree",
    "verify_state",
    "parse_visual_regions",
    "get_screen_size",
    "get_cursor_position",
    "zoom",
    "get_session",
];

/// Whether a tool only looks at an app.
pub fn look_only(name: &str) -> bool {
    LOOK_ONLY.contains(&name)
}

fn initialize_result(params: &Value) -> Value {
    let asked = params
        .get("protocolVersion")
        .and_then(Value::as_str)
        .unwrap_or("");
    let version = PROTOCOL_VERSIONS
        .iter()
        .find(|known| **known == asked)
        .copied()
        .unwrap_or(PROTOCOL_VERSIONS[0]);
    json!({
        "protocolVersion": version,
        "capabilities": { "tools": { "listChanged": true } },
        "serverInfo": { "name": "derm-computer-use", "version": env!("CARGO_PKG_VERSION") },
        "instructions": "Computer use through derm: one tool, computer_use. Start with action='capture' and app=<the app's name>; the first time an app is named, the user is asked to approve it for this chat, and input works only in approved apps. Foreground input needs its own approval. derm, its helper and Cua's own app are never available, nor the whole screen. The user can stop computer use at any time."
    })
}

fn result(id: Value, result: Value) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "result": result})
}

fn error(id: Value, code: i64, message: &str) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "error": {"code": code, "message": message}})
}

fn tool_error(text: &str) -> Value {
    json!({"content": [{"type": "text", "text": text}], "isError": true})
}

/// At most `max` characters, with control characters other than a plain
/// space removed, so model text cannot draw lines on the card.
pub fn printable(text: &str, max: usize) -> String {
    text.chars()
        .map(|c| if c.is_whitespace() { ' ' } else { c })
        .filter(|c| !c.is_control() && !is_invisible(*c))
        .take(max)
        .collect()
}

fn is_invisible(c: char) -> bool {
    matches!(
        c,
        '\u{200B}'..='\u{200F}'
            | '\u{202A}'..='\u{202E}'
            | '\u{2060}'..='\u{2064}'
            | '\u{FEFF}'
            // FP10-S5: other Default_Ignorable_Code_Point characters a
            // card would draw as nothing.
            | '\u{00AD}'
            | '\u{034F}'
            | '\u{115F}'..='\u{1160}'
            | '\u{17B4}'..='\u{17B5}'
            | '\u{3164}'
            | '\u{FFA0}'
            | '\u{FE00}'..='\u{FE0F}'
            | '\u{E0000}'..='\u{E007F}'
            | '\u{E0100}'..='\u{E01EF}'
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    /// FP10-S5: tag characters and other ignorables are dropped from text a
    /// card or a record shows.
    #[test]
    fn fp10_s5_printable_drops_default_ignorables() {
        let shown = printable("cal\u{E0068}\u{E0069}c\u{AD}\u{FE0F}\u{3164}", 80);
        assert_eq!(shown, "calc");
    }

    struct Fake {
        grants: RefCell<Vec<Grant>>,
        answer: RefCell<AccessAnswer>,
        asked: RefCell<Vec<AccessRequest>>,
        calls: RefCell<Vec<(String, Value)>>,
        plan: RefCell<bool>,
        on: RefCell<bool>,
    }

    impl Fake {
        fn new() -> Self {
            Self {
                grants: RefCell::new(Vec::new()),
                answer: RefCell::new(AccessAnswer::Denied),
                asked: RefCell::new(Vec::new()),
                calls: RefCell::new(Vec::new()),
                plan: RefCell::new(false),
                on: RefCell::new(true),
            }
        }
        fn grant(&self, bundle: &str) {
            self.grants.borrow_mut().push(Grant {
                chat_id: "c1".into(),
                bundle_id: bundle.into(),
                app_name: Some("Calculator".into()),
                granted_at: 1,
                ended_at: None,
                approval_id: "a1".into(),
            });
        }
    }

    impl Backend for Fake {
        fn grants(&self, _chat: &str) -> Vec<Grant> {
            self.grants.borrow().clone()
        }
        fn request_access(
            &self,
            _chat: &str,
            request: AccessRequest,
            _wait: Duration,
        ) -> AccessAnswer {
            self.asked.borrow_mut().push(request);
            self.answer.borrow().clone()
        }
        fn runtime_tools(&self, _chat: &str) -> Result<Vec<Value>, String> {
            self.calls
                .borrow_mut()
                .push(("tools/list".into(), json!({})));
            Ok(Vec::new())
        }
        fn runtime_call(&self, _chat: &str, name: &str, arguments: Value) -> Result<Value, String> {
            self.calls.borrow_mut().push((name.into(), arguments));
            Ok(json!({"content": [{"type": "text", "text": "ok"}]}))
        }
        fn plan_turn(&self, _chat: &str) -> bool {
            *self.plan.borrow()
        }
        fn enabled(&self, _chat: &str) -> bool {
            *self.on.borrow()
        }
    }

    #[test]
    fn while_off_nothing_is_listed_and_every_call_is_refused() {
        let backend = Fake::new();
        backend.grant("com.apple.calculator");
        *backend.on.borrow_mut() = false;
        let mut facade = Facade::new("c1");
        init(&mut facade, &backend);
        let reply = facade
            .handle(
                &backend,
                &json!({"jsonrpc":"2.0","id":1,"method":"tools/list"}),
            )
            .unwrap();
        assert_eq!(reply["result"]["tools"], json!([]));
        for name in ["computer_use", "request_app_access", "click"] {
            let reply = facade
                .handle(&backend, &json!({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":name,"arguments":{"action":"capture","app":"com.apple.calculator"}}}))
                .unwrap();
            assert_eq!(reply["result"]["isError"], true, "{name}");
            assert_eq!(reply["result"]["content"][0]["text"], OFF_TEXT);
        }
        assert!(backend.calls.borrow().is_empty());
        assert!(backend.asked.borrow().is_empty());
    }

    #[test]
    fn every_switch_on_or_off_tells_the_harness() {
        let backend = Fake::new();
        let mut facade = Facade::new("c1");
        init(&mut facade, &backend);
        let list = json!({"jsonrpc":"2.0","id":1,"method":"tools/list"});
        facade.handle(&backend, &list);
        assert!(facade.list_changed(&backend).is_none());
        *backend.on.borrow_mut() = false;
        assert_eq!(
            facade.list_changed(&backend).unwrap()["method"],
            "notifications/tools/list_changed"
        );
        assert!(facade.list_changed(&backend).is_none(), "once per change");
        facade.handle(&backend, &list);
        *backend.on.borrow_mut() = true;
        assert!(facade.list_changed(&backend).is_some());
    }

    fn init(facade: &mut Facade, backend: &Fake) {
        let reply = facade
            .handle(
                backend,
                &json!({"jsonrpc":"2.0","id":0,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"t","version":"1"}}}),
            )
            .unwrap();
        assert_eq!(reply["result"]["protocolVersion"], "2025-06-18");
        assert_eq!(
            reply["result"]["capabilities"]["tools"]["listChanged"],
            true
        );
    }

    fn names(reply: &Value) -> Vec<String> {
        reply["result"]["tools"]
            .as_array()
            .unwrap()
            .iter()
            .map(|tool| tool["name"].as_str().unwrap().to_string())
            .collect()
    }

    #[test]
    fn the_one_tool_is_computer_use_in_the_contracts_shape_grant_or_not() {
        // Lane U: Hermes's single tool replaces lane K's request tool, status
        // tool and Cua's own tools; listing never starts a runtime.
        for granted in [false, true] {
            let backend = Fake::new();
            if granted {
                backend.grant("com.apple.calculator");
            }
            let mut facade = Facade::new("c1");
            init(&mut facade, &backend);
            let reply = facade
                .handle(
                    &backend,
                    &json!({"jsonrpc":"2.0","id":1,"method":"tools/list"}),
                )
                .unwrap();
            assert_eq!(names(&reply), vec!["computer_use"]);
            let tool = &reply["result"]["tools"][0];
            let contract: Value =
                serde_json::from_str(include_str!("../../../../contracts/cu-tool.schema.json"))
                    .unwrap();
            assert_eq!(tool["inputSchema"]["properties"], contract["properties"]);
            assert_eq!(tool["inputSchema"]["required"], json!(["action"]));
            assert_eq!(tool["inputSchema"]["additionalProperties"], false);
            assert_eq!(tool["description"], contract["x-derm-tool"]["description"]);
            assert_eq!(tool["annotations"]["destructiveHint"], true);
            assert!(backend.calls.borrow().is_empty(), "listing ran nothing");
        }
    }

    #[test]
    fn a_call_to_any_other_name_never_reaches_the_runtime() {
        let backend = Fake::new();
        backend.grant("com.apple.calculator");
        let mut facade = Facade::new("c1");
        init(&mut facade, &backend);
        for name in [
            "request_app_access",
            "computer_use_status",
            "click",
            "get_window_state",
            "start_recording",
            "get_desktop_state",
            "run_script",
            "check_for_update",
            "Computer_Use",
            "",
        ] {
            let reply = facade
                .handle(
                    &backend,
                    &json!({"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":name,"arguments":{"action":"capture","x":1}}}),
                )
                .unwrap();
            assert_eq!(reply["result"]["isError"], true, "{name}");
        }
        assert!(backend.calls.borrow().is_empty());
        assert!(backend.asked.borrow().is_empty());
    }

    #[test]
    fn a_grant_does_not_change_the_list_only_the_switch_does() {
        let backend = Fake::new();
        let mut facade = Facade::new("c1");
        init(&mut facade, &backend);
        assert!(
            facade.list_changed(&backend).is_none(),
            "nothing listed yet"
        );
        facade.handle(
            &backend,
            &json!({"jsonrpc":"2.0","id":1,"method":"tools/list"}),
        );
        backend.grant("com.apple.calculator");
        assert!(facade.list_changed(&backend).is_none());
        *backend.on.borrow_mut() = false;
        assert!(facade.list_changed(&backend).is_some());
    }

    #[test]
    fn protocol_basics() {
        let backend = Fake::new();
        let mut facade = Facade::new("c1");
        let reply = facade
            .handle(
                &backend,
                &json!({"jsonrpc":"2.0","id":1,"method":"tools/list"}),
            )
            .unwrap();
        assert_eq!(reply["error"]["code"], -32002, "list before initialize");
        let reply = facade
            .handle(&backend, &json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"1999-01-01"}}))
            .unwrap();
        assert_eq!(reply["result"]["protocolVersion"], PROTOCOL_VERSIONS[0]);
        assert!(facade
            .handle(
                &backend,
                &json!({"jsonrpc":"2.0","method":"notifications/initialized"})
            )
            .is_none());
        let reply = facade
            .handle(&backend, &json!({"jsonrpc":"2.0","id":"p","method":"ping"}))
            .unwrap();
        assert_eq!(reply["result"], json!({}));
        let reply = facade
            .handle(
                &backend,
                &json!({"jsonrpc":"2.0","id":2,"method":"sampling/createMessage"}),
            )
            .unwrap();
        assert_eq!(reply["error"]["code"], -32601);
        let reply = facade
            .handle(
                &backend,
                &json!({"jsonrpc":"2.0","id":{"x":1},"method":"ping"}),
            )
            .unwrap();
        assert_eq!(reply["error"]["code"], -32600);
    }
}
