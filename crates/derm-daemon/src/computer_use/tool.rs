//! The one `computer_use` tool derm serves to every harness (wave 5 lane U;
//! `plans/toolkit_universal_plan.md`, lane U; note AR section 3).
//!
//! The model-facing shape is Hermes Agent's (`tools/computer_use/schema.py`
//! at tag v2026.9.24, MIT, Copyright (c) 2025 Nous Research;
//! `contracts/cu-tool.schema.json`, `NOTICE`), and so are these rules, read
//! in Hermes's source at that tag (`plans/parallel/tk_lane_U.md`, Research):
//!
//! - **Hard blocks first** (`tool.py:39-71`): destructive system shortcuts
//!   and dangerous shell text typed through `type` are refused before any
//!   card or call.
//! - **A sticky target** (`cua_backend_capture.py:291-317`): `capture` and
//!   `focus_app` choose `(pid, window_id)`; every input action goes there;
//!   an `app=` on an input action is a guard, not a target, and a clear
//!   mismatch is refused. A capture that finds no window fails; it never
//!   falls back to the frontmost window.
//! - **Background first, one rung at a time** (`tool.py:526-544`): each
//!   result carries a verdict from cua-driver's `effect`, `verified` and
//!   `escalation`; foreground is its own approval.
//! - **At most once** (`cua_backend_session.py:70-86, 483-505`): a call that
//!   times out or loses its transport is never sent again. The result says
//!   the outcome is unknown, the chat's runtime is ended so the next call
//!   starts a fresh one, and only reads are replayed after a lost transport
//!   (rules case 120).
//!
//! What derm does differently (rules cases 71, 83, 119 to 121):
//!
//! - **Approval is a person, through the daemon.** An app is granted on the
//!   card lane K built (`facade.rs`, `core.rs`, `service.rs`: the daemon's
//!   `approve`, no answer is no). The grant covers background input in that
//!   app for the chat's run. Foreground delivery, `bring_to_front` and
//!   `raise_window` take a second card per app. Nothing defaults to allow;
//!   Hermes's gate is not copied.
//! - **Mode is `bounded`, always.** Nothing here can lift cua-driver's mode;
//!   a full-access chat gets the same cards (case 83).
//! - **One input at a time on the screen.** An input action takes a lock
//!   shared by every chat (cua-driver admits one input at a time, note W
//!   section 3.1); a chat that cannot take it in `SCREEN_WAIT` is told the
//!   screen is busy and nothing is sent (case 121). Each chat's runtime is
//!   bounded to its own apps, so its input never lands in another chat's.
//! - **No whole screen.** `app='screen'` and `app='desktop'` are refused:
//!   the manifest never grants the display (lane K's `manifest.rs`).
//! - **Every action is recorded** (`cu.action`, `contracts/events.md`
//!   section 5): the action, the app, the delivery, the verdict, the
//!   screenshot's SHA-256 and the grant. Never the screenshot, the typed
//!   text or the keys.

use std::collections::HashMap;
use std::sync::{Arc, Condvar, Mutex, OnceLock};
use std::time::{Duration, Instant};

use base64::Engine as _;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

use super::facade::{printable, AccessAnswer, AccessRequest, Backend, CallOutcome, ACCESS_WAIT};
use super::grants::Grant;
use super::manifest::tool_allowed;

pub const TOOL_NAME: &str = "computer_use";

/// The contract, compiled in so the tool and its schema cannot drift.
const SCHEMA: &str = include_str!("../../../../contracts/cu-tool.schema.json");

/// How long an input action waits for another chat's input to finish.
pub const SCREEN_WAIT: Duration = Duration::from_secs(20);
/// The longest `wait` (Hermes: "max 30").
const MAX_WAIT_SECONDS: f64 = 30.0;
/// Elements put in one result, and characters of each label (Hermes's
/// `_DEFAULT_MAX_ELEMENTS` and `_MAX_ELEMENT_LABEL_CHARS`, `tool.py:546-552`).
const MAX_ELEMENTS: usize = 100;
const MAX_LABEL: usize = 120;
/// Scroll ticks are clamped as Hermes does (`cua_backend_input.py`).
const MAX_SCROLL: i64 = 50;
/// The longest text `type` takes, and the longest key combo.
const MAX_TEXT: usize = 10_000;
const MAX_KEYS: usize = 64;
/// The longest app name taken from the model.
const MAX_APP: usize = 255;

/// The tool's definition for `tools/list`: Hermes's name, description and
/// input schema from the contract, with derm's annotations.
pub fn definition() -> Value {
    let schema: Value = serde_json::from_str(SCHEMA).unwrap_or(Value::Null);
    let meta = schema.get("x-derm-tool").cloned().unwrap_or(Value::Null);
    let mut input = Map::new();
    for key in ["type", "properties", "required", "additionalProperties"] {
        if let Some(value) = schema.get(key) {
            input.insert(key.to_string(), value.clone());
        }
    }
    json!({
        "name": meta.get("name").cloned().unwrap_or_else(|| json!(TOOL_NAME)),
        "description": meta.get("description").cloned().unwrap_or_else(|| json!("")),
        "inputSchema": Value::Object(input),
        "annotations": { "readOnlyHint": false, "destructiveHint": true, "openWorldHint": false }
    })
}

/// Actions that only look. Everything else asks for an app grant first and
/// is refused in a plan turn (case 36).
pub fn look_only(action: &str) -> bool {
    matches!(action, "capture" | "wait" | "list_apps" | "list_windows")
}

fn is_input(action: &str) -> bool {
    matches!(
        action,
        "click"
            | "double_click"
            | "right_click"
            | "middle_click"
            | "drag"
            | "scroll"
            | "type"
            | "key"
            | "set_value"
    )
}

/// What a capture or `focus_app` chose. Input goes here.
#[derive(Clone, Debug, PartialEq)]
pub struct Target {
    pub pid: i64,
    pub window_id: i64,
    pub app: String,
    /// The grant (bundle id or derm's id) the target's app is held under.
    pub grant: Option<String>,
}

/// One harness connection's computer-use state (Hermes's per-session
/// backend state): the sticky target and the last capture's element tokens.
pub struct State {
    target: Option<Target>,
    tokens: HashMap<i64, String>,
    /// The screen's input lock (`Screen::global` outside tests).
    screen: Arc<Screen>,
    /// How long input waits for another chat's input (`SCREEN_WAIT`).
    screen_wait: Duration,
}

impl Default for State {
    fn default() -> Self {
        State {
            target: None,
            tokens: HashMap::new(),
            screen: Screen::global(),
            screen_wait: SCREEN_WAIT,
        }
    }
}

impl State {
    pub fn target(&self) -> Option<&Target> {
        self.target.as_ref()
    }

    /// A state with its own screen lock and wait, for tests.
    #[cfg(test)]
    pub fn with_screen(screen: Arc<Screen>, wait: Duration) -> Self {
        State {
            target: None,
            tokens: HashMap::new(),
            screen,
            screen_wait: wait,
        }
    }
}

/// How a call ended, for the record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    Ok,
    Denied,
    Blocked,
    TimeoutOutcomeUnknown,
    Error,
}

impl Verdict {
    fn as_str(self) -> &'static str {
        match self {
            Verdict::Ok => "ok",
            Verdict::Denied => "denied",
            Verdict::Blocked => "blocked",
            Verdict::TimeoutOutcomeUnknown => "timeout_outcome_unknown",
            Verdict::Error => "error",
        }
    }
}

/// One result to the model and what the record says about it.
struct Answer {
    result: Value,
    verdict: Verdict,
    app: Option<String>,
    /// The app a refused grant was for, as its SHA-256 and length: the name
    /// is the model's text, which a record never keeps (FP10-S1).
    app_asked: Option<Box<(String, usize)>>,
    grant: Option<String>,
    effect: Option<bool>,
    verified: Option<bool>,
    screenshot: Option<String>,
}

impl Answer {
    fn new(result: Value, verdict: Verdict) -> Self {
        Answer {
            result,
            verdict,
            app: None,
            app_asked: None,
            grant: None,
            effect: None,
            verified: None,
            screenshot: None,
        }
    }

    fn refusal(code: &str, message: &str, verdict: Verdict) -> Self {
        Answer::new(
            error_result(json!({"ok": false, "code": code, "error": message})),
            verdict,
        )
    }

    fn at(mut self, target: Option<&Target>) -> Self {
        if let Some(t) = target {
            self.app.get_or_insert_with(|| t.app.clone());
            if self.grant.is_none() {
                self.grant = t.grant.clone();
            }
        }
        self
    }
}

/// Handles one `tools/call` of `computer_use`. Always returns an MCP tool
/// result; the record goes to the backend.
pub fn handle(backend: &dyn Backend, chat: &str, state: &mut State, arguments: &Value) -> Value {
    let args = match validate(arguments) {
        Ok(args) => args,
        Err(message) => {
            let action = arguments
                .get("action")
                .and_then(Value::as_str)
                .filter(|a| ACTIONS.contains(a));
            let answer = Answer::refusal("bad_arguments", &message, Verdict::Error);
            if let Some(action) = action {
                record(backend, chat, action, &args_delivery(arguments), &answer);
            }
            return answer.result;
        }
    };
    let action = str_arg(&args, "action").unwrap_or_default().to_string();
    let answer = run(backend, chat, state, &action, &args);
    record(backend, chat, &action, &args_delivery(&args), &answer);
    answer.result
}

fn run(backend: &dyn Backend, chat: &str, state: &mut State, action: &str, args: &Value) -> Answer {
    if let Some(blocked) = reject_unsafe(action, args) {
        return Answer::refusal("blocked", &blocked, Verdict::Blocked).at(state.target());
    }
    if backend.plan_turn(chat) && !look_only(action) {
        return Answer::refusal(
            "plan_turn",
            "This is a plan turn: only capture, list_apps, list_windows and wait run. Describe the action in the plan instead.",
            Verdict::Denied,
        );
    }
    match action {
        "wait" => {
            let seconds = args
                .get("seconds")
                .and_then(Value::as_f64)
                .unwrap_or(1.0)
                .clamp(0.0, MAX_WAIT_SECONDS);
            std::thread::sleep(Duration::from_secs_f64(seconds));
            Answer::new(
                text_json(json!({"ok": true, "action": "wait", "seconds": seconds})),
                Verdict::Ok,
            )
        }
        "list_apps" | "list_windows" => listing(backend, chat, action),
        "capture" => capture(backend, chat, state, args),
        "focus_app" => focus_app(backend, chat, state, args),
        _ if is_input(action) => input(backend, chat, state, action, args),
        _ => Answer::refusal("unknown_action", "Unknown action.", Verdict::Error),
    }
}

// --- Validation -----------------------------------------------------------

const ACTIONS: &[&str] = &[
    "capture",
    "click",
    "double_click",
    "right_click",
    "middle_click",
    "drag",
    "scroll",
    "type",
    "key",
    "set_value",
    "wait",
    "list_apps",
    "list_windows",
    "focus_app",
];

/// The schema's checks, by hand: the known keys only
/// (`additionalProperties: false`), each of its type and enum.
pub fn validate(arguments: &Value) -> Result<Value, String> {
    let schema: Value =
        serde_json::from_str(SCHEMA).map_err(|_| "derm's computer_use schema is unreadable")?;
    let properties = schema
        .get("properties")
        .and_then(Value::as_object)
        .ok_or("derm's computer_use schema has no properties")?;
    let object = arguments
        .as_object()
        .ok_or("computer_use takes an object of arguments.")?;
    let action = object
        .get("action")
        .and_then(Value::as_str)
        .ok_or("computer_use needs `action`.")?;
    if !ACTIONS.contains(&action) {
        let hint = match action {
            "hotkey" | "press_key" | "keypress" | "key_combo" | "shortcut" => {
                " Did you mean `key`?"
            }
            "type_text" | "input_text" => " Did you mean `type`?",
            "screenshot" | "get_window_state" => " Did you mean `capture`?",
            "left_click" | "mouse_click" => " Did you mean `click`?",
            _ => "",
        };
        return Err(format!("Unknown action {:?}.{hint}", printable(action, 40)));
    }
    for (key, value) in object {
        let Some(spec) = properties.get(key) else {
            return Err(format!(
                "computer_use takes no argument {:?}.",
                printable(key, 40)
            ));
        };
        check_value(key, spec, value)?;
    }
    Ok(arguments.clone())
}

fn check_value(key: &str, spec: &Value, value: &Value) -> Result<(), String> {
    let bad = || Err(format!("`{key}` has the wrong type."));
    match spec.get("type").and_then(Value::as_str) {
        Some("string") => {
            let Some(text) = value.as_str() else {
                return bad();
            };
            if let Some(allowed) = spec.get("enum").and_then(Value::as_array) {
                if !allowed.iter().any(|a| a.as_str() == Some(text)) {
                    return Err(format!("`{key}` is not one of its allowed values."));
                }
            }
            Ok(())
        }
        Some("integer") => {
            if value.is_i64() || value.is_u64() {
                Ok(())
            } else {
                bad()
            }
        }
        Some("number") => {
            if value.is_number() {
                Ok(())
            } else {
                bad()
            }
        }
        Some("boolean") => {
            if value.is_boolean() {
                Ok(())
            } else {
                bad()
            }
        }
        Some("array") => {
            let Some(items) = value.as_array() else {
                return bad();
            };
            let min = spec.get("minItems").and_then(Value::as_u64).unwrap_or(0) as usize;
            let max = spec.get("maxItems").and_then(Value::as_u64).unwrap_or(16) as usize;
            if items.len() < min || items.len() > max {
                return Err(format!("`{key}` has the wrong number of items."));
            }
            let item_spec = spec.get("items").cloned().unwrap_or(Value::Null);
            items
                .iter()
                .try_for_each(|item| check_value(key, &item_spec, item))
        }
        _ => bad(),
    }
}

fn str_arg<'a>(args: &'a Value, key: &str) -> Option<&'a str> {
    args.get(key).and_then(Value::as_str)
}

fn int_arg(args: &Value, key: &str) -> Option<i64> {
    args.get(key).and_then(Value::as_i64)
}

fn pair_arg(args: &Value, key: &str) -> Option<(i64, i64)> {
    let items = args.get(key)?.as_array()?;
    Some((items.first()?.as_i64()?, items.get(1)?.as_i64()?))
}

fn foreground(args: &Value) -> bool {
    str_arg(args, "delivery_mode") == Some("foreground")
}

fn args_delivery(args: &Value) -> Option<&'static str> {
    let action = str_arg(args, "action").unwrap_or("");
    if is_input(action) {
        Some(if foreground(args) {
            "foreground"
        } else {
            "background"
        })
    } else if action == "focus_app" && args.get("raise_window") == Some(&Value::Bool(true)) {
        Some("foreground")
    } else {
        None
    }
}

// --- Hard blocks (Hermes `tool.py:39-71`) -------------------------------------

/// Canonical name of one key, Hermes's aliases (`tool.py:46-47`).
fn canon_key(part: &str) -> String {
    let lower = part.trim().to_lowercase();
    match lower.as_str() {
        "command" | "⌘" => "cmd".into(),
        "control" => "ctrl".into(),
        "alt" | "⌥" => "option".into(),
        "windows" | "super" | "meta" => "win".into(),
        _ => lower,
    }
}

/// The keys of a combo, split on `+` and `-` (cua-driver takes both).
pub fn key_set(keys: &str) -> Vec<String> {
    let mut out: Vec<String> = keys
        .split(['+', '-'])
        .map(canon_key)
        .filter(|k| !k.is_empty())
        .collect();
    out.sort();
    out.dedup();
    out
}

const BLOCKED_COMBOS: &[&[&str]] = &[
    &["cmd", "shift", "backspace"],
    &["cmd", "option", "backspace"],
    &["cmd", "ctrl", "q"],
    &["cmd", "shift", "q"],
    &["cmd", "option", "shift", "q"],
    &["win", "l"],
    &["ctrl", "option", "delete"],
    &["ctrl", "option", "del"],
    &["option", "f4"],
];

/// Hermes's blocked shell text (`tool.py:48-50`), written without a regex
/// engine: each is the same match on the lower-cased text with runs of
/// whitespace read as one space.
fn blocked_text(text: &str) -> Option<&'static str> {
    let lower: String = text.to_lowercase();
    let squashed = squash(&lower);
    // curl ... | bash, curl ... | sh, wget ... | bash
    for (fetch, shell, name) in [
        ("curl", "bash", "curl ... | bash"),
        ("curl", "sh", "curl ... | sh"),
        ("wget", "bash", "wget ... | bash"),
    ] {
        if piped_into(&squashed, fetch, shell) {
            return Some(name);
        }
    }
    if words(&squashed)
        .windows(2)
        .any(|w| w[0] == "sudo" && w[1] == "rm")
        && sudo_rm_flag(&squashed)
    {
        return Some("sudo rm -r/-f");
    }
    if squashed.trim_end().ends_with("rm -rf /") && word_starts(&squashed, "rm -rf /") {
        return Some("rm -rf /");
    }
    let bare: String = lower.chars().filter(|c| !c.is_whitespace()).collect();
    if bare.contains(":(){:|:&}") {
        return Some("fork bomb");
    }
    None
}

fn squash(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn words(text: &str) -> Vec<&str> {
    text.split(' ').collect()
}

fn word_starts(text: &str, phrase: &str) -> bool {
    text.match_indices(phrase).any(|(i, _)| {
        i == 0
            || !text[..i]
                .chars()
                .last()
                .is_some_and(|c| c.is_alphanumeric() || c == '_')
    })
}

/// `<fetch> [^|]* | <shell>` as a word: Hermes's `curl\s+[^|]*\|\s*bash`.
fn piped_into(text: &str, fetch: &str, shell: &str) -> bool {
    text.match_indices(fetch).any(|(i, _)| {
        let after = &text[i + fetch.len()..];
        if !after.starts_with(' ') {
            return false;
        }
        let Some(pipe) = after.find('|') else {
            return false;
        };
        after[pipe + 1..].trim_start().starts_with(shell)
    })
}

/// `\bsudo\s+rm\s+-[rf]`.
fn sudo_rm_flag(text: &str) -> bool {
    text.match_indices("sudo rm -").any(|(i, phrase)| {
        let start_ok = i == 0 || !text[..i].chars().last().is_some_and(char::is_alphanumeric);
        start_ok
            && text[i + phrase.len()..]
                .chars()
                .next()
                .is_some_and(|c| c == 'r' || c == 'f')
    })
}

/// The refusal for blocked input, before any card (Hermes: "Runs BEFORE the
/// approval prompt").
pub fn reject_unsafe(action: &str, args: &Value) -> Option<String> {
    if action == "type" {
        if let Some(name) = blocked_text(str_arg(args, "text").unwrap_or("")) {
            return Some(format!(
                "Blocked: {name} cannot be typed through computer_use."
            ));
        }
    }
    if action == "key" {
        let keys = key_set(str_arg(args, "keys").unwrap_or(""));
        if let Some(combo) = BLOCKED_COMBOS
            .iter()
            .find(|combo| combo.iter().all(|k| keys.iter().any(|have| have == k)))
        {
            // Keys are matched by their macOS names; the refusal names
            // them as this system's keyboard does (BW5-20).
            let named: Vec<&str> = combo
                .iter()
                .map(|k| match *k {
                    "option" if !cfg!(target_os = "macos") => "alt",
                    k => k,
                })
                .collect();
            return Some(format!(
                "Blocked: {} is a destructive system shortcut.",
                named.join("+")
            ));
        }
    }
    if args.get("bring_to_front") == Some(&Value::Bool(true)) && !foreground(args) {
        return Some("bring_to_front needs delivery_mode='foreground'.".into());
    }
    None
}

// --- Grants -----------------------------------------------------------------

const WHOLE_SCREEN: &[&str] = &["screen", "fullscreen", "full_screen", "desktop"];

/// The grant that covers `app` (its bundle id or name), if the chat holds one.
pub fn grant_for<'a>(grants: &'a [Grant], app: &str) -> Option<&'a Grant> {
    let app = app.trim();
    grants.iter().find(|g| {
        g.bundle_id.eq_ignore_ascii_case(app)
            || g.app_name
                .as_deref()
                .is_some_and(|name| name.eq_ignore_ascii_case(app))
    })
}

/// The grant for `app`, asking the person for one when the chat holds none.
fn ensure_grant(
    backend: &dyn Backend,
    chat: &str,
    app: &str,
    action: &str,
) -> Result<String, Answer> {
    if WHOLE_SCREEN.contains(&app.trim().to_ascii_lowercase().as_str()) {
        return Err(Answer::refusal(
            "whole_screen_refused",
            "derm grants computer use one app at a time; the whole screen and the desktop are never granted. Capture an app by name.",
            Verdict::Denied,
        ));
    }
    if let Some(grant) = grant_for(&backend.grants(chat), app) {
        return Ok(grant.bundle_id.clone());
    }
    let request = AccessRequest {
        app: app.trim().to_string(),
        reason: format!("computer_use {action}"),
    };
    match backend.request_access(chat, request, ACCESS_WAIT) {
        AccessAnswer::Granted { bundle_id } => Ok(bundle_id),
        AccessAnswer::Pending => Err(Answer::refusal(
            "approval_pending",
            "The user has not answered the card for this app yet. Call the same action again to keep waiting.",
            Verdict::Denied,
        )),
        AccessAnswer::Denied => Err(Answer::refusal(
            "app_denied",
            "The user did not approve this app for this chat. Do not ask for it again in this turn.",
            Verdict::Denied,
        )),
        AccessAnswer::Refused(message) => Err(Answer::refusal(
            "app_refused",
            &printable(&message, 400),
            Verdict::Denied,
        )),
    }
}

/// The second card, for a visible focus change in a granted app.
fn ensure_foreground(backend: &dyn Backend, chat: &str, target: &Target) -> Result<(), Answer> {
    let grant = target.grant.clone().unwrap_or_else(|| target.app.clone());
    let summary = format!(
        "Let this chat bring {} to the front and give it focus (foreground input) until the chat ends.",
        printable(&target.app, 80)
    );
    match backend.ask_scope(chat, &format!("foreground:{grant}"), &summary, ACCESS_WAIT) {
        AccessAnswer::Granted { .. } => Ok(()),
        AccessAnswer::Pending => Err(Answer::refusal(
            "approval_pending",
            "The user has not answered the foreground card yet. Call again to keep waiting, or stay in background delivery.",
            Verdict::Denied,
        )),
        AccessAnswer::Denied => Err(Answer::refusal(
            "foreground_denied",
            "The user did not allow foreground input in this app. Stay in background delivery.",
            Verdict::Denied,
        )),
        AccessAnswer::Refused(message) => Err(Answer::refusal(
            "foreground_refused",
            &printable(&message, 400),
            Verdict::Denied,
        )),
    }
}

// --- Calls to the runtime ---------------------------------------------------

/// Reads that can be sent again after a lost transport (Hermes's
/// `_TRANSPORT_REPLAY_SAFE_TOOLS`, `cua_backend_session.py:179-181`).
const REPLAY_SAFE: &[&str] = &[
    "get_cursor_position",
    "get_displays",
    "get_screen_size",
    "get_window_state",
    "list_apps",
    "list_windows",
];

/// A runtime call's flattened result (Hermes's `_extract_tool_result`).
#[derive(Debug, Default)]
struct Flat {
    data: Value,
    images: Vec<(String, Option<String>)>,
    structured: Value,
    is_error: bool,
}

fn flatten(result: &Value) -> Flat {
    let mut texts = Vec::new();
    let mut images = Vec::new();
    for part in result
        .get("content")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        match part.get("type").and_then(Value::as_str) {
            Some("text") => {
                if let Some(t) = part.get("text").and_then(Value::as_str) {
                    texts.push(t.to_string());
                }
            }
            Some("image") => {
                if let Some(d) = part.get("data").and_then(Value::as_str) {
                    let mime = part
                        .get("mimeType")
                        .and_then(Value::as_str)
                        .map(str::to_string);
                    images.push((d.to_string(), mime));
                }
            }
            _ => {}
        }
    }
    let text = texts.join("\n");
    let data = serde_json::from_str::<Value>(text.trim())
        .ok()
        .filter(|v| v.is_object() || v.is_array())
        .unwrap_or(Value::String(text));
    let structured = result
        .get("structuredContent")
        .cloned()
        .unwrap_or(Value::Null);
    if images.is_empty() {
        let b64 = structured
            .get("screenshot_png_b64")
            .or_else(|| structured.get("png_b64"))
            .and_then(Value::as_str);
        if let Some(b64) = b64 {
            let mime = structured
                .get("screenshot_mime_type")
                .or_else(|| structured.get("mime_type"))
                .and_then(Value::as_str)
                .map(str::to_string);
            images.push((b64.to_string(), mime));
        }
    }
    Flat {
        data,
        images,
        structured,
        is_error: result.get("isError") == Some(&Value::Bool(true)),
    }
}

/// A call whose outcome is not known: never sent again (case 120).
fn outcome_unknown(backend: &dyn Backend, chat: &str, name: &str, code: &str) -> Answer {
    // Hermes recreates a timed-out session before the next call; derm ends
    // the chat's runtime now, and the next call starts a fresh one.
    backend.reset_runtime(chat);
    let message = format!(
        "{name} did not finish: the outcome is unknown and it may still have taken effect. derm did not send it again. Capture fresh state before deciding whether to act again."
    );
    let verdict = if code == "timeout_outcome_unknown" {
        Verdict::TimeoutOutcomeUnknown
    } else {
        Verdict::Error
    };
    Answer::new(
        error_result(json!({
            "ok": false, "code": code, "error": message, "next_step": "fresh_state",
            "verdict": {"decision": "verify_fresh_state"}
        })),
        verdict,
    )
}

/// One runtime call. Reads are replayed once after a lost transport;
/// nothing is replayed after a timeout.
fn call(backend: &dyn Backend, chat: &str, name: &str, args: Value) -> Result<Flat, Answer> {
    // Only the tools lane K's manifest allows; the manifest bounds the
    // runtime the same way (`manifest.rs`).
    if !tool_allowed(name) {
        return Err(Answer::refusal(
            "not_allowed",
            "That runtime tool is not allowed in derm's computer use.",
            Verdict::Error,
        ));
    }
    let mut outcome = backend.call(chat, name, args.clone());
    if matches!(outcome, CallOutcome::Lost(_)) && REPLAY_SAFE.contains(&name) {
        outcome = backend.call(chat, name, args);
    }
    match outcome {
        CallOutcome::Done(result) if result.is_object() => Ok(flatten(&result)),
        CallOutcome::Done(_) => Err(Answer::refusal(
            "malformed_result",
            "The computer-use runtime sent a malformed result.",
            Verdict::Error,
        )),
        CallOutcome::TimedOut => Err(outcome_unknown(
            backend,
            chat,
            name,
            "timeout_outcome_unknown",
        )),
        CallOutcome::Lost(_) => Err(outcome_unknown(
            backend,
            chat,
            name,
            "transport_outcome_unknown",
        )),
        CallOutcome::Failed(message) => Err(Answer::refusal(
            "runtime_error",
            &printable(&message, 500),
            Verdict::Error,
        )),
    }
}

// --- The screen lock (case 121) -----------------------------------------

/// The screen's input lock. One per daemon (`Screen::global`); a test makes
/// its own so parallel tests never share it.
pub struct Screen {
    busy: Mutex<Option<String>>,
    freed: Condvar,
}

impl Screen {
    pub fn new() -> Self {
        Screen {
            busy: Mutex::new(None),
            freed: Condvar::new(),
        }
    }

    /// The daemon's one screen, shared by every chat's connection.
    pub fn global() -> Arc<Screen> {
        static SCREEN: OnceLock<Arc<Screen>> = OnceLock::new();
        SCREEN.get_or_init(|| Arc::new(Screen::new())).clone()
    }
}

impl Default for Screen {
    fn default() -> Self {
        Screen::new()
    }
}

/// Held while one chat's input is on the screen.
pub struct ScreenTurn {
    screen: Arc<Screen>,
}

impl Drop for ScreenTurn {
    fn drop(&mut self) {
        let mut busy = match self.screen.busy.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        *busy = None;
        self.screen.freed.notify_all();
    }
}

/// Takes `screen` for `chat`, waiting up to `wait` for another chat's input
/// to end. None: the screen stayed busy.
pub fn take_screen(screen: &Arc<Screen>, chat: &str, wait: Duration) -> Option<ScreenTurn> {
    let deadline = Instant::now() + wait;
    let mut busy = match screen.busy.lock() {
        Ok(g) => g,
        Err(p) => p.into_inner(),
    };
    while busy.is_some() {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return None;
        }
        busy = match screen.freed.wait_timeout(busy, left) {
            Ok((g, _)) => g,
            Err(p) => p.into_inner().0,
        };
    }
    *busy = Some(chat.to_string());
    Some(ScreenTurn {
        screen: screen.clone(),
    })
}

// --- Actions --------------------------------------------------------------

fn listing(backend: &dyn Backend, chat: &str, action: &str) -> Answer {
    if backend.grants(chat).is_empty() {
        return Answer::refusal(
            "no_app_granted",
            "No app is approved for this chat yet. Call capture or focus_app with app=<name> to ask the user for one.",
            Verdict::Denied,
        );
    }
    let (tool, args, key) = if action == "list_apps" {
        ("list_apps", json!({}), "apps")
    } else {
        ("list_windows", json!({"on_screen_only": true}), "windows")
    };
    match call(backend, chat, tool, args) {
        Ok(flat) if !flat.is_error => {
            let items = if key == "apps" {
                apps_of(&flat)
            } else {
                windows_of(&flat)
                    .into_iter()
                    .map(|w| {
                        json!({"app_name": w.app, "pid": w.pid, "window_id": w.window_id, "title": w.title})
                    })
                    .collect()
            };
            Answer::new(
                text_json(json!({key: items, "count": items.len()})),
                Verdict::Ok,
            )
        }
        Ok(flat) => Answer::refusal("runtime_error", &flat_message(&flat), Verdict::Error),
        Err(answer) => answer,
    }
}

#[derive(Clone, Debug)]
struct Window {
    app: String,
    pid: i64,
    window_id: i64,
    title: String,
    z: i64,
    off_screen: bool,
    bundle: Option<String>,
}

fn windows_of(flat: &Flat) -> Vec<Window> {
    let list = [
        flat.structured.get("windows"),
        flat.data.get("windows"),
        flat.data.get("_legacy_windows"),
    ]
    .into_iter()
    .flatten()
    .find_map(|v| v.as_array().filter(|a| !a.is_empty()))
    .cloned()
    .unwrap_or_default();
    let mut out: Vec<Window> = list
        .iter()
        .filter_map(|w| {
            let pid = w.get("pid").and_then(Value::as_i64).filter(|p| *p > 0)?;
            let window_id = w
                .get("window_id")
                .or_else(|| w.get("windowId"))
                .and_then(Value::as_i64)
                .filter(|id| *id > 0)?;
            let text = |k: &str| {
                w.get(k)
                    .and_then(Value::as_str)
                    .map(|s| printable(s, 200))
                    .unwrap_or_default()
            };
            Some(Window {
                app: {
                    let name = text("app_name");
                    if name.is_empty() {
                        text("app")
                    } else {
                        name
                    }
                },
                pid,
                window_id,
                title: text("title"),
                z: w.get("z_index").and_then(Value::as_i64).unwrap_or(0),
                off_screen: w.get("off_screen") == Some(&Value::Bool(true))
                    || w.get("on_screen") == Some(&Value::Bool(false)),
                bundle: w
                    .get("bundle_id")
                    .or_else(|| w.get("bundleId"))
                    .and_then(Value::as_str)
                    .map(|s| printable(s, 255)),
            })
        })
        .collect();
    out.sort_by_key(|w| std::cmp::Reverse(w.z));
    out
}

fn apps_of(flat: &Flat) -> Vec<Value> {
    [
        flat.structured.get("apps"),
        Some(&flat.data),
        flat.data.get("apps"),
    ]
    .into_iter()
    .flatten()
    .find_map(|v| v.as_array().filter(|a| !a.is_empty()))
    .cloned()
    .unwrap_or_default()
    .into_iter()
    .filter_map(|app| {
        let name = app
            .get("name")
            .or_else(|| app.get("app_name"))
            .and_then(Value::as_str)
            .map(|s| printable(s, 200))?;
        Some(json!({
            "name": name,
            "pid": app.get("pid").and_then(Value::as_i64),
            "bundle_id": app.get("bundle_id").or_else(|| app.get("bundleId")).and_then(Value::as_str).map(|s| printable(s, 255)),
        }))
    })
    .collect()
}

/// Windows of `app`: exact name, exact bundle id, then a substring of the
/// name (Hermes's tiers, `cua_backend_capture.py:165-197`, without the
/// title tier: a title is the app's own text).
fn match_app(windows: &[Window], app: &str) -> Vec<Window> {
    let want = app.trim().to_lowercase();
    if want.is_empty() {
        return Vec::new();
    }
    let exact = |w: &Window| w.app.trim().to_lowercase() == want;
    let bundle = |w: &Window| {
        w.bundle
            .as_deref()
            .is_some_and(|b| b.to_lowercase() == want)
    };
    let part = |w: &Window| !w.app.is_empty() && w.app.to_lowercase().contains(&want);
    for tier in [&exact as &dyn Fn(&Window) -> bool, &bundle, &part] {
        let hit: Vec<Window> = windows.iter().filter(|w| tier(w)).cloned().collect();
        if !hit.is_empty() {
            return hit;
        }
    }
    Vec::new()
}

/// The window to target among those the runtime lists, for a grant the
/// chat holds: on screen first, frontmost first.
fn choose(windows: &[Window]) -> Option<Window> {
    windows
        .iter()
        .find(|w| !w.off_screen)
        .or_else(|| windows.first())
        .cloned()
}

fn grant_of_window(grants: &[Grant], window: &Window) -> Option<String> {
    window
        .bundle
        .as_deref()
        .and_then(|b| grant_for(grants, b))
        .or_else(|| grant_for(grants, &window.app))
        .map(|g| g.bundle_id.clone())
}

/// Resolves the capture or focus target, asking for the app's grant first.
fn resolve_target(
    backend: &dyn Backend,
    chat: &str,
    state: &State,
    args: &Value,
    action: &str,
) -> Result<Target, Answer> {
    let app = str_arg(args, "app").map(|a| printable(a, MAX_APP));
    let app = app.as_deref().map(str::trim).filter(|a| !a.is_empty());
    let pid = int_arg(args, "pid").filter(|p| *p > 0);
    let window_id = int_arg(args, "window_id").filter(|w| *w > 0);
    if pid.is_some() != window_id.is_some() {
        return Err(Answer::refusal(
            "target_needs_pid_and_window",
            "An exact target needs both pid and window_id.",
            Verdict::Error,
        ));
    }
    let wanted_grant = match app {
        // A refusal still says which app it was for in `cu.action` (box test
        // w5 retest 2, BW5R2-3: a refused capture was recorded with only
        // `app: null`), by the name's SHA-256 and length: the name is the
        // model's text, and a record keeps no content (FP10-S1).
        Some(app) => Some(
            ensure_grant(backend, chat, app, action).map_err(|mut refused| {
                refused.app_asked.get_or_insert_with(|| {
                    let hash = Sha256::digest(app.as_bytes())
                        .iter()
                        .map(|b| format!("{b:02x}"))
                        .collect();
                    Box::new((hash, app.chars().count()))
                });
                refused
            })?,
        ),
        None => None,
    };
    let grants = backend.grants(chat);
    if grants.is_empty() {
        return Err(Answer::refusal(
            "no_app_granted",
            "No app is approved for this chat yet. Call capture or focus_app with app=<name> to ask the user for one.",
            Verdict::Denied,
        ));
    }
    let flat = match call(
        backend,
        chat,
        "list_windows",
        json!({"on_screen_only": true}),
    ) {
        Ok(flat) if !flat.is_error => flat,
        Ok(flat) => {
            return Err(Answer::refusal(
                "runtime_error",
                &flat_message(&flat),
                Verdict::Error,
            ))
        }
        Err(answer) => return Err(answer),
    };
    let windows = windows_of(&flat);
    let picked = match (pid, window_id, app) {
        (Some(pid), Some(window_id), _) => windows
            .iter()
            .find(|w| w.pid == pid && w.window_id == window_id)
            .cloned(),
        (_, _, Some(app)) => {
            let mut hits = match_app(&windows, app);
            if hits.is_empty() {
                // A localized or differently spelled name: the granted
                // app's own name or id.
                if let Some(g) = wanted_grant.as_deref().and_then(|g| grant_for(&grants, g)) {
                    hits = match_app(&windows, &g.bundle_id);
                    if hits.is_empty() {
                        if let Some(name) = &g.app_name {
                            hits = match_app(&windows, name);
                        }
                    }
                }
            }
            choose(&hits)
        }
        _ => {
            // No app named: the sticky target if it is still listed, else
            // the frontmost window of an app the chat holds.
            let sticky = state.target().and_then(|t| {
                windows
                    .iter()
                    .find(|w| w.pid == t.pid && w.window_id == t.window_id)
            });
            sticky.cloned().or_else(|| {
                choose(
                    &windows
                        .iter()
                        .filter(|w| grant_of_window(&grants, w).is_some())
                        .cloned()
                        .collect::<Vec<_>>(),
                )
            })
        }
    };
    let Some(window) = picked else {
        return Err(Answer::refusal(
            "no_window",
            &match app {
                Some(app) => format!(
                    "No on-screen window of {} was found. Open it, or check its name with list_windows.",
                    printable(app, 80)
                ),
                None => "No on-screen window of an approved app was found. Name the app with app=.".to_string(),
            },
            Verdict::Error,
        ));
    };
    let grant = grant_of_window(&grants, &window).or(wanted_grant);
    Ok(Target {
        pid: window.pid,
        window_id: window.window_id,
        app: if window.app.is_empty() {
            app.unwrap_or("").to_string()
        } else {
            window.app.clone()
        },
        grant,
    })
}

fn capture(backend: &dyn Backend, chat: &str, state: &mut State, args: &Value) -> Answer {
    let target = match resolve_target(backend, chat, state, args, "capture") {
        Ok(t) => t,
        Err(answer) => return answer,
    };
    state.target = Some(target.clone());
    state.tokens.clear();
    let mode = str_arg(args, "mode").unwrap_or("som");
    capture_target(backend, chat, state, &target, mode).at(Some(&target))
}

fn capture_target(
    backend: &dyn Backend,
    chat: &str,
    state: &mut State,
    target: &Target,
    mode: &str,
) -> Answer {
    let mut gws = json!({"pid": target.pid, "window_id": target.window_id});
    if mode != "vision" {
        gws["max_elements"] = json!(MAX_ELEMENTS * 4);
    }
    let flat = match call(backend, chat, "get_window_state", gws) {
        Ok(flat) if !flat.is_error => flat,
        Ok(flat) => return Answer::refusal("runtime_error", &flat_message(&flat), Verdict::Error),
        Err(answer) => return answer,
    };
    let elements = if mode == "vision" {
        Vec::new()
    } else {
        elements_of(&flat)
    };
    state.tokens = elements
        .iter()
        .filter_map(|e| e.token.clone().map(|t| (e.index, t)))
        .collect();
    let title = flat
        .structured
        .get("window_title")
        .or_else(|| flat.structured.get("title"))
        .and_then(Value::as_str)
        .map(|t| printable(t, 200))
        .unwrap_or_default();
    let image = flat.images.first().filter(|_| mode != "ax").cloned();
    let digest = image.as_ref().and_then(|(b64, _)| sha256_b64(b64));
    let shown: Vec<Value> = elements
        .iter()
        .take(MAX_ELEMENTS)
        .map(|e| {
            json!({
                "index": e.index, "role": e.role, "label": truncate(&e.label, MAX_LABEL),
                "bounds": e.bounds,
            })
        })
        .collect();
    let mut summary = format!(
        "capture mode={mode} app={} window={:?}\n{} interactable element(s)",
        target.app,
        title,
        elements.len()
    );
    for e in elements.iter().take(40) {
        summary.push_str(&format!(
            "\n  #{} {} {:?}",
            e.index,
            e.role,
            truncate(&e.label.replace('\n', " "), 60)
        ));
    }
    if elements.len() > 40 {
        summary.push_str(&format!("\n  ... +{} more", elements.len() - 40));
    }
    let payload = json!({
        "ok": true, "action": "capture", "mode": mode, "app": target.app,
        "pid": target.pid, "window_id": target.window_id, "window_title": title,
        "elements": shown, "total_elements": elements.len(), "summary": summary,
    });
    let mut content = vec![json!({"type": "text", "text": payload.to_string()})];
    if let Some((b64, mime)) = image {
        content.push(json!({
            "type": "image",
            "data": b64,
            "mimeType": mime.unwrap_or_else(|| sniff_mime(&b64)),
        }));
    }
    let mut answer = Answer::new(json!({"content": content}), Verdict::Ok);
    answer.screenshot = digest;
    answer
}

#[derive(Debug)]
struct Element {
    index: i64,
    role: String,
    label: String,
    bounds: Option<[i64; 4]>,
    token: Option<String>,
}

fn elements_of(flat: &Flat) -> Vec<Element> {
    flat.structured
        .get("elements")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|raw| {
            let index = raw.get("element_index").and_then(Value::as_i64)?;
            let text = |k: &str| {
                raw.get(k)
                    .and_then(Value::as_str)
                    .map(|s| printable(s, 2_000))
                    .unwrap_or_default()
            };
            let frame = raw.get("frame");
            let bounds = frame.and_then(|f| {
                let n = |k: &str| f.get(k).and_then(Value::as_f64).map(|v| v as i64);
                let b = [n("x")?, n("y")?, n("w")?, n("h")?];
                (b != [0, 0, 0, 0]).then_some(b)
            });
            Some(Element {
                index,
                role: text("role"),
                label: text("label"),
                bounds,
                token: raw
                    .get("element_token")
                    .and_then(Value::as_str)
                    .filter(|t| !t.is_empty() && t.len() <= 256)
                    .map(str::to_string),
            })
        })
        .collect()
}

fn focus_app(backend: &dyn Backend, chat: &str, state: &mut State, args: &Value) -> Answer {
    if str_arg(args, "app").is_none_or(|a| a.trim().is_empty()) {
        return Answer::refusal("focus_needs_app", "focus_app needs `app`.", Verdict::Error);
    }
    let target = match resolve_target(backend, chat, state, args, "focus_app") {
        Ok(t) => t,
        Err(answer) => return answer,
    };
    state.target = Some(target.clone());
    state.tokens.clear();
    if args.get("raise_window") != Some(&Value::Bool(true)) {
        return Answer::new(
            text_json(json!({
                "ok": true, "action": "focus_app",
                "message": format!("Targeted {} (pid {}, window {}) without raising it.", target.app, target.pid, target.window_id),
                "verdict": {"decision": "done"}
            })),
            Verdict::Ok,
        )
        .at(Some(&target));
    }
    if let Err(answer) = ensure_foreground(backend, chat, &target) {
        return answer.at(Some(&target));
    }
    let Some(_turn) = take_screen(&state.screen, chat, state.screen_wait) else {
        return screen_busy().at(Some(&target));
    };
    action_answer(
        backend,
        chat,
        "bring_to_front",
        json!({"pid": target.pid, "window_id": target.window_id}),
        "focus_app",
    )
    .at(Some(&target))
}

fn screen_busy() -> Answer {
    Answer::refusal(
        "screen_busy",
        "Another chat's input is on the screen. Nothing was sent; try again shortly.",
        Verdict::Denied,
    )
}

fn input(
    backend: &dyn Backend,
    chat: &str,
    state: &mut State,
    action: &str,
    args: &Value,
) -> Answer {
    let Some(target) = state.target.clone() else {
        return Answer::refusal(
            "no_target",
            "No target window: call capture (or focus_app) with app= first.",
            Verdict::Error,
        );
    };
    // The app= guard (Hermes `tool.py:509-517`): input goes to the sticky
    // target; a clearly different app is refused, never redirected.
    if let Some(wanted) = str_arg(args, "app")
        .map(str::trim)
        .filter(|a| !a.is_empty())
    {
        let current = target.app.to_lowercase();
        let wanted_l = wanted.to_lowercase();
        let same = current.is_empty()
            || current.contains(&wanted_l)
            || wanted_l.contains(&current)
            || target
                .grant
                .as_deref()
                .is_some_and(|g| g.eq_ignore_ascii_case(wanted));
        if !same {
            return Answer::refusal(
                "input_target_mismatch",
                &format!(
                    "{action} would go to the current target {:?}, not {:?}. Call capture(app={:?}) or focus_app first.",
                    target.app,
                    printable(wanted, 80),
                    printable(wanted, 80)
                ),
                Verdict::Error,
            )
            .at(Some(&target));
        }
    }
    // The target's app must still be held: a revoked grant stops input.
    let grants = backend.grants(chat);
    let held = target
        .grant
        .as_deref()
        .is_some_and(|g| grants.iter().any(|h| h.bundle_id.eq_ignore_ascii_case(g)));
    if !held {
        state.target = None;
        return Answer::refusal(
            "app_not_granted",
            "This app is no longer approved for this chat. Capture with app= to ask again.",
            Verdict::Denied,
        )
        .at(Some(&target));
    }
    let tool_args = match input_args(action, args, &target, &state.tokens) {
        Ok(a) => a,
        Err(message) => {
            return Answer::refusal("bad_arguments", &message, Verdict::Error).at(Some(&target))
        }
    };
    let fg = foreground(args);
    if fg {
        if let Err(answer) = ensure_foreground(backend, chat, &target) {
            return answer.at(Some(&target));
        }
    }
    let answer = {
        let Some(_turn) = take_screen(&state.screen, chat, state.screen_wait) else {
            return screen_busy().at(Some(&target));
        };
        if fg && args.get("bring_to_front") == Some(&Value::Bool(true)) {
            let raised = action_answer(
                backend,
                chat,
                "bring_to_front",
                json!({"pid": target.pid, "window_id": target.window_id}),
                action,
            );
            if raised.verdict != Verdict::Ok {
                return raised.at(Some(&target));
            }
        }
        let (tool, call_args) = tool_args;
        action_answer(backend, chat, tool, call_args, action)
    };
    let mut answer = answer.at(Some(&target));
    if answer.verdict == Verdict::Ok && args.get("capture_after") == Some(&Value::Bool(true)) {
        let after = capture_target(backend, chat, state, &target, "som");
        if let Some(parts) = after.result.get("content").and_then(Value::as_array) {
            let mut content = answer
                .result
                .get("content")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default();
            content.extend(parts.iter().cloned());
            answer.result = json!({"content": content});
            answer.screenshot = after.screenshot;
        }
    }
    answer
}

/// The cua-driver tool and arguments for one input action (Hermes's
/// `cua_backend_input.py`).
fn input_args(
    action: &str,
    args: &Value,
    target: &Target,
    tokens: &HashMap<i64, String>,
) -> Result<(&'static str, Value), String> {
    let mut out = json!({"pid": target.pid, "window_id": target.window_id});
    let element = |out: &mut Value, key: &str, index: i64| {
        out[key] = json!(index);
        if let Some(token) = tokens.get(&index) {
            out["element_token"] = json!(token);
        }
    };
    if foreground(args) {
        out["delivery_mode"] = json!("foreground");
    }
    if let Some(mods) = args.get("modifiers").and_then(Value::as_array) {
        if !mods.is_empty()
            && matches!(
                action,
                "click" | "double_click" | "right_click" | "middle_click"
            )
        {
            out["modifier"] = Value::Array(mods.clone());
        }
    }
    let tool = match action {
        "click" | "double_click" | "right_click" | "middle_click" => {
            let button = match action {
                "right_click" => "right",
                "middle_click" => "middle",
                _ => str_arg(args, "button").unwrap_or("left"),
            };
            out["button"] = json!(button);
            if let Some(index) = int_arg(args, "element") {
                element(&mut out, "element_index", index);
            } else if let Some((x, y)) = pair_arg(args, "coordinate") {
                out["x"] = json!(x);
                out["y"] = json!(y);
            } else {
                return Err(format!("{action} needs element= or coordinate=."));
            }
            if action == "double_click" {
                "double_click"
            } else {
                "click"
            }
        }
        "drag" => {
            match (
                int_arg(args, "from_element"),
                int_arg(args, "to_element"),
                pair_arg(args, "from_coordinate"),
                pair_arg(args, "to_coordinate"),
            ) {
                (Some(from), Some(to), _, _) => {
                    out["from_element"] = json!(from);
                    out["to_element"] = json!(to);
                }
                (_, _, Some((fx, fy)), Some((tx, ty))) => {
                    out["from_x"] = json!(fx);
                    out["from_y"] = json!(fy);
                    out["to_x"] = json!(tx);
                    out["to_y"] = json!(ty);
                }
                _ => return Err(
                    "drag needs from_element and to_element, or from_coordinate and to_coordinate."
                        .into(),
                ),
            }
            if let Some(button) = str_arg(args, "button") {
                out["button"] = json!(button);
            }
            "drag"
        }
        "scroll" => {
            out["direction"] = json!(str_arg(args, "direction").unwrap_or("down"));
            out["amount"] = json!(int_arg(args, "amount").unwrap_or(3).clamp(1, MAX_SCROLL));
            if let Some(index) = int_arg(args, "element") {
                element(&mut out, "element_index", index);
            } else if let Some((x, y)) = pair_arg(args, "coordinate") {
                out["x"] = json!(x);
                out["y"] = json!(y);
            }
            "scroll"
        }
        "type" => {
            let text = str_arg(args, "text").unwrap_or("");
            if text.is_empty() {
                return Err("type needs `text`.".into());
            }
            if text.chars().count() > MAX_TEXT {
                return Err(format!("type takes at most {MAX_TEXT} characters at once."));
            }
            out["text"] = json!(text);
            "type_text"
        }
        "key" => {
            let keys = str_arg(args, "keys").unwrap_or("");
            if keys.is_empty() || keys.len() > MAX_KEYS {
                return Err("key needs `keys`, e.g. 'cmd+s' or 'return'.".into());
            }
            let (key, mods) = parse_combo(keys);
            let Some(key) = key else {
                return Err(format!(
                    "Could not read a key from {:?}.",
                    printable(keys, 64)
                ));
            };
            if mods.is_empty() {
                out["key"] = json!(key);
                "press_key"
            } else {
                let mut all = mods;
                all.push(key);
                out["keys"] = json!(all);
                "hotkey"
            }
        }
        "set_value" => {
            let Some(index) = int_arg(args, "element") else {
                return Err("set_value needs element= (an element index).".into());
            };
            let Some(value) = args.get("value").and_then(Value::as_str) else {
                return Err("set_value needs `value`.".into());
            };
            element(&mut out, "element_index", index);
            out["value"] = json!(value);
            "set_value"
        }
        _ => return Err("Unknown input action.".into()),
    };
    Ok((tool, out))
}

/// `'cmd+s'` into its key and modifiers; the last non-modifier wins
/// (Hermes's `_parse_key_combo`, `cua_backend_parse.py:133-146`).
pub fn parse_combo(keys: &str) -> (Option<String>, Vec<String>) {
    let mut mods = Vec::new();
    let mut key = None;
    for part in keys
        .split(['+', '-'])
        .map(str::trim)
        .filter(|p| !p.is_empty())
    {
        let lower = part.to_lowercase();
        let named = match lower.as_str() {
            "command" => "cmd".to_string(),
            "alt" => "option".to_string(),
            "control" => "ctrl".to_string(),
            other => other.to_string(),
        };
        if matches!(
            named.as_str(),
            "cmd" | "shift" | "option" | "ctrl" | "fn" | "win" | "super" | "meta" | "windows"
        ) {
            mods.push(named);
        } else {
            key = Some(lower);
        }
    }
    (key, mods)
}

/// One mutating runtime call and its verdict.
fn action_answer(
    backend: &dyn Backend,
    chat: &str,
    tool: &str,
    args: Value,
    action: &str,
) -> Answer {
    let foreground_asked = args.get("delivery_mode").and_then(Value::as_str) == Some("foreground");
    let flat = match call(backend, chat, tool, args) {
        Ok(flat) => flat,
        Err(answer) => return answer,
    };
    let sc = flat.structured.as_object().cloned().unwrap_or_default();
    let field = |k: &str| sc.get(k).or_else(|| flat.data.get(k)).cloned();
    let ok = !flat.is_error;
    let effect = field("effect").and_then(|v| v.as_str().map(str::to_string));
    let verified = field("verified").and_then(|v| v.as_bool());
    let code = field("code")
        .or_else(|| field("reason_code"))
        .and_then(|v| v.as_str().map(|s| printable(s, 80)));
    let escalation = field("escalation").filter(Value::is_object);
    let verdict = classify(
        ok,
        effect.as_deref(),
        verified,
        code.as_deref(),
        escalation.as_ref(),
    );
    let mut payload = json!({"ok": ok, "action": action});
    let message = flat_message(&flat);
    if !message.is_empty() {
        payload["message"] = json!(truncate(&message, 500));
    }
    for (key, value) in [
        ("effect", effect.clone().map(Value::String)),
        ("verified", verified.map(Value::Bool)),
        ("code", code.map(Value::String)),
        ("escalation", escalation),
        ("path", field("path").filter(Value::is_string)),
    ] {
        if let Some(value) = value {
            payload[key] = value;
        }
    }
    if foreground_asked {
        payload["delivery_mode"] = json!("foreground");
    }
    payload["verdict"] = verdict;
    let mut answer = Answer::new(
        if ok {
            text_json(payload)
        } else {
            error_result(payload)
        },
        if ok { Verdict::Ok } else { Verdict::Error },
    );
    answer.effect = match effect.as_deref() {
        Some("confirmed") => Some(true),
        Some("suspected_noop") => Some(false),
        _ => None,
    };
    answer.verified = verified;
    answer
}

/// Hermes's ladder (`tool.py:526-544`): the next step from the evidence.
pub fn classify(
    ok: bool,
    effect: Option<&str>,
    verified: Option<bool>,
    code: Option<&str>,
    escalation: Option<&Value>,
) -> Value {
    if effect == Some("confirmed") || verified == Some(true) {
        return json!({"decision": "done"});
    }
    if effect == Some("unverifiable") {
        return json!({"decision": "verify_fresh_state", "hint": "Input was delivered but not confirmed. Capture again and check BEFORE any retry; do not repeat the input on an escalation alone."});
    }
    if effect == Some("suspected_noop") || !ok || code.is_some() {
        let mut v = json!({"decision": "escalate", "hint": "The input likely did not land. Climb one rung following `recommended`: 'px' means re-issue by coordinate; 'foreground' (or a failed pixel click) means re-issue with delivery_mode='foreground', which needs its own approval."});
        if let Some(rec) = escalation
            .and_then(|e| e.get("recommended"))
            .filter(|r| r.is_string())
        {
            v["recommended"] = rec.clone();
        }
        return v;
    }
    json!({"decision": "verify_fresh_state", "hint": "Sent, but the effect is unproven. Capture again and confirm before continuing."})
}

// --- Results and records ---------------------------------------------------

fn text_json(payload: Value) -> Value {
    json!({"content": [{"type": "text", "text": payload.to_string()}]})
}

fn error_result(payload: Value) -> Value {
    json!({"content": [{"type": "text", "text": payload.to_string()}], "isError": true})
}

fn flat_message(flat: &Flat) -> String {
    let from = |v: &Value| v.get("message").and_then(Value::as_str).map(str::to_string);
    let text = from(&flat.structured)
        .or_else(|| from(&flat.data))
        .or_else(|| flat.data.as_str().map(str::to_string))
        .unwrap_or_default();
    printable(&text, 500)
}

fn truncate(text: &str, max: usize) -> String {
    text.chars().take(max).collect()
}

fn sniff_mime(b64: &str) -> String {
    if b64.starts_with("/9j/") {
        "image/jpeg".into()
    } else {
        "image/png".into()
    }
}

/// SHA-256 of a screenshot's bytes, lower-case hex.
pub fn sha256_b64(b64: &str) -> Option<String> {
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(b64.trim())
        .ok()?;
    Some(
        Sha256::digest(&bytes)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect(),
    )
}

/// The `cu.action` record (`contracts/wave5-records.schema.json`,
/// `cuAction`). Nothing the model typed, no key and no image.
fn record(
    backend: &dyn Backend,
    chat: &str,
    action: &str,
    delivery: &Option<&str>,
    answer: &Answer,
) {
    let detail = json!({
        "trust": "daemon",
        "action": action,
        "app": answer.app.as_deref().map(|a| truncate(a, 4096)),
        "appAskedSha256": answer.app_asked.as_ref().map(|a| &a.0),
        "appAskedChars": answer.app_asked.as_ref().map(|a| a.1),
        "delivery": delivery,
        "verdict": answer.verdict.as_str(),
        "effect": answer.effect,
        "verified": answer.verified,
        "screenshotSha256": answer.screenshot,
        "grant": answer.grant.as_deref().map(|g| truncate(g, 128)),
        "contentKept": false,
    });
    backend.record(chat, detail);
}

#[cfg(test)]
#[path = "tool_tests.rs"]
mod tests;
