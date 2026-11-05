//! Case 94's fold, for a local upstream only.
//!
//! Claude Code 2.1.311 puts `role: "system"` entries inside `messages`
//! (the measurement session; Claude Code's gateway guide also names "`role:
//! "system"` entries appended mid-conversation", V), and llama.cpp passes
//! them to a model template that refuses them (Qwen3.8's: HTTP 500). For an
//! upstream the user marked as their own local server, the tap moves each
//! such entry's text to the end of the top-level `system`, in order. A
//! hosted upstream gets the body byte for byte: the guide says to "inspect
//! without modifying", since a rewritten body breaks header and body pairs.

use serde_json::{json, Value};

/// Folds `body` in place; true when it changed.
pub fn fold_system_messages(body: &mut Value) -> bool {
    let Some(messages) = body.get_mut("messages").and_then(Value::as_array_mut) else {
        return false;
    };
    let mut moved: Vec<Value> = Vec::new();
    messages.retain(|m| {
        if m.get("role").and_then(Value::as_str) != Some("system") {
            return true;
        }
        match m.get("content") {
            Some(Value::String(s)) => moved.push(json!({"type": "text", "text": s})),
            Some(Value::Array(blocks)) => {
                for b in blocks {
                    if let Some(t) = b.get("text").and_then(Value::as_str) {
                        moved.push(json!({"type": "text", "text": t}));
                    }
                }
            }
            _ => {}
        }
        false
    });
    if moved.is_empty() {
        return false;
    }
    let system = match body.get_mut("system").map(Value::take) {
        Some(Value::String(s)) if !s.is_empty() => vec![json!({"type": "text", "text": s})],
        Some(Value::Array(blocks)) => blocks,
        _ => Vec::new(),
    };
    let mut all = system;
    all.extend(moved);
    body["system"] = Value::Array(all);
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn system_entries_move_to_the_end_of_the_system_prompt() {
        let mut body = json!({
            "system": [{"type": "text", "text": "base", "cache_control": {"type": "ephemeral"}}],
            "messages": [
                {"role": "user", "content": "hi"},
                {"role": "system", "content": "note one"},
                {"role": "assistant", "content": "ok"},
                {"role": "system", "content": [{"type": "text", "text": "note two"}]}
            ]
        });
        assert!(fold_system_messages(&mut body));
        assert_eq!(body["messages"].as_array().unwrap().len(), 2);
        let texts: Vec<&str> = body["system"].as_array().unwrap().iter().map(|b| b["text"].as_str().unwrap()).collect();
        assert_eq!(texts, vec!["base", "note one", "note two"]);
        assert_eq!(body["system"][0]["cache_control"]["type"], "ephemeral");
    }

    #[test]
    fn a_body_with_no_system_entry_is_untouched() {
        let mut body = json!({"system": "s", "messages": [{"role": "user", "content": "hi"}]});
        let before = body.clone();
        assert!(!fold_system_messages(&mut body));
        assert_eq!(body, before);
        let mut string_system = json!({"system": "s", "messages": [{"role": "system", "content": "x"}]});
        assert!(fold_system_messages(&mut string_system));
        assert_eq!(string_system["system"], json!([{"type":"text","text":"s"},{"type":"text","text":"x"}]));
    }
}
