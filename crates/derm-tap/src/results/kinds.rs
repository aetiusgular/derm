//! Which tools bring content an attacker may control into a chat
//! (`contracts/policy.md` section 9, "What taints a chat"): one list for the
//! gate (`derm-cli`'s `gate/taint/`) and the tap ([`super::observe`]).
//!
//! A name is the gate's normalized one (`derm_core::policy::normalize_tool_name_for`:
//! lowercase, `server/tool` for an MCP tool). The reading follows OpenMoat
//! 0.19.0's `UntrustedKind` (`openmoat-core` `src/engine/taint.rs`, MIT OR
//! Apache-2.0; prior art, no code copied): a fetch or a web search, an MCP
//! tool's result, and a tool the gate does not know. derm has no way yet to
//! mark an MCP server trusted (the policy's `servers` list only names
//! servers), so every MCP result counts, but a browser's own bookkeeping
//! tools (OpenMoat's `METADATA_TOOLS`, Claude in Chrome's tab and window
//! lists), whose result is the browser's state, not a page.

/// Tools that fetch a page or search the web, across the agents derm gates:
/// Claude Code (`WebFetch`, `WebSearch`), Gemini CLI 0.68.0 (`web_fetch`,
/// `google_web_search`: `@google/gemini-cli-core@0.68.0`
/// `dist/src/tools/definitions/base-declarations.js`, E0's read), Codex
/// (`web_search`, `web.run`), Antigravity (`read_url_content`), and the
/// generic names other agents use.
pub const FETCH_TOOLS: &[&str] = &[
    "webfetch",
    "websearch",
    "web_fetch",
    "web_search",
    "google_web_search",
    "web_run",
    "web.run",
    "fetch",
    "read_url_content",
    "search_web",
    "browse",
    "browser",
];

/// Claude Code's own MCP resource tools: what they return is a server's.
const MCP_RESOURCE_TOOLS: &[&str] = &["listmcpresourcestool", "readmcpresourcetool"];

/// The browser's bookkeeping, not a page (OpenMoat 0.19.0 `src/taint.rs`
/// `METADATA_TOOLS`), in the gate's normalized form.
const METADATA_TOOLS: &[&str] = &[
    "claude_in_chrome/list_connected_browsers",
    "claude_in_chrome/resize_window",
    "claude_in_chrome/select_browser",
    "claude_in_chrome/shortcuts_list",
    "claude_in_chrome/switch_browser",
    "claude_in_chrome/tabs_close_mcp",
    "claude_in_chrome/tabs_context_mcp",
    "claude_in_chrome/tabs_create_mcp",
];

/// Tools that work on the chat's own machine and bring nothing in from
/// outside: the shells (`derm_core::policy::SHELL_TOOLS`), the file tools,
/// planning and asking. Claude Code 2.1.322's names (the recorded hook
/// inputs, `contracts/fixtures/hook-w6/claude-code-2.1.322.json`, and its
/// tool list), Codex 0.167.2's (`apply_patch`, `update_plan`, `view_image`,
/// Code Mode's `exec` and `wait`, `request_user_input`), Gemini CLI 0.68.0's,
/// Copilot CLI's and Antigravity's (MoatBench 0.19.0's host models, E0).
pub const LOCAL_TOOLS: &[&str] = &[
    // files
    "read",
    "write",
    "edit",
    "multiedit",
    "notebookedit",
    "notebookread",
    "glob",
    "grep",
    "ls",
    "read_file",
    "read_many_files",
    "write_file",
    "replace",
    "search_file_content",
    "list_directory",
    "view",
    "view_file",
    "create",
    "edit_file",
    "write_to_file",
    "replace_file_content",
    "str_replace_editor",
    "apply_patch",
    "patch",
    "view_image",
    // planning, asking, the agent's own state
    "todowrite",
    "todoread",
    "task",
    "agent",
    "exitplanmode",
    "enterplanmode",
    "bashoutput",
    "killshell",
    "killbash",
    "update_plan",
    "request_user_input",
    "request_user_input_async",
    "askuserquestion",
    "skill",
    "slashcommand",
    "save_memory",
    "write_stdin",
    "exec",
    "wait",
    "sleep",
];

/// Why a tool's result is untrusted, or `None` when it is local.
pub fn untrusted(normalized: &str) -> Option<&'static str> {
    if METADATA_TOOLS.contains(&normalized) {
        return None;
    }
    if normalized.contains('/') || MCP_RESOURCE_TOOLS.contains(&normalized) {
        return Some("mcp");
    }
    if FETCH_TOOLS.contains(&normalized) {
        return Some("web");
    }
    if derm_core::policy::SHELL_TOOLS.contains(&normalized) || LOCAL_TOOLS.contains(&normalized) {
        return None;
    }
    Some("unknown-tool")
}

#[cfg(test)]
mod tests {
    use super::untrusted;

    #[test]
    fn fetches_searches_mcp_and_unknown_tools_are_untrusted() {
        assert_eq!(untrusted("webfetch"), Some("web"));
        assert_eq!(untrusted("google_web_search"), Some("web"));
        assert_eq!(untrusted("playwright/browser_navigate"), Some("mcp"));
        assert_eq!(untrusted("readmcpresourcetool"), Some("mcp"));
        assert_eq!(untrusted("someones_new_tool"), Some("unknown-tool"));
        for local in [
            "bash",
            "read",
            "write",
            "edit",
            "run_shell_command",
            "todowrite",
        ] {
            assert_eq!(untrusted(local), None, "{local}");
        }
        assert_eq!(untrusted("claude_in_chrome/tabs_context_mcp"), None);
        assert_eq!(untrusted("claude_in_chrome/get_page_text"), Some("mcp"));
    }
}
