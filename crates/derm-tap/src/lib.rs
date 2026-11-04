//! derm's model tap (wave 5, lane S; `plans/toolkit_universal_plan.md` lane S,
//! note AR section 2). A loopback HTTP and WebSocket proxy the daemon starts:
//! it speaks the Anthropic Messages API, the OpenAI Responses API (HTTP and
//! WebSocket), Chat Completions and the Gemini API, forwards to the upstream
//! the harness would have used, and records each tool call as a `tap.call`
//! (`contracts/events.md` section 5). No header is logged, written or echoed
//! (rules case 114).
//!
//! Empty until lane S. The record's shape is in `contracts/`, with examples
//! in `contracts/fixtures/tap/`.
