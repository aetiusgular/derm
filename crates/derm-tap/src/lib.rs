//! derm's model tap (wave 5, lane S; `plans/toolkit_universal_plan.md` lane S,
//! note AR section 2). A loopback HTTP proxy the daemon starts: it speaks the
//! Anthropic Messages API, the OpenAI Responses API, Chat Completions and the
//! Gemini API, forwards to the upstream the harness would have used, and
//! records each tool call as a `tap.call` (`contracts/events.md` section 5).
//! No header is logged, written or echoed (rules case 114).
//!
//! The pieces:
//! - [`route`]: which chat a request belongs to (a route derived from the
//!   chat token's hash, in the path or a header);
//! - [`upstream`]: the fixed table of hosts the tap forwards to;
//! - [`http`]: the loopback side's HTTP/1.1;
//! - [`apis`] and [`sse`]: what a request offers and a response asks for;
//! - [`record`]: hashes, sizes, paths, and the `tap.request` and `tap.call`
//!   records;
//! - [`content`]: content capture's files, when the user turned it on;
//! - [`fold`]: case 94's fold for a local upstream;
//! - [`launch`]: what `derm run` adds to a harness's start;
//! - [`settings`]: the tap's and content's keys in `~/.derm/settings.json`;
//! - [`tap`]: the server.
//!
//! What it does not do yet (lane S status doc, "Not built"): the Responses
//! API over WebSocket (Codex is started with `supports_websockets = false`).

pub mod apis;
pub mod content;
pub mod fold;
pub mod http;
pub mod launch;
pub mod record;
pub mod route;
pub mod settings;
pub mod sse;
pub mod tap;
pub mod upstream;

pub use tap::{default_agent, Chat, Config, ContentPolicy, Resolver, Sink, Tap};
