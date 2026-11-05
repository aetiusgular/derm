//! How `derm run` points a harness at the tap, from its preset row's `tap`
//! value (`crates/derm-cli/src/connect/presets/wave5/tap.json`,
//! `contracts/harness-presets.schema.json` `$defs.tap`). Always the launch
//! environment or argv of this one start, never a settings file (case 56).
//!
//! - `via: "env"`: the variable `name` holds the tap's URL with the route in
//!   its path (`<tap>/r/<route>/<upstream key>`). Claude Code reads
//!   `ANTHROPIC_BASE_URL` (its gateway guide), Gemini CLI
//!   `GOOGLE_GEMINI_BASE_URL` (lane I's checks, V).
//! - `via: "codex-provider"`: a custom provider through `-c`, with HTTP only
//!   and the user's own login (Codex 0.163.0, `model-provider-info/src/
//!   lib.rs:140-205`; WebSocket would stall the first turn, `core/src/
//!   client.rs:2414-2427`). The route rides in a header Codex fills from a
//!   variable (`env_http_headers`), so no route sits in an argv a run record
//!   keeps. The flags go after a session subcommand (`exec`): Codex 0.163.0
//!   ignores a provider set before it (run 4 Nov 2026); `derm run` places
//!   them.
//! - `via: "none"`: the harness takes no base URL; its intent comes from
//!   `intent` (hooks for Cursor, note AS).

use serde_json::Value;

use crate::record::Api;
use crate::route;
use crate::upstream;

/// The variable Codex's provider header is filled from.
pub const CODEX_ROUTE_VAR: &str = "DERM_TAP_ROUTE";
/// The provider id derm adds to Codex.
pub const CODEX_PROVIDER: &str = "derm-tap";

/// What to add to the child.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Launch {
    pub env: Vec<(String, String)>,
    pub args: Vec<String>,
    /// For `run.start`'s `tap`: `env` or `codex-provider`.
    pub via: &'static str,
    pub api: Api,
    /// The upstream's host, for `run.start` (never a path or a query).
    pub upstream: String,
}

/// Why a harness runs untapped (`run.start`'s `tap.reason`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Off {
    NoBaseUrl,
}

fn api_of(name: &str) -> Option<Api> {
    match name {
        "anthropic-messages" => Some(Api::AnthropicMessages),
        "openai-responses" => Some(Api::OpenAiResponses),
        "openai-chat" => Some(Api::OpenAiChat),
        "gemini" => Some(Api::Gemini),
        _ => None,
    }
}

fn key_of(api: Api) -> &'static str {
    match api {
        Api::AnthropicMessages => upstream::ANTHROPIC,
        Api::OpenAiResponses | Api::OpenAiChat => upstream::OPENAI,
        Api::Gemini => upstream::GEMINI,
    }
}

/// The launch for one harness. `endpoint` is the tap as the harness will
/// reach it (`http://127.0.0.1:<port>`, or `host.docker.internal` under
/// sbx), `route` the chat's route.
pub fn launch(row: &Value, endpoint: &str, route_text: &str) -> Result<Launch, Off> {
    let via = row.get("via").and_then(Value::as_str).unwrap_or("none");
    let api = row
        .get("api")
        .and_then(Value::as_array)
        .and_then(|a| a.iter().filter_map(Value::as_str).find_map(api_of))
        .ok_or(Off::NoBaseUrl)?;
    let endpoint = endpoint.trim_end_matches('/');
    let builtin = upstream::builtin();
    match via {
        "env" => {
            let name = row
                .get("name")
                .and_then(Value::as_str)
                .ok_or(Off::NoBaseUrl)?;
            let key = key_of(api);
            Ok(Launch {
                env: vec![(name.to_string(), format!("{endpoint}/r/{route_text}/{key}"))],
                args: Vec::new(),
                via: "env",
                api,
                upstream: builtin.get(key).map(|u| u.host()).unwrap_or_default(),
            })
        }
        "codex-provider" => {
            let p = format!("model_providers.{CODEX_PROVIDER}");
            let pairs = [
                (
                    "model_provider".to_string(),
                    format!("\"{CODEX_PROVIDER}\""),
                ),
                (format!("{p}.name"), "\"derm tap\"".to_string()),
                (
                    format!("{p}.base_url"),
                    format!("\"{endpoint}/{}\"", upstream::OPENAI_AUTO),
                ),
                (format!("{p}.wire_api"), "\"responses\"".to_string()),
                (format!("{p}.requires_openai_auth"), "true".to_string()),
                (format!("{p}.supports_websockets"), "false".to_string()),
                (
                    format!("{p}.env_http_headers.{}", route::HEADER),
                    format!("\"{CODEX_ROUTE_VAR}\""),
                ),
            ];
            let mut args = Vec::new();
            for (k, v) in pairs {
                args.push("-c".to_string());
                args.push(format!("{k}={v}"));
            }
            Ok(Launch {
                env: vec![(CODEX_ROUTE_VAR.to_string(), route_text.to_string())],
                args,
                via: "codex-provider",
                api,
                upstream: "chatgpt.com or api.openai.com".to_string(),
            })
        }
        _ => Err(Off::NoBaseUrl),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const R: &str = "0123456789abcdef0123456789abcdef";

    #[test]
    fn env_rows_put_the_route_in_the_variable_only() {
        let row = json!({"via":"env","name":"ANTHROPIC_BASE_URL","api":["anthropic-messages"],"verifiedAt":"2.1.311"});
        let l = launch(&row, "http://127.0.0.1:4000/", R).unwrap();
        assert_eq!(
            l.env,
            vec![(
                "ANTHROPIC_BASE_URL".to_string(),
                format!("http://127.0.0.1:4000/r/{R}/anthropic")
            )]
        );
        assert!(l.args.is_empty());
        assert_eq!(l.upstream, "api.anthropic.com");
        let g = launch(
            &json!({"via":"env","name":"GOOGLE_GEMINI_BASE_URL","api":["gemini"]}),
            "http://h:1",
            R,
        )
        .unwrap();
        assert_eq!(g.env[0].1, format!("http://h:1/r/{R}/gemini"));
    }

    #[test]
    fn codex_gets_a_provider_whose_argv_holds_no_route() {
        let row = json!({"via":"codex-provider","api":["openai-responses"]});
        let l = launch(&row, "http://127.0.0.1:4000", R).unwrap();
        assert!(!l.args.iter().any(|a| a.contains(R)));
        assert_eq!(l.env, vec![(CODEX_ROUTE_VAR.to_string(), R.to_string())]);
        assert!(l
            .args
            .contains(&"model_providers.derm-tap.supports_websockets=false".to_string()));
        assert!(l
            .args
            .contains(&"model_providers.derm-tap.requires_openai_auth=true".to_string()));
        assert!(l.args.contains(
            &"model_providers.derm-tap.base_url=\"http://127.0.0.1:4000/openai-auto\"".to_string()
        ));
        assert!(l.args.contains(
            &"model_providers.derm-tap.env_http_headers.x-derm-tap-route=\"DERM_TAP_ROUTE\""
                .to_string()
        ));
        assert_eq!(l.args.iter().filter(|a| *a == "-c").count(), 7);
    }

    #[test]
    fn none_or_an_unknown_api_runs_untapped() {
        assert_eq!(
            launch(
                &json!({"via":"none","api":[],"intent":"hooks"}),
                "http://h:1",
                R
            ),
            Err(Off::NoBaseUrl)
        );
        assert_eq!(
            launch(
                &json!({"via":"env","name":"X","api":["openai-responses-ws"]}),
                "http://h:1",
                R
            ),
            Err(Off::NoBaseUrl)
        );
        assert_eq!(
            launch(&json!({"via":"env","api":["gemini"]}), "http://h:1", R),
            Err(Off::NoBaseUrl)
        );
    }
}
