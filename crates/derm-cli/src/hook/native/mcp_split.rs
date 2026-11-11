//! `mcp_<server>_<tool>` with single underscores (Crush, Kiro): a server name
//! may hold `_` itself, so `mcp_exa_evil_t` could be server `exa` with tool
//! `evil_t` or server `exa_evil` with tool `t`. Integration w2's re-review
//! (W2-R1) left this class of name to the agent's own server list: the split
//! is taken from the MCP server names the agent is configured with, and a
//! name more than one of them, or none, could start is ambiguous, so an allow
//! asks. A name that can split only one way needs no list.
//!
//! Ported from `packages/derm-hooks-native/src/mcpSplit.ts` at `e29ce27`.

/// The MCP server names an agent is configured with, and whether the list is
/// whole (`ServerNames`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ServerNames {
    pub names: Vec<String>,
    pub complete: bool,
    pub why: Option<String>,
}

/// A name as the core reads it, and why its split is in doubt, if it is.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Named {
    pub tool: String,
    pub ambiguous: Option<String>,
}

impl Named {
    pub fn plain(tool: impl Into<String>) -> Named {
        Named {
            tool: tool.into(),
            ambiguous: None,
        }
    }
}

/// The core's `mcp__<server>__<tool>` when the split is plain; else the name
/// as it came, marked ambiguous (`splitSingleUnderscore`).
pub fn split_single_underscore(raw: &str, names: &ServerNames, agent: &str) -> Named {
    if !raw.starts_with("mcp_") || raw.starts_with("mcp__") {
        return Named::plain(raw);
    }
    let rest = &raw[4..];
    let canonical =
        |server: &str| Named::plain(format!("mcp__{server}__{}", &rest[server.len() + 1..]));
    let bytes = rest.as_bytes();
    // `_` is one byte, so a byte index stands for the TypeScript's code unit
    // index: never the first or the last character.
    let splits: Vec<usize> = (1..bytes.len().saturating_sub(1))
        .filter(|&i| bytes[i] == b'_')
        .collect();
    if splits.len() == 1 {
        return canonical(&rest[..splits[0]]);
    }
    let fits: Vec<&String> = names
        .names
        .iter()
        .filter(|s| !s.is_empty() && rest.starts_with(&format!("{s}_")) && rest.len() > s.len() + 1)
        .collect();
    if fits.len() == 1 && names.complete {
        return canonical(fits[0]);
    }
    let why = if fits.is_empty() {
        format!("no configured {agent} MCP server name fits")
    } else if fits.len() > 1 {
        format!("more than one configured {agent} MCP server name fits")
    } else {
        names
            .why
            .clone()
            .unwrap_or_else(|| format!("{agent}'s server list could not be read whole"))
    };
    Named {
        tool: raw.to_string(),
        ambiguous: Some(format!("ambiguous server name: {why}")),
    }
}
