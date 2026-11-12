//! The MCP server names Kiro CLI is configured with, so the Kiro dialect can
//! split `mcp_<server>_<tool>`: V3 hook events carry the sanitized internal
//! id `mcp_<server>_<tool>`, not the `@server/tool` display name
//! (kiro.dev/docs/hooks/types, "Page updated: November 6, 2026", read by this
//! lane 10 Nov). Where Kiro reads MCP servers (read 3 Nov by lane N):
//! `~/.kiro/settings/mcp.json` and the workspace's `.kiro/settings/mcp.json`,
//! `mcpServers` in each, and `mcpServers` in an agent profile. A Markdown
//! profile and Powers bring servers derm cannot list: either makes the list
//! incomplete. How Kiro sanitizes a server name into the id was not found, so
//! each name counts as written and with every character outside
//! `[A-Za-z0-9_-]` as `_`; more names can only make a split ambiguous.
//!
//! Ported from `packages/derm-hooks-native/src/kiroServers.ts` at `e29ce27`.

use std::path::Path;

use super::crush_servers::{json_keys, read_small, Collect, Small};
use super::mcp_split::ServerNames;

const MAX_PROFILES: usize = 256;

fn sanitized(n: &str) -> String {
    n.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '_' || c == '-' {
                c
            } else {
                '_'
            }
        })
        .collect()
}

/// `kiroServerNames`.
pub fn kiro_server_names(cwd: Option<&str>, home: &Path) -> ServerNames {
    let mut c = Collect::new();
    let mut roots = vec![home.join(".kiro")];
    match cwd.filter(|c| Path::new(c).is_absolute()) {
        None => c.fail("the hook input has no absolute cwd".into()),
        Some(cwd) => roots.push(Path::new(cwd).join(".kiro")),
    }
    for root in roots {
        let mut files = vec![root.join("settings").join("mcp.json")];
        match std::fs::read_dir(root.join("agents")) {
            Ok(entries) => {
                let mut all: Vec<String> = entries
                    .filter_map(Result::ok)
                    .map(|e| e.file_name().to_string_lossy().into_owned())
                    .collect();
                all.sort();
                if all.iter().any(|f| f.ends_with(".md")) {
                    c.fail("a Markdown agent profile".into());
                }
                let profiles: Vec<&String> = all.iter().filter(|f| f.ends_with(".json")).collect();
                if profiles.len() > MAX_PROFILES {
                    c.fail("too many agent profiles".into());
                }
                for p in profiles.into_iter().take(MAX_PROFILES) {
                    files.push(root.join("agents").join(p));
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => c.fail("an agents folder could not be listed".into()),
        }
        if std::fs::metadata(root.join("powers")).is_ok_and(|m| m.is_dir()) {
            c.fail("Kiro Powers bring servers derm cannot list".into());
        }
        for f in files {
            let name = f
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default();
            match read_small(&f) {
                Small::Missing => {}
                Small::Text(t) => match json_keys(&t, "mcpServers") {
                    Some(ns) => {
                        for n in ns {
                            let s = sanitized(&n);
                            c.add(n);
                            c.add(s);
                        }
                    }
                    None => c.fail(format!("{name} could not be read")),
                },
                Small::Unreadable => c.fail(format!("{name} could not be read")),
            }
        }
    }
    c.done()
}
