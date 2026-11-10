//! The per-harness table: where each harness keeps its MCP servers, in
//! what shape, and what derm must never write. Lane C verified it,
//! integration w1 made it the one copy, and integration w2 split it into one
//! file per agent under `presets/` with `presets/index.json` naming the lists
//! and their order, so each wave 4 lane edits only its own agents' files
//! (`plans/parallel_build_tk.md`, section 7a). The files are embedded at
//! build time and assembled once; `table_json()` is the whole table in the
//! shape `contracts/harness-presets.schema.json` describes.

use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use serde::Deserialize;

const INDEX: &str = include_str!("presets/index.json");

/// Every row file, by id. A file in the folder that is not listed here, or
/// listed here and not in the index, fails `the_folder_index_and_rows_agree`.
const ROWS: &[(&str, &str)] = &[
    ("claude-code", include_str!("presets/claude-code.json")),
    ("codex", include_str!("presets/codex.json")),
    ("pi", include_str!("presets/pi.json")),
    ("opencode", include_str!("presets/opencode.json")),
    ("gemini", include_str!("presets/gemini.json")),
    ("cursor", include_str!("presets/cursor.json")),
    ("hermes", include_str!("presets/hermes.json")),
    ("openclaw", include_str!("presets/openclaw.json")),
    ("goose", include_str!("presets/goose.json")),
    ("qwen-code", include_str!("presets/qwen-code.json")),
    ("copilot-cli", include_str!("presets/copilot-cli.json")),
    ("amp", include_str!("presets/amp.json")),
    ("crush", include_str!("presets/crush.json")),
    ("zed", include_str!("presets/zed.json")),
    ("grok", include_str!("presets/grok.json")),
    ("antigravity", include_str!("presets/antigravity.json")),
    ("openclaude", include_str!("presets/openclaude.json")),
    ("oh-my-pi", include_str!("presets/oh-my-pi.json")),
    ("auggie", include_str!("presets/auggie.json")),
    ("cline", include_str!("presets/cline.json")),
    ("codebuff", include_str!("presets/codebuff.json")),
    ("command-code", include_str!("presets/command-code.json")),
    ("continue", include_str!("presets/continue.json")),
    ("droid", include_str!("presets/droid.json")),
    ("kilo", include_str!("presets/kilo.json")),
    ("kimi", include_str!("presets/kimi.json")),
    ("kiro", include_str!("presets/kiro.json")),
    ("mistral-vibe", include_str!("presets/mistral-vibe.json")),
    ("rovo-dev", include_str!("presets/rovo-dev.json")),
];

/// Wave 5's sibling tables (the wave 5 base, `plans/parallel_build_tk.md`
/// section 7c), each one lane's: a field per preset id, merged into the rows
/// by `assemble`. `tap` is lane S's, `kit` lane T's, `executables` lane W's.
const WAVE5: &[(&str, &str)] = &[
    ("tap", include_str!("presets/wave5/tap.json")),
    ("kit", include_str!("presets/wave5/kit.json")),
    (
        "executables",
        include_str!("presets/wave5/executables.json"),
    ),
];

/// The assembled table as JSON text: `{"$comment", "version", "harnesses",
/// "planned"}`, rows in the index's order, with wave 5's fields merged in.
pub fn table_json() -> &'static str {
    static TABLE: OnceLock<String> = OnceLock::new();
    TABLE.get_or_init(|| {
        assemble_with(INDEX, ROWS, WAVE5).expect("presets/ is checked by its tests")
    })
}

#[cfg(test)]
fn assemble(index: &str, rows: &[(&str, &str)]) -> Result<String, String> {
    assemble_with(index, rows, &[])
}

/// Merges each sibling table's values into the rows as its field. Refuses a
/// table whose `field` is not its name, an id the index does not name, a row
/// that already sets the field, and a value that is not the field's shape
/// (the schema, `contracts/harness-presets.schema.json`, has the rest).
fn merge_wave5(
    out: &mut serde_json::Map<String, serde_json::Value>,
    tables: &[(&str, &str)],
) -> Result<(), String> {
    use serde_json::Value;
    for (field, text) in tables {
        let table: Value =
            serde_json::from_str(text).map_err(|e| format!("wave5/{field}.json: {e}"))?;
        if table.get("field").and_then(Value::as_str) != Some(field) {
            return Err(format!("wave5/{field}.json: its field is not {field}"));
        }
        let values = table
            .get("rows")
            .and_then(Value::as_object)
            .ok_or(format!("wave5/{field}.json: no rows object"))?;
        for (id, value) in values {
            let shape_ok = match *field {
                "executables" => value
                    .as_array()
                    .is_some_and(|a| a.iter().all(Value::is_string)),
                _ => value.is_object() || value.is_null(),
            };
            if !shape_ok {
                return Err(format!("wave5/{field}.json: {id}'s value is not a {field}"));
            }
            // Find the row by position first, then borrow it once.
            let at = ["harnesses", "planned"].iter().find_map(|list| {
                out.get(*list)
                    .and_then(Value::as_array)
                    .and_then(|items| {
                        items
                            .iter()
                            .position(|r| r.get("id").and_then(Value::as_str) == Some(id.as_str()))
                    })
                    .map(|i| (*list, i))
            });
            let (list, i) = at.ok_or(format!(
                "wave5/{field}.json names {id}, which index.json does not"
            ))?;
            let row = out
                .get_mut(list)
                .and_then(Value::as_array_mut)
                .and_then(|items| items.get_mut(i))
                .and_then(Value::as_object_mut)
                .ok_or(format!("{id}.json: not an object"))?;
            if row.contains_key(*field) {
                return Err(format!(
                    "{id}.json sets {field}, which wave5/{field}.json owns"
                ));
            }
            row.insert((*field).to_string(), value.clone());
        }
    }
    Ok(())
}

fn assemble_with(
    index: &str,
    rows: &[(&str, &str)],
    wave5: &[(&str, &str)],
) -> Result<String, String> {
    use serde_json::{Map, Value};
    let index: Value = serde_json::from_str(index).map_err(|e| format!("index.json: {e}"))?;
    let mut seen = std::collections::HashSet::new();
    let mut out = Map::new();
    if let Some(c) = index.get("$comment") {
        out.insert("$comment".into(), c.clone());
    }
    out.insert(
        "version".into(),
        index.get("version").cloned().unwrap_or(Value::Null),
    );
    for list in ["harnesses", "planned"] {
        let ids = index
            .get(list)
            .and_then(Value::as_array)
            .ok_or(format!("index.json: no {list} list"))?;
        let mut items = Vec::new();
        for id in ids {
            let id = id
                .as_str()
                .ok_or(format!("index.json: {list} holds a non-string"))?;
            if !seen.insert(id.to_string()) {
                return Err(format!("index.json: {id} listed twice"));
            }
            let (_, text) = rows
                .iter()
                .find(|(r, _)| *r == id)
                .ok_or(format!("index.json names {id}, which has no row file"))?;
            let row: Value = serde_json::from_str(text).map_err(|e| format!("{id}.json: {e}"))?;
            if row.get("id").and_then(Value::as_str) != Some(id) {
                return Err(format!("{id}.json: its id is not {id}"));
            }
            items.push(row);
        }
        out.insert(list.into(), Value::Array(items));
    }
    if let Some((id, _)) = rows.iter().find(|(id, _)| !seen.contains(*id)) {
        return Err(format!("{id}.json is in no list of index.json"));
    }
    merge_wave5(&mut out, wave5)?;
    serde_json::to_string(&Value::Object(out)).map_err(|e| e.to_string())
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OsPaths {
    pub macos: Option<String>,
    pub linux: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
// `project` is listed so readers of the table (lane J's `derm status`) can
// show it; derm connect never writes it.
#[allow(dead_code)]
pub struct ConfigFiles {
    pub user: OsPaths,
    pub project: Option<String>,
}

/// How derm treats the file.
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum Format {
    /// Strict JSON: comments make the file unwritable (Claude Code, Pi).
    Json,
    /// JSON with comments and trailing commas allowed and kept.
    Jsonc,
    Toml,
    Yaml,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
// The descriptive fields (tool names, gates, list_changed) are the table's
// record for other readers; derm connect reads only the ones it needs.
#[allow(dead_code)]
pub struct Preset {
    pub id: String,
    pub name: String,
    pub cli: Option<String>,
    pub config_files: ConfigFiles,
    /// An environment variable that names the harness's own folder, which
    /// then replaces the folder of the user path (`CODEX_HOME`).
    #[serde(default)]
    pub home_env: Option<String>,
    /// Honour `XDG_CONFIG_HOME` for a `~/.config/...` path on Linux.
    #[serde(default)]
    pub xdg_config: bool,
    pub format: Format,
    pub entry_shape: String,
    /// Keys from the file's root to the object that holds servers by name.
    pub entry_path: Vec<String>,
    /// Which renderer shapes the entry (`render.rs`).
    pub entry_style: String,
    /// Whether the harness ends the file with a newline when it creates
    /// it (recorded, or read in its source).
    #[serde(default)]
    pub trailing_newline: bool,
    /// `write`, or `print` when derm only prints the entry (with the reason
    /// in `writeNote`).
    pub write: String,
    #[serde(default)]
    pub write_note: Option<String>,
    #[serde(default)]
    pub managed_files: Option<serde_json::Value>,
    #[serde(default)]
    pub add_command: Option<serde_json::Value>,
    #[serde(default)]
    pub tool_name_form: Option<String>,
    #[serde(default)]
    pub name_mangling: Option<String>,
    #[serde(default)]
    pub in_harness_gate: Option<String>,
    #[serde(default)]
    pub list_changed: Option<String>,
    #[serde(default)]
    pub enable_key: Option<String>,
    #[serde(default)]
    pub notes: Option<String>,
    #[serde(default)]
    pub sources: Vec<String>,
    pub verified: String,
    #[serde(default)]
    pub entry_example: Option<serde_json::Value>,
    #[serde(default)]
    pub env_ref: Option<String>,
    /// The harness reads a reference only when it is the whole value
    /// (Copilot CLI's `$VAR`), so `Bearer ${VAR}` cannot be expressed.
    #[serde(default)]
    pub env_ref_whole_value: bool,
    /// Server names the harness keeps for itself.
    #[serde(default)]
    pub reserved_names: Vec<String>,
    #[serde(default)]
    pub allowlist: Option<String>,
    /// Wave 5 (the wave 5 base): from `presets/wave5/`, merged by
    /// `assemble_with`. `None` or empty until the lane that owns the table
    /// fills it: `tap` lane S, `kit` lane T, `executables` lane W.
    #[serde(default)]
    pub tap: Option<serde_json::Value>,
    #[serde(default)]
    pub kit: Option<serde_json::Value>,
    #[serde(default)]
    pub executables: Vec<String>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct Table {
    pub version: u32,
    pub harnesses: Vec<Preset>,
}

pub fn table() -> Table {
    let t: Table = serde_json::from_str(table_json()).expect("presets/ is checked by its tests");
    assert_eq!(t.version, 1, "presets.json version");
    t
}

pub fn find(id: &str) -> Option<Preset> {
    table().harnesses.into_iter().find(|p| p.id == id)
}

/// Expands `~` against `home`.
pub fn expand(path: &str, home: &Path) -> PathBuf {
    if path == "~" {
        home.to_path_buf()
    } else if let Some(rest) = path.strip_prefix("~/") {
        home.join(rest)
    } else {
        PathBuf::from(path)
    }
}

/// What a lookup of the environment needs (tests pass a map).
pub trait Env {
    fn var(&self, key: &str) -> Option<String>;
}

impl Preset {
    pub fn writes(&self) -> bool {
        self.write == "write"
    }

    /// The user-level file for this OS. `None` when the harness has none
    /// that derm knows.
    pub fn user_path(&self, home: &Path, macos: bool, env: &dyn Env) -> Option<PathBuf> {
        let raw = if macos {
            self.config_files.user.macos.as_deref()
        } else {
            self.config_files.user.linux.as_deref()
        }?;
        if raw.contains("TODO") {
            return None;
        }
        if let Some(var) = &self.home_env {
            if let Some(dir) = env.var(var).filter(|d| d.starts_with('/')) {
                let file = Path::new(raw).file_name()?;
                return Some(PathBuf::from(dir).join(file));
            }
        }
        if self.xdg_config && !macos {
            if let (Some(xdg), Some(rest)) = (
                env.var("XDG_CONFIG_HOME").filter(|d| d.starts_with('/')),
                raw.strip_prefix("~/.config/"),
            ) {
                return Some(PathBuf::from(xdg).join(rest));
            }
        }
        Some(expand(raw, home))
    }

    /// Every managed (admin or enterprise) file this harness reads, for
    /// this OS. derm never writes one (case 65).
    pub fn managed_paths(&self, home: &Path, macos: bool) -> Vec<PathBuf> {
        let mut out = Vec::new();
        let Some(m) = &self.managed_files else {
            return out;
        };
        let key = if macos { "macos" } else { "linux" };
        let mut push = |v: &serde_json::Value| match v {
            serde_json::Value::String(s) if s.starts_with('/') || s.starts_with('~') => {
                out.push(expand(s, home))
            }
            serde_json::Value::Array(items) => {
                for i in items {
                    if let Some(s) = i.as_str() {
                        if s.starts_with('/') || s.starts_with('~') {
                            out.push(expand(s, home));
                        }
                    }
                }
            }
            _ => {}
        };
        if let Some(v) = m.get(key) {
            push(v);
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    pub struct MapEnv(pub HashMap<String, String>);
    impl Env for MapEnv {
        fn var(&self, key: &str) -> Option<String> {
            self.0.get(key).cloned()
        }
    }

    #[test]
    fn the_folder_index_and_rows_agree() {
        // Every *.json in presets/ but the index is a row and is in ROWS.
        let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/connect/presets");
        let mut files: Vec<String> = std::fs::read_dir(&dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .filter(|n| n.ends_with(".json") && n != "index.json")
            .map(|n| n.trim_end_matches(".json").to_string())
            .collect();
        files.sort();
        let mut listed: Vec<String> = ROWS.iter().map(|(id, _)| id.to_string()).collect();
        listed.sort();
        assert_eq!(files, listed, "every row file is embedded, and only those");
        assemble(INDEX, ROWS).unwrap();
        // Wave 5's sibling tables: every file in presets/wave5/ is embedded.
        let mut tables: Vec<String> = std::fs::read_dir(dir.join("wave5"))
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        tables.sort();
        let mut embedded: Vec<String> = WAVE5.iter().map(|(f, _)| format!("{f}.json")).collect();
        embedded.sort();
        assert_eq!(
            tables, embedded,
            "every wave5 table is embedded, and only those"
        );
        assemble_with(INDEX, ROWS, WAVE5).unwrap();
    }

    #[test]
    fn wave5_tables_merge_into_rows_and_refuse_what_they_do_not_own() {
        let index = r#"{"version":1,"harnesses":["a"],"planned":["b"]}"#;
        let rows = &[("a", r#"{"id":"a"}"#), ("b", r#"{"id":"b"}"#)];
        let tap =
            r#"{"field":"tap","rows":{"a":{"via":"env","name":"ANTHROPIC_BASE_URL"},"b":null}}"#;
        let exe = r#"{"field":"executables","rows":{"b":["agent-b"]}}"#;
        let t: serde_json::Value = serde_json::from_str(
            &assemble_with(index, rows, &[("tap", tap), ("executables", exe)]).unwrap(),
        )
        .unwrap();
        assert_eq!(t["harnesses"][0]["tap"]["name"], "ANTHROPIC_BASE_URL");
        assert!(t["planned"][0]["tap"].is_null());
        assert_eq!(t["planned"][0]["executables"][0], "agent-b");
        assert!(
            t["harnesses"][0].get("executables").is_none(),
            "absent stays absent"
        );
        let stranger = r#"{"field":"tap","rows":{"zzz":{"via":"none"}}}"#;
        assert!(assemble_with(index, rows, &[("tap", stranger)])
            .unwrap_err()
            .contains("does not"));
        let owned = &[
            ("a", r#"{"id":"a","tap":{"via":"none"}}"#),
            ("b", r#"{"id":"b"}"#),
        ];
        assert!(assemble_with(index, owned, &[("tap", tap)])
            .unwrap_err()
            .contains("owns"));
        let misnamed = r#"{"field":"kit","rows":{}}"#;
        assert!(assemble_with(index, rows, &[("tap", misnamed)])
            .unwrap_err()
            .contains("its field"));
        let bad = r#"{"field":"executables","rows":{"a":"agent-a"}}"#;
        assert!(assemble_with(index, rows, &[("executables", bad)])
            .unwrap_err()
            .contains("not a executables"));
    }

    #[test]
    fn assembly_refuses_a_bad_folder() {
        let index = r#"{"version":1,"harnesses":["a"],"planned":[]}"#;
        assert!(assemble(index, &[("a", r#"{"id":"a"}"#)]).is_ok());
        assert!(assemble(index, &[("a", r#"{"id":"b"}"#)])
            .unwrap_err()
            .contains("its id"));
        assert!(assemble(index, &[]).unwrap_err().contains("no row file"));
        assert!(
            assemble(index, &[("a", r#"{"id":"a"}"#), ("c", r#"{"id":"c"}"#)])
                .unwrap_err()
                .contains("in no list")
        );
        let twice = r#"{"version":1,"harnesses":["a"],"planned":["a"]}"#;
        assert!(assemble(twice, &[("a", r#"{"id":"a"}"#)])
            .unwrap_err()
            .contains("twice"));
    }

    #[test]
    fn every_contract_harness_is_here_and_verified() {
        let contract: serde_json::Value = serde_json::from_str(table_json()).unwrap();
        let ids: Vec<String> = contract["harnesses"]
            .as_array()
            .unwrap()
            .iter()
            .map(|h| h["id"].as_str().unwrap().to_string())
            .collect();
        let t = table();
        assert_eq!(t.version, 1);
        let mine: Vec<String> = t.harnesses.iter().map(|p| p.id.clone()).collect();
        assert_eq!(mine, ids, "same harnesses, same order as the index");
        for p in &t.harnesses {
            assert!(
                p.verified.starts_with("2026-"),
                "{} verified: {}",
                p.id,
                p.verified
            );
            assert!(!p.sources.is_empty(), "{} has no sources", p.id);
            assert!(p.write == "write" || p.write == "print", "{}", p.id);
            if !p.writes() {
                assert!(p.write_note.is_some(), "{} prints only and says why", p.id);
            }
            assert!(
                !p.entry_path.is_empty() || p.format == Format::Yaml,
                "{}",
                p.id
            );
        }
        // The verified rows carry no TODO. The `planned` rows (integration
        // w1: the agents derm connect does not cover yet) are TODO by design.
        let rows = serde_json::to_string(&contract["harnesses"]).unwrap();
        assert!(!rows.contains("TODO"), "no TODO left in the verified rows");
        assert!(
            contract["planned"].is_array(),
            "the planned rows are listed apart"
        );
    }

    #[test]
    fn paths_expand_and_follow_env_overrides() {
        let home = Path::new("/home/u");
        let codex = find("codex").unwrap();
        let none = MapEnv(HashMap::new());
        assert_eq!(
            codex.user_path(home, false, &none).unwrap(),
            home.join(".codex/config.toml")
        );
        let env = MapEnv(HashMap::from([(
            "CODEX_HOME".to_string(),
            "/srv/codex".to_string(),
        )]));
        assert_eq!(
            codex.user_path(home, false, &env).unwrap(),
            Path::new("/srv/codex/config.toml")
        );
        let rel = MapEnv(HashMap::from([(
            "CODEX_HOME".to_string(),
            "rel/dir".to_string(),
        )]));
        assert_eq!(
            codex.user_path(home, false, &rel).unwrap(),
            home.join(".codex/config.toml"),
            "relative override ignored"
        );
        let claude = find("claude-code").unwrap();
        assert_eq!(
            claude.user_path(home, true, &none).unwrap(),
            home.join(".claude.json")
        );
        assert!(!claude.managed_paths(home, true).is_empty());
    }
}
