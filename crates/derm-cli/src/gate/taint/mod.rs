//! Taint and injected input at the gate (wave 6, lane 6D;
//! `plans/toolkit_wave6_plan.md` section 2.2; `contracts/policy.md` section
//! 9; `contracts/events.md` section 6.2). [`decide_call`] passes every
//! answer through [`adjust`] before full access applies.
//!
//! A chat is tainted once a call it ran brought in untrusted content (a
//! fetch, a web search, an MCP result, a tool the gate does not know;
//! `derm_tap::results::kinds`) or read a secret ([`paths::secret`]). After
//! that, these calls get the chat's verdict ([`rules`]):
//! - `protected-write`: a write under a folder or to a file that runs code or
//!   steers an agent later ([`paths::protected`]: CI, git hooks, editor
//!   tasks, build files, agent instructions, shell startup files, and step
//!   7a's control paths);
//! - `install`: a package install (`contracts/policy.md` section 6);
//! - `push`: a `git push`;
//! - `new-host`: a host the chat has not reached before;
//! - `named-in-result`: a host an untrusted result in the chat named
//!   (OpenMoat ADR-057), under `derm run` only: the tap keeps those, in the
//!   daemon's memory (note AZ D4). The light tier has no key the agent cannot
//!   read, so it applies the coarse rules only.
//!
//! Whether or not the chat is tainted, `session-written-code`: running a
//! file the chat itself wrote (E0's request R-E0-6). OpenMoat 0.19.0 holds
//! this rule apart from taint too (`session_code.rs`, ADR-039: "running a
//! file the same session wrote needs review" where no OS sandbox holds the
//! command); the contract lists it under taint, and the lane's status doc
//! records the reading and asks integration to fix the contract's wording.
//!
//! **The verdict** is the chat's (`derm run --taint`, else the setting, else
//! `ask`): `ask` turns an allow into an ask, `deny` turns an allow or an ask
//! into a deny, `record` changes nothing and writes `taint.review` with
//! `wouldBe: ask`. Taint only raises (rules section 5, item 7): a call the
//! policy already denies, or asks about under `ask`, keeps its answer and
//! gets no record, so a control-path ask is never counted as taint's.
//!
//! **Marks come at the decision.** The mark is made when the gate answers a
//! call that will bring the content in (anything but a deny), not when its
//! result comes back: 13 of the 17 agents derm gates send no post event
//! (note AZ D2; `connect/gates.json` registers `post` only for Claude Code,
//! Codex, Gemini and Hermes), and the post handlers reach no seam this lane
//! owns. A fetch the person then declines at the agent's own prompt still
//! marks the chat: a false positive E1 counts (case 220).
//!
//! Not covered (note AZ, S1): calls decided outside `crates/derm-cli/src/gate/`
//! (Amp's plugin, the sbx kit's embedded hook, template-registered compat and
//! native gates) never reach this seam.
//!
//! [`decide_call`]: super::core::decide_call

pub mod facts;
pub mod paths;
pub mod shell;
pub mod state;

#[cfg(test)]
mod tests;

use std::path::{Path, PathBuf};

use derm_core::policy::Action;
use derm_tap::results::verdict::{From, Verdict};
use derm_tap::results::{fingerprint, verdict};
use serde_json::{Map, Value};

use super::core::{GateAnswer, GateCall};
use super::daemon::{self, AdapterEvent, Env};
use facts::Facts;
use state::{Mark, State};

/// One rule a call met.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Hit {
    pub rule: &'static str,
    pub why: String,
    pub paths: Vec<String>,
}

/// Where the chat's state lives for this call.
enum Store {
    /// The daemon answered `op: "taint"`.
    Daemon,
    /// The light tier's file.
    File(PathBuf),
    /// Neither: nothing is kept.
    None,
}

/// The rules `facts` meets against `state`. `named`: the hosts an untrusted
/// result in the chat named (the daemon's; empty in the light tier).
pub fn rules(facts: &Facts, st: &State, named: &[String]) -> Vec<Hit> {
    let mut hits = Vec::new();
    let own: Vec<String> = facts
        .runs
        .iter()
        .filter(|(raw, key)| {
            st.unreadable
                || st.written_full
                || st
                    .written
                    .iter()
                    .chain(facts.writes.iter())
                    .any(|w| paths::same_file(raw, key, w))
        })
        .map(|(_, key)| key.clone())
        .collect();
    if !own.is_empty() {
        hits.push(Hit {
            rule: "session-written-code",
            why: format!("runs code this chat wrote ({})", shown(&own)),
            paths: own,
        });
    }
    if !st.tainted() {
        return hits;
    }
    let after = match st.marks.first() {
        Some(m) if m.reason == "secret-read" => format!("after a secret read ({})", m.tool),
        Some(m) => format!("after untrusted content ({}, {})", m.kind, m.tool),
        None => "after a taint state that could not be read".to_string(),
    };
    let protected: Vec<(String, String)> = facts
        .writes
        .iter()
        .filter_map(|w| paths::protected(w).map(|why| (w.clone(), why)))
        .collect();
    if !protected.is_empty() {
        hits.push(Hit {
            rule: "protected-write",
            why: format!(
                "writes {} ({}) {after}",
                shown(&protected.iter().map(|p| p.0.clone()).collect::<Vec<_>>()),
                protected[0].1
            ),
            paths: protected.into_iter().map(|p| p.0).collect(),
        });
    }
    if facts.install {
        hits.push(Hit {
            rule: "install",
            why: format!("installs a package {after}"),
            paths: Vec::new(),
        });
    }
    if facts.push {
        hits.push(Hit {
            rule: "push",
            why: format!("pushes {after}"),
            paths: Vec::new(),
        });
    }
    let named_here: Vec<String> = facts
        .hosts
        .iter()
        .filter(|h| named.contains(h))
        .cloned()
        .collect();
    if !named_here.is_empty() {
        hits.push(Hit {
            rule: "named-in-result",
            why: format!(
                "reaches {}, which an untrusted result in this chat named",
                shown(&named_here)
            ),
            paths: Vec::new(),
        });
    }
    let new: Vec<String> = facts
        .hosts
        .iter()
        .filter(|h| st.hosts_full || !st.hosts.contains(&fingerprint(h)))
        .cloned()
        .collect();
    if !new.is_empty() {
        hits.push(Hit {
            rule: "new-host",
            why: format!("reaches {} for the first time {after}", shown(&new)),
            paths: Vec::new(),
        });
    }
    hits
}

fn action_str(a: Action) -> &'static str {
    match a {
        Action::Allow => "allow",
        Action::Ask => "ask",
        Action::Deny => "deny",
    }
}

fn shown(items: &[String]) -> String {
    let mut s = items.iter().take(3).cloned().collect::<Vec<_>>().join(", ");
    if items.len() > 3 {
        s.push_str(&format!(" and {} more", items.len() - 3));
    }
    s
}

fn clean(s: &str, max: usize) -> String {
    let c: String = s
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | ':' | '-') {
                c
            } else {
                '_'
            }
        })
        .take(max)
        .collect();
    if c.is_empty() {
        "unknown".into()
    } else {
        c
    }
}

/// The `taint.mark` id of the call `tool_use_id` (`contracts/events.md`
/// section 6.2: `<harness>-<tool_use_id>-taint`).
pub fn mark_id(harness: &str, tool_use_id: Option<&str>) -> String {
    match tool_use_id {
        Some(t) => format!("{harness}-{}-taint", clean(t, 96)),
        None => format!("{harness}-unknown-{}-taint", uuid::Uuid::new_v4().simple()),
    }
}

fn mark_event(m: &Mark, chat: &str, harness: &str) -> AdapterEvent {
    let mut detail = Map::new();
    detail.insert("reason".into(), Value::from(m.reason.clone()));
    detail.insert("kind".into(), Value::from(m.kind.clone()));
    detail.insert("tool".into(), Value::from(m.tool.clone()));
    detail.insert("via".into(), Value::from("hook"));
    if let Some(t) = &m.tool_use_id {
        detail.insert("toolUseId".into(), Value::from(t.clone()));
    }
    AdapterEvent {
        id: m.id.clone(),
        chat_id: chat.to_string(),
        harness: harness.to_string(),
        kind: "taint.mark".into(),
        summary: format!(
            "taint: {} ({})",
            if m.reason == "secret-read" {
                "a secret read"
            } else {
                "untrusted content"
            },
            m.tool
        ),
        detail,
    }
}

struct Review<'a> {
    hits: &'a [Hit],
    verdict: Verdict,
    from: From,
    gave: Action,
    marks: Vec<String>,
}

fn review_event(r: &Review, call: &GateCall, chat: &str) -> AdapterEvent {
    let mut detail = Map::new();
    detail.insert("verdict".into(), Value::from(r.verdict.as_str()));
    detail.insert("from".into(), Value::from(r.from.as_str()));
    detail.insert("gave".into(), Value::from(action_str(r.gave)));
    if r.verdict == Verdict::Record {
        detail.insert("wouldBe".into(), Value::from("ask"));
    }
    detail.insert("rule".into(), Value::from(r.hits[0].rule));
    detail.insert(
        "rules".into(),
        Value::from(r.hits.iter().map(|h| h.rule).collect::<Vec<_>>()),
    );
    detail.insert("marks".into(), Value::from(r.marks.clone()));
    let paths: Vec<String> = r
        .hits
        .iter()
        .flat_map(|h| h.paths.clone())
        .take(8)
        .collect();
    if !paths.is_empty() {
        detail.insert("paths".into(), Value::from(paths));
    }
    if let Some(t) = &call.tool_use_id {
        detail.insert("toolUseId".into(), Value::from(t.clone()));
    }
    let call_part = clean(call.tool_use_id.as_deref().unwrap_or("unknown"), 48);
    AdapterEvent {
        id: format!(
            "{}-{call_part}-taint-review-{}",
            call.harness,
            uuid::Uuid::new_v4().simple()
        ),
        chat_id: chat.to_string(),
        harness: call.harness.clone(),
        kind: "taint.review".into(),
        summary: format!(
            "taint {}: {} {}",
            r.hits[0].rule,
            r.verdict.as_str(),
            action_str(r.gave)
        ),
        detail,
    }
}

/// The verdict of a light-tier chat: the setting, else `ask`.
fn light_verdict(home: Option<&Path>) -> (Verdict, From) {
    let setting = home
        .map(|h| verdict::from_settings(&h.join(".derm").join("settings.json")).0)
        .unwrap_or(None);
    match setting {
        Some(v) => (v, From::Setting),
        None => (Verdict::Ask, From::Default),
    }
}

/// The seam `decide_call` calls with the policy's answer.
pub fn adjust(answer: GateAnswer, call: &GateCall, env: &Env) -> GateAnswer {
    let Some(chat) = call.chat.as_deref().filter(|c| !c.is_empty()) else {
        return answer;
    };
    let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("/"));
    adjust_in(answer, call, env, chat, &cwd)
}

/// [`adjust`], reading relative paths from `cwd`.
pub fn adjust_in(
    answer: GateAnswer,
    call: &GateCall,
    env: &Env,
    chat: &str,
    cwd: &Path,
) -> GateAnswer {
    adjust_with(answer, call, env, chat, cwd, DAEMON_TIER)
}

/// Whether a `derm run` chat (one whose hook has a chat token) keeps its
/// taint in the daemon. On since integration w6's phase 2 merge routed
/// `op: "taint"` to `derm_daemon::taint::Taints::handle` and its ingest to
/// `Taints::on_event` (lane 6D's request 6D-1). The hook-case replays
/// (`tests/hook_cases_5bA.rs`, `_5bB.rs`) compare the daemon lines a hook
/// sends with the TypeScript's, which had no taint: they leave taint's own
/// lines out (`tests/support/replay.rs`), and taint's tests hold them.
pub const DAEMON_TIER: bool = true;

/// [`adjust_in`], with the daemon tier on or off.
pub fn adjust_with(
    answer: GateAnswer,
    call: &GateCall,
    env: &Env,
    chat: &str,
    cwd: &Path,
    daemon_tier: bool,
) -> GateAnswer {
    let token = daemon::chat_token(env, cwd).is_some();
    if token && !daemon_tier {
        return answer;
    }
    let home = state::home(env);
    // With no home the light tier keeps nothing: its log cannot be written
    // either, and the dialect denies the call for that (`daemon::lost_deny`).
    if !token && home.is_none() {
        return answer;
    }
    let facts = facts::of(
        &answer.normalized_tool,
        &call.tool_input,
        cwd,
        home.as_deref(),
    );
    if facts.is_empty() {
        return answer;
    }
    // Under `derm run` the daemon holds the chat's state and verdict; when
    // it refuses `op: "taint"` (an older daemon, a chat id the token does
    // not hold, the sbx VM's route) the file is used, with the strictest
    // verdict, since the person's `--taint` cannot be read (rules section 9,
    // item 7: fail safe).
    let (from_daemon, accepted) = if token {
        state::daemon_ask(env, cwd, chat, &facts.hosts)
    } else {
        (None, false)
    };
    // A token alone may be a project's (case 227): only a hook whose daemon
    // took its token, or whose token a real `derm run` above it gave, skips
    // the light tier's fail-safe rules (integration w6's review, W6C-S4;
    // re-review W6C-R6).
    let run_chat = token && (accepted || daemon::derm_run_chat(env, cwd));
    let (st, verdict, from, named, store) = match from_daemon {
        Some(d) => (d.state, d.verdict, d.from, d.named, Store::Daemon),
        None => {
            let path = home.as_deref().map(|h| state::file_path(h, chat));
            let loaded = path.as_deref().map(state::load);
            match (path, loaded) {
                (Some(p), Some(Ok(s))) => {
                    let (v, f) = if token {
                        (Verdict::Deny, From::Default)
                    } else {
                        light_verdict(home.as_deref())
                    };
                    (s, v, f, Vec::new(), Store::File(p))
                }
                // A `derm run` chat whose daemon and file both refused (srt
                // denies `~/.derm` to its hooks, note AZ B8): taint is off
                // for it until the daemon answers (the lane's Open items).
                _ if run_chat => return answer,
                // The light tier whose state cannot be read (a lock held
                // past the deadline, a folder others can write): fail safe,
                // as a state that does not parse.
                _ => {
                    let (v, f) = light_verdict(home.as_deref());
                    let s = State {
                        v: 1,
                        unreadable: true,
                        ..State::default()
                    };
                    (s, v, f, Vec::new(), Store::None)
                }
            }
        }
    };
    let hits = rules(&facts, &st, &named);
    let mut out = answer.clone();
    let mut review = None;
    if !hits.is_empty() {
        let why = hits
            .iter()
            .map(|h| h.why.clone())
            .collect::<Vec<_>>()
            .join("; ");
        let raised = match verdict {
            Verdict::Deny if answer.action != Action::Deny => Some(Action::Deny),
            Verdict::Ask if answer.action == Action::Allow => Some(Action::Ask),
            _ => None,
        };
        let record =
            raised.is_some() || (verdict == Verdict::Record && answer.action == Action::Allow);
        if let Some(a) = raised {
            out.action = a;
            out.reason = format!(
                "taint: {why} (the chat's verdict is {}, {}); {}",
                verdict.as_str(),
                from.as_str(),
                answer.reason
            );
            out.updated_input = None;
        }
        if record {
            review = Some(Review {
                hits: &hits,
                verdict,
                from,
                gave: out.action,
                marks: st.marks.iter().map(|m| m.id.clone()).collect(),
            });
        }
    }
    // What this call adds to the chat's state.
    let mut add = State {
        v: 1,
        ..State::default()
    };
    let mut new_mark = None;
    if out.action != Action::Deny {
        if let Some(src) = facts.source {
            let id = mark_id(&call.harness, call.tool_use_id.as_deref());
            if !st.marks.iter().any(|m| m.id == id) {
                let m = Mark {
                    id,
                    reason: src.reason.into(),
                    kind: src.kind.into(),
                    tool: out.normalized_tool.clone(),
                    tool_use_id: call.tool_use_id.clone(),
                };
                add.marks.push(m.clone());
                new_mark = Some(m);
            }
        }
        add.written = facts.writes.clone();
    }
    if out.action == Action::Allow {
        add.hosts = facts.hosts.iter().map(|h| fingerprint(h)).collect();
    }
    if !add.is_empty() {
        let kept = match &store {
            Store::Daemon => state::daemon_add(env, cwd, chat, &add),
            Store::File(p) => state::save(p, &add),
            Store::None => Err("no taint state could be read".into()),
        };
        // The light tier fails closed, as its log does: a call that taints
        // the chat or writes a file is not run when that cannot be kept,
        // or a later call would not know.
        if let Err(why) = kept {
            let carries = !add.marks.is_empty() || !add.written.is_empty();
            if !run_chat && carries && out.action != Action::Deny {
                out.action = Action::Deny;
                out.reason = format!(
                    "derm's taint state: {why}; with no daemon a call that taints the chat or writes a file is not run unkept (the light tier fails closed)"
                );
                out.updated_input = None;
            }
        }
    }
    if let Some(m) = &new_mark {
        let _ = daemon::post_event_kept(&mark_event(m, chat, &call.harness), env, cwd);
    }
    if let Some(mut r) = review {
        r.gave = out.action;
        if let Some(m) = &new_mark {
            r.marks.push(m.id.clone());
        }
        let _ = daemon::post_event_kept(&review_event(&r, call, chat), env, cwd);
    }
    out
}
