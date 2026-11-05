//! A standalone tap for the contract checks (`tests/cli-contract/checks/S/`):
//! the same server the daemon starts, with records written to a file as
//! JSON lines instead of the daemon's log. Never shipped.
//!
//!   cargo build -p derm-tap --example tap_dev
//!   tap_dev --token <64 hex> --chat <id> --harness <id> --records <file>
//!           --upstream <key>=<base>[,local] ... [--content <dir> --days <n>]
//!           [--launch <harness>]
//!
//! It prints `listening <endpoint>` on its first line; with `--launch`, a
//! second line holds the JSON of `derm_tap::launch` for that harness's row
//! as `derm run` would build it (read from the preset table passed with
//! `--row`). It stops when its stdin closes.

use std::collections::BTreeMap;
use std::io::{BufRead, Write};
use std::sync::{Arc, Mutex};

use derm_tap::upstream::Upstream;
use derm_tap::{content, launch, route, Chat, Config, Tap};
use serde_json::{json, Value};

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut token = String::new();
    let mut chat = "chat-dev".to_string();
    let mut harness = "claude-code".to_string();
    let mut records = String::new();
    let mut upstreams = BTreeMap::new();
    let mut content_dir: Option<String> = None;
    let mut days: u8 = 1;
    let mut row: Option<Value> = None;
    let mut i = 0;
    while i < args.len() {
        let v = args.get(i + 1).cloned().unwrap_or_default();
        match args[i].as_str() {
            "--token" => token = v,
            "--chat" => chat = v,
            "--harness" => harness = v,
            "--records" => records = v,
            "--content" => content_dir = Some(v),
            "--days" => days = v.parse().unwrap_or(1),
            "--row" => row = serde_json::from_str(&v).ok(),
            "--upstream" => {
                let (key, rest) = v.split_once('=').expect("--upstream key=base");
                let (base, local) = match rest.strip_suffix(",local") {
                    Some(b) => (b, true),
                    None => (rest, false),
                };
                upstreams.insert(
                    key.to_string(),
                    Upstream {
                        base: base.trim_end_matches('/').to_string(),
                        local,
                    },
                );
            }
            other => panic!("unknown argument {other}"),
        }
        i += 2;
    }
    assert!(
        derm_core::token::well_formed(&token),
        "--token takes 64 hex characters"
    );
    let want = route::of_token(&token);
    let out = Arc::new(Mutex::new(
        std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&records)
            .expect("--records"),
    ));
    let sink_out = out.clone();
    let the_chat = Chat { id: chat, harness };
    let resolve_chat = the_chat.clone();
    let mut config = Config::new(
        Arc::new(move |r: &str| (r == want).then(|| resolve_chat.clone())),
        Arc::new(move |events| {
            if let Ok(mut f) = sink_out.lock() {
                for e in events {
                    let _ = writeln!(f, "{}", serde_json::to_string(&e).unwrap_or_default());
                }
                let _ = f.flush();
            }
        }),
    );
    if !upstreams.is_empty() {
        config.upstreams = upstreams;
    }
    if let Some(dir) = content_dir {
        config.content = Arc::new(move |_| {
            Some(content::Target {
                root: dir.clone().into(),
                retention_days: days,
            })
        });
    }
    let tap = Tap::start(config).expect("start");
    println!("listening {}", tap.endpoint());
    if let Some(r) = row {
        let l = launch::launch(&r, &tap.endpoint(), &route::of_token(&token));
        let v = match l {
            Ok(l) => json!({"env": l.env, "args": l.args, "via": l.via}),
            Err(_) => json!({"off": "no-base-url"}),
        };
        println!("{v}");
    }
    let _ = std::io::stdout().flush();
    for _ in std::io::stdin().lock().lines() {}
    tap.stop();
}
