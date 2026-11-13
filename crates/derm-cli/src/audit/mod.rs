//! `derm audit` (wave 6, lane 6E; `plans/toolkit_wave6_plan.md` section 2.1;
//! `contracts/events.md` sections 6.4 and 6.5; note AZ rows E1 to E4, AZ-1):
//!
//! - `verify`: checks a chain with no daemon: the daemon's log (v1), a
//!   light-tier log or an export (v2), against a start and anchors;
//! - `export`: a chain as JSON Lines, content left out unless asked for;
//! - `anchor`: records a chain's head in a file or on a git ref the person
//!   names, from a terminal only;
//! - `why <call>`: one call's intent, decision and effects on one screen.
//!
//! The line formats are the references': `derm_core::audit_chain` (v2) and
//! `derm_daemon::activity::chain` (v1); nothing here hashes a line itself.
//! The OCSF 1.9.0 mapping (E4) is not built.

mod anchor;
mod chains;
mod export;
mod sources;
mod verify;
mod why;

#[cfg(test)]
mod tests;

use sources::Source;

pub const USAGE: &str = "usage: derm audit <verify|export|anchor|why> ...\n  derm audit verify [<file>... | --light <chat>] [--data-dir <dir>] [--start <seq>:<prev>] [--anchor <seq>:<hash>]... [--anchors <file|git repo> [--chain <label>]] [--json]\n  derm audit export [<file>... | --light <chat>] [--data-dir <dir>] [--out <file>] [--content]\n  derm audit anchor (--file <path> | --git <repo>) [<file>... | --light <chat>] [--data-dir <dir>]\n  derm audit why <call id> [--chat <chat>] [--data-dir <dir>] [--all] [--json]";

pub fn main(args: &[String]) -> u8 {
    match args.first().map(String::as_str) {
        Some("verify") => verify::main(&args[1..]),
        Some("export") => export::main(&args[1..]),
        Some("anchor") => anchor_main(&args[1..], &|v| std::env::var_os(v), anchor::on_terminal()),
        Some("why") => why::main(&args[1..]),
        Some("-h") | Some("--help") => {
            println!("{USAGE}");
            0
        }
        _ => {
            eprintln!("{USAGE}");
            2
        }
    }
}

const ANCHOR_USAGE: &str = "usage: derm audit anchor (--file <path> | --git <repo>) [<file>... | --light <chat>] [--data-dir <dir>]";

/// `derm audit anchor`: refuses inside a chat and without a terminal, then
/// refuses a chain that does not hold (OpenMoat's \"refusing to anchor a
/// broken log\"), then keeps the head and the first line read.
fn anchor_main(args: &[String], var: &dyn Fn(&str) -> Option<std::ffi::OsString>, tty: bool) -> u8 {
    let mut files = Vec::new();
    let mut light: Option<String> = None;
    let mut data: Option<String> = None;
    let mut place: Option<anchor::Place> = None;
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--file" | "--git" | "--light" | "--data-dir" => {
                let Some(v) = it.next() else {
                    eprintln!("derm audit anchor: {a} needs a value\n{ANCHOR_USAGE}");
                    return 2;
                };
                match a.as_str() {
                    "--file" | "--git" => {
                        let p = std::path::PathBuf::from(v);
                        if !p.is_absolute() {
                            eprintln!("derm audit anchor: {a} {v:?}: give an absolute path");
                            return 2;
                        }
                        place = Some(if a == "--git" {
                            anchor::Place::Git(p)
                        } else {
                            anchor::Place::File(p)
                        });
                    }
                    "--light" => light = Some(v.clone()),
                    _ => data = Some(v.clone()),
                }
            }
            s if s.starts_with('-') => {
                eprintln!("derm audit anchor: unknown flag {s}\n{ANCHOR_USAGE}");
                return 2;
            }
            s => files.push(std::path::PathBuf::from(s)),
        }
    }
    let Some(place) = place else {
        eprintln!("derm audit anchor: give --file <path> or --git <repo>\n{ANCHOR_USAGE}");
        return 2;
    };
    if let Some(why) = anchor::refuse(var, tty) {
        eprintln!("derm audit anchor: refused: {why}");
        return 2;
    }
    let src = if !files.is_empty() {
        Source::Files(files)
    } else if let Some(c) = light {
        match sources::light_file(&c) {
            Some(file) => Source::Light { chat: c, file },
            None => {
                eprintln!("derm audit anchor: no home folder");
                return 2;
            }
        }
    } else {
        match sources::data_dir(data.as_deref()) {
            Ok(d) => Source::Daemon(d),
            Err(e) => {
                eprintln!("derm audit anchor: {e}");
                return 2;
            }
        }
    };
    anchor_source(&src, &place, derm_daemon::activity::store::now_ms())
}

fn anchor_source(src: &Source, place: &anchor::Place, now_ms: i64) -> u8 {
    let o = verify::check(src, None, &[]);
    if let Some((n, why)) = &o.failure {
        eprintln!(
            "derm audit anchor: refusing to anchor a chain that does not hold: {} at {}: {why}; keep the file as evidence",
            src.describe(),
            o.place(*n)
        );
        return 1;
    }
    let Some(record) = verify::head_record(&o, now_ms) else {
        eprintln!(
            "derm audit anchor: {} has no lines yet; nothing to anchor",
            src.describe()
        );
        return 1;
    };
    match place.append(&record) {
        Ok(commit) => {
            println!(
                "anchored {} at seq {} hash {} in {}",
                record.chain,
                record.seq,
                record.hash,
                place.describe()
            );
            if let Some(c) = commit {
                println!("  committed {c} on {}; nothing was pushed", anchor::REF);
            } else {
                println!("  nothing was sent anywhere: keep a copy off this machine yourself");
            }
            println!(
                "  check it later: derm audit verify --anchors {}",
                match place {
                    anchor::Place::Git(p) | anchor::Place::File(p) => p.display(),
                }
            );
            0
        }
        Err(e) => {
            eprintln!("derm audit anchor: {e}");
            2
        }
    }
}
