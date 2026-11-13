//! `derm audit export`: a chain as JSON Lines (`contracts/events.md`
//! section 6.5, E1, case 221).
//!
//! - The light tier's log (chain v2) is carried line for line.
//! - The daemon's log (v1) is carried with the v1 rule: each line with
//!   `"v": 1` added, which the v1 hash does not cover (it hashes `prev` and
//!   the record, `derm-daemon/src/activity/chain.rs`), so the line still
//!   verifies as the daemon wrote it. It is not re-chained as v2: v1 records
//!   can hold floating-point numbers (a harness's OTel attributes), which
//!   chain v2 refuses (note AZ, E2), and a new chain would vouch only for the
//!   export, not for the daemon's log. Migrating the daemon's own log to v2
//!   is integration's (a request in the lane's status doc).
//! - Content stays out unless the person asks (`--content`): a record that
//!   holds content becomes a withheld line (`chains::WITHHELD`), which keeps
//!   the chain. Today's records hold none (content lives in content files,
//!   `derm-tap/src/content.rs:1-11`), so this bites only on an old log.
//! - A chain that breaks is exported up to the line before the break, and
//!   the command says where and exits 1: nothing past a break is vouched for.
//!
//! Every exported file verifies with `derm audit verify <file>`, with the
//! `--start` the summary prints when the export does not begin a chain.

use std::fs::OpenOptions;
use std::io::{BufWriter, Write};
use std::path::PathBuf;

use super::chains::{self, Version};
use super::sources::{self, Source};
use super::verify;

pub const USAGE: &str = "usage: derm audit export [<file>... | --light <chat>] [--data-dir <dir>] [--out <file>] [--content]";

/// What an export wrote.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Summary {
    pub lines: usize,
    pub withheld: usize,
    pub with_content: usize,
    pub start: Option<(u64, String)>,
    pub head: Option<(u64, String)>,
    pub broken: Option<String>,
}

/// Writes `src`'s chain to `out`.
pub fn export(src: &Source, content: bool, out: &mut dyn Write) -> Result<Summary, String> {
    let o = verify::check(src, None, &[]);
    if o.lines.is_empty() {
        if let Some((_, why)) = &o.failure {
            return Err(why.clone());
        }
        return Ok(Summary::default());
    }
    let version = o.report.version.unwrap_or(Version::V2);
    let mut s = Summary {
        start: o.report.first().and_then(|f| {
            let genesis = f.seq == version.first_seq() && f.prev == derm_core::audit_chain::GENESIS;
            (!genesis).then(|| (f.seq, f.prev.clone()))
        }),
        head: o.report.last().map(|l| (l.seq, l.hash.clone())),
        broken: o
            .failure
            .as_ref()
            .map(|(n, why)| format!("{}: {why}", o.place(*n))),
        ..Summary::default()
    };
    for (i, link) in o.report.links.iter().enumerate() {
        let text = &o.lines[i].text;
        let line = match &link.record {
            // Already withheld in what was read: carried as it is.
            None => {
                s.withheld += 1;
                text.clone()
            }
            Some(r) if chains::holds_content(r) && !content => {
                s.withheld += 1;
                chains::withheld_line(version, link)
            }
            Some(r) => {
                if chains::holds_content(r) {
                    s.with_content += 1;
                }
                match version {
                    Version::V2 => text.clone(),
                    Version::V1 => chains::v1_export_line(link),
                }
            }
        };
        out.write_all(line.as_bytes())
            .and_then(|()| out.write_all(b"\n"))
            .map_err(|e| format!("writing: {e}"))?;
        s.lines += 1;
    }
    out.flush().map_err(|e| format!("writing: {e}"))?;
    Ok(s)
}

pub fn main(args: &[String]) -> u8 {
    let mut files = Vec::new();
    let mut light: Option<String> = None;
    let mut data: Option<String> = None;
    let mut out_path: Option<PathBuf> = None;
    let mut content = false;
    let mut it = args.iter();
    while let Some(a) = it.next() {
        let r: Result<(), String> = match a.as_str() {
            "--light" | "--data-dir" | "--out" => match it.next() {
                Some(v) => {
                    match a.as_str() {
                        "--light" => light = Some(v.clone()),
                        "--data-dir" => data = Some(v.clone()),
                        _ => out_path = Some(PathBuf::from(v)),
                    }
                    Ok(())
                }
                None => Err(format!("{a} needs a value")),
            },
            "--content" => {
                content = true;
                Ok(())
            }
            "--ocsf" => {
                Err("--ocsf: the OCSF 1.9.0 mapping is not built (lane 6E's status doc)".into())
            }
            "-h" | "--help" => Err(String::new()),
            s if s.starts_with('-') => Err(format!("unknown flag {s}")),
            s => {
                files.push(PathBuf::from(s));
                Ok(())
            }
        };
        if let Err(e) = r {
            if !e.is_empty() {
                eprintln!("derm audit export: {e}");
            }
            eprintln!("{USAGE}");
            return 2;
        }
    }
    let src = if !files.is_empty() {
        if light.is_some() {
            eprintln!("derm audit export: give files or --light, not both\n{USAGE}");
            return 2;
        }
        Source::Files(files)
    } else if let Some(c) = light {
        match sources::light_file(&c) {
            Some(file) => Source::Light { chat: c, file },
            None => {
                eprintln!("derm audit export: no home folder");
                return 2;
            }
        }
    } else {
        match sources::data_dir(data.as_deref()) {
            Ok(d) => Source::Daemon(d),
            Err(e) => {
                eprintln!("derm audit export: {e}");
                return 2;
            }
        }
    };
    let result = match &out_path {
        Some(p) => match create_private(p) {
            Ok(f) => export(&src, content, &mut BufWriter::new(f)),
            Err(e) => Err(e),
        },
        None => {
            let stdout = std::io::stdout();
            let mut lock = stdout.lock();
            export(&src, content, &mut lock)
        }
    };
    let s = match result {
        Ok(s) => s,
        Err(e) => {
            eprintln!("derm audit export: {}: {e}", src.describe());
            return 2;
        }
    };
    eprintln!(
        "derm audit export: {} line(s) from {}{}",
        s.lines,
        src.describe(),
        out_path
            .as_ref()
            .map(|p| format!(" to {}", p.display()))
            .unwrap_or_default()
    );
    if s.withheld > 0 {
        eprintln!(
            "  {} line(s) withheld for their content (give --content to keep them)",
            s.withheld
        );
    }
    if s.with_content > 0 {
        eprintln!("  {} line(s) hold content (--content)", s.with_content);
    }
    if let Some((seq, prev)) = &s.start {
        eprintln!("  it does not begin a chain: verify it with --start {seq}:{prev}");
    }
    if let Some((seq, hash)) = &s.head {
        eprintln!("  head {seq}:{hash}");
    }
    if let Some(b) = &s.broken {
        eprintln!("  the chain breaks at {b}; nothing from that line on was exported");
        return 1;
    }
    0
}

/// A new file of the person's: 0600, never an existing file, never through
/// a link (rules section 5, items 3 and 10).
fn create_private(path: &std::path::Path) -> Result<std::fs::File, String> {
    let mut o = OpenOptions::new();
    o.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    o.open(path)
        .map_err(|e| format!("{}: {e} (an export never replaces a file)", path.display()))
}
