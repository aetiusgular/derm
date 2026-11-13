//! Reading a shell call for taint: which files it writes, which files it
//! runs, which hosts it reaches, whether it pushes. The text is the gate's
//! folded input (`derm_core::policy::fold_text`), so words are lowercase.
//!
//! What it follows, and the prior art for each (OpenMoat 0.19.0's
//! `openmoat-core` classifier, MIT OR Apache-2.0; read, no code copied):
//! output redirections (`>`, `>>`, `>|`, `&>`, `2>`), `tee`, the destination
//! of `cp`, `mv`, `install` and `ln`, `curl -o`, `wget -O`, `sed -i` and
//! `dd of=` as writes; a script an interpreter is given, a program named by a
//! path (`./run.sh`) and `source` as runs (`session_code.rs`, ADR-039);
//! inline interpreter code that writes (`python3 -c 'open("x.py","w")'`)
//! writes every file name it shows as literal text
//! (`shell/commands/payload/writes.rs`); wrappers (`sudo`, `env`, `timeout`,
//! `xargs`, `npx`), `sh -c`, `bash -c` and `eval` are read through, four
//! deep, as `derm_core::command` reads them for command rules (case 144).
//! Here-document bodies are skipped: they are data, not commands.
//!
//! Every reading is conservative where it guesses: a word read as a write or
//! a host that is not one only asks more (taint only raises).

use super::paths;
use derm_tap::results::hosts;

/// One simple command: its words, as the shell would pass them.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Cmd {
    pub words: Vec<String>,
}

/// What [`read`] found in a shell call.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Shell {
    /// Files written, as the words named them.
    pub writes: Vec<String>,
    /// Files run as code, as the words named them.
    pub runs: Vec<String>,
    /// Hosts reached, canonical.
    pub hosts: Vec<String>,
    /// A `git push` somewhere in the call.
    pub push: bool,
    /// Every word of every command, for the secret-path check.
    pub words: Vec<String>,
}

const MAX_DEPTH: usize = 4;

/// The lexer's state while it reads one text.
#[derive(Default)]
struct Lex {
    cmds: Vec<Cmd>,
    outs: Vec<String>,
    words: Vec<String>,
    word: String,
    in_word: bool,
    heredocs: Vec<(String, bool)>,
    /// What the next word is for: `None` a plain word; `Some(true)` an
    /// output target; `Some(false)` an input or a here-string.
    next_is: Option<bool>,
    /// The next word is a here-document's delimiter (`true`: `<<-`).
    delimiter_next: Option<bool>,
}

impl Lex {
    fn end_word(&mut self) {
        if self.in_word {
            let w = std::mem::take(&mut self.word);
            if let Some(strip) = self.delimiter_next.take() {
                self.heredocs.push((w, strip));
                self.next_is = None;
            } else {
                match self.next_is.take() {
                    Some(true) => self.outs.push(w),
                    Some(false) => {}
                    None => self.words.push(w),
                }
            }
        }
        self.word.clear();
        self.in_word = false;
    }

    fn end_cmd(&mut self) {
        self.end_word();
        if !self.words.is_empty() {
            let words = std::mem::take(&mut self.words);
            self.cmds.push(Cmd { words });
        }
    }
}

/// Splits shell text into simple commands, and the targets of every output
/// redirection in it.
pub fn split(text: &str) -> (Vec<Cmd>, Vec<String>) {
    let chars: Vec<char> = text.chars().collect();
    let mut l = Lex::default();
    let mut i = 0;
    while i < chars.len() {
        let ch = chars[i];
        match ch {
            '\'' => {
                l.in_word = true;
                i += 1;
                while i < chars.len() && chars[i] != '\'' {
                    l.word.push(chars[i]);
                    i += 1;
                }
            }
            '"' => {
                l.in_word = true;
                i += 1;
                while i < chars.len() && chars[i] != '"' {
                    if chars[i] == '\\' && i + 1 < chars.len() {
                        i += 1;
                    }
                    l.word.push(chars[i]);
                    i += 1;
                }
            }
            '\\' => {
                l.in_word = true;
                if i + 1 < chars.len() && chars[i + 1] != '\n' {
                    l.word.push(chars[i + 1]);
                }
                i += 1;
            }
            '#' if !l.in_word => {
                while i < chars.len() && chars[i] != '\n' {
                    i += 1;
                }
                continue;
            }
            '\n' => {
                l.end_cmd();
                // Here-document bodies follow the line that opened them.
                for (delim, strip) in std::mem::take(&mut l.heredocs) {
                    i += 1;
                    loop {
                        let start = i;
                        while i < chars.len() && chars[i] != '\n' {
                            i += 1;
                        }
                        let line: String = chars[start..i].iter().collect();
                        let line = if strip {
                            line.trim_start_matches('\t').to_string()
                        } else {
                            line
                        };
                        if line.trim_end() == delim || i >= chars.len() {
                            break;
                        }
                        i += 1;
                    }
                }
            }
            ';' | '|' | '(' | ')' | '`' | '\r' => l.end_cmd(),
            '&' => {
                if chars.get(i + 1) == Some(&'>') {
                    // `&>` and `&>>`: both streams to a file.
                    l.end_word();
                    i += 1;
                    while chars.get(i + 1) == Some(&'>') {
                        i += 1;
                    }
                    l.next_is = Some(true);
                } else {
                    l.end_cmd();
                }
            }
            '>' | '<' => {
                if l.in_word && !l.word.is_empty() && l.word.chars().all(|c| c.is_ascii_digit()) {
                    l.word.clear();
                    l.in_word = false;
                }
                l.end_word();
                let mut op = String::from(ch);
                while matches!(chars.get(i + 1), Some('>' | '<' | '&' | '|' | '-')) {
                    let c = chars[i + 1];
                    if c == '-' && op != "<<" {
                        break;
                    }
                    op.push(c);
                    i += 1;
                }
                // `>&2` and `2>&-` name a descriptor, not a file.
                let dup = op.ends_with('&')
                    && chars
                        .get(i + 1)
                        .is_some_and(|c| c.is_ascii_digit() || *c == '-');
                if dup {
                    i += 1;
                    while chars.get(i + 1).is_some_and(|c| c.is_ascii_digit()) {
                        i += 1;
                    }
                } else if op == "<<" || op == "<<-" {
                    l.delimiter_next = Some(op == "<<-");
                } else if op.starts_with('>') || op == "<>" {
                    l.next_is = Some(true);
                } else {
                    l.next_is = Some(false);
                }
            }
            c if c.is_whitespace() => l.end_word(),
            _ => {
                l.word.push(ch);
                l.in_word = true;
            }
        }
        i += 1;
    }
    l.end_cmd();
    (l.cmds, l.outs)
}

fn base(word: &str) -> &str {
    let b = word.rsplit('/').next().unwrap_or(word);
    b.strip_suffix(".exe").unwrap_or(b)
}

fn is_assignment(w: &str) -> bool {
    let Some((name, _)) = w.split_once('=') else {
        return false;
    };
    let mut c = name.chars();
    c.next()
        .is_some_and(|f| f.is_ascii_alphabetic() || f == '_')
        && c.all(|x| x.is_ascii_alphanumeric() || x == '_')
}

const SHELLS: &[&str] = &["sh", "bash", "zsh", "dash", "ksh", "mksh", "ash", "fish"];

/// Wrappers and the options of each that take a value.
fn wrapper_values(head: &str) -> Option<&'static [&'static str]> {
    Some(match head {
        "sudo" | "doas" => &["-u", "-g", "-c", "-C", "-D", "-h", "-p", "-r", "-t", "-U"],
        "env" => &["-u", "-C", "--unset", "--chdir"],
        "timeout" => &["-s", "--signal", "-k", "--kill-after"],
        "nice" => &["-n", "--adjustment"],
        "ionice" => &["-c", "-n", "-p"],
        "xargs" => &[
            "-n", "-I", "-i", "-P", "-L", "-l", "-d", "-a", "-E", "-e", "-s",
        ],
        "stdbuf" => &["-i", "-o", "-e"],
        "taskset" | "chrt" => &[],
        "command" | "exec" | "builtin" | "nohup" | "time" | "chronic" | "unbuffer" | "npx"
        | "bunx" | "pnpx" | "corepack" | "busybox" => &[],
        _ => return None,
    })
}

/// The commands a simple command runs, read through wrappers, shells' `-c`
/// and `eval`.
pub fn effective(text: &str) -> (Vec<Cmd>, Vec<String>) {
    let mut out = Vec::new();
    let mut outs = Vec::new();
    expand_text(text, 0, &mut out, &mut outs);
    (out, outs)
}

fn expand_text(text: &str, depth: usize, out: &mut Vec<Cmd>, outs: &mut Vec<String>) {
    if depth > MAX_DEPTH {
        return;
    }
    let (cmds, o) = split(text);
    outs.extend(o);
    for c in cmds {
        expand(c.words, depth, out, outs);
    }
}

fn expand(mut words: Vec<String>, depth: usize, out: &mut Vec<Cmd>, outs: &mut Vec<String>) {
    for _ in 0..16 {
        while words.first().is_some_and(|w| is_assignment(w)) {
            words.remove(0);
        }
        let Some(first) = words.first() else {
            return;
        };
        let head = base(first).to_string();
        if head == "eval" {
            expand_text(&words[1..].join(" "), depth + 1, out, outs);
            return;
        }
        if SHELLS.contains(&head.as_str()) {
            if let Some(s) = command_string(&words[1..]) {
                out.push(Cmd {
                    words: words.clone(),
                });
                expand_text(&s, depth + 1, out, outs);
                return;
            }
            out.push(Cmd { words });
            return;
        }
        let Some(values) = wrapper_values(&head) else {
            out.push(Cmd { words });
            return;
        };
        if head == "env" {
            if let Some(i) = words[1..]
                .iter()
                .position(|w| w == "-s" || w == "--split-string")
            {
                if let Some(s) = words.get(i + 2) {
                    expand_text(&s.clone(), depth + 1, out, outs);
                }
                return;
            }
        }
        // The wrapper's own options (and their values), then for `timeout`
        // its duration; what is left is the command.
        let mut j = 1;
        while j < words.len() {
            let w = words[j].as_str();
            if w == "--" {
                j += 1;
                break;
            }
            if is_assignment(w) && head == "env" {
                j += 1;
                continue;
            }
            if !w.starts_with('-') {
                break;
            }
            let takes = values.contains(&w);
            j += if takes { 2 } else { 1 };
        }
        if head == "timeout" && j < words.len() {
            j += 1;
        }
        if j >= words.len() {
            return;
        }
        words = words[j..].to_vec();
    }
}

/// `-c <string>` of a shell, as `derm_core::command` reads it.
fn command_string(words: &[String]) -> Option<String> {
    let mut saw_c = false;
    let mut i = 0;
    while i < words.len() {
        let w = words[i].as_str();
        if w == "--" {
            return if saw_c {
                words.get(i + 1).cloned()
            } else {
                None
            };
        }
        if !w.starts_with('-') && !w.starts_with('+') {
            return if saw_c { Some(w.to_string()) } else { None };
        }
        if matches!(w, "-o" | "+o" | "--rcfile" | "--init-file") {
            i += 2;
            continue;
        }
        let letters = &w[1..];
        if w.starts_with('-')
            && !letters.is_empty()
            && letters.bytes().all(|b| b.is_ascii_lowercase())
            && letters.contains('c')
        {
            saw_c = true;
        }
        i += 1;
    }
    None
}

/// Interpreters: their inline-code flags, the options that take a value, and
/// the flags after which no file runs (a module, stdin).
struct Interp {
    inline: &'static [&'static str],
    values: &'static [&'static str],
    no_file: &'static [&'static str],
}

fn interpreter(head: &str) -> Option<Interp> {
    let stem = head.trim_end_matches(|c: char| c.is_ascii_digit() || c == '.');
    Some(match stem {
        "python" | "pypy" => Interp {
            inline: &["-c"],
            values: &["-w", "-x", "-q"],
            no_file: &["-m", "-"],
        },
        "node" | "nodejs" => Interp {
            inline: &["-e", "--eval", "-p", "--print"],
            values: &[
                "-r",
                "--require",
                "--import",
                "--loader",
                "--experimental-loader",
                "--env-file",
                "--input-type",
                "-c",
            ],
            no_file: &["-", "--check", "-c", "--test"],
        },
        "bun" => Interp {
            inline: &["-e", "--eval", "-p", "--print"],
            values: &["-r", "--preload", "--cwd", "--env-file"],
            no_file: &["-"],
        },
        "deno" => Interp {
            inline: &["eval"],
            values: &["--config", "-c", "--import-map", "--env-file"],
            no_file: &["-"],
        },
        "ruby" => Interp {
            inline: &["-e"],
            values: &["-r", "-i", "-c", "-x"],
            no_file: &["-"],
        },
        "perl" => Interp {
            inline: &["-e", "-E"],
            values: &["-m", "-M", "-I"],
            no_file: &["-"],
        },
        "php" => Interp {
            inline: &["-r"],
            values: &["-c", "-d"],
            no_file: &["-"],
        },
        "lua" | "luajit" => Interp {
            inline: &["-e"],
            values: &["-l"],
            no_file: &["-"],
        },
        "rscript" => Interp {
            inline: &["-e"],
            values: &[],
            no_file: &["-"],
        },
        "osascript" | "pwsh" | "powershell" => Interp {
            inline: &["-e", "-c", "-command"],
            values: &[],
            no_file: &["-"],
        },
        "tsx" | "ts-node" => Interp {
            inline: &["-e", "--eval"],
            values: &[],
            no_file: &["-"],
        },
        _ if SHELLS.contains(&head) => Interp {
            inline: &["-c"],
            values: &["-o", "+o", "--rcfile", "--init-file"],
            no_file: &["-s", "-"],
        },
        _ => return None,
    })
}

/// A run's script and the inline code it was given, if any.
fn interpreter_parts(words: &[String], it: &Interp) -> (Option<String>, Option<String>) {
    let mut i = 1;
    // `deno run x.ts`, `bun run x.ts`: the subcommand, then the file.
    if matches!(
        base(&words[0]).trim_end_matches(|c: char| c.is_ascii_digit() || c == '.'),
        "deno" | "bun"
    ) && words.get(1).is_some_and(|w| w == "run")
    {
        i = 2;
    }
    while i < words.len() {
        let w = words[i].as_str();
        if it.inline.contains(&w) {
            return (None, words.get(i + 1).cloned());
        }
        if let Some((flag, code)) = w.split_once('=') {
            if it.inline.contains(&flag) {
                return (None, Some(code.to_string()));
            }
        }
        if it.no_file.contains(&w) {
            return (None, None);
        }
        if w == "--" {
            return (words.get(i + 1).cloned(), None);
        }
        if w.starts_with('-') || w.starts_with('+') {
            i += if it.values.contains(&w) { 2 } else { 1 };
            continue;
        }
        return (Some(w.to_string()), None);
    }
    (None, None)
}

/// Calls in inline code that write a file whatever their arguments
/// (OpenMoat 0.19.0 `payload/writes.rs`'s list, lowercased since the text
/// is folded).
const CODE_WRITERS: &[&str] = &[
    "write_text",
    "write_bytes",
    ".touch(",
    "shutil.copy",
    "shutil.move",
    "os.rename",
    "os.replace",
    "os.symlink",
    "os.link",
    "writefilesync",
    "writefile(",
    "appendfilesync",
    "appendfile(",
    "createwritestream",
    "copyfilesync",
    "copyfile(",
    "renamesync",
    "symlinksync",
    "deno.writetextfile",
    "deno.writefile",
    "bun.write",
    "file.write",
    "io.write",
    "binwrite",
    "fileutils.",
    "file_put_contents",
    "set-content",
    "add-content",
    "out-file",
];

/// Whether inline code opens a file for writing: an `open(` (or `fopen(`,
/// `opensync(`, `file.new(`) with a mode that writes (`w`, `a`, `x`, `+`), or
/// an `o_wronly`/`o_creat`-style flag, or Perl's `open(f, ">x")`.
fn code_writes(code: &str) -> bool {
    if CODE_WRITERS.iter().any(|w| code.contains(w)) {
        return true;
    }
    if ["o_wronly", "o_rdwr", "o_creat", "o_append", "o_trunc"]
        .iter()
        .any(|f| code.contains(f))
    {
        return true;
    }
    for opener in ["open(", "fopen(", "opensync(", "file.new("] {
        for (at, _) in code.match_indices(opener) {
            let rest = &code[at + opener.len()..];
            let args = &rest[..rest.find(')').unwrap_or(rest.len())];
            if literals(args).iter().skip(1).any(|m| {
                let m = m.trim();
                !m.is_empty()
                    && m.len() <= 3
                    && m.chars()
                        .all(|c| matches!(c, 'w' | 'a' | 'x' | '+' | 'b' | 't' | 'r'))
                    && m.contains(['w', 'a', 'x', '+'])
            }) || literals(args)
                .first()
                .is_some_and(|l| l.starts_with(['>', '+']))
            {
                return true;
            }
        }
    }
    false
}

/// The quoted literals of inline code, in order.
fn literals(code: &str) -> Vec<String> {
    let mut out = Vec::new();
    let chars: Vec<char> = code.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        let q = chars[i];
        if matches!(q, '"' | '\'' | '`') {
            let mut s = String::new();
            i += 1;
            while i < chars.len() && chars[i] != q {
                if chars[i] == '\\' && i + 1 < chars.len() {
                    i += 1;
                }
                s.push(chars[i]);
                i += 1;
            }
            out.push(s);
        }
        i += 1;
    }
    out
}

/// A literal that names a file: a path, or a name with an extension.
fn names_a_file(l: &str) -> bool {
    let l = l.trim_start_matches(['+', '>', '<', ' ']);
    if l.is_empty() || l.len() > 4096 || l.contains(char::is_whitespace) || l.contains("://") {
        return false;
    }
    if l.contains('/') {
        return true;
    }
    match l.rsplit_once('.') {
        Some((stem, ext)) => {
            !stem.is_empty()
                && !ext.is_empty()
                && ext.len() <= 8
                && ext.chars().all(|c| c.is_ascii_alphanumeric())
        }
        None => false,
    }
}

/// Files inline `code` writes: every file name it shows, when it writes at
/// all (OpenMoat's reading: it cannot tell which name the write goes to).
pub fn inline_writes(code: &str) -> Vec<String> {
    if !code_writes(code) {
        return Vec::new();
    }
    literals(code)
        .into_iter()
        .map(|l| l.trim_start_matches(['+', '>', '<', ' ']).to_string())
        .filter(|l| names_a_file(l))
        .collect()
}

/// Network programs and the options of each that take a value.
fn net_values(head: &str) -> Option<&'static [&'static str]> {
    Some(match head {
        "curl" => &[
            "-o",
            "--output",
            "-d",
            "--data",
            "--data-raw",
            "--data-binary",
            "--data-urlencode",
            "-h",
            "--header",
            "-u",
            "--user",
            "-x",
            "--request",
            "-t",
            "--upload-file",
            "-f",
            "--form",
            "-a",
            "--user-agent",
            "-e",
            "--referer",
            "-b",
            "--cookie",
            "-c",
            "--cookie-jar",
            "-k",
            "--config",
            "-m",
            "--max-time",
            "-w",
            "--write-out",
            "--cacert",
            "--cert",
            "--key",
            "--connect-timeout",
            "--retry",
            "-r",
            "--range",
            "--resolve",
            "--connect-to",
            "-y",
            "-y",
            "--json",
        ],
        "wget" => &[
            "-o",
            "--output-document",
            "--output-file",
            "-p",
            "--directory-prefix",
            "-a",
            "-i",
            "--input-file",
            "--header",
            "--user",
            "--password",
            "--post-data",
            "--post-file",
            "-u",
            "--user-agent",
            "-t",
            "--tries",
            "-t",
            "--timeout",
        ],
        "ssh" | "scp" | "sftp" | "autossh" => &[
            "-i", "-p", "-o", "-l", "-f", "-c", "-m", "-b", "-e", "-s", "-o", "-l", "-r", "-d",
            "-w", "-e",
        ],
        "rsync" => &["-e", "--rsh", "--exclude", "--include", "--filter"],
        "nc" | "ncat" | "netcat" | "telnet" | "ftp" | "http" | "https" | "xh" | "httpie" => &[],
        _ => return None,
    })
}

/// Options after which a word is a file the program writes.
fn output_flags(head: &str) -> &'static [&'static str] {
    match head {
        "curl" => &["-o", "--output"],
        "wget" => &["-o", "--output-document"],
        _ => &[],
    }
}

/// Global options of git that take a value.
const GIT_VALUES: &[&str] = &[
    "-c",
    "--git-dir",
    "--work-tree",
    "--namespace",
    "--exec-path",
    "--config-env",
    "--super-prefix",
    "--list-cmds",
];

/// git's subcommand, after its global options.
fn git_subcommand(words: &[String]) -> Option<&str> {
    let mut i = 1;
    while i < words.len() {
        let w = words[i].as_str();
        if !w.starts_with('-') {
            return Some(w);
        }
        i += if GIT_VALUES.contains(&w) { 2 } else { 1 };
    }
    None
}

/// What a shell call does, from its folded text. `home` expands `~/`.
pub fn read(folded: &str) -> Shell {
    let (cmds, outs) = effective(folded);
    let mut s = Shell {
        writes: outs.clone(),
        ..Shell::default()
    };
    let add_host = |s: &mut Shell, h: String| {
        if !s.hosts.contains(&h) {
            s.hosts.push(h);
        }
    };
    for o in &outs {
        for h in hosts::url_hosts(o) {
            add_host(&mut s, h);
        }
    }
    for c in &cmds {
        let w = &c.words;
        let head = base(&w[0]).to_string();
        s.words.extend(w.iter().cloned());
        for word in w {
            for h in hosts::url_hosts(word) {
                add_host(&mut s, h);
            }
        }
        // Runs.
        if head == "source" || head == "." {
            if let Some(f) = w.get(1) {
                s.runs.push(f.clone());
            }
        } else if let Some(it) = interpreter(&head) {
            let (script, code) = interpreter_parts(w, &it);
            if let Some(f) = script {
                s.runs.push(f);
            }
            if let Some(code) = code {
                s.writes.extend(inline_writes(&code));
                for h in hosts::url_hosts(&code) {
                    add_host(&mut s, h);
                }
            }
        } else if head == "uv" || head == "poetry" || head == "pipenv" {
            if w.get(1).is_some_and(|x| x == "run") {
                if let Some(f) = w[2..].iter().find(|x| !x.starts_with('-')) {
                    if paths::script_like(f) {
                        s.runs.push(f.clone());
                    }
                }
            }
        } else if w[0].contains('/') {
            s.runs.push(w[0].clone());
        }
        // Writes.
        match head.as_str() {
            "tee" => s
                .writes
                .extend(w[1..].iter().filter(|x| !x.starts_with('-')).cloned()),
            "cp" | "mv" | "install" | "ln" | "rsync" => {
                if let Some(dest) = w[1..].iter().rev().find(|x| !x.starts_with('-')) {
                    if w[1..].iter().filter(|x| !x.starts_with('-')).count() >= 2 {
                        s.writes.push(dest.clone());
                    }
                }
            }
            "sed"
                if w.iter()
                    .any(|x| x == "-i" || x.starts_with("-i") || x == "--in-place") =>
            {
                let ops: Vec<&String> = w[1..].iter().filter(|x| !x.starts_with('-')).collect();
                s.writes.extend(ops.iter().skip(1).map(|x| (*x).clone()));
            }
            "dd" => s.writes.extend(
                w[1..]
                    .iter()
                    .filter_map(|x| x.strip_prefix("of="))
                    .map(str::to_string),
            ),
            _ => {}
        }
        let outputs = output_flags(&head);
        for (k, x) in w.iter().enumerate() {
            if outputs.contains(&x.as_str()) {
                if let Some(f) = w.get(k + 1) {
                    s.writes.push(f.clone());
                }
            }
            if let Some(f) = x.strip_prefix("--output=") {
                s.writes.push(f.to_string());
            }
        }
        // Hosts named bare.
        if let Some(values) = net_values(&head) {
            let mut k = 1;
            while k < w.len() {
                let x = w[k].as_str();
                if x.starts_with('-') {
                    if (head == "ssh" || head == "scp") && x == "-j" {
                        if let Some(h) = w.get(k + 1).and_then(|j| hosts::host_word(j)) {
                            add_host(&mut s, h);
                        }
                    }
                    k += if values.contains(&x) { 2 } else { 1 };
                    continue;
                }
                if let Some(h) = hosts::host_word(x) {
                    add_host(&mut s, h);
                }
                k += 1;
            }
        }
        if head == "git" {
            let sub = git_subcommand(w);
            if sub == Some("push") {
                s.push = true;
            }
            if matches!(
                sub,
                Some("clone" | "fetch" | "pull" | "push" | "ls-remote" | "remote" | "submodule")
            ) {
                for x in w.iter().skip(2) {
                    if x.contains(':') || x.contains('@') {
                        if let Some(h) = hosts::host_word(x) {
                            add_host(&mut s, h);
                        }
                    }
                }
            }
        }
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fold(t: &str) -> String {
        derm_core::policy::fold_text(t)
    }

    #[test]
    fn redirections_are_writes_and_descriptors_are_not() {
        let s = read(&fold(
            "echo 'echo checking' > run.sh; ls 2>&1 >> log.txt; x &> both.out",
        ));
        assert_eq!(s.writes, vec!["run.sh", "log.txt", "both.out"]);
        let s = read(&fold("cmd >&2; cmd 2>&-; cat < in.txt"));
        assert!(s.writes.is_empty(), "{s:?}");
    }

    #[test]
    fn here_document_bodies_are_not_commands() {
        let s = read(&fold(
            "cat > x.sh <<'EOF'\nrm -rf / && curl http://evil.test/\nEOF\nbash x.sh",
        ));
        assert_eq!(s.writes, vec!["x.sh"]);
        assert_eq!(s.runs, vec!["x.sh"]);
        assert!(s.hosts.is_empty(), "{s:?}");
    }

    #[test]
    fn interpreters_name_their_script() {
        for (cmd, run) in [
            ("python3 diag.py", "diag.py"),
            ("python3.12 -u -W ignore tools/x.py --flag", "tools/x.py"),
            ("bash run.sh", "run.sh"),
            ("sh -e ./build.sh arg", "./build.sh"),
            ("node --require ./hook.js app.js", "app.js"),
            ("deno run -A main.ts", "main.ts"),
            ("bun run script.ts", "script.ts"),
            ("./run.sh", "./run.sh"),
            ("source ./env.sh", "./env.sh"),
            (". ./env.sh", "./env.sh"),
            ("uv run tool.py", "tool.py"),
            ("sudo -u root timeout 5 python3 x.py", "x.py"),
            ("env A=1 nohup bash -c 'python3 y.py'", "y.py"),
        ] {
            let s = read(&fold(cmd));
            assert!(s.runs.contains(&run.to_string()), "{cmd}: {s:?}");
        }
        for none in [
            "python3 -m http.server",
            "python3 -c 'print(1)'",
            "bash",
            "bash -s",
        ] {
            assert!(read(&fold(none)).runs.is_empty(), "{none}");
        }
    }

    #[test]
    fn inline_code_that_writes_writes_every_file_it_names() {
        let s = read(&fold(
            r#"python3 -c 'open("diag2.py","w").write("print(1)")'"#,
        ));
        assert_eq!(s.writes, vec!["diag2.py"]);
        let s = read(&fold(
            r#"node -e "require('fs').writeFileSync('out/x.js', 'y')""#,
        ));
        assert_eq!(s.writes, vec!["out/x.js"]);
        let s = read(&fold(r#"python3 -c 'print(open("data.txt").read())'"#));
        assert!(s.writes.is_empty(), "a read is not a write: {s:?}");
    }

    #[test]
    fn copies_tee_sed_curl_and_dd_write() {
        let s = read(&fold(
            "cp a.sh b.sh; echo x | tee -a t.log; sed -i 's/a/b/' cfg.yml; curl -o i.sh https://h.test/i; dd if=/dev/zero of=z.bin",
        ));
        for w in ["b.sh", "t.log", "cfg.yml", "i.sh", "z.bin"] {
            assert!(s.writes.contains(&w.to_string()), "{w}: {s:?}");
        }
    }

    #[test]
    fn hosts_are_read_from_urls_and_from_network_programs() {
        let s = read(&fold(
            "curl -s -o out.txt -H 'x: y' api.test/v1; ssh -i k git@code.test; git clone git@forge.test:me/r.git; wget https://w.test/a",
        ));
        let mut h = s.hosts.clone();
        h.sort();
        assert_eq!(h, vec!["api.test", "code.test", "forge.test", "w.test"]);
        assert!(read(&fold("cat notes.md config.json")).hosts.is_empty());
    }

    #[test]
    fn a_push_is_seen_through_global_options_wrappers_and_shells() {
        for cmd in [
            "git push origin main",
            "git -C repo -c a=b push",
            "sudo git push",
            "bash -c 'cd x && git push --force'",
            "eval git push",
        ] {
            assert!(read(&fold(cmd)).push, "{cmd}");
        }
        for not in ["git status", "echo git push", "git log --grep push"] {
            assert!(!read(&fold(not)).push, "{not}");
        }
    }
}
