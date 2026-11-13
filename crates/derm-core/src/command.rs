//! Command rules (`contracts/policy.md` section 7; wave 5 lane W). A rule may
//! name a CLI command by its first words (`"tool": "bash", "command": ["gh",
//! "pr", "create"]`). The same logic as the hook core's `command.ts`
//! (`packages/derm-claude-plugin/src/core/command.ts`, canonical) and
//! derm-pi's copy; all three are tested against `contracts/fixtures/policy/`.
//!
//! A deny or an ask rule narrows: it meets any simple command of the text,
//! past separators, subshells, backticks, lane X's wrappers, `bash -c`,
//! `eval`, `env -S` and global flags before a subcommand; a rule word that
//! starts with `-` meets that flag anywhere after the words before it. An
//! allow rule widens only a call whose whole text is one plain simple command
//! whose first words are the rule's, exactly.

use crate::installs::parse::commands;

/// At most this many words in a rule's `command`.
pub const MAX_COMMAND_WORDS: usize = 8;

fn word_char(b: u8) -> bool {
    b.is_ascii_lowercase()
        || b.is_ascii_digit()
        || matches!(b, b'.' | b'_' | b':' | b'=' | b'+' | b'-')
}

/// `^[a-z0-9][a-z0-9._:=+-]{0,63}$`: a command's name or subcommand.
pub fn is_command_word(w: &str) -> bool {
    let b = w.as_bytes();
    !b.is_empty()
        && b.len() <= 64
        && (b[0].is_ascii_lowercase() || b[0].is_ascii_digit())
        && b.iter().all(|c| word_char(*c))
}

/// `^--?[a-z0-9][a-z0-9._:=+-]{0,61}$`: a flag, allowed after the first word.
pub fn is_flag_word(w: &str) -> bool {
    let rest = w
        .strip_prefix("--")
        .or_else(|| w.strip_prefix('-'))
        .unwrap_or("");
    let b = rest.as_bytes();
    !b.is_empty()
        && b.len() <= 62
        && (b[0].is_ascii_lowercase() || b[0].is_ascii_digit())
        && b.iter().all(|c| word_char(*c))
}

/// Why `words` is not a valid `command`, or `None` when it is.
pub fn command_problem(words: &[String]) -> Option<String> {
    if words.is_empty() || words.len() > MAX_COMMAND_WORDS {
        return Some(format!(
            "command has {} words (1 to {MAX_COMMAND_WORDS})",
            words.len()
        ));
    }
    for (i, w) in words.iter().enumerate() {
        if is_command_word(w) || (i > 0 && is_flag_word(w)) {
            continue;
        }
        return Some(format!("command word {i} is not a plain lowercase word"));
    }
    None
}

const WRAPPERS: &[&str] = &[
    "sudo", "doas", "env", "command", "exec", "builtin", "nohup", "time", "stdbuf", "chronic",
    "unbuffer", "nice", "ionice", "chrt", "taskset", "timeout", "xargs", "corepack", "busybox",
    "parallel", "setsid", "flock", "unshare", "run0",
];
const SHELLS: &[&str] = &[
    "sh", "bash", "zsh", "dash", "ksh", "mksh", "ash", "fish", "csh", "tcsh", "rbash", "yash",
];
const MAX_DEPTH: usize = 4;

fn is_assignment(w: &str) -> bool {
    let Some((name, _)) = w.split_once('=') else {
        return false;
    };
    let b = name.as_bytes();
    !b.is_empty()
        && (b[0].is_ascii_lowercase() || b[0] == b'_')
        && b.iter()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'_')
}

/// A word's program name: no folder, no `.exe` or `.cmd`.
pub fn command_base(word: &str) -> &str {
    let b = word.rsplit('/').next().unwrap_or(word);
    b.strip_suffix(".exe")
        .or_else(|| b.strip_suffix(".cmd"))
        .unwrap_or(b)
}

/// `-c <string>` (or a combined short flag holding `c`, as `-lc`).
fn shell_command_string(words: &[String]) -> Option<String> {
    // The first word that is not an option, once `-c` has been seen; options
    // before or after `-c`, `+x` style too; `-o`, `+o`, `--rcfile` and
    // `--init-file` take a value; `--` ends the options (integration w5's
    // close, review W5-S3).
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

/// Every simple command in folded shell text that starts with one of `heads`
/// (a rule's first word), its first word the bare program name. Read as
/// written and with every backslash removed; backticks end a command.
pub fn head_commands(folded: &str, heads: &[&str]) -> Vec<Vec<String>> {
    let mut out = Vec::new();
    let plain = folded.replace('\\', "");
    for text in [folded, plain.as_str()] {
        walk(&text.replace('`', "\n"), heads, 0, &mut out);
    }
    out
}

fn walk(text: &str, heads: &[&str], depth: usize, out: &mut Vec<Vec<String>>) {
    if depth > MAX_DEPTH {
        return;
    }
    for words in commands(text) {
        read(&words, heads, depth, out);
    }
}

fn is_head(word: &str, heads: &[&str]) -> bool {
    let b = command_base(word);
    heads.contains(&b) || WRAPPERS.contains(&b) || SHELLS.contains(&b) || b == "eval"
}

fn read(input: &[String], heads: &[&str], depth: usize, out: &mut Vec<Vec<String>>) {
    let mut words: Vec<String> = input.to_vec();
    for _ in 0..16 {
        while words.first().is_some_and(|w| is_assignment(w)) {
            words.remove(0);
        }
        let Some(first) = words.first() else {
            return;
        };
        let head = command_base(first).to_string();
        let rest: Vec<String> = words[1..].to_vec();
        if heads.contains(&head.as_str()) {
            let mut c = vec![head];
            c.extend(rest);
            out.push(c);
            return;
        }
        if head == "env" {
            if let Some(i) = rest.iter().position(|w| {
                w == "-s" || w == "--split-string" || w.starts_with("--split-string=")
            }) {
                let w = &rest[i];
                let s = match w.strip_prefix("--split-string=") {
                    Some(v) => Some(v.to_string()),
                    None => rest.get(i + 1).cloned(),
                };
                if let Some(s) = s {
                    walk(&s, heads, depth + 1, out);
                }
                return;
            }
        }
        if head == "eval" {
            walk(&rest.join(" "), heads, depth + 1, out);
            return;
        }
        // GNU parallel runs its command words and its `:::` arguments
        // through a shell (`parallel ::: 'git push --force'`; W6C-R3).
        if head == "parallel" {
            for w in rest.iter().filter(|w| !w.starts_with('-')) {
                walk(w, heads, depth + 1, out);
            }
        }
        if SHELLS.contains(&head.as_str()) {
            if let Some(c) = shell_command_string(&rest) {
                walk(&c, heads, depth + 1, out);
            }
            return;
        }
        if !WRAPPERS.contains(&head.as_str()) {
            return;
        }
        let Some(next) = rest
            .iter()
            .position(|w| !is_assignment(w) && is_head(w, heads))
        else {
            return;
        };
        words = rest[next..].to_vec();
    }
}

// --- A program read from input (contract section 4, step 7b; E0's R-E0-1) --

/// What feeds a simple command's standard input, as the line shows it.
#[derive(Clone, Copy, Default)]
struct Feed {
    /// After `|` or `|&` (not `||`).
    piped: bool,
    /// `<<<`: a here-string, which the splitter keeps as one quoted word.
    here_string: bool,
    /// `<<` or `<<-`: a here-document, whose lines follow as lines.
    here_doc: bool,
    /// `<(`: a process substitution as an operand or input.
    process: bool,
}

impl Feed {
    /// A command fed either way is fed.
    fn or(self, o: Feed) -> Feed {
        Feed {
            piped: self.piped || o.piped,
            here_string: self.here_string || o.here_string,
            here_doc: self.here_doc || o.here_doc,
            process: self.process || o.process,
        }
    }
}

/// Words that open a compound command whose inner commands share the input
/// it was given (`curl x | if true; then sh; fi`), and the words that close
/// one (integration w6's re-review, W6C-R1).
const OPENERS: &[&str] = &["if", "while", "until", "for", "case", "select"];
const CLOSERS: &[&str] = &["fi", "done", "esac"];
/// Reserved words a simple command may start with before its program:
/// `then sh` runs `sh`.
const RESERVED: &[&str] = &[
    "if", "then", "else", "elif", "do", "while", "until", "!", "{", "coproc",
];

/// An open `(`: a subshell or group whose commands share `Feed`, or a
/// process substitution inside a command, with that command's words and
/// feed so far.
enum Frame {
    Group(Feed),
    Process(Vec<String>, Feed),
}

/// The splitter's state for [`fed_commands`].
struct Split {
    out: Vec<(Vec<String>, Feed)>,
    words: Vec<String>,
    word: String,
    in_word: bool,
    skip_next: bool,
    feed: Feed,
    /// What the whole text is fed (the outer command's feed for a `-c`,
    /// `env -S` or `eval` string, W6C-R1).
    base: Feed,
    frames: Vec<Frame>,
    compounds: Vec<Feed>,
}

impl Split {
    fn end_word(&mut self) {
        if self.in_word {
            if self.skip_next {
                self.skip_next = false;
            } else {
                self.words.push(std::mem::take(&mut self.word));
            }
        }
        self.word.clear();
        self.in_word = false;
    }

    /// The feed every command inside the open groups and compounds shares.
    fn shared(&self) -> Feed {
        let mut f = self.base;
        for fr in &self.frames {
            if let Frame::Group(g) = fr {
                f = f.or(*g);
            }
        }
        for c in &self.compounds {
            f = f.or(*c);
        }
        f
    }

    fn end_command(&mut self, piped_next: bool) {
        self.end_word();
        if !self.words.is_empty() {
            let first = self
                .words
                .iter()
                .map(String::as_str)
                .find(|w| !matches!(*w, "!" | "{" | "then" | "else" | "do"))
                .unwrap_or("");
            if CLOSERS.contains(&self.words[0].as_str()) {
                self.compounds.pop();
            } else if OPENERS.contains(&first) {
                self.compounds.push(self.feed);
            }
            self.out.push((std::mem::take(&mut self.words), self.feed));
        }
        self.skip_next = false;
        let shared = self.shared();
        self.feed = if piped_next {
            Feed {
                piped: true,
                ..Feed::default()
            }
            .or(shared)
        } else {
            shared
        };
    }
}

/// Simple commands of folded shell text with what feeds each: the same
/// splitting as `installs::parse::commands` (quotes, `#`, separators, a
/// redirect's target dropped), keeping the pipe and redirect forms it drops.
/// A subshell or compound command right after a pipe passes the pipe's input
/// to every command inside it, and a process substitution feeds the command
/// it sits in, before or after its program word (W6C-R1).
fn fed_commands(text: &str, base: Feed) -> Vec<(Vec<String>, Feed)> {
    let chars: Vec<char> = text.chars().collect();
    let mut s = Split {
        out: Vec::new(),
        words: Vec::new(),
        word: String::new(),
        in_word: false,
        skip_next: false,
        feed: base,
        base,
        frames: Vec::new(),
        compounds: Vec::new(),
    };
    let mut quote: Option<char> = None;
    let mut i = 0;
    while i < chars.len() {
        let ch = chars[i];
        if let Some(q) = quote {
            if ch == q {
                quote = None;
            } else {
                s.word.push(ch);
            }
            i += 1;
            continue;
        }
        match ch {
            '\'' | '"' => {
                quote = Some(ch);
                s.in_word = true;
            }
            '#' if !s.in_word => {
                while i < chars.len() && chars[i] != '\n' {
                    i += 1;
                }
                s.end_command(false);
                continue;
            }
            '|' => {
                // `||` is a list operator; `|` and `|&` pipe.
                let or = chars.get(i + 1) == Some(&'|');
                if or || chars.get(i + 1) == Some(&'&') {
                    i += 1;
                }
                s.end_command(!or);
            }
            // A subshell or group: right after a pipe it takes the pipe's
            // input (`curl x | (true; sh)`; W6C-S2, W6C-R1).
            '(' => {
                if s.words.is_empty() && !s.in_word {
                    let f = s.feed;
                    s.frames.push(Frame::Group(f));
                } else {
                    s.end_command(false);
                    s.frames.push(Frame::Group(Feed::default()));
                    s.feed = s.shared();
                }
            }
            ')' => {
                s.end_command(false);
                match s.frames.pop() {
                    // The command a process substitution sat in goes on,
                    // fed by it (`< <(curl x) sh`, `bash <(curl x)`).
                    Some(Frame::Process(words, feed)) => {
                        s.words = words;
                        s.feed = Feed {
                            process: true,
                            ..feed
                        };
                    }
                    _ => s.feed = s.shared(),
                }
            }
            ';' | '&' | '\n' | '\r' => s.end_command(false),
            '<' | '>' => {
                if s.in_word && !s.word.is_empty() && s.word.chars().all(|c| c.is_ascii_digit()) {
                    s.word.clear();
                    s.in_word = false;
                }
                s.end_word();
                if ch == '<' && chars.get(i + 1) == Some(&'(') {
                    // `<(` opens a command of its own; the command around it
                    // is held until its `)`.
                    let words = std::mem::take(&mut s.words);
                    let feed = s.feed;
                    s.frames.push(Frame::Process(words, feed));
                    s.feed = s.shared();
                    s.skip_next = false;
                    i += 2;
                    continue;
                }
                if ch == '<' {
                    let run = chars[i..].iter().take_while(|c| **c == '<').count();
                    match run {
                        2 => s.feed.here_doc = true,
                        n if n >= 3 => s.feed.here_string = true,
                        _ => {}
                    }
                }
                while i + 1 < chars.len() && matches!(chars[i + 1], '>' | '<' | '&' | '|' | '-') {
                    i += 1;
                }
                s.skip_next = true;
            }
            ' ' | '\t' | '\u{b}' | '\u{c}' => s.end_word(),
            _ => {
                s.word.push(ch);
                s.in_word = true;
            }
        }
        i += 1;
    }
    s.end_word();
    if !s.words.is_empty() {
        let (w, f) = (std::mem::take(&mut s.words), s.feed);
        s.out.push((w, f));
    }
    s.out
}

/// Interpreters that run a program from their input when the line gives
/// none (OpenMoat 0.19.0's `pipe-to-shell`, `policies/default-v1.yaml:258-
/// 270`: `{python*,node,perl,ruby,php,deno,bun,pwsh}`).
fn interpreter(base: &str) -> bool {
    // OpenMoat's `python*`: `python3.12`, `python3-dbg`, `pypy3` (W6C-S2).
    python(base)
        || matches!(
            base,
            "node" | "nodejs" | "perl" | "ruby" | "php" | "deno" | "bun" | "pwsh"
        )
}

/// A Python by name: `python*` and `pypy*`.
fn python(base: &str) -> bool {
    base.starts_with("python") || base.starts_with("pypy")
}

/// Paths a program reads its own standard input through, read lexically as
/// the kernel resolves them: `//`, `/./` and `..` (`/dev/../dev/stdin`),
/// and under `/proc/self/root` (W6C-S2, W6C-R2). A relative path whose last
/// part is `stdin` or `fd/0` counts too, since a `cd` may have put it under
/// `/dev` (`cd /dev && bash ./stdin`).
fn stdin_path(w: &str) -> bool {
    if w == "-" {
        return true;
    }
    let abs = w.starts_with('/');
    let mut parts: Vec<&str> = Vec::new();
    for p in w.split('/') {
        match p {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            x => parts.push(x),
        }
    }
    if !abs {
        return parts.last() == Some(&"stdin") || parts.ends_with(&["fd", "0"]);
    }
    let mut rest: &[&str] = &parts;
    while rest.len() > 3
        && rest[0] == "proc"
        && matches!(rest[1], "self" | "thread-self")
        && rest[2] == "root"
    {
        rest = &rest[3..];
    }
    matches!(
        rest,
        ["dev", "stdin"]
            | ["dev", "fd", "0"]
            | ["proc", "self", "fd", "0"]
            | ["proc", "thread-self", "fd", "0"]
    )
}

/// A pwsh parameter by any prefix pwsh accepts: `-c`, `-com`, `-command`.
fn pwsh_param(word: &str, full: &str, shortest: usize) -> bool {
    word.len() >= shortest && full.starts_with(word)
}

/// Does `program`, run with `args`, read its program from its input? A shell
/// does with `-s`, a stdin path, or no operand and no `-c`; `source` and `.`
/// with a stdin path or no operand; an interpreter with a stdin path, or no
/// operand and none of its program flags. Folded text is lowercase, so
/// `-E` reads as `-e` and `-X` as `-x`; where that joins a valued flag and
/// one that takes none, it is read as valued, which only reads more as fed.
fn reads_its_input(program: &str, args: &[String]) -> bool {
    let shell = SHELLS.contains(&program);
    let source = matches!(program, "source" | ".");
    // (letters that put the program on the line, short flags that take a
    // value, long flags that put the program on the line, long flags that
    // take a value)
    let (program_letters, valued_letters, program_long, valued_long): (
        &str,
        &str,
        &[&str],
        &[&str],
    ) = if shell {
        ("c", "o", &[], &["--rcfile", "--init-file"])
    } else if source {
        ("", "", &[], &[])
    } else if python(program) {
        ("cm", "wx", &[], &["--check-hash-based-pycs"])
    } else if matches!(program, "node" | "nodejs" | "bun") {
        (
            "ep",
            "rc",
            &["--eval", "--print"],
            &[
                "--require",
                "--import",
                "--loader",
                "--experimental-loader",
                "--conditions",
                "--input-type",
                "--title",
            ],
        )
    } else if program == "perl" {
        ("e", "", &[], &[])
    } else if program == "ruby" {
        ("e", "ric", &[], &[])
    } else if program == "php" {
        ("rf", "cdz", &[], &[])
    } else if program == "pwsh" {
        (
            "cfe",
            "",
            &["-command", "-file", "-encodedcommand", "-ec"],
            &[
                "-executionpolicy",
                "-ep",
                "-ex",
                "-workingdirectory",
                "-wd",
                "-configurationname",
                "-settingsfile",
            ],
        )
    } else {
        ("", "", &[], &[])
    };
    let mut i = 0;
    let mut operands: Vec<&str> = Vec::new();
    while i < args.len() {
        let w = args[i].as_str();
        if w == "--" {
            operands.extend(args[i + 1..].iter().map(String::as_str));
            break;
        }
        let flag =
            (w.starts_with('-') && w.len() > 1) || (shell && w.starts_with('+') && w.len() > 1);
        if !flag {
            operands.push(w);
            i += 1;
            continue;
        }
        let name = w.split('=').next().unwrap_or(w);
        // pwsh takes one-dash long names by prefix and has no letter
        // bundles: `-noprofile` is no `-n -o -p ...` (W6C-S2).
        if program == "pwsh" && w.starts_with('-') && !w.starts_with("--") {
            let command = pwsh_param(name, "-command", 2)
                || pwsh_param(name, "-file", 2)
                || pwsh_param(name, "-encodedcommand", 2)
                || name == "-ec";
            if command {
                let value = args.get(i + 1).map(String::as_str);
                return value.is_some_and(stdin_path);
            }
            let valued = pwsh_param(name, "-executionpolicy", 3)
                || pwsh_param(name, "-workingdirectory", 3)
                || pwsh_param(name, "-configurationname", 4)
                || pwsh_param(name, "-settingsfile", 3)
                || matches!(name, "-ep" | "-ex" | "-wd");
            i += if valued { 2 } else { 1 };
            continue;
        }
        if program_long.contains(&name) {
            // pwsh's `-command -` reads the command from its input.
            let value = if w.contains('=') {
                w.split_once('=').map(|(_, v)| v)
            } else {
                args.get(i + 1).map(String::as_str)
            };
            return program == "pwsh" && value.is_some_and(stdin_path);
        }
        if valued_long.contains(&name) {
            i += if w.contains('=') { 1 } else { 2 };
            continue;
        }
        if w.starts_with("--") {
            i += 1;
            continue;
        }
        let letters = &w[1..];
        if shell && letters.contains('s') && w.starts_with('-') {
            return true;
        }
        if letters.chars().any(|c| program_letters.contains(c)) {
            return false;
        }
        // A short flag that takes a value consumes the next word unless
        // the value is attached (`-oerrexit` reads as one word).
        if letters.len() == 1 && valued_letters.contains(letters) {
            i += 2;
            continue;
        }
        i += 1;
    }
    match operands.first() {
        None => true,
        Some(first) => {
            if stdin_path(first) {
                return true;
            }
            // deno and bun name a subcommand first: `deno run -`, bare
            // `deno run` with nothing after it.
            if matches!(program, "deno" | "bun") && *first == "run" {
                return operands.get(1).is_none_or(|w| stdin_path(w));
            }
            false
        }
    }
}

/// The program name of a shell or interpreter in folded shell text that
/// reads its program from its input, fed by a pipe, a here-string, a process
/// substitution or xargs, or (an interpreter only) a here-document; `None`
/// when there is none. A shell's here-document is not counted: its lines are
/// on the line, and the matcher reads them as commands. Read as written and
/// with every backslash removed, inside `-c`, `eval` and `env -S` strings to
/// the same depth as the command rules (E0's R-E0-1; OpenMoat 0.19.0's
/// `pipe-to-shell` and `opaque-code`'s `<shell> @stdin`, read in
/// `src/shell/tests/stdin.rs`).
pub fn stdin_program(folded: &str) -> Option<String> {
    let plain = folded.replace('\\', "");
    for text in [folded, plain.as_str()] {
        if let Some(p) = stdin_walk(&text.replace('`', "\n"), 0, Feed::default()) {
            return Some(p);
        }
    }
    None
}

/// `base` is what feeds the whole text: a `-c`, `env -S` or `eval` string
/// is read by commands that take the outer command's input (W6C-R1).
fn stdin_walk(text: &str, depth: usize, base: Feed) -> Option<String> {
    if depth > MAX_DEPTH {
        return None;
    }
    for (words, feed) in fed_commands(text, base) {
        if let Some(p) = stdin_read(&words, feed, depth) {
            return Some(p);
        }
    }
    None
}

/// The words xargs fills from its input in a command it runs: `-I x`,
/// `-ix`, `-i` (`{}`), `--replace[=x]`; `{}` always, which only asks more.
fn xargs_tokens(args: &[String]) -> Vec<String> {
    let mut out = vec!["{}".to_string()];
    let mut i = 0;
    while i < args.len() {
        let w = args[i].as_str();
        if !w.starts_with('-') {
            break;
        }
        if w == "-i" || w == "--replace" {
            // `{}` is already there.
        } else if w == "-I" || w == "-i" {
            if let Some(v) = args.get(i + 1) {
                out.push(v.clone());
            }
            i += 1;
        } else if let Some(v) = w.strip_prefix("--replace=") {
            out.push(v.to_string());
        } else if let Some(v) = w.strip_prefix("-I").or_else(|| w.strip_prefix("-i")) {
            if !v.is_empty() {
                out.push(v.to_string());
            }
        }
        i += 1;
    }
    out.retain(|t| !t.is_empty());
    out
}

fn stdin_read(input: &[String], feed: Feed, depth: usize) -> Option<String> {
    let mut words: Vec<String> = input.to_vec();
    // `Some(tokens)` behind xargs or parallel: the words it fills from its
    // input in the command it runs.
    let mut xargs: Option<Vec<String>> = None;
    for _ in 0..16 {
        while words
            .first()
            .is_some_and(|w| is_assignment(w) || RESERVED.contains(&w.as_str()))
        {
            words.remove(0);
        }
        let first = words.first()?;
        let head = command_base(first).to_string();
        let rest: Vec<String> = words[1..].to_vec();
        if head == "env" {
            if let Some(i) = rest.iter().position(|w| {
                w == "-s" || w == "--split-string" || w.starts_with("--split-string=")
            }) {
                let s = match rest[i].strip_prefix("--split-string=") {
                    Some(v) => Some(v.to_string()),
                    None => rest.get(i + 1).cloned(),
                };
                return s.and_then(|s| stdin_walk(&s, depth + 1, feed));
            }
        }
        if head == "eval" {
            return stdin_walk(&rest.join(" "), depth + 1, feed);
        }
        let program = SHELLS.contains(&head.as_str())
            || matches!(head.as_str(), "source" | ".")
            || interpreter(&head);
        if program {
            if SHELLS.contains(&head.as_str()) {
                // Behind xargs or parallel a shell's `-c` takes its string
                // from the input when the line gives none, or when the
                // string holds a word the input fills (`xargs -i% sh -c %`;
                // W6C-S2); a fixed string only gets the input as arguments
                // (W6C-R5).
                if let Some(tokens) = &xargs {
                    if has_c_flag(&rest) {
                        match shell_command_string(&rest) {
                            None => return Some(head),
                            Some(c) if tokens.iter().any(|t| c.contains(t.as_str())) => {
                                return Some(head)
                            }
                            Some(_) => {}
                        }
                    }
                }
                if let Some(c) = shell_command_string(&rest) {
                    return stdin_walk(&c, depth + 1, feed);
                }
            }
            let shellish =
                SHELLS.contains(&head.as_str()) || matches!(head.as_str(), "source" | ".");
            let fed = feed.piped
                || feed.here_string
                || feed.process
                || xargs.is_some()
                || (feed.here_doc && !shellish);
            return (fed && reads_its_input(&head, &rest)).then_some(head);
        }
        if head == "parallel" {
            // GNU parallel runs each input line as a command when its line
            // names none, and runs its command words and `:::` arguments
            // through a shell (GNU parallel 20231122, run; W6C-R3).
            let fed = feed.piped || feed.here_string || feed.process;
            let command = rest
                .iter()
                .take_while(|w| *w != ":::" && *w != "::::")
                .any(|w| !w.starts_with('-') && !w.chars().all(|c| c.is_ascii_digit()));
            if fed && !command && !rest.iter().any(|w| w == ":::" || w == "::::") {
                return Some(head);
            }
            for w in rest.iter().filter(|w| !w.starts_with('-')) {
                if let Some(p) = stdin_walk(w, depth + 1, Feed::default()) {
                    return Some(p);
                }
            }
        }
        if !WRAPPERS.contains(&head.as_str()) {
            return None;
        }
        if head == "xargs" {
            xargs = Some(xargs_tokens(&rest));
        } else if head == "parallel" {
            xargs = Some(vec!["{".to_string()]);
        }
        let next = rest.iter().position(|w| {
            let b = command_base(w);
            !is_assignment(w)
                && (WRAPPERS.contains(&b)
                    || SHELLS.contains(&b)
                    || interpreter(b)
                    || matches!(b, "source" | "." | "eval"))
        })?;
        words = rest[next..].to_vec();
    }
    None
}

/// Does a shell's argument list hold `-c` among its flags (`-c`, `-ec`)?
/// The values of `-o`, `+o`, `--rcfile` and `--init-file` are skipped, as
/// [`shell_command_string`] skips them (W6C-R3).
fn has_c_flag(args: &[String]) -> bool {
    let mut i = 0;
    while i < args.len() {
        let w = args[i].as_str();
        if w == "--" || !(w.starts_with('-') || w.starts_with('+')) {
            return false;
        }
        if matches!(w, "-o" | "+o" | "--rcfile" | "--init-file") {
            i += 2;
            continue;
        }
        if w.starts_with('-') && !w.starts_with("--") && w[1..].contains('c') {
            return true;
        }
        i += 1;
    }
    false
}

/// Does a command's flag word meet a rule's flag word? `-f` also meets `-fu`.
fn flag_meets(word: &str, flag: &str) -> bool {
    if word == flag
        || word
            .strip_prefix(flag)
            .is_some_and(|rest| rest.starts_with('='))
    {
        return true;
    }
    // A long flag also meets a prefix of it of two letters or more (`--forc`,
    // `--ha`): git and others take an unambiguous prefix (integration w5's
    // close, review W5-S4). Reading more only narrows more.
    if let (Some(f), Some(w)) = (flag.strip_prefix("--"), word.strip_prefix("--")) {
        let name = w.split('=').next().unwrap_or("");
        if name.len() >= 2 && f.starts_with(name) {
            return true;
        }
    }
    let short = |w: &str, min: usize| {
        w.len() > min
            && w.starts_with('-')
            && !w.starts_with("--")
            && w[1..]
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
    };
    flag.len() == 2
        && short(flag, 1)
        && word.len() >= 3
        && short(word, 2)
        && word[1..].contains(&flag[1..])
}

/// Does a deny or ask rule's `command` meet one simple command?
pub fn command_narrows(rule: &[String], words: &[String]) -> bool {
    match (rule.first(), words.first()) {
        (Some(r), Some(w)) if r == w => meets(rule, 1, words, 1),
        _ => false,
    }
}

fn meets(rule: &[String], j: usize, words: &[String], i: usize) -> bool {
    let Some(want) = rule.get(j) else {
        return true;
    };
    if want.starts_with('-') {
        return words.iter().skip(i).any(|w| flag_meets(w, want)) && meets(rule, j + 1, words, i);
    }
    let mut value_allowed = false;
    for k in i..words.len() {
        let w = words[k].as_str();
        if w == want && meets(rule, j + 1, words, k + 1) {
            return true;
        }
        if w.starts_with('-') {
            value_allowed = !w.contains('=') && w != "--";
            continue;
        }
        if value_allowed {
            value_allowed = false;
            continue;
        }
        return false;
    }
    false
}

const SPACES: [char; 4] = [' ', '\t', '\u{b}', '\u{c}'];

/// Does an allow rule's `command` cover the whole folded text? Only one plain
/// simple command whose first words are the rule's, in order and exactly.
pub fn command_allows(rule: &[String], folded: &str) -> bool {
    if folded.chars().any(|c| {
        matches!(
            c,
            ';' | '&' | '|' | '(' | ')' | '<' | '>' | '`' | '\n' | '\r' | '#'
        )
    }) {
        return false;
    }
    let words: Vec<&str> = folded
        .trim_matches(SPACES)
        .split(SPACES)
        .filter(|w| !w.is_empty())
        .collect();
    words.len() >= rule.len()
        && rule.iter().zip(&words).all(|(r, w)| r == w)
        // After the rule's own words only plain operands widen: no flag and
        // no `=` (integration w5's close, review W5-S1: `git log
        // --output=<file>` wrote through a committed link into .git/config).
        && words[rule.len()..]
            .iter()
            .all(|w| !w.starts_with('-') && !w.contains('='))
}

/// The reason a command rule gives: `rule bash <words>`.
pub fn command_reason(rule: &[String]) -> String {
    format!("rule bash {}", rule.join(" "))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| x.to_string()).collect()
    }

    #[test]
    fn words_and_flags() {
        assert!(command_problem(&s(&["gh", "pr", "create"])).is_none());
        assert!(command_problem(&s(&["git", "push", "--force"])).is_none());
        assert!(command_problem(&s(&["--force"])).is_some(), "a flag first");
        assert!(command_problem(&s(&["Git"])).is_some(), "a capital");
        assert!(command_problem(&s(&["git", "$x"])).is_some(), "a dollar");
        assert!(command_problem(&s(&[])).is_some());
        assert!(command_problem(&s(&["a"; 9])).is_some());
        assert!(command_problem(&s(&["git", "---x"])).is_some());
    }

    #[test]
    fn narrowing_reads_wrappers_shells_and_global_flags() {
        let r = s(&["git", "push"]);
        let heads = ["git"];
        let hit = |t: &str| {
            head_commands(t, &heads)
                .iter()
                .any(|c| command_narrows(&r, c))
        };
        for t in [
            "git push",
            "ls && git push origin main",
            "sudo -u me git push",
            "env a=1 git push",
            "bash -c 'git push'",
            "eval git push",
            "timeout 10 git push",
            "git -c repo push",
            "/usr/bin/git push",
            "echo `git push`",
            "g\\it push",
            "x=$(git push)",
        ] {
            assert!(hit(t), "{t}");
        }
        for t in [
            "git commit -m \"push the fix\"",
            "echo git push",
            "git status",
        ] {
            assert!(!hit(t), "{t}");
        }
    }

    #[test]
    fn flags_anywhere() {
        let r = s(&["git", "push", "--force"]);
        let c = |t: &str| head_commands(t, &["git"]);
        assert!(c("git push origin main --force")
            .iter()
            .any(|w| command_narrows(&r, w)));
        assert!(!c("git push origin main")
            .iter()
            .any(|w| command_narrows(&r, w)));
        let f = s(&["git", "push", "-f"]);
        assert!(c("git push -fu origin x")
            .iter()
            .any(|w| command_narrows(&f, w)));
    }

    #[test]
    fn allow_is_exact_and_plain() {
        let r = s(&["gh", "pr", "view"]);
        assert!(command_allows(&r, "gh pr view 12"));
        assert!(!command_allows(&r, "gh pr view 12; rm -rf x"));
        assert!(!command_allows(&r, "sudo gh pr view 12"));
        assert!(!command_allows(&r, "/usr/bin/gh pr view"));
        assert!(!command_allows(&r, "gh pr view > out"));
        assert!(!command_allows(&r, "gh pr"));
    }
}
