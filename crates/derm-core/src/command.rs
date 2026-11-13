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
];
const SHELLS: &[&str] = &["sh", "bash", "zsh", "dash", "ksh", "mksh", "ash", "fish"];
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

/// Simple commands of folded shell text with what feeds each: the same
/// splitting as `installs::parse::commands` (quotes, `#`, separators, a
/// redirect's target dropped), keeping the pipe and redirect forms it drops.
fn fed_commands(text: &str) -> Vec<(Vec<String>, Feed)> {
    let chars: Vec<char> = text.chars().collect();
    let mut out = Vec::new();
    let mut words: Vec<String> = Vec::new();
    let mut word = String::new();
    let mut in_word = false;
    let mut quote: Option<char> = None;
    let mut skip_next = false;
    let mut feed = Feed::default();
    let end_word =
        |words: &mut Vec<String>, word: &mut String, in_word: &mut bool, skip_next: &mut bool| {
            if *in_word {
                if *skip_next {
                    *skip_next = false;
                } else {
                    words.push(std::mem::take(word));
                }
            }
            word.clear();
            *in_word = false;
        };
    let mut i = 0;
    while i < chars.len() {
        let ch = chars[i];
        if let Some(q) = quote {
            if ch == q {
                quote = None;
            } else {
                word.push(ch);
            }
            i += 1;
            continue;
        }
        let mut end_command = |piped_next: bool,
                               words: &mut Vec<String>,
                               word: &mut String,
                               in_word: &mut bool,
                               skip_next: &mut bool,
                               feed: &mut Feed| {
            end_word(words, word, in_word, skip_next);
            if !words.is_empty() {
                out.push((std::mem::take(words), *feed));
            }
            *skip_next = false;
            *feed = Feed {
                piped: piped_next,
                ..Feed::default()
            };
        };
        match ch {
            '\'' | '"' => {
                quote = Some(ch);
                in_word = true;
            }
            '#' if !in_word => {
                while i < chars.len() && chars[i] != '\n' {
                    i += 1;
                }
                end_command(
                    false,
                    &mut words,
                    &mut word,
                    &mut in_word,
                    &mut skip_next,
                    &mut feed,
                );
                continue;
            }
            '|' => {
                // `||` is a list operator; `|` and `|&` pipe.
                let or = chars.get(i + 1) == Some(&'|');
                if or || chars.get(i + 1) == Some(&'&') {
                    i += 1;
                }
                end_command(
                    !or,
                    &mut words,
                    &mut word,
                    &mut in_word,
                    &mut skip_next,
                    &mut feed,
                );
            }
            ';' | '&' | '(' | ')' | '\n' | '\r' => {
                end_command(
                    false,
                    &mut words,
                    &mut word,
                    &mut in_word,
                    &mut skip_next,
                    &mut feed,
                );
            }
            '<' | '>' => {
                if in_word && !word.is_empty() && word.chars().all(|c| c.is_ascii_digit()) {
                    word.clear();
                    in_word = false;
                }
                end_word(&mut words, &mut word, &mut in_word, &mut skip_next);
                if ch == '<' {
                    let run = chars[i..].iter().take_while(|c| **c == '<').count();
                    match run {
                        1 if chars.get(i + 1) == Some(&'(') => feed.process = true,
                        2 => feed.here_doc = true,
                        n if n >= 3 => feed.here_string = true,
                        _ => {}
                    }
                }
                // `<(` opens a command of its own: `(` splits next round.
                if ch == '<' && chars.get(i + 1) == Some(&'(') {
                    i += 1;
                    continue;
                }
                while i + 1 < chars.len() && matches!(chars[i + 1], '>' | '<' | '&' | '|' | '-') {
                    i += 1;
                }
                skip_next = true;
            }
            ' ' | '\t' | '\u{b}' | '\u{c}' => {
                end_word(&mut words, &mut word, &mut in_word, &mut skip_next);
            }
            _ => {
                word.push(ch);
                in_word = true;
            }
        }
        i += 1;
    }
    end_word(&mut words, &mut word, &mut in_word, &mut skip_next);
    if !words.is_empty() {
        out.push((words, feed));
    }
    out
}

/// Interpreters that run a program from their input when the line gives
/// none (OpenMoat 0.19.0's `pipe-to-shell`, `policies/default-v1.yaml:258-
/// 270`: `{python*,node,perl,ruby,php,deno,bun,pwsh}`).
fn interpreter(base: &str) -> bool {
    let py = base
        .strip_prefix("python")
        .is_some_and(|v| v.chars().all(|c| c.is_ascii_digit() || c == '.'));
    py || matches!(
        base,
        "node" | "nodejs" | "perl" | "ruby" | "php" | "deno" | "bun" | "pwsh"
    )
}

/// Paths a program reads its own standard input through.
fn stdin_path(w: &str) -> bool {
    matches!(w, "-" | "/dev/stdin" | "/dev/fd/0" | "/proc/self/fd/0")
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
    } else if program.starts_with("python") {
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
        if let Some(p) = stdin_walk(&text.replace('`', "\n"), 0) {
            return Some(p);
        }
    }
    None
}

fn stdin_walk(text: &str, depth: usize) -> Option<String> {
    if depth > MAX_DEPTH {
        return None;
    }
    for (words, feed) in fed_commands(text) {
        if let Some(p) = stdin_read(&words, feed, depth) {
            return Some(p);
        }
    }
    None
}

fn stdin_read(input: &[String], feed: Feed, depth: usize) -> Option<String> {
    let mut words: Vec<String> = input.to_vec();
    let mut xargs = false;
    for _ in 0..16 {
        while words.first().is_some_and(|w| is_assignment(w)) {
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
                return s.and_then(|s| stdin_walk(&s, depth + 1));
            }
        }
        if head == "eval" {
            return stdin_walk(&rest.join(" "), depth + 1);
        }
        let program = SHELLS.contains(&head.as_str())
            || matches!(head.as_str(), "source" | ".")
            || interpreter(&head);
        if program {
            if SHELLS.contains(&head.as_str()) {
                if let Some(c) = shell_command_string(&rest) {
                    return stdin_walk(&c, depth + 1);
                }
            }
            let shellish =
                SHELLS.contains(&head.as_str()) || matches!(head.as_str(), "source" | ".");
            let fed = feed.piped
                || feed.here_string
                || feed.process
                || xargs
                || (feed.here_doc && !shellish);
            return (fed && reads_its_input(&head, &rest)).then_some(head);
        }
        if !WRAPPERS.contains(&head.as_str()) {
            return None;
        }
        if head == "xargs" {
            xargs = true;
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
