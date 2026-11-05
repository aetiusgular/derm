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
