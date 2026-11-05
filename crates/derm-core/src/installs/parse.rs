//! Reads package installs out of a shell call's text (`contracts/policy.md`
//! section 6; wave 5 lane X). Pure: no file, no process, no network. The
//! text is the matcher's folded input (lowercase, NFKD-folded, escapes
//! decoded), so `$`, backticks, `\`, globs and braces never reach here: step
//! 7b already asked on them.
//!
//! A port of the hook core's `installs/parse.ts`, held equal to it and to
//! derm-pi's copy by `contracts/fixtures/installs/cases.json` and
//! `cases-x.json`. The forms are read in each manager's own help at the
//! version in use on 4 Nov 2026 (`plans/parallel/tk_lane_X.md`, Research).

use serde::Serialize;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Manager {
    Npm,
    Pnpm,
    Yarn,
    Bun,
    Pip,
    Uv,
    Poetry,
    Pdm,
    Pipx,
    Cargo,
    Go,
}

impl Manager {
    pub fn as_str(self) -> &'static str {
        match self {
            Manager::Npm => "npm",
            Manager::Pnpm => "pnpm",
            Manager::Yarn => "yarn",
            Manager::Bun => "bun",
            Manager::Pip => "pip",
            Manager::Uv => "uv",
            Manager::Poetry => "poetry",
            Manager::Pdm => "pdm",
            Manager::Pipx => "pipx",
            Manager::Cargo => "cargo",
            Manager::Go => "go",
        }
    }

    /// The registry the manager's packages come from (`wave5-records.schema.json`).
    pub fn ecosystem(self) -> &'static str {
        match self {
            Manager::Npm | Manager::Pnpm | Manager::Yarn | Manager::Bun => "npm",
            Manager::Pip | Manager::Uv | Manager::Poetry | Manager::Pdm | Manager::Pipx => "PyPI",
            Manager::Cargo => "crates.io",
            Manager::Go => "Go",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Form {
    Add,
    Run,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Package {
    pub name: String,
    pub version: Option<String>,
}

/// Something an install fetches that the check cannot name by registry.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Unseen {
    Path,
    Url,
    Git,
    Requirements,
    Update,
    Stdin,
    Spec,
    Registry,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Install {
    pub manager: Manager,
    pub form: Form,
    /// Installed for the user, not the project: no project lockfile vouches for it.
    pub global: bool,
    pub packages: Vec<Package>,
    pub unseen: Vec<Unseen>,
}

const MAX_DEPTH: usize = 4;

/// Stands for the words `xargs` reads from its input. No argv holds a NUL.
pub const STDIN_WORD: &str = "\u{0}stdin\u{0}";

/// Every install in the text, in order. Empty when there is none.
pub fn parse_installs(text: &str) -> Vec<Install> {
    let mut out = Vec::new();
    walk(text, 0, &mut out);
    out
}

fn walk(text: &str, depth: usize, out: &mut Vec<Install>) {
    if depth > MAX_DEPTH {
        return;
    }
    for words in commands(text) {
        read_command(&words, depth, out);
    }
}

// --- Words and commands ------------------------------------------------------

/// Splits shell text into simple commands, each a list of words (the hook
/// core's `commands`).
pub fn commands(text: &str) -> Vec<Vec<String>> {
    let chars: Vec<char> = text.chars().collect();
    let mut out = Vec::new();
    let mut words: Vec<String> = Vec::new();
    let mut word = String::new();
    let mut in_word = false;
    let mut quote: Option<char> = None;
    let mut skip_next = false;
    fn end_word(
        words: &mut Vec<String>,
        word: &mut String,
        in_word: &mut bool,
        skip_next: &mut bool,
    ) {
        if *in_word {
            if *skip_next {
                *skip_next = false;
            } else {
                words.push(std::mem::take(word));
            }
        }
        word.clear();
        *in_word = false;
    }
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
        match ch {
            '\'' | '"' => {
                quote = Some(ch);
                in_word = true;
            }
            '#' if !in_word => {
                while i < chars.len() && chars[i] != '\n' {
                    i += 1;
                }
                end_word(&mut words, &mut word, &mut in_word, &mut skip_next);
                if !words.is_empty() {
                    out.push(std::mem::take(&mut words));
                }
                skip_next = false;
            }
            ';' | '&' | '|' | '(' | ')' | '\n' | '\r' => {
                end_word(&mut words, &mut word, &mut in_word, &mut skip_next);
                if !words.is_empty() {
                    out.push(std::mem::take(&mut words));
                }
                skip_next = false;
            }
            '<' | '>' => {
                if in_word && !word.is_empty() && word.chars().all(|c| c.is_ascii_digit()) {
                    word.clear();
                    in_word = false;
                }
                end_word(&mut words, &mut word, &mut in_word, &mut skip_next);
                while i + 1 < chars.len() && matches!(chars[i + 1], '>' | '<' | '&' | '|') {
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
        out.push(words);
    }
    out
}

fn is_assignment(w: &str) -> bool {
    let mut chars = w.chars();
    match chars.next() {
        Some(c) if c.is_ascii_lowercase() || c == '_' => {}
        _ => return false,
    }
    for c in chars {
        if c == '=' {
            return true;
        }
        if !(c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_') {
            return false;
        }
    }
    false
}

fn base(word: &str) -> &str {
    let mut b = match word.rfind('/') {
        Some(i) => &word[i + 1..],
        None => word,
    };
    // In turn, as the hook core strips them.
    for ext in [".exe", ".cmd"] {
        if let Some(s) = b.strip_suffix(ext) {
            b = s;
        }
    }
    b
}

const SHELLS: &[&str] = &["sh", "bash", "zsh", "dash", "ksh", "mksh", "ash", "fish"];
const WRAPPERS: &[&str] = &[
    "sudo", "doas", "env", "command", "exec", "builtin", "nohup", "time", "stdbuf", "chronic",
    "unbuffer", "nice", "ionice", "chrt", "taskset", "timeout", "xargs", "corepack",
];
const MANAGER_HEADS: &[&str] = &[
    "npm", "npx", "pnpm", "pn", "pnpx", "pnx", "yarn", "yarnpkg", "bun", "bunx", "uv", "uvx",
    "poetry", "pdm", "pipx", "cargo", "go", "py", "eval",
];

/// `python`, `python3`, `python3.12`.
fn is_python(w: &str) -> bool {
    versioned(w, "python")
}

/// `pip`, `pip3`, `pip3.12`.
fn is_pip(w: &str) -> bool {
    versioned(w, "pip")
}

fn versioned(w: &str, stem: &str) -> bool {
    let Some(rest) = w.strip_prefix(stem) else {
        return false;
    };
    if rest.is_empty() {
        return true;
    }
    let mut parts = rest.split('.');
    let major = parts.next().unwrap_or("");
    let minor = parts.next();
    parts.next().is_none()
        && !major.is_empty()
        && major.chars().all(|c| c.is_ascii_digit())
        && minor.is_none_or(|m| !m.is_empty() && m.chars().all(|c| c.is_ascii_digit()))
}

fn is_head(word: &str) -> bool {
    let b = base(word);
    WRAPPERS.contains(&b)
        || MANAGER_HEADS.contains(&b)
        || SHELLS.contains(&b)
        || is_pip(b)
        || is_python(b)
}

fn read_command(input: &[String], depth: usize, out: &mut Vec<Install>) {
    let mut words: Vec<String> = input.to_vec();
    let mut from_stdin = false;
    for _ in 0..16 {
        while words.first().is_some_and(|w| is_assignment(w)) {
            words.remove(0);
        }
        let Some(first) = words.first() else {
            return;
        };
        let head = base(first).to_string();
        let rest: Vec<String> = words[1..].to_vec();
        if head == "env" {
            if let Some(split) = rest.iter().position(|w| {
                w == "-s" || w == "--split-string" || w.starts_with("--split-string=")
            }) {
                let w = &rest[split];
                let s = match w.strip_prefix("--split-string=") {
                    Some(v) => Some(v.to_string()),
                    None => rest.get(split + 1).cloned(),
                };
                if let Some(s) = s {
                    walk(&s, depth + 1, out);
                }
                return;
            }
        }
        if head == "eval" {
            walk(&rest.join(" "), depth + 1, out);
            return;
        }
        if SHELLS.contains(&head.as_str()) {
            if let Some(c) = shell_command_string(&rest) {
                walk(&c, depth + 1, out);
            }
            return;
        }
        if !WRAPPERS.contains(&head.as_str()) {
            break;
        }
        if head == "xargs" {
            from_stdin = true;
        }
        let Some(next) = rest.iter().position(|w| !is_assignment(w) && is_head(w)) else {
            return;
        };
        words = rest[next..].to_vec();
        if head == "xargs" {
            words.push(STDIN_WORD.to_string());
        }
    }
    if words.is_empty() {
        return;
    }
    let before = out.len();
    read_manager(&words, depth, out);
    if from_stdin {
        for inst in &mut out[before..] {
            if !inst.unseen.contains(&Unseen::Stdin) {
                inst.unseen.push(Unseen::Stdin);
            }
        }
    }
}

fn read_manager(words: &[String], depth: usize, out: &mut Vec<Install>) {
    let head = base(&words[0]);
    let rest = &words[1..];
    match head {
        "npm" => npm(rest, out, depth),
        "npx" => npx(rest, Manager::Npm, out, depth),
        "pnpm" | "pn" => pnpm(rest, out),
        "pnpx" | "pnx" => dlx(rest, Manager::Pnpm, out),
        "yarn" | "yarnpkg" => yarn(rest, out, false),
        "bun" => bun(rest, out),
        "bunx" => bunx(rest, out),
        "uv" => uv(rest, out),
        "uvx" => uv_run(rest, out),
        "poetry" => poetry(rest, out),
        "pdm" => pdm(rest, out),
        "pipx" => pipx(rest, out),
        "cargo" => cargo(rest, out),
        "go" => go(rest, out),
        h if is_pip(h) => pip(rest, Manager::Pip, out),
        h if is_python(h) || h == "py" => {
            if let Some((module, args)) = python_module(rest) {
                if is_pip(&module) {
                    pip(&args, Manager::Pip, out);
                } else if module == "uv" {
                    uv(&args, out);
                } else if module == "pipx" {
                    pipx(&args, out);
                }
            }
        }
        _ => {}
    }
}

/// `-c <string>` (or a combined short flag holding `c`, as `-lc`).
fn shell_command_string(words: &[String]) -> Option<String> {
    let mut i = 0;
    while i < words.len() {
        let w = &words[i];
        if w == "--" || !w.starts_with('-') {
            return None;
        }
        if w.len() > 1 && w[1..].chars().all(|c| c.is_ascii_lowercase()) && w[1..].contains('c') {
            return words.get(i + 1).cloned();
        }
        if w == "-o" || w == "+o" {
            i += 1;
        }
        i += 1;
    }
    None
}

/// `python -m <module> args` (the hook core's `pythonModule`).
fn python_module(words: &[String]) -> Option<(String, Vec<String>)> {
    for i in 0..words.len() {
        let w = &words[i];
        if w == "-m" {
            return words
                .get(i + 1)
                .map(|m| (m.clone(), words[i + 2..].to_vec()));
        }
        if w.starts_with("-m") && w.len() > 2 && !w.starts_with("--") {
            return Some((w[2..].to_string(), words[i + 1..].to_vec()));
        }
        if w == "-c" || w == "--" {
            return None;
        }
        if w.starts_with('-') {
            continue;
        }
        if i > 0 && (words[i - 1] == "-w" || words[i - 1] == "-x") {
            continue;
        }
        return None;
    }
    None
}

// --- Specs -------------------------------------------------------------------

enum Spec {
    Pkg(Package),
    Unseen(Unseen),
}

fn npm_name(s: &str) -> bool {
    let (scope, name) = match s.strip_prefix('@') {
        Some(rest) => match rest.split_once('/') {
            Some((sc, n)) => (Some(sc), n),
            None => return false,
        },
        None => (None, s),
    };
    let part = |p: &str| {
        let mut c = p.chars();
        matches!(c.next(), Some(f) if f.is_ascii_lowercase() || f.is_ascii_digit() || f == '~')
            && p.chars().all(|c| {
                c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '.' | '_' | '~' | '-')
            })
    };
    scope.is_none_or(part) && part(name)
}

fn pypi_name(s: &str) -> bool {
    let first = s.chars().next();
    let last = s.chars().last();
    matches!(first, Some(c) if c.is_ascii_lowercase() || c.is_ascii_digit())
        && matches!(last, Some(c) if c.is_ascii_lowercase() || c.is_ascii_digit())
        && s.chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '.' | '_' | '-'))
}

fn crate_name(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && s.chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '-')
}

fn go_path(s: &str) -> bool {
    let mut parts = s.split('/');
    let host = parts.next().unwrap_or("");
    let host_ok = {
        let labels: Vec<&str> = host.split('.').collect();
        labels.len() >= 2
            && labels.iter().all(|l| {
                !l.is_empty()
                    && l.chars()
                        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
            })
    };
    host_ok
        && parts.all(|p| {
            !p.is_empty()
                && p.chars().all(|c| {
                    c.is_ascii_lowercase()
                        || c.is_ascii_digit()
                        || matches!(c, '.' | '_' | '~' | '+' | '-')
                })
        })
}

fn clean_version(v: &str) -> Option<String> {
    if v.is_empty() || v.chars().count() > 64 {
        return None;
    }
    v.chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || ".^~<>=!*+_, -".contains(c))
        .then(|| v.to_string())
}

fn looks_like_url(s: &str) -> bool {
    if s.starts_with("git@") {
        return true;
    }
    let Some(i) = s.find("://") else {
        return false;
    };
    let scheme = &s[..i];
    let mut c = scheme.chars();
    matches!(c.next(), Some(f) if f.is_ascii_lowercase())
        && c.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '+' | '.' | '-'))
}

fn looks_like_path(s: &str) -> bool {
    s.starts_with('.')
        || s.starts_with('/')
        || s.starts_with('~')
        || s.starts_with("file:")
        || [".tgz", ".tar.gz", ".tar", ".zip", ".whl"]
            .iter()
            .any(|e| s.ends_with(e))
}

fn npm_spec(spec: &str) -> Spec {
    for p in ["git+", "github:", "gitlab:", "bitbucket:", "gist:"] {
        if spec.starts_with(p) {
            return Spec::Unseen(Unseen::Git);
        }
    }
    if looks_like_url(spec) {
        return Spec::Unseen(Unseen::Url);
    }
    if looks_like_path(spec) {
        return Spec::Unseen(Unseen::Path);
    }
    for p in ["workspace:", "link:", "portal:", "patch:"] {
        if spec.starts_with(p) {
            return Spec::Unseen(Unseen::Path);
        }
    }
    let at = spec.get(1..).and_then(|s| s.find('@')).map(|i| i + 1);
    let (name, range) = match at {
        Some(i) => (&spec[..i], &spec[i + 1..]),
        None => (spec, ""),
    };
    if let Some(inner) = range.strip_prefix("npm:") {
        return npm_spec(inner);
    }
    if range.starts_with("git")
        || range.starts_with("http")
        || range.starts_with("file:")
        || range.contains('/')
    {
        return Spec::Unseen(if range.starts_with("file:") {
            Unseen::Path
        } else {
            Unseen::Git
        });
    }
    if !npm_name(name) {
        // `user/repo` is a GitHub shorthand: a git source.
        let shorthand = spec.split_once('#').map_or(spec, |(a, _)| a);
        if let Some((u, r)) = shorthand.split_once('/') {
            let ok = |p: &str| {
                !p.is_empty()
                    && p.chars().all(|c| {
                        c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '.' | '_' | '-')
                    })
            };
            if ok(u) && ok(r) {
                return Spec::Unseen(Unseen::Git);
            }
        }
        return Spec::Unseen(Unseen::Spec);
    }
    let version = if range.is_empty() {
        None
    } else {
        clean_version(range)
    };
    if !range.is_empty() && version.is_none() {
        return Spec::Unseen(Unseen::Spec);
    }
    Spec::Pkg(Package {
        name: name.chars().take(214).collect(),
        version,
    })
}

fn pypi_spec(spec: &str, poetry_at: bool) -> Spec {
    for p in ["git+", "hg+", "svn+", "bzr+"] {
        if spec.starts_with(p) {
            return Spec::Unseen(Unseen::Git);
        }
    }
    if looks_like_url(spec) {
        return Spec::Unseen(Unseen::Url);
    }
    if looks_like_path(spec) {
        return Spec::Unseen(Unseen::Path);
    }
    // name, optional [extras], then the rest.
    let first = spec.chars().next();
    if !matches!(first, Some(c) if c.is_ascii_lowercase() || c.is_ascii_digit()) {
        return Spec::Unseen(Unseen::Spec);
    }
    let name_end = spec
        .find(|c: char| {
            !(c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '.' | '_' | '-'))
        })
        .unwrap_or(spec.len());
    let raw_name = &spec[..name_end];
    let mut rest = &spec[name_end..];
    if let Some(r) = rest.strip_prefix('[') {
        let Some(close) = r.find(']') else {
            return Spec::Unseen(Unseen::Spec);
        };
        let extras = &r[..close];
        if !extras.chars().all(|c| {
            c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '.' | '_' | ',' | ' ' | '-')
        }) {
            return Spec::Unseen(Unseen::Spec);
        }
        rest = &r[close + 1..];
    }
    let name = collapse_separators(raw_name);
    if !pypi_name(&name) {
        return Spec::Unseen(Unseen::Spec);
    }
    let mut rest = rest.trim().to_string();
    if let Some(r) = rest.strip_prefix('@') {
        if poetry_at {
            rest = r.trim().to_string();
        } else {
            return Spec::Unseen(Unseen::Url);
        }
    }
    if rest.starts_with(';') {
        rest.clear();
    }
    if let Some(semi) = rest.find(';') {
        rest = rest[..semi].trim().to_string();
    }
    if let Some(r) = rest.strip_prefix("===") {
        rest = r.to_string();
    } else if let Some(r) = rest.strip_prefix("==") {
        rest = r.to_string();
    }
    let version = if rest.is_empty() {
        None
    } else {
        clean_version(&rest)
    };
    if !rest.is_empty() && version.is_none() {
        return Spec::Unseen(Unseen::Spec);
    }
    Spec::Pkg(Package { name, version })
}

/// PEP 503: runs of `-`, `_` and `.` are one `-`.
pub(crate) fn collapse_separators(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut last_sep = false;
    for c in s.chars() {
        if matches!(c, '-' | '_' | '.') {
            if !last_sep {
                out.push('-');
            }
            last_sep = true;
        } else {
            out.push(c);
            last_sep = false;
        }
    }
    out
}

fn crate_spec(spec: &str) -> Spec {
    if looks_like_url(spec) {
        return Spec::Unseen(Unseen::Url);
    }
    if looks_like_path(spec) {
        return Spec::Unseen(Unseen::Path);
    }
    let (name, range) = spec.split_once('@').unwrap_or((spec, ""));
    if !crate_name(name) {
        return Spec::Unseen(Unseen::Spec);
    }
    let range = range.strip_prefix('=').unwrap_or(range);
    let version = if range.is_empty() {
        None
    } else {
        clean_version(range)
    };
    if !range.is_empty() && version.is_none() {
        return Spec::Unseen(Unseen::Spec);
    }
    Spec::Pkg(Package {
        name: name.to_string(),
        version,
    })
}

fn go_spec(spec: &str) -> Option<Spec> {
    if spec == "."
        || spec.starts_with("./")
        || spec.starts_with("../")
        || spec.starts_with('/')
        || spec == "all"
        || spec == "..."
    {
        return None;
    }
    let (path, range) = spec.split_once('@').unwrap_or((spec, ""));
    if range == "none" {
        return None;
    }
    let path = path.strip_suffix("/...").unwrap_or(path);
    if !go_path(path) {
        return Some(Spec::Unseen(Unseen::Spec));
    }
    let version = if range.is_empty() {
        None
    } else {
        clean_version(range)
    };
    if !range.is_empty() && version.is_none() {
        return Some(Spec::Unseen(Unseen::Spec));
    }
    Some(Spec::Pkg(Package {
        name: path.to_string(),
        version,
    }))
}

// --- Argument walking ---------------------------------------------------------

#[derive(Default)]
struct Args {
    positionals: Vec<String>,
    values: Vec<(String, String)>,
    flags: Vec<String>,
    after: Vec<String>,
}

impl Args {
    fn values_of(&self, names: &[&str]) -> Vec<String> {
        // In the order the names are given, as the hook core's `valuesOf`.
        names
            .iter()
            .flat_map(|n| {
                self.values
                    .iter()
                    .filter(move |(k, _)| k == n)
                    .map(|(_, v)| v.clone())
            })
            .collect()
    }
    fn has(&self, names: &[&str]) -> bool {
        names
            .iter()
            .any(|n| self.flags.iter().any(|f| f == n) || self.values.iter().any(|(k, _)| k == n))
    }
}

/// Splits words into flags and positionals (the hook core's `args`).
fn args(words: &[String], valued: &[&str], stop_at_first_positional: bool) -> Args {
    let mut a = Args::default();
    let mut i = 0;
    while i < words.len() {
        let w = &words[i];
        if w == "--" {
            a.after = words[i + 1..].to_vec();
            break;
        }
        if w.starts_with('-') && w != "-" {
            if let Some(eq) = w.find('=').filter(|&e| e > 0) {
                a.values
                    .push((w[..eq].to_string(), w[eq + 1..].to_string()));
                i += 1;
                continue;
            }
            if valued.contains(&w.as_str()) && i + 1 < words.len() {
                a.values.push((w.clone(), words[i + 1].clone()));
                i += 2;
                continue;
            }
            a.flags.push(w.clone());
            i += 1;
            continue;
        }
        a.positionals.push(w.clone());
        if stop_at_first_positional {
            a.after = words[i + 1..].to_vec();
            break;
        }
        i += 1;
    }
    a
}

fn build(
    manager: Manager,
    form: Form,
    specs: &[String],
    read: &dyn Fn(&str) -> Option<Spec>,
    extra: Vec<Unseen>,
    global: bool,
) -> Install {
    let mut inst = Install {
        manager,
        form,
        global,
        packages: Vec::new(),
        unseen: extra,
    };
    for s in specs {
        if s == STDIN_WORD {
            if !inst.unseen.contains(&Unseen::Stdin) {
                inst.unseen.push(Unseen::Stdin);
            }
            continue;
        }
        match read(s) {
            Some(Spec::Pkg(p)) => inst.packages.push(p),
            Some(Spec::Unseen(u)) if !inst.unseen.contains(&u) => inst.unseen.push(u),
            Some(Spec::Unseen(_)) | None => {}
        }
    }
    inst
}

fn npm_read(s: &str) -> Option<Spec> {
    Some(npm_spec(s))
}
fn pypi_read(s: &str) -> Option<Spec> {
    Some(pypi_spec(s, false))
}
fn poetry_read(s: &str) -> Option<Spec> {
    Some(pypi_spec(s, true))
}
fn crate_read(s: &str) -> Option<Spec> {
    Some(crate_spec(s))
}

fn registry_flags(a: &Args, names: &[&str]) -> Vec<Unseen> {
    if a.has(names) {
        vec![Unseen::Registry]
    } else {
        Vec::new()
    }
}

/// The first word that names one of `known`, past flags and their values
/// (the hook core's `subcommand`).
fn subcommand(words: &[String], known: &[&str], valued: &[&str]) -> Option<(String, Vec<String>)> {
    let mut i = 0;
    while i < words.len() {
        let w = &words[i];
        if w == "--" {
            return None;
        }
        if w.starts_with('-') {
            if !w.contains('=') && valued.contains(&w.as_str()) {
                i += 1;
            }
            i += 1;
            continue;
        }
        if known.contains(&w.as_str()) {
            let mut rest = words[..i].to_vec();
            rest.extend_from_slice(&words[i + 1..]);
            return Some((w.clone(), rest));
        }
        i += 1;
    }
    None
}

/// `name @ url` arrives as three words: keep it one spec.
fn join_at_urls(words: &[String]) -> Vec<String> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < words.len() {
        if words.get(i + 1).is_some_and(|w| w == "@") && i + 2 < words.len() {
            out.push(format!("{} @ {}", words[i], words[i + 2]));
            i += 3;
        } else {
            out.push(words[i].clone());
            i += 1;
        }
    }
    out
}

fn concat(a: Vec<Unseen>, b: Vec<Unseen>) -> Vec<Unseen> {
    let mut v = a;
    v.extend(b);
    v
}

// --- npm -----------------------------------------------------------------------

const NPM_INSTALL: &[&str] = &[
    "install",
    "i",
    "in",
    "ins",
    "inst",
    "insta",
    "instal",
    "isnt",
    "isnta",
    "isntal",
    "isntall",
    "add",
    "install-test",
    "it",
];
const NPM_UPDATE: &[&str] = &["update", "up", "upgrade", "udpate"];
const NPM_EXEC: &[&str] = &["exec", "x"];
const NPM_OTHER: &[&str] = &[
    "ci",
    "clean-install",
    "install-clean",
    "isntall-clean",
    "install-ci-test",
    "cit",
    "clean-install-test",
    "sit",
    "run",
    "run-script",
    "rum",
    "urn",
    "test",
    "t",
    "tst",
    "start",
    "stop",
    "restart",
    "ls",
    "list",
    "la",
    "ll",
    "view",
    "info",
    "show",
    "v",
    "outdated",
    "audit",
    "uninstall",
    "remove",
    "rm",
    "r",
    "un",
    "unlink",
    "prune",
    "dedupe",
    "ddp",
    "find-dupes",
    "rebuild",
    "rb",
    "init",
    "create",
    "innit",
    "pack",
    "publish",
    "config",
    "c",
    "get",
    "set",
    "cache",
    "help",
    "explain",
    "why",
    "query",
    "pkg",
    "version",
    "doctor",
    "root",
    "prefix",
    "bin",
    "link",
    "ln",
    "approve-scripts",
    "deny-scripts",
    "install-scripts",
    "sbom",
    "search",
    "fund",
    "login",
    "logout",
    "whoami",
    "token",
    "owner",
    "access",
    "team",
    "org",
    "profile",
    "star",
    "stars",
    "unstar",
    "repo",
    "docs",
    "home",
    "bugs",
    "issues",
    "edit",
    "explore",
    "diff",
    "dist-tag",
    "deprecate",
    "undeprecate",
    "unpublish",
    "ping",
    "completion",
    "hook",
    "shrinkwrap",
    "stage",
    "trust",
    "patch",
];
const NPM_VALUED: &[&str] = &[
    "-w",
    "--workspace",
    "--prefix",
    "-c",
    "--call",
    "--registry",
    "--userconfig",
    "--globalconfig",
    "--cache",
    "--omit",
    "--include",
    "--install-strategy",
    "--cpu",
    "--os",
    "--libc",
    "--before",
    "--min-release-age",
    "--min-release-age-exclude",
    "--allow-scripts",
    "--allow-directory",
    "--allow-file",
    "--allow-git",
    "--allow-remote",
    "--tag",
    "--loglevel",
    "--package",
];
const NPM_REGISTRY: &[&str] = &["--registry"];

fn npm(words: &[String], out: &mut Vec<Install>, depth: usize) {
    let known: Vec<&str> = [NPM_INSTALL, NPM_UPDATE, NPM_EXEC, NPM_OTHER].concat();
    let Some((name, rest)) = subcommand(words, &known, NPM_VALUED) else {
        return;
    };
    if NPM_EXEC.contains(&name.as_str()) {
        return npx(&rest, Manager::Npm, out, depth);
    }
    let a = args(&rest, NPM_VALUED, false);
    let global = a.has(&["-g", "--global"]);
    if NPM_INSTALL.contains(&name.as_str()) {
        if a.positionals.is_empty() {
            return;
        }
        out.push(build(
            Manager::Npm,
            Form::Add,
            &a.positionals,
            &npm_read,
            registry_flags(&a, NPM_REGISTRY),
            global,
        ));
        return;
    }
    if NPM_UPDATE.contains(&name.as_str()) {
        out.push(build(
            Manager::Npm,
            Form::Add,
            &a.positionals,
            &npm_read,
            concat(vec![Unseen::Update], registry_flags(&a, NPM_REGISTRY)),
            global,
        ));
    }
}

fn npx(words: &[String], manager: Manager, out: &mut Vec<Install>, depth: usize) {
    let a = args(
        words,
        &[
            "-p",
            "--package",
            "-c",
            "--call",
            "-w",
            "--workspace",
            "--registry",
            "--prefix",
            "--cache",
            "--userconfig",
            "--loglevel",
        ],
        true,
    );
    let call = a.values_of(&["-c", "--call"]);
    for c in &call {
        walk(c, depth + 1, out);
    }
    let pkgs = a.values_of(&["-p", "--package"]);
    let first = a
        .positionals
        .first()
        .cloned()
        .or_else(|| a.after.iter().find(|w| !w.starts_with('-')).cloned());
    let specs: Vec<String> = if !pkgs.is_empty() {
        pkgs
    } else {
        match first {
            Some(f) if call.is_empty() => vec![f],
            _ => Vec::new(),
        }
    };
    if specs.is_empty() {
        return;
    }
    out.push(build(
        manager,
        Form::Run,
        &specs,
        &npm_read,
        registry_flags(&a, NPM_REGISTRY),
        false,
    ));
}

// --- pnpm ----------------------------------------------------------------------

const PNPM_ADD: &[&str] = &["add", "install", "i"];
const PNPM_UPDATE: &[&str] = &["update", "up", "upgrade"];
const PNPM_OTHER: &[&str] = &[
    "dlx",
    "exec",
    "run",
    "test",
    "t",
    "start",
    "ls",
    "list",
    "ll",
    "why",
    "outdated",
    "audit",
    "remove",
    "rm",
    "uninstall",
    "un",
    "prune",
    "rebuild",
    "rb",
    "store",
    "init",
    "create",
    "pack",
    "publish",
    "config",
    "c",
    "link",
    "ln",
    "unlink",
    "import",
    "fetch",
    "patch",
    "patch-commit",
    "dedupe",
    "setup",
    "env",
    "root",
    "bin",
    "licenses",
    "approve-builds",
    "ignored-builds",
    "deploy",
    "doctor",
    "server",
    "self-update",
    "cat-file",
    "cat-index",
    "find-hash",
    "recursive",
    "sbom",
    "view",
    "info",
];
const PNPM_VALUED: &[&str] = &[
    "-c",
    "--dir",
    "-f",
    "--filter",
    "--filter-prod",
    "--workspace-dir",
    "--store-dir",
    "--state-dir",
    "--virtual-store-dir",
    "--global-dir",
    "--registry",
    "--loglevel",
    "--reporter",
    "--cpu",
    "--os",
    "--libc",
    "--allow-build",
    "--lockfile-dir",
    "--save-prefix",
    "--save-catalog-name",
    "--env-file",
    "--npmrc-auth-file",
    "--workspace-packages",
    "--https-proxy",
    "--http-proxy",
    "--no-proxy",
    "--package",
    "--changed-files-ignore-pattern",
    "--test-pattern",
];

fn pnpm(words: &[String], out: &mut Vec<Install>) {
    let known: Vec<&str> = [PNPM_ADD, PNPM_UPDATE, PNPM_OTHER].concat();
    let Some((name, rest)) = subcommand(words, &known, PNPM_VALUED) else {
        return;
    };
    if name == "dlx" {
        return dlx(&rest, Manager::Pnpm, out);
    }
    let a = args(&rest, PNPM_VALUED, false);
    let global = a.has(&["-g", "--global"]);
    if PNPM_ADD.contains(&name.as_str()) {
        if a.positionals.is_empty() {
            return;
        }
        out.push(build(
            Manager::Pnpm,
            Form::Add,
            &a.positionals,
            &npm_read,
            registry_flags(&a, &["--registry"]),
            global,
        ));
        return;
    }
    if PNPM_UPDATE.contains(&name.as_str()) {
        out.push(build(
            Manager::Pnpm,
            Form::Add,
            &a.positionals,
            &npm_read,
            concat(vec![Unseen::Update], registry_flags(&a, &["--registry"])),
            global,
        ));
    }
}

fn dlx(words: &[String], manager: Manager, out: &mut Vec<Install>) {
    let a = args(
        words,
        &[
            "--package",
            "-p",
            "--allow-build",
            "--cpu",
            "--os",
            "--libc",
            "--registry",
            "--dir",
        ],
        true,
    );
    let pkgs = a.values_of(&["--package", "-p"]);
    let mut first = a.positionals.first().cloned();
    if a.has(&["-c", "--shell-mode"]) {
        if let Some(f) = &first {
            first = commands(f)
                .into_iter()
                .next()
                .and_then(|w| w.into_iter().next());
        }
    }
    let specs: Vec<String> = if !pkgs.is_empty() {
        pkgs
    } else {
        first.into_iter().collect()
    };
    if specs.is_empty() {
        return;
    }
    out.push(build(
        manager,
        Form::Run,
        &specs,
        &npm_read,
        registry_flags(&a, &["--registry"]),
        false,
    ));
}

// --- yarn ----------------------------------------------------------------------

const YARN_KNOWN: &[&str] = &[
    "add",
    "dlx",
    "global",
    "up",
    "upgrade",
    "install",
    "run",
    "test",
    "remove",
    "info",
    "why",
    "list",
    "workspace",
    "workspaces",
    "exec",
    "node",
    "npm",
    "set",
    "config",
    "cache",
    "init",
    "pack",
    "plugin",
    "constraints",
    "dedupe",
    "explain",
    "patch",
    "rebuild",
    "unlink",
    "link",
    "bin",
    "outdated",
    "audit",
    "autoclean",
    "check",
    "create",
    "generate-lock-entry",
    "import",
    "licenses",
    "login",
    "logout",
    "owner",
    "policies",
    "publish",
    "tag",
    "team",
    "version",
    "versions",
];
const YARN_VALUED: &[&str] = &[
    "--cwd",
    "--mode",
    "--package",
    "--use-yarnrc",
    "--modules-folder",
    "--cache-folder",
    "--registry",
    "--network-timeout",
    "--network-concurrency",
    "--mutex",
    "--global-folder",
    "--link-folder",
];

fn yarn(words: &[String], out: &mut Vec<Install>, global: bool) {
    let Some((name, rest)) = subcommand(words, YARN_KNOWN, YARN_VALUED) else {
        return;
    };
    if name == "dlx" {
        return dlx(&rest, Manager::Yarn, out);
    }
    if name == "workspace" {
        let a = args(&rest, YARN_VALUED, true);
        return yarn(&a.after, out, global);
    }
    if name == "global" {
        return yarn(&rest, out, true);
    }
    let a = args(&rest, YARN_VALUED, false);
    if name == "add" {
        if a.positionals.is_empty() {
            return;
        }
        out.push(build(
            Manager::Yarn,
            Form::Add,
            &a.positionals,
            &npm_read,
            registry_flags(&a, &["--registry"]),
            global,
        ));
        return;
    }
    if name == "up" || name == "upgrade" {
        out.push(build(
            Manager::Yarn,
            Form::Add,
            &a.positionals,
            &npm_read,
            vec![Unseen::Update],
            global,
        ));
    }
}

// --- bun -----------------------------------------------------------------------

const BUN_KNOWN: &[&str] = &[
    "add", "a", "install", "i", "x", "update", "run", "test", "remove", "rm", "pm", "link",
    "unlink", "outdated", "audit", "info", "why", "publish", "patch", "init", "create", "c",
    "build", "upgrade", "repl", "exec",
];
const BUN_VALUED: &[&str] = &[
    "-c",
    "--config",
    "--cwd",
    "--registry",
    "--backend",
    "--cache-dir",
    "--ca",
    "--cafile",
    "--env-file",
    "--concurrent-scripts",
    "--network-concurrency",
    "--omit",
    "--linker",
    "--minimum-release-age",
    "--minimum-release-age-excludes",
    "--cpu",
    "--os",
    "--libc",
    "-f",
    "--filter",
    "--catalog",
];

fn bun(words: &[String], out: &mut Vec<Install>) {
    let Some((name, rest)) = subcommand(words, BUN_KNOWN, BUN_VALUED) else {
        return;
    };
    if name == "x" {
        return bunx(&rest, out);
    }
    let a = args(&rest, BUN_VALUED, false);
    let global = a.has(&["-g", "--global"]);
    if matches!(name.as_str(), "add" | "a" | "install" | "i") {
        if a.positionals.is_empty() {
            return;
        }
        out.push(build(
            Manager::Bun,
            Form::Add,
            &a.positionals,
            &npm_read,
            registry_flags(&a, &["--registry"]),
            global,
        ));
        return;
    }
    if name == "update" {
        out.push(build(
            Manager::Bun,
            Form::Add,
            &a.positionals,
            &npm_read,
            vec![Unseen::Update],
            global,
        ));
    }
}

fn bunx(words: &[String], out: &mut Vec<Install>) {
    let valued: Vec<&str> = [BUN_VALUED, &["-p", "--package"]].concat();
    let a = args(words, &valued, true);
    let pkgs = a.values_of(&["-p", "--package"]);
    let specs: Vec<String> = if !pkgs.is_empty() {
        pkgs
    } else {
        a.positionals.first().cloned().into_iter().collect()
    };
    if specs.is_empty() {
        return;
    }
    out.push(build(
        Manager::Bun,
        Form::Run,
        &specs,
        &npm_read,
        registry_flags(&a, &["--registry"]),
        false,
    ));
}

// --- pip -----------------------------------------------------------------------

const PIP_VALUED: &[&str] = &[
    "-r",
    "--requirement",
    "-c",
    "--constraint",
    "-e",
    "--editable",
    "-t",
    "--target",
    "--config-settings",
    "-i",
    "--index-url",
    "--extra-index-url",
    "-f",
    "--find-links",
    "--platform",
    "--python-version",
    "--implementation",
    "--abi",
    "--root",
    "--prefix",
    "--src",
    "--upgrade-strategy",
    "--build-constraint",
    "--no-binary",
    "--only-binary",
    "--progress-bar",
    "--root-user-action",
    "--report",
    "--log",
    "--proxy",
    "--retries",
    "--timeout",
    "--exists-action",
    "--trusted-host",
    "--cert",
    "--client-cert",
    "--cache-dir",
    "--use-feature",
    "--use-deprecated",
    "--keyring-provider",
    "--python",
    "--resume-retries",
    "--uploaded-prior-to",
    "--requirements-from-script",
    "--refresh-package",
    "--all-releases",
    "--only-final",
    "--group",
];
const PIP_REGISTRY: &[&str] = &[
    "-i",
    "--index-url",
    "--extra-index-url",
    "-f",
    "--find-links",
];

fn pip(words: &[String], manager: Manager, out: &mut Vec<Install>) {
    let known = [
        "install",
        "download",
        "wheel",
        "uninstall",
        "list",
        "show",
        "freeze",
        "check",
        "config",
        "cache",
        "index",
        "inspect",
        "hash",
        "help",
        "debug",
        "completion",
        "lock",
    ];
    let Some((name, rest)) = subcommand(words, &known, PIP_VALUED) else {
        return;
    };
    if name != "install" {
        return;
    }
    let a = args(&rest, PIP_VALUED, false);
    let mut extra = registry_flags(&a, PIP_REGISTRY);
    if a.has(&[
        "-r",
        "--requirement",
        "--requirements-from-script",
        "--group",
    ]) {
        extra.push(Unseen::Requirements);
    }
    if a.has(&["-e", "--editable"]) {
        extra.push(Unseen::Path);
    }
    let specs = join_at_urls(&a.positionals);
    if specs.is_empty() && extra.is_empty() {
        return;
    }
    out.push(build(manager, Form::Add, &specs, &pypi_read, extra, false));
}

// --- uv ------------------------------------------------------------------------

const UV_VALUED: &[&str] = &[
    "--directory",
    "--project",
    "--cache-dir",
    "--config-file",
    "--color",
    "--python",
    "-p",
    "--allow-insecure-host",
    "--bounds",
    "--branch",
    "--rev",
    "--tag",
    "--config-setting",
    "--config-settings-package",
    "--constraints",
    "-c",
    "--default-index",
    "--exclude-newer",
    "--exclude-newer-package",
    "--extra",
    "--extra-index-url",
    "--find-links",
    "-f",
    "--fork-strategy",
    "--group",
    "--index",
    "--index-strategy",
    "--index-url",
    "-i",
    "--keyring-provider",
    "--link-mode",
    "--marker",
    "-m",
    "--no-binary-package",
    "--no-build-isolation-package",
    "--no-build-package",
    "--no-install-package",
    "--no-sources-package",
    "--optional",
    "--package",
    "--prerelease",
    "--prerelease-package",
    "--refresh-package",
    "--reinstall-package",
    "--requirements",
    "-r",
    "--resolution",
    "--script",
    "--upgrade-group",
    "--upgrade-package",
    "--build-constraints",
    "-b",
    "--editable",
    "-e",
    "--excludes",
    "--no-binary",
    "--only-binary",
    "--output-format",
    "--overrides",
    "--prefix",
    "--python-platform",
    "--python-version",
    "--target",
    "-t",
    "--torch-backend",
    "--env-file",
    "--from",
    "--with",
    "-w",
    "--with-editable",
    "--with-requirements",
    "--with-executables-from",
    "--no-editable-package",
];
const UV_REGISTRY: &[&str] = &[
    "--index",
    "--index-url",
    "-i",
    "--default-index",
    "--extra-index-url",
    "--find-links",
    "-f",
];
const UV_KNOWN: &[&str] = &[
    "add", "pip", "tool", "run", "sync", "lock", "remove", "init", "tree", "export", "venv",
    "build", "publish", "python", "cache", "self", "version", "help", "format", "auth",
];

fn uv(words: &[String], out: &mut Vec<Install>) {
    let Some((name, rest)) = subcommand(words, UV_KNOWN, UV_VALUED) else {
        return;
    };
    if name == "pip" {
        let inner = subcommand(
            &rest,
            &[
                "install",
                "sync",
                "compile",
                "uninstall",
                "list",
                "show",
                "freeze",
                "check",
                "tree",
            ],
            UV_VALUED,
        );
        let Some((iname, irest)) = inner else {
            return;
        };
        if iname != "install" {
            return;
        }
        let a = args(&irest, UV_VALUED, false);
        let mut extra = registry_flags(&a, UV_REGISTRY);
        if a.has(&["-r", "--requirements"]) {
            extra.push(Unseen::Requirements);
        }
        if a.has(&["-e", "--editable"]) {
            extra.push(Unseen::Path);
        }
        let specs = join_at_urls(&a.positionals);
        if specs.is_empty() && extra.is_empty() {
            return;
        }
        out.push(build(
            Manager::Uv,
            Form::Add,
            &specs,
            &pypi_read,
            extra,
            false,
        ));
        return;
    }
    if name == "tool" {
        let Some((iname, irest)) = subcommand(
            &rest,
            &[
                "run",
                "install",
                "upgrade",
                "list",
                "uninstall",
                "update-shell",
                "dir",
            ],
            UV_VALUED,
        ) else {
            return;
        };
        if iname == "run" {
            return uv_run(&irest, out);
        }
        if iname == "install" {
            let a = args(&irest, UV_VALUED, false);
            let mut specs = join_at_urls(&a.positionals);
            specs.extend(a.values_of(&["--with", "-w", "--with-executables-from"]));
            let mut extra = registry_flags(&a, UV_REGISTRY);
            if a.has(&["--with-requirements"]) {
                extra.push(Unseen::Requirements);
            }
            if a.has(&["--with-editable"]) {
                extra.push(Unseen::Path);
            }
            out.push(build(
                Manager::Uv,
                Form::Add,
                &specs,
                &pypi_read,
                extra,
                true,
            ));
        }
        if iname == "upgrade" {
            out.push(build(
                Manager::Uv,
                Form::Add,
                &[],
                &pypi_read,
                vec![Unseen::Update],
                true,
            ));
        }
        return;
    }
    let a = args(&rest, UV_VALUED, false);
    if name == "add" {
        let mut extra = registry_flags(&a, UV_REGISTRY);
        if a.has(&["-r", "--requirements"]) {
            extra.push(Unseen::Requirements);
        }
        if a.has(&["--editable", "-e"]) {
            extra.push(Unseen::Path);
        }
        let specs = join_at_urls(&a.positionals);
        if specs.is_empty() && extra.is_empty() {
            return;
        }
        out.push(build(
            Manager::Uv,
            Form::Add,
            &specs,
            &pypi_read,
            extra,
            false,
        ));
        return;
    }
    if matches!(name.as_str(), "sync" | "lock" | "run")
        && a.has(&["-u", "--upgrade", "--upgrade-package"])
    {
        out.push(build(
            Manager::Uv,
            Form::Add,
            &[],
            &pypi_read,
            vec![Unseen::Update],
            false,
        ));
    }
    if name == "run" {
        let withs = a.values_of(&["--with", "-w"]);
        let extra: Vec<Unseen> = if a.has(&["--with-requirements"]) {
            vec![Unseen::Requirements]
        } else {
            Vec::new()
        };
        if !withs.is_empty() || !extra.is_empty() {
            out.push(build(
                Manager::Uv,
                Form::Run,
                &withs,
                &pypi_read,
                concat(extra, registry_flags(&a, UV_REGISTRY)),
                false,
            ));
        }
    }
}

fn uv_run(words: &[String], out: &mut Vec<Install>) {
    let a = args(words, UV_VALUED, true);
    let from = a.values_of(&["--from"]);
    let mut specs: Vec<String> = if !from.is_empty() {
        from
    } else {
        a.positionals
            .first()
            .map(|f| {
                if f.contains('@') && !f.contains(" @ ") {
                    f.replacen('@', "==", 1)
                } else {
                    f.clone()
                }
            })
            .into_iter()
            .collect()
    };
    let withs = a.values_of(&["--with", "-w"]);
    let mut extra = registry_flags(&a, UV_REGISTRY);
    if a.has(&["--with-requirements"]) {
        extra.push(Unseen::Requirements);
    }
    if a.has(&["--with-editable"]) {
        extra.push(Unseen::Path);
    }
    if specs.is_empty() && withs.is_empty() {
        return;
    }
    specs.extend(withs);
    out.push(build(
        Manager::Uv,
        Form::Run,
        &specs,
        &pypi_read,
        extra,
        false,
    ));
}

// --- poetry, pdm, pipx ---------------------------------------------------------

const POETRY_VALUED: &[&str] = &[
    "-g",
    "--group",
    "--extras",
    "--optional",
    "--python",
    "--platform",
    "--markers",
    "--source",
    "-p",
    "--project",
    "-c",
    "--directory",
];

fn poetry(words: &[String], out: &mut Vec<Install>) {
    let known = [
        "add", "update", "install", "lock", "sync", "remove", "show", "run", "build", "publish",
        "init", "new", "check", "config", "env", "cache", "export", "list", "search", "self",
        "source", "version", "debug", "about", "help", "python",
    ];
    let Some((name, rest)) = subcommand(words, &known, POETRY_VALUED) else {
        return;
    };
    let a = args(&rest, POETRY_VALUED, false);
    let extra = registry_flags(&a, &["--source"]);
    if name == "add" {
        if a.positionals.is_empty() {
            return;
        }
        out.push(build(
            Manager::Poetry,
            Form::Add,
            &a.positionals,
            &poetry_read,
            extra.clone(),
            false,
        ));
    }
    if name == "update" {
        out.push(build(
            Manager::Poetry,
            Form::Add,
            &a.positionals,
            &poetry_read,
            concat(vec![Unseen::Update], extra.clone()),
            false,
        ));
    }
    if name == "self" {
        if let Some((iname, irest)) =
            subcommand(&rest, &["add", "update", "install"], POETRY_VALUED)
        {
            if iname == "add" {
                let b = args(&irest, POETRY_VALUED, false);
                out.push(build(
                    Manager::Poetry,
                    Form::Add,
                    &b.positionals,
                    &poetry_read,
                    Vec::new(),
                    false,
                ));
            }
        }
    }
}

const PDM_VALUED: &[&str] = &[
    "-p",
    "--project",
    "-l",
    "--lockfile",
    "--override",
    "--venv",
    "-k",
    "--skip",
    "--group",
    "-e",
    "--editable",
    "-c",
    "--config-setting",
];

fn pdm(words: &[String], out: &mut Vec<Install>) {
    let known = [
        "add", "update", "install", "sync", "lock", "remove", "list", "run", "build", "publish",
        "init", "info", "show", "search", "config", "venv", "cache", "export", "import", "fix",
        "outdated", "self", "use", "python", "py",
    ];
    let Some((name, rest)) = subcommand(words, &known, PDM_VALUED) else {
        return;
    };
    let a = args(&rest, PDM_VALUED, false);
    let extra: Vec<Unseen> = if a.has(&["-e", "--editable"]) {
        vec![Unseen::Path]
    } else {
        Vec::new()
    };
    if name == "add" {
        if a.positionals.is_empty() && extra.is_empty() {
            return;
        }
        out.push(build(
            Manager::Pdm,
            Form::Add,
            &a.positionals,
            &pypi_read,
            extra,
            false,
        ));
        return;
    }
    if name == "update" {
        out.push(build(
            Manager::Pdm,
            Form::Add,
            &a.positionals,
            &pypi_read,
            vec![Unseen::Update],
            false,
        ));
    }
}

const PIPX_VALUED: &[&str] = &[
    "--spec",
    "--python",
    "--pip-args",
    "--suffix",
    "-i",
    "--index-url",
    "--preinstall",
    "--include-resources-from",
    "--cooldown",
    "--app",
    "--python-args",
    "--with",
];

fn pipx(words: &[String], out: &mut Vec<Install>) {
    let known = [
        "install",
        "install-all",
        "inject",
        "upgrade",
        "upgrade-all",
        "upgrade-shared",
        "uninstall",
        "uninstall-all",
        "reinstall",
        "reinstall-all",
        "list",
        "interpreter",
        "run",
        "runpip",
        "ensurepath",
        "environment",
        "completions",
        "pin",
        "unpin",
    ];
    let Some((name, rest)) = subcommand(words, &known, PIPX_VALUED) else {
        return;
    };
    let extra = |a: &Args| {
        let mut v = registry_flags(a, &["-i", "--index-url"]);
        if a.has(&["--pip-args"]) {
            v.push(Unseen::Spec);
        }
        v
    };
    match name.as_str() {
        "install" => {
            let a = args(&rest, PIPX_VALUED, false);
            let mut specs = a.positionals.clone();
            specs.extend(a.values_of(&["--preinstall"]));
            out.push(build(
                Manager::Pipx,
                Form::Add,
                &specs,
                &pypi_read,
                extra(&a),
                true,
            ));
        }
        "inject" => {
            let a = args(&rest, PIPX_VALUED, false);
            let specs: Vec<String> = a.positionals.iter().skip(1).cloned().collect();
            out.push(build(
                Manager::Pipx,
                Form::Add,
                &specs,
                &pypi_read,
                extra(&a),
                true,
            ));
        }
        "run" => {
            let a = args(&rest, PIPX_VALUED, true);
            let spec = a.values_of(&["--spec"]);
            let mut specs: Vec<String> = if !spec.is_empty() {
                spec
            } else {
                a.positionals.iter().take(1).cloned().collect()
            };
            specs.extend(a.values_of(&["--with"]));
            out.push(build(
                Manager::Pipx,
                Form::Run,
                &specs,
                &pypi_read,
                extra(&a),
                false,
            ));
        }
        "upgrade" | "upgrade-all" => {
            out.push(build(
                Manager::Pipx,
                Form::Add,
                &[],
                &pypi_read,
                vec![Unseen::Update],
                true,
            ));
        }
        _ => {}
    }
}

// --- cargo, go -----------------------------------------------------------------

const CARGO_VALUED: &[&str] = &[
    "--git",
    "--branch",
    "--tag",
    "--rev",
    "--path",
    "--base",
    "--registry",
    "--index",
    "--rename",
    "--features",
    "-f",
    "--target",
    "--manifest-path",
    "-p",
    "--package",
    "--version",
    "--vers",
    "--root",
    "--jobs",
    "-j",
    "--target-dir",
    "--profile",
    "--bin",
    "--example",
    "--color",
    "--config",
    "-z",
    "--message-format",
    "--lockfile-path",
    "--precise",
];

fn cargo(words: &[String], out: &mut Vec<Install>) {
    let known = [
        "add",
        "install",
        "update",
        "build",
        "b",
        "check",
        "c",
        "run",
        "r",
        "test",
        "t",
        "remove",
        "rm",
        "uninstall",
        "fetch",
        "generate-lockfile",
        "tree",
        "metadata",
        "new",
        "init",
        "clean",
        "doc",
        "fmt",
        "clippy",
        "publish",
        "search",
        "vendor",
        "fix",
        "bench",
        "help",
        "login",
        "logout",
        "owner",
        "package",
        "pkgid",
        "yank",
        "info",
        "locate-project",
        "report",
        "rustc",
        "rustdoc",
        "verify-project",
        "version",
    ];
    let Some((name, rest)) = subcommand(words, &known, CARGO_VALUED) else {
        return;
    };
    let a = args(&rest, CARGO_VALUED, false);
    let mut extra = Vec::new();
    if a.has(&["--git"]) {
        extra.push(Unseen::Git);
    }
    if a.has(&["--path"]) {
        extra.push(Unseen::Path);
    }
    if a.has(&["--registry", "--index"]) {
        extra.push(Unseen::Registry);
    }
    match name.as_str() {
        "add" => {
            if a.positionals.is_empty() && extra.is_empty() {
                return;
            }
            out.push(build(
                Manager::Cargo,
                Form::Add,
                &a.positionals,
                &crate_read,
                extra,
                false,
            ));
        }
        "install" => {
            let version = a.values_of(&["--version", "--vers"]).into_iter().next();
            let specs: Vec<String> = a
                .positionals
                .iter()
                .map(|p| match &version {
                    Some(v) if !p.contains('@') => format!("{p}@{v}"),
                    _ => p.clone(),
                })
                .collect();
            if specs.is_empty() && extra.is_empty() {
                return;
            }
            out.push(build(
                Manager::Cargo,
                Form::Add,
                &specs,
                &crate_read,
                extra,
                true,
            ));
        }
        "update" => {
            let named = a.values_of(&["-p", "--package"]);
            let precise = a.values_of(&["--precise"]).into_iter().next();
            let mut specs: Vec<String> = named
                .iter()
                .map(|n| match &precise {
                    Some(p) => format!("{n}@{p}"),
                    None => n.clone(),
                })
                .collect();
            specs.extend(a.positionals.iter().cloned());
            let extra = if precise.is_some() && !named.is_empty() {
                Vec::new()
            } else {
                vec![Unseen::Update]
            };
            out.push(build(
                Manager::Cargo,
                Form::Add,
                &specs,
                &crate_read,
                extra,
                false,
            ));
        }
        _ => {}
    }
}

const GO_VALUED: &[&str] = &[
    "-c",
    "-o",
    "-tags",
    "-ldflags",
    "-gcflags",
    "-asmflags",
    "-mod",
    "-modfile",
    "-p",
    "-exec",
    "-overlay",
    "-pgo",
    "-pkgdir",
    "-toolexec",
    "-buildmode",
    "-compiler",
    "-gccgoflags",
    "-installsuffix",
];

fn go(words: &[String], out: &mut Vec<Install>) {
    let known = [
        "get",
        "install",
        "run",
        "build",
        "mod",
        "test",
        "vet",
        "fmt",
        "generate",
        "list",
        "env",
        "version",
        "work",
        "tool",
        "clean",
        "doc",
        "fix",
        "help",
        "bug",
        "telemetry",
    ];
    let mut sub_valued: Vec<&str> = GO_VALUED.to_vec();
    sub_valued.extend(["-covermode", "-coverpkg"]);
    let Some((name, rest)) = subcommand(words, &known, &sub_valued) else {
        return;
    };
    let a = args(&rest, GO_VALUED, false);
    let go_read = |s: &str| go_spec(s);
    if name == "get" {
        let extra = if a.has(&["-u"]) {
            vec![Unseen::Update]
        } else {
            Vec::new()
        };
        let inst = build(
            Manager::Go,
            Form::Add,
            &a.positionals,
            &go_read,
            extra,
            false,
        );
        if !inst.packages.is_empty() || !inst.unseen.is_empty() {
            out.push(inst);
        }
        return;
    }
    if name == "install" || name == "run" {
        let candidates: Vec<String> = if name == "run" {
            a.positionals.iter().take(1).cloned().collect()
        } else {
            a.positionals.clone()
        };
        let versioned: Vec<String> = candidates.into_iter().filter(|p| p.contains('@')).collect();
        if versioned.is_empty() {
            return;
        }
        let form = if name == "run" { Form::Run } else { Form::Add };
        let inst = build(
            Manager::Go,
            form,
            &versioned,
            &go_read,
            Vec::new(),
            name == "install",
        );
        if !inst.packages.is_empty() || !inst.unseen.is_empty() {
            out.push(inst);
        }
    }
}
