//! The questions `derm setup` asks, one per switch. A person answers on the
//! terminal; tests answer from a script. Nothing here decides anything: an
//! empty answer, end of input or anything not offered is the default, which
//! is always the choice that changes nothing or the safe one.

use std::io::Write;

/// Where answers come from.
pub trait Ask {
    /// Shows `question` with its `choices` (the first is the default) and
    /// returns the chosen one, by its full word or its first letter.
    fn choose(&mut self, question: &str, choices: &[&str]) -> String;
    /// A free line of text (a URL, a key), trimmed; empty when none.
    fn line(&mut self, question: &str) -> String;
    /// Text for the person (what was found, what changed).
    fn say(&mut self, text: &str);
}

/// Picks a choice from an answer: the full word or its first letter, any
/// case; anything else, the default (the first).
pub fn pick(answer: &str, choices: &[&str]) -> String {
    let a = answer.trim().to_ascii_lowercase();
    if !a.is_empty() {
        if let Some(c) = choices.iter().find(|c| c.eq_ignore_ascii_case(&a)) {
            return c.to_string();
        }
        let firsts: Vec<&&str> = choices
            .iter()
            .filter(|c| c.chars().next().map(|f| f.to_ascii_lowercase()) == a.chars().next())
            .collect();
        if a.chars().count() == 1 && firsts.len() == 1 {
            return firsts[0].to_string();
        }
    }
    choices.first().map(|c| c.to_string()).unwrap_or_default()
}

/// The terminal: questions on stderr, answers read one byte at a time from
/// descriptor 0, so nothing past the line is taken (the boundary question's
/// rule, lane T's D4).
pub struct Tty;

impl Tty {
    /// Both stdin and stderr are terminals. A pty is not a person (case 89):
    /// this guards against a script, not against an agent.
    #[cfg(not(test))]
    pub fn present() -> bool {
        // SAFETY: isatty reads only the descriptor number.
        unsafe { libc::isatty(0) == 1 && libc::isatty(2) == 1 }
    }

    /// Never in a test build: `cargo test` run from a terminal must not start
    /// asking (main.rs's dispatch test runs `derm setup` with no arguments).
    #[cfg(test)]
    pub fn present() -> bool {
        false
    }

    fn read_line() -> String {
        let mut out = Vec::new();
        let mut b = [0u8; 1];
        loop {
            // SAFETY: reads one byte into a one-byte buffer from descriptor 0.
            let n = unsafe { libc::read(0, b.as_mut_ptr().cast(), 1) };
            if n != 1 || b[0] == b'\n' || out.len() > 4096 {
                break;
            }
            out.push(b[0]);
        }
        String::from_utf8_lossy(&out).trim().to_string()
    }
}

impl Ask for Tty {
    fn choose(&mut self, question: &str, choices: &[&str]) -> String {
        let shown: Vec<String> = choices
            .iter()
            .enumerate()
            .map(|(i, c)| {
                if i == 0 {
                    format!("[{c}]")
                } else {
                    c.to_string()
                }
            })
            .collect();
        eprint!("{question} {}: ", shown.join(" / "));
        let _ = std::io::stderr().flush();
        pick(&Tty::read_line(), choices)
    }

    fn line(&mut self, question: &str) -> String {
        eprint!("{question}: ");
        let _ = std::io::stderr().flush();
        Tty::read_line()
    }

    fn say(&mut self, text: &str) {
        eprintln!("{text}");
    }
}

/// Answers from a list, in order, for tests; what is said is kept.
#[cfg(test)]
pub struct Script {
    pub answers: std::collections::VecDeque<String>,
    pub said: String,
    pub asked: Vec<String>,
}

#[cfg(test)]
impl Script {
    pub fn new(answers: &[&str]) -> Script {
        Script {
            answers: answers.iter().map(|a| a.to_string()).collect(),
            said: String::new(),
            asked: Vec::new(),
        }
    }
}

#[cfg(test)]
impl Ask for Script {
    fn choose(&mut self, question: &str, choices: &[&str]) -> String {
        self.asked.push(question.to_string());
        let a = self.answers.pop_front().unwrap_or_default();
        pick(&a, choices)
    }
    fn line(&mut self, question: &str) -> String {
        self.asked.push(question.to_string());
        self.answers.pop_front().unwrap_or_default()
    }
    fn say(&mut self, text: &str) {
        self.said.push_str(text);
        self.said.push('\n');
    }
}
