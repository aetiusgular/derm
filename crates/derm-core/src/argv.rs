//! An argument vector's shape, for records kept with content off (rules
//! case 85 as changed 4 Nov): the program, every flag's name, and the length
//! of every other word. The same rule `derm run` applies to its own
//! `run.start` (`derm-cli`'s `recorded_argv`), here for the OS feeds' `exec`
//! records, whose argv held a harness's prompt and every command an agent
//! ran (box test w5, BW5-12).

/// A flag: `-x`, or `--name` with letters, digits and `-` after a first
/// letter, at most 40 (`-pPROMPT`, or a prompt that starts with `-`, is a
/// word, not a flag).
fn flag(f: &str) -> bool {
    let (name, short) = match f.strip_prefix("--") {
        Some(n) => (n, false),
        None => (f.strip_prefix('-').unwrap_or(""), true),
    };
    name.chars().next().is_some_and(|c| c.is_ascii_alphabetic())
        && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
        && if short {
            name.len() == 1
        } else {
            name.len() <= 41
        }
}

fn length(v: &str) -> String {
    format!("[{} chars]", v.chars().count())
}

/// The program as given, then each word's shape.
pub fn shape(argv: &[String]) -> Vec<String> {
    let mut out = Vec::with_capacity(argv.len());
    for (i, w) in argv.iter().enumerate() {
        if i == 0 || w == "--" {
            out.push(w.clone());
            continue;
        }
        out.push(match w.split_once('=') {
            Some((f, value)) if flag(f) => format!("{f}={}", length(value)),
            None if flag(w) => w.clone(),
            _ => length(w),
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| x.to_string()).collect()
    }

    #[test]
    fn a_prompt_and_a_commands_words_keep_only_their_length() {
        assert_eq!(
            shape(&s(&[
                "/usr/bin/claude",
                "-p",
                "MARKERZEBRA42 do it",
                "--model=haiku",
                "--",
                "-x"
            ])),
            s(&[
                "/usr/bin/claude",
                "-p",
                "[19 chars]",
                "--model=[5 chars]",
                "--",
                "-x"
            ])
        );
        assert_eq!(
            shape(&s(&[
                "bash",
                "-c",
                "curl -H 'Authorization: x' y",
                "-pSECRET"
            ])),
            s(&["bash", "-c", "[28 chars]", "[8 chars]"])
        );
        assert_eq!(shape(&[]), Vec::<String>::new());
    }
}
