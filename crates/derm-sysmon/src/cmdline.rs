//! A Windows command line as the words a program sees, by the Microsoft C
//! runtime's rules ("Parsing C command-line arguments", Microsoft Learn,
//! read 10 Nov 2026; V for the rules and the table below). Sysmon's event 1
//! carries a process's `CommandLine` as one string; the daemon keeps its
//! shape only (case 168), and the shape needs words.
//!
//! The rules: words split on spaces and tabs; the first word (the program)
//! takes quoted parts with no escapes; later words: `2n` backslashes and a
//! quote give `n` backslashes and toggle quoting, `2n+1` backslashes and a
//! quote give `n` backslashes and a literal quote, backslashes not before a
//! quote are literal, `""` inside quotes is one literal quote, and a line
//! that ends inside quotes ends its last word there.
//!
//! A line that starts with a space or tab gets an empty program, so that
//! no word is kept as the program by mistake.
//!
//! A program that parses its own command line otherwise (cmd.exe does) may
//! see other words; the shape is a record, never a decision.

/// The words of `line`.
pub fn split(line: &str) -> Vec<String> {
    let chars: Vec<char> = line.chars().collect();
    let mut out = Vec::new();
    let mut i = 0;
    // The program: quotes group, nothing escapes.
    let mut prog = String::new();
    let mut quoted = false;
    while i < chars.len() {
        let c = chars[i];
        if c == '"' {
            quoted = !quoted;
        } else if !quoted && (c == ' ' || c == '\t') {
            break;
        } else {
            prog.push(c);
        }
        i += 1;
    }
    // A line that starts with a space has an empty program (NF what the C
    // runtime gives there): the shape keeps a program word as it is, so
    // the safe reading shapes every later word.
    if !chars.is_empty() {
        out.push(prog);
    }
    loop {
        while i < chars.len() && (chars[i] == ' ' || chars[i] == '\t') {
            i += 1;
        }
        if i >= chars.len() {
            break;
        }
        let mut word = String::new();
        let mut quoted = false;
        while i < chars.len() {
            let c = chars[i];
            if c == '\\' {
                let mut n = 0;
                while i < chars.len() && chars[i] == '\\' {
                    n += 1;
                    i += 1;
                }
                if i < chars.len() && chars[i] == '"' {
                    word.extend(std::iter::repeat_n('\\', n / 2));
                    if n % 2 == 1 {
                        word.push('"');
                        i += 1;
                    }
                } else {
                    word.extend(std::iter::repeat_n('\\', n));
                }
                continue;
            }
            if c == '"' {
                if quoted && chars.get(i + 1) == Some(&'"') {
                    word.push('"');
                    i += 2;
                    continue;
                }
                quoted = !quoted;
                i += 1;
                continue;
            }
            if !quoted && (c == ' ' || c == '\t') {
                break;
            }
            word.push(c);
            i += 1;
        }
        out.push(word);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn words(line: &str) -> Vec<String> {
        split(line)
    }

    /// Microsoft's table, each line after a program name.
    #[test]
    fn microsofts_examples_split_as_the_c_runtime_does() {
        let table: &[(&str, &[&str])] = &[
            (r#""a b c" d e"#, &["a b c", "d", "e"]),
            (r#""ab\"c" "\\" d"#, &["ab\"c", "\\", "d"]),
            (r#"a\\\b d"e f"g h"#, &[r"a\\\b", "de fg", "h"]),
            (r#"a\\\"b c d"#, &[r#"a\"b"#, "c", "d"]),
            (r#"a\\\\"b c" d e"#, &[r"a\\b c", "d", "e"]),
            (r#"a"b"" c d"#, &[r#"ab" c d"#]),
        ];
        for (line, want) in table {
            let got = words(&format!("prog {line}"));
            assert_eq!(&got[1..], *want, "{line}");
            assert_eq!(got[0], "prog");
        }
    }

    #[test]
    fn the_program_keeps_its_backslashes_and_drops_its_quotes() {
        assert_eq!(
            words(r#""C:\Program Files\nodejs\node.exe" C:\npm\codex.js -p "do it""#),
            vec![
                r"C:\Program Files\nodejs\node.exe",
                r"C:\npm\codex.js",
                "-p",
                "do it"
            ]
        );
        assert_eq!(words(r"C:\a\b\"), vec![r"C:\a\b\"]);
        assert_eq!(words(""), Vec::<String>::new());
        assert_eq!(words("  x"), vec!["", "x"]);
        assert_eq!(words("x\t\ty  "), vec!["x", "y"]);
    }

    #[test]
    fn the_shape_of_a_command_line_keeps_no_word() {
        let argv = split(r#"node codex.js -p "MARKERZEBRA42 secret" --model=o5"#);
        let shaped = derm_core::argv::shape(&argv);
        assert_eq!(
            shaped,
            vec!["node", "[8 chars]", "-p", "[20 chars]", "--model=[2 chars]"]
        );
        assert!(!shaped.join(" ").contains("MARKERZEBRA42"));
    }
}
