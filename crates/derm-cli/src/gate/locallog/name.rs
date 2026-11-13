//! A chat id as a file name (`contracts/events.md` section 6.4; rules
//! section 5, item 3). The chat id comes from the agent's input or from
//! `DERM_CHAT_ID`, which a project's settings can set, so it is cleaned as
//! `daemon::decision_id` cleans a call id: ASCII letters, digits and
//! `_ . : -` kept, everything else `_`, at most 128 characters; then `_` in
//! front of a cleaned id that is empty or starts with `.`, so no id names
//! `.`, `..` or a hidden file.
//!
//! Windows adds two rules (Microsoft, "Naming Files, Paths, and
//! Namespaces", https://learn.microsoft.com/en-us/windows/win32/fileio/naming-a-file,
//! read 12 Nov through a search excerpt): `:` is a reserved character (on
//! NTFS it names a file's alternate data stream, so `a:b.jsonl` would write
//! into a stream of a file `a`), and CON, PRN, AUX, NUL, COM0 to COM9 and
//! LPT0 to LPT9 are device names even with an extension ("NUL.txt and
//! NUL.tar.gz are both equivalent to NUL"). There `:` becomes `_` and a
//! device name gets `_` in front. This differs from the contract's text on
//! Windows only; recorded as a request in `plans/parallel/tk_lane_6B.md`.

/// The most characters of a chat id a file name keeps.
pub const MAX: usize = 128;

/// `<chat>.jsonl` for `chat`, by the rules above.
pub fn file_name(chat: &str) -> String {
    let windows = cfg!(windows);
    let mut s: String = chat
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-') || (c == ':' && !windows) {
                c
            } else {
                '_'
            }
        })
        .take(MAX)
        .collect();
    if s.is_empty() || s.starts_with('.') || (windows && device_name(&s)) {
        s.insert(0, '_');
    }
    format!("{s}.jsonl")
}

/// Whether `s` (before its first `.`) is a Windows device name, in any
/// letter case.
fn device_name(s: &str) -> bool {
    let stem = s.split('.').next().unwrap_or("").to_ascii_uppercase();
    match stem.as_str() {
        "CON" | "PRN" | "AUX" | "NUL" => true,
        _ => {
            let b = stem.as_bytes();
            b.len() == 4
                && (stem.starts_with("COM") || stem.starts_with("LPT"))
                && b[3].is_ascii_digit()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_chat_id_never_names_a_parent_a_hidden_file_or_another_folder() {
        assert_eq!(file_name(""), "_.jsonl");
        assert_eq!(file_name("."), "_..jsonl");
        assert_eq!(file_name(".."), "_...jsonl");
        assert_eq!(file_name("../../etc/passwd"), "_.._.._etc_passwd.jsonl");
        assert_eq!(file_name(".hidden"), "_.hidden.jsonl");
        assert_eq!(file_name("a/b\\c"), "a_b_c.jsonl");
        assert_eq!(file_name("sess ion\n\0"), "sess_ion__.jsonl");
        assert_eq!(file_name("é-1"), "_-1.jsonl");
        for name in ["", ".", "..", "../x", "/abs", "a/../b"] {
            let f = file_name(name);
            assert!(!f.contains('/') && !f.contains('\\'), "{f}");
            assert!(!f.starts_with('.'), "{f}");
        }
    }

    #[test]
    fn a_real_session_id_is_kept_as_it_is() {
        let id = "82caee7b-1bd7-4840-a08c-99c2e156e486";
        assert_eq!(file_name(id), format!("{id}.jsonl"));
    }

    #[test]
    fn a_long_id_is_cut_at_128_characters() {
        let f = file_name(&"a".repeat(500));
        assert_eq!(f.len(), MAX + ".jsonl".len());
        let f = file_name(&format!(".{}", "a".repeat(500)));
        assert_eq!(f.len(), MAX + 1 + ".jsonl".len());
    }

    #[cfg(not(windows))]
    #[test]
    fn a_colon_is_kept_where_it_is_a_plain_character() {
        assert_eq!(file_name("derm:chat-1"), "derm:chat-1.jsonl");
        assert_eq!(file_name("CON"), "CON.jsonl");
    }

    #[cfg(windows)]
    #[test]
    fn on_windows_a_colon_and_a_device_name_cannot_reach_a_stream_or_a_device() {
        assert_eq!(file_name("derm:chat-1"), "derm_chat-1.jsonl");
        assert_eq!(file_name("a:b"), "a_b.jsonl");
        for d in [
            "CON", "con", "NUL", "aux", "COM1", "lpt9", "nul.x", "PRN.tar",
        ] {
            assert!(file_name(d).starts_with('_'), "{d}");
        }
        for ok in ["CONSOLE", "COM10", "NULL", "com"] {
            assert!(!file_name(ok).starts_with('_'), "{ok}");
        }
    }

    #[test]
    fn device_names_are_matched_by_stem_in_any_case() {
        assert!(device_name("con"));
        assert!(device_name("Lpt0.log"));
        assert!(device_name("COM9"));
        assert!(!device_name("COM"));
        assert!(!device_name("COM10"));
        assert!(!device_name("CONx"));
    }
}
