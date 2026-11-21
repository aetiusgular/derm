//! Screen text, as `derm_terminal_read` serves it (lane PD's;
//! `contracts/project-tools.md` section 3). Shared by `derm run`, which
//! renders the harness's output and cleans it before `screen.put`, and the
//! daemon, which cleans it again before a reply leaves (section 3.4).
//!
//! The base declares the signature; lane PD builds it. Until then `clean`
//! returns its input unchanged, which is what the red test
//! `pd_a_terminal_read_returns_no_control_bytes` shows failing.

/// Most UTF-8 bytes one `screen.put` text or one `derm_terminal_read` reply
/// carries: under the socket's 1 MiB line cap (`derm-daemon`'s
/// `socket::MAX_LINE_BYTES`; case 185). Cut from the top.
pub const MAX_TEXT_BYTES: usize = 512 * 1024;

/// Most scrollback lines a reader keeps per chat.
pub const MAX_SCROLLBACK_LINES: usize = 10_000;

/// Most lines one `derm_terminal_read` asks for.
pub const MAX_READ_LINES: u32 = 2_000;

/// What `clean` kept and what it removed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Clean {
    pub text: String,
    /// Characters removed (Cc other than `\n` and `\t`, every Cf, U+FFFD).
    pub removed: usize,
    /// The text was cut from the top to fit `MAX_TEXT_BYTES`.
    pub truncated: bool,
}

/// Removes every character of Unicode category Cc other than `\n` and
/// `\t`, every Cf character, and U+FFFD; trims trailing spaces on each
/// line; cuts from the top to `MAX_TEXT_BYTES` on a character boundary
/// (contracts/project-tools.md section 3.3).
///
/// Not built (lane PD): returns `text` unchanged.
pub fn clean(text: &str) -> Clean {
    Clean {
        text: text.to_string(),
        removed: 0,
        truncated: false,
    }
}
