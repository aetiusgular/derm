//! The terminal reader (lane PD's; `contracts/project-tools.md` section 3;
//! plan step P5, call 18).
//!
//! `derm run` holds the harness on its own pty ([`Session`], Unix), copies
//! the harness's output to the person's terminal unchanged, and feeds the
//! same bytes to a [`Reader`] that keeps a rendered screen and scrollback.
//! The rendered text goes to the daemon by `screen.put` ([`Publisher`]),
//! where `derm_terminal_read` (lane PE) serves it.
//!
//! Nothing ever writes to the harness's input from here: the parser
//! (vt100 0.18.1) has no writer, so a query in the output (a cursor report,
//! a device attribute, DECRQSS, an OSC 52 read) is never answered by derm.
//! The person's own terminal still sees it and answers, as before.
//!
//! What the text holds: the terminal's rows joined by `\n`, after
//! `derm_core::project::screen::clean` (no Cc but `\n` and `\t`, no Cf, no
//! U+FFFD), at most `MAX_TEXT_BYTES`, cut from the top.

pub(crate) mod put;
#[cfg(unix)]
pub(crate) mod session;
#[cfg(test)]
mod tests;

use std::num::NonZeroU16;

use derm_core::project::screen::{self, Clean, MAX_READ_LINES};

/// Scrollback the reader keeps: what one read can ask for
/// (`MAX_READ_LINES`), below the contract's ceiling of
/// `MAX_SCROLLBACK_LINES`. A row costs 32 bytes a column in vt100 0.18.1
/// (`cell.rs`: `size_of::<Cell>() == 32`), so 2,000 rows of 80 columns are
/// about 5 MB per chat; 10,000 would be 25 MB and no read could reach the
/// rest.
pub(crate) const SCROLLBACK_ROWS: usize = MAX_READ_LINES as usize;

/// The largest screen the reader renders. vt100 allocates every cell of the
/// screen up front, and a terminal (or a harness asking its terminal to
/// resize) can report up to 65,535 by 65,535; past this the reader keeps
/// the top left part and says so in `rows` and `cols` (the pty itself keeps
/// the real size).
pub(crate) const MAX_ROWS: u16 = 500;
pub(crate) const MAX_COLS: u16 = 500;

/// The size used when a terminal reports none (0 rows or 0 columns).
pub(crate) const DEFAULT_ROWS: u16 = 24;
pub(crate) const DEFAULT_COLS: u16 = 80;

/// One chat's screen, sized to the person's terminal.
pub(crate) struct Reader {
    parser: vt100::Parser,
}

/// What a reader hands to `screen.put`: the screen with up to
/// `SCROLLBACK_ROWS` of scrollback above it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Rendered {
    pub rows: u16,
    pub cols: u16,
    pub text: String,
    /// Lines of `text` above the screen's own rows.
    pub scrollback_lines: u32,
    pub truncated: bool,
}

fn fit(v: u16, default: u16, max: u16) -> NonZeroU16 {
    let v = if v == 0 { default } else { v.min(max) };
    NonZeroU16::new(v).unwrap_or(NonZeroU16::MIN)
}

impl Reader {
    pub(crate) fn new(rows: u16, cols: u16) -> Reader {
        Reader {
            parser: vt100::Parser::new(
                fit(rows, DEFAULT_ROWS, MAX_ROWS),
                fit(cols, DEFAULT_COLS, MAX_COLS),
                SCROLLBACK_ROWS,
            ),
        }
    }

    /// The harness's output, as it reached the person's terminal.
    pub(crate) fn feed(&mut self, bytes: &[u8]) {
        self.parser.process(bytes);
    }

    /// The person's terminal changed size.
    pub(crate) fn resize(&mut self, rows: u16, cols: u16) {
        self.parser.set_size(
            fit(rows, DEFAULT_ROWS, MAX_ROWS),
            fit(cols, DEFAULT_COLS, MAX_COLS),
        );
    }

    /// The size the reader renders at (at most `MAX_ROWS` by `MAX_COLS`).
    pub(crate) fn size(&self) -> (u16, u16) {
        let (r, c) = self.parser.screen().size();
        (r.get(), c.get())
    }

    /// The screen's rows, and above them the last `lines` rows of
    /// scrollback (at most `MAX_READ_LINES`; none on the alternate screen,
    /// which has no scrollback in vt100), as `(scrollback, screen)`.
    fn rows(&mut self, lines: u32) -> (Vec<String>, Vec<String>) {
        let (rows, cols) = self.size();
        let screen = self.parser.screen_mut();
        let want = (lines.min(MAX_READ_LINES) as usize).min(screen.scrollback_len());
        let mut back = Vec::with_capacity(want);
        // `set_scrollback(o)` shows the window that starts `o` rows above the
        // screen (vt100 `grid.rs` `visible_rows`); take its first
        // `min(o, rows)` rows, which are scrollback, and step down.
        let mut offset = want;
        while offset > 0 {
            screen.set_scrollback(offset);
            let take = offset.min(usize::from(rows));
            back.extend(screen.rows(0, cols).take(take));
            offset -= take;
        }
        screen.set_scrollback(0);
        let now: Vec<String> = screen.rows(0, cols).collect();
        (back, now)
    }

    /// The screen and up to `lines` of scrollback above it, cleaned by
    /// `derm_core::project::screen::clean`.
    pub(crate) fn text(&mut self, lines: Option<u32>) -> Clean {
        let (back, now) = self.rows(lines.unwrap_or(0));
        let mut all = back;
        all.extend(now);
        screen::clean(&all.join("\n"))
    }

    /// What `screen.put` sends: the screen and up to `SCROLLBACK_ROWS` of
    /// scrollback, cleaned and cut.
    pub(crate) fn render(&mut self) -> Rendered {
        let (rows, cols) = self.size();
        let c = self.text(Some(MAX_READ_LINES));
        let lines = c.text.split('\n').count();
        Rendered {
            rows,
            cols,
            scrollback_lines: u32::try_from(lines.saturating_sub(usize::from(rows)))
                .unwrap_or(u32::MAX),
            text: c.text,
            truncated: c.truncated,
        }
    }
}
