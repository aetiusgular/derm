//! The terminal reader (lane PD's; `contracts/project-tools.md` section 3;
//! plan step P5, call 18).
//!
//! `derm run` holds the harness on its own pty, copies the harness's output
//! to the person's terminal unchanged, and feeds the same bytes to a reader
//! that keeps a rendered screen and scrollback. Nothing ever writes to the
//! harness's input from here.
//!
//! The base declares the reader's shape. Until lane PD builds it, `feed`
//! keeps the raw bytes and `text` returns them as text, control bytes and
//! all, which is what the red test
//! `pd_a_terminal_read_returns_no_control_bytes` shows failing.

use derm_core::project::screen::{self, Clean};

/// One chat's screen, sized to the person's terminal.
pub(crate) struct Reader {
    rows: u16,
    cols: u16,
    raw: Vec<u8>,
}

impl Reader {
    pub(crate) fn new(rows: u16, cols: u16) -> Reader {
        Reader {
            rows,
            cols,
            raw: Vec::new(),
        }
    }

    /// The harness's output, as it reached the person's terminal.
    pub(crate) fn feed(&mut self, bytes: &[u8]) {
        self.raw.extend_from_slice(bytes);
    }

    /// The person's terminal changed size.
    pub(crate) fn resize(&mut self, rows: u16, cols: u16) {
        self.rows = rows;
        self.cols = cols;
    }

    pub(crate) fn size(&self) -> (u16, u16) {
        (self.rows, self.cols)
    }

    /// The screen and up to `lines` of scrollback above it, cleaned by
    /// `derm_core::project::screen::clean`. Not built (lane PD): the raw
    /// bytes as text.
    pub(crate) fn text(&self, _lines: Option<u32>) -> Clean {
        screen::clean(&String::from_utf8_lossy(&self.raw))
    }
}
