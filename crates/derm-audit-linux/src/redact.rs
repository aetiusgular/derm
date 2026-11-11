//! Moved to `derm_core::redact` by the wave 5b base, unchanged; this
//! re-export keeps every caller (`map.rs`, `derm connect`'s diff printer,
//! `derm run`) as it was.

pub use derm_core::redact::{argv, secret_like, secret_word, text, REDACTED};
