//! Test support shared by `derm-cli`'s integration tests (the wave 5b base):
//! the fake daemon (also used by `gate/`'s unit tests) and the replay of the
//! recorded TypeScript hook cases.
#![allow(dead_code)]

#[cfg(unix)]
pub mod fake_daemon;
pub mod replay;
