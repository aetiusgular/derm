//! Shared types for the toolkit layer. Owned by lane B (wave 1); lane C and
//! lane D read it. The contracts these types follow are in `contracts/`:
//! `policy.md` and `policy.schema.json` for `policy`, `daemon-protocol.md`
//! for `event` and `token`.
//!
//! Session 0 wrote the types, the tool-name normalizer and the reject-list
//! token table, because the contract fixture tests them. The policy matcher
//! (`policy::evaluate`) is a stub that answers `Ask`; lane B fills it against
//! `contracts/fixtures/policy/cases.json`.

// Wave 5 lane W: command rules (contracts/policy.md section 7).
pub mod argv;
// Wave 6 (the wave 6 base): the chain v2 line format, `contracts/events.md`
// section 6.4, which lanes 6B and 6E build against.
pub mod audit_chain;
pub mod command;
pub mod event;
pub mod harness;
// Wave 5 lane X's seam (the wave 5 base): `policy::evaluate` calls it.
pub mod installs;
#[cfg(unix)]
pub mod peer;
// Wave 5 lane Z's seam (the wave 5 base): `platform/windows/` is cfg(windows).
pub mod platform;
#[rustfmt::skip]
mod fold_tables;
pub mod policy;
// The wave 5b base: one redactor and the trusted owners, for `derm hook`.
pub mod owner;
pub mod redact;
pub mod runtime;
pub mod token;
