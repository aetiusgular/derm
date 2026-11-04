//! The join (wave 5, lane S; `plans/toolkit_universal_plan.md` miss 10, rules
//! cases 115, 123, 124): intent to decision on the call id, decision to
//! effect by process tree, then path, then time window, under case 35's rule.
//! An effect that fits more than one call is recorded as a candidate set
//! (`kind: "join.candidates"`, `contracts/events.md` section 5), never as the
//! nearest call. Empty until lane S.
