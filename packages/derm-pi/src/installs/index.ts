// Package installs at the gate (wave 5, lane X; plans/toolkit_universal_plan.md
// lane X, contracts/policy.md section 6, note AT), derm-pi's copy. The wave 5 base cut
// this seam: `evaluate` calls `installDecision` for a shell tool whose
// answer is still allow after every other step, and returns what it says.
// Lane X owns this folder; the matcher around it stays integration's.
//
// The base's stub says "not an install" for every call, so nothing changes
// until lane X fills it against contracts/fixtures/installs/. It is held
// equal to the hook core's (`packages/derm-claude-plugin/src/core/installs/`) and derm-core's (`crates/derm-core/src/installs/`) by the same fixture.

import type { Action } from "../policy.ts";

export type InstallDecision = { action: Exclude<Action, "allow">; reason: string };

/**
 * What the install check says about a shell call, or undefined when the call
 * is not an install (or the check has nothing to add). `normalizedTool` is
 * the matcher's normalized name; `folded` the folded, escape-decoded input.
 * The wave 5 base's stub: never an install.
 */
export function installDecision(normalizedTool: string, folded: string): InstallDecision | undefined {
  void normalizedTool;
  void folded;
  return undefined;
}
