// Cline's own control files. The shared core's control list (src/core/
// policy.ts CONTROL_PATHS) does not name Cline's; an allowed call whose input
// names one is asked here instead, as the core does for its own list. A
// request for integration adds them to the core and derm-core
// (plans/parallel/tk_lane_P.md).
//
// Why each one (Cline source at tag cli-v3.0.74, 071e1b2):
// - `.cline/`: `$CLINE_DIR`'s default `~/.cline` (plugins/, hooks/, data/
//   with the settings and the MCP file) and a project's `.cline/` (plugins/ and
//   hooks/, loaded with no trust prompt), sdk/packages/shared/src/storage/
//   paths.ts:157-168, 495-509, 618-625.
// - `documents/cline/`: `~/Documents/Cline/Plugins` and `Hooks`, searched too
//   (paths.ts:171-180, 624).
// - `.clinerules`: the old project config folder, still searched for hooks
//   (paths.ts:34, 503-505).
// - `.agents/plugins`: Agent Plugins from the home folder, which bring MCP
//   servers (paths.ts:638-640).
// - `cline_dir`, `cline_data_dir`: the variables that move those folders.
// - `cline_tool_approval`: CLINE_TOOL_APPROVAL_MODE and _DIR, which route
//   approvals (apps/cli/src/utils/approval.ts:59-62, 106-114).
// - `cline_plugin_`: CLINE_PLUGIN_MODE, CLINE_PLUGIN_RUNTIME_DIR and the
//   others that change how plugins load (sdk/packages/core/src/extensions/
//   plugin/).
// - `cline-approvals/`: the folder derm's approval responder answers in
//   (responder.ts APPROVAL_FOLDER_NAME): a decision file written there is an
//   answer Cline reads.

import { decodeEscapes, fold } from "./core/fold.ts";
import { unquote, type Action } from "./core/policy.ts";

export const CLINE_CONTROL_PATHS = [
  ".cline/",
  "documents/cline/",
  ".clinerules",
  ".agents/plugins",
  "cline_dir",
  "cline_data_dir",
  "cline_tool_approval",
  "cline_plugin_",
  "cline-approvals/",
] as const;

/**
 * True when `text` holds `marker`, or a folder marker without its trailing
 * `/` where a path ends there (`cd ~/.cline && cp x plugins/y.ts`), the way a
 * shell names a folder it then works in (lane P review, P-S4).
 */
export function namesMarker(text: string, marker: string): boolean {
  if (text.includes(marker)) return true;
  if (!marker.endsWith("/")) return false;
  const base = marker.slice(0, -1);
  for (let i = text.indexOf(base); i >= 0; i = text.indexOf(base, i + 1)) {
    const next = text[i + base.length];
    if (next === undefined || /[\s;&|)'"`<>]/.test(next)) return true;
  }
  return false;
}

export function clineControlPath(inputText: string): string | undefined {
  const folded = fold(decodeEscapes(inputText));
  const unquoted = unquote(folded);
  return CLINE_CONTROL_PATHS.find((p) => namesMarker(folded, p) || namesMarker(unquoted, p));
}

/** Narrows an allow to ask when the input names a Cline control path. Never widens. */
export function narrowForControl(action: Action, inputText: string): { action: Action; control?: string } {
  if (action !== "allow") return { action };
  const control = clineControlPath(inputText);
  return control ? { action: "ask", control } : { action };
}
