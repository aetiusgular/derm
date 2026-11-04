// Amp's own control files. The shared core's control list (src/core/policy.ts
// CONTROL_PATHS) does not name Amp's; an allowed call whose input names one is
// asked here instead, as the core does for its own list. A request for
// integration adds them to the core and derm-core (plans/parallel/tk_lane_P.md).
//
// Why each one (@ampcode/plugin 0.0.0-20261104001221-gc8c68be index.d.ts, and
// https://ampcode.com/docs/customize/plugins read 3 Nov 2026):
// - `.config/amp/`: the user's settings.json (or settings.jsonc) and plugins/,
//   where every `.ts` file and `<name>/index.ts` is loaded as a plugin, this
//   one included (index.d.ts:10; the docs page, "Locations").
// - `.amp/`: a project's settings and plugins/ (index.d.ts:10).
// - `amp/plugins`: the plugin folder under `$XDG_CONFIG_HOME` when that is set
//   (the docs page), in whatever folder the variable names.
// - `xdg_config_home`: the variable that moves that folder.
// - `ampcode/`: the managed settings folders, `/Library/Application
//   Support/ampcode/` and `/etc/ampcode/` (crates/derm-cli/src/connect/presets/amp.json).
// - `dangerouslyallowall`: the `amp.dangerouslyAllowAll` setting, which skips
//   Amp's own permission prompts (the flag form `--dangerously-allow-all` is on
//   the core's reject list already).

import { decodeEscapes, fold } from "./core/fold.ts";
import { unquote, type Action } from "./core/policy.ts";

export const AMP_CONTROL_PATHS = [".config/amp/", ".amp/", "amp/plugins", "xdg_config_home", "ampcode/", "dangerouslyallowall"] as const;

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

export function ampControlPath(inputText: string): string | undefined {
  const folded = fold(decodeEscapes(inputText));
  const unquoted = unquote(folded);
  return AMP_CONTROL_PATHS.find((p) => namesMarker(folded, p) || namesMarker(unquoted, p));
}

/** Narrows an allow to ask when the input names an Amp control path. Never widens. */
export function narrowForControl(action: Action, inputText: string): { action: Action; control?: string } {
  if (action !== "allow") return { action };
  const control = ampControlPath(inputText);
  return control ? { action: "ask", control } : { action };
}
