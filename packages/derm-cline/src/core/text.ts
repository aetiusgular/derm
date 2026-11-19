// The small helpers a plugin shim needs from the hook core without its
// matcher: the action type, the quote-stripped reading of a text, and the
// folder test. Split out of policy.ts on 19 Nov 2026, word for word, so the
// shims whose gate is `derm gate serve` (Kilo, OpenClaw, OpenCode, Cline,
// Amp) carry this file with fold.ts, owner.ts and redact.ts, and no copy of
// the matcher. policy.ts imports and re-exports all three.
// Canonical copy: packages/derm-claude-plugin/src/core/.

import { realpathSync } from "node:fs";
import path from "node:path";

export type Action = "allow" | "ask" | "deny";

/** The real path of `p`, following links on every part that exists; a missing tail is appended as written. */
function realish(p: string): string {
  const abs = path.resolve(p);
  let head = abs;
  const tail: string[] = [];
  for (;;) {
    try {
      return path.join(realpathSync(head), ...tail.reverse());
    } catch {
      const parent = path.dirname(head);
      if (parent === head) return abs;
      tail.push(path.basename(head));
      head = parent;
    }
  }
}

/** True when `file` is `folder` or lies under it, after links are followed. */
export function insideFolder(file: string, folder: string): boolean {
  const rel = path.relative(realish(folder), realish(file));
  return rel === "" || (!rel.startsWith("..") && !path.isAbsolute(rel));
}

/**
 * The text with every quote removed. The shell joins `ANTHROPIC_"BASE_URL"`
 * and `g''it` into one word, so the reject list and the control files are
 * also read this way (integration w1, finding S1). Only adds matches.
 */
export function unquote(text: string): string {
  return text.replace(/["']/g, "");
}
