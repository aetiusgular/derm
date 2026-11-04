// The preset rows (crates/derm-cli/src/connect/presets/<id>.json) say what
// each dialect does; these hold the two in step.
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { ANTIGRAVITY_SHELL } from "./dialects/antigravity.ts";
import { CRUSH_SHELL } from "./dialects/crush.ts";
import { CURSOR_SHELL } from "./dialects/cursor.ts";
import { GOOSE_SHELL } from "./dialects/goose.ts";
import { KIRO_SHELL } from "./dialects/kiro.ts";
import { VIBE_SHELL } from "./dialects/mistralVibe.ts";
import { DIALECTS } from "./hook.ts";

const row = (id: string) => JSON.parse(readFileSync(new URL(`../../../crates/derm-cli/src/connect/presets/${id}.json`, import.meta.url), "utf8")) as { coverage: { shellAliases: string[]; ask: string; gate: { lane: string; package?: string } } };
const SHELL: Record<string, readonly string[]> = { cursor: CURSOR_SHELL.names, antigravity: ANTIGRAVITY_SHELL.names, goose: GOOSE_SHELL.names, "mistral-vibe": VIBE_SHELL.names, crush: CRUSH_SHELL.names, kiro: KIRO_SHELL.names };

describe("preset rows and dialects", () => {
  for (const id of Object.keys(DIALECTS)) {
    it(`${id}: shell aliases, ask route and package agree (case 82)`, () => {
      const r = row(id);
      expect(r.coverage.shellAliases).toEqual([...(SHELL[id] ?? [])]);
      expect(r.coverage.gate.lane).toBe("N");
      expect(r.coverage.gate.package).toBe("packages/derm-hooks-native");
      const own = id === "cursor" || id === "antigravity";
      expect(r.coverage.ask).toBe(own ? "own-prompt" : "approver-or-deny");
    });
  }
});
