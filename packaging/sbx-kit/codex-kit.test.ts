// derm's sbx kit for Codex carries the trust entries Codex wants before it
// runs a plugin's hook. They are a hash of each handler in the plugin's
// hooks.json, so the file in the kit is held equal to what the same
// function writes for the Terminal-Bench bundle and the contract check
// (tests/eval/lib/terminal-bench.mjs, trustToml). A change to hooks.json
// fails this until packaging/sbx-kit/codex/trust.toml is written again:
//
//   node -e 'import("./tests/eval/lib/terminal-bench.mjs").then(async (m) => { const fs = await import("node:fs"); fs.writeFileSync("packaging/sbx-kit/codex/trust.toml", "\n" + m.trustToml(JSON.parse(fs.readFileSync("packages/derm-codex-plugin/hooks/hooks.json", "utf8")))); })'

import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
// @ts-expect-error plain ES module, no types
import { trustToml } from "../../tests/eval/lib/terminal-bench.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const read = (...p: string[]) => readFileSync(path.join(HERE, ...p), "utf8").replace(/\r\n/g, "\n");

describe("the Codex kit's trust entries", () => {
  it("are the ones Codex computes for derm's plugin hooks", () => {
    const hooks = JSON.parse(read("..", "..", "packages", "derm-codex-plugin", "hooks", "hooks.json"));
    expect(read("codex", "trust.toml")).toBe(`\n${trustToml(hooks)}`);
  });

  it("name the marketplace and plugin the kit's scripts add", () => {
    const trust = read("codex", "trust.toml");
    expect(trust).toContain('[hooks.state."derm@derm:hooks/hooks.json:pre_tool_use:0:0"]');
    expect(trust).toContain('[hooks.state."derm@derm:hooks/hooks.json:post_tool_use:0:0"]');
    const setup = read("codex", "setup.sh");
    expect(setup).toContain("codex plugin add derm@derm");
    expect(setup).toContain("derm@derm:hooks/hooks.json");
  });
});
