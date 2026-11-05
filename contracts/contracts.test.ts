// Checks that every contract fixture validates against its schema, so a lane
// that builds against a fixture builds against a valid one. Session 0.
import { readFileSync, readdirSync } from "node:fs";
import { createHash } from "node:crypto";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { Ajv2020 } from "ajv/dist/2020.js";
import { loadPresetTable, mergeWave5, type PresetTable } from "./presets.ts";

const here = dirname(fileURLToPath(import.meta.url));
const read = (p: string): unknown => JSON.parse(readFileSync(join(here, p), "utf8"));

function validator() {
  const ajv = new Ajv2020({ allErrors: true, strict: true, validateFormats: false });
  // cu-tool.schema.json carries the tool's name and model-facing description
  // beside its input schema (the wave 5 base).
  ajv.addKeyword({ keyword: "x-derm-tool", schemaType: "object" });
  for (const p of [
    "entry.schema.json",
    "policy.schema.json",
    "shapes/server.min.schema.json",
    "shapes/skill.schema.json",
    "shapes/plugin.schema.json",
    "shapes/marketplace.schema.json",
    "harness-presets.schema.json",
    // Wave 5 (the wave 5 base).
    "wave5-records.schema.json",
    "settings.schema.json",
    "cu-tool.schema.json",
  ]) {
    ajv.addSchema(read(p) as object);
  }
  return ajv;
}

const base = "https://github.com/aetiusgular/derm/contracts/";

function check(schemaId: string, data: unknown): string[] {
  const ajv = validator();
  const validate = ajv.getSchema(base + schemaId);
  if (!validate) throw new Error(`no schema ${schemaId}`);
  return validate(data) ? [] : (validate.errors ?? []).map((e: { instancePath: string; message?: string }) => `${e.instancePath} ${e.message ?? ""}`);
}

describe("policy contract", () => {
  it("the fixture policy validates", () => {
    expect(check("policy.schema.json", read("fixtures/policy/policy.json"))).toEqual([]);
  });

  it("the pinned description hash is sha256 of the text case 16 sends", () => {
    const policy = read("fixtures/policy/policy.json") as { rules: { descriptionSha256?: string }[] };
    const pin = policy.rules.find((r) => r.descriptionSha256)?.descriptionSha256;
    expect(pin).toBe(createHash("sha256").update("Write a file.").digest("hex"));
  });

  it("has at least twenty cases with unique ids and a known action", () => {
    const { cases } = read("fixtures/policy/cases.json") as { cases: { id: number; expect: { action: string } }[] };
    expect(cases.length).toBeGreaterThanOrEqual(20);
    expect(new Set(cases.map((c) => c.id)).size).toBe(cases.length);
    for (const c of cases) expect(["allow", "ask", "deny"]).toContain(c.expect.action);
  });

  it("refuses a rule with an unknown field and an unnormalized tool", () => {
    expect(check("policy.schema.json", { version: 1, rules: [{ tool: "exa/x", action: "allow", widen: true }] })).not.toEqual([]);
    expect(check("policy.schema.json", { version: 1, rules: [{ tool: "mcp__Exa__X", action: "allow" }] })).not.toEqual([]);
  });

  it("refuses every command shape in fixtures/policy/invalid.json (section 7, wave 5 lane W)", () => {
    const { policies } = read("fixtures/policy/invalid.json") as { policies: { id: string; matchersOnly?: boolean; policy: unknown }[] };
    expect(policies.length).toBe(10);
    for (const p of policies.filter((x) => !x.matchersOnly)) expect([p.id, check("policy.schema.json", p.policy)]).not.toEqual([p.id, []]);
  });

  it("takes a command rule on bash, with a harness or a chat, and flags after the first word", () => {
    expect(check("policy.schema.json", { version: 1, rules: [{ tool: "bash", command: ["git", "push", "--force"], action: "deny" }] })).toEqual([]);
    expect(check("policy.schema.json", { version: 1, rules: [{ tool: "bash", harness: "codex", chat: "c1", command: ["gh", "pr", "view"], action: "allow" }] })).toEqual([]);
  });
});

describe("entry contract", () => {
  it("the server fixture validates as server.json with derm's _meta", () => {
    expect(check("shapes/server.min.schema.json", read("fixtures/entry/server.json"))).toEqual([]);
  });

  it("the skill fixture validates", () => {
    expect(check("shapes/skill.schema.json", read("fixtures/entry/skill/skill.json"))).toEqual([]);
  });

  it("the bundle fixture validates as plugin.json", () => {
    expect(check("shapes/plugin.schema.json", read("fixtures/entry/bundle/.claude-plugin/plugin.json"))).toEqual([]);
  });

  it("the marketplace fixture validates and pins a full sha", () => {
    expect(check("shapes/marketplace.schema.json", read("fixtures/entry/marketplace/.claude-plugin/marketplace.json"))).toEqual([]);
  });

  it("refuses a host runner that does not say it runs as you", () => {
    const entry = { kind: "server", tier: "own", status: "active", runner: { kind: "host" }, exposure: { default: "direct" },
      trust: { contentSha256: "0".repeat(64), scans: [], liveness: { state: "unknown" } } };
    expect(check("entry.schema.json", entry)).not.toEqual([]);
  });

  it("refuses an unpinned github source in a marketplace export", () => {
    const m = { name: "x", owner: { name: "y" }, plugins: [{ name: "p", source: { source: "github", repo: "a/b" } }] };
    expect(check("shapes/marketplace.schema.json", m)).not.toEqual([]);
  });
});

describe("harness presets", () => {
  const presets = loadPresetTable() as unknown as { harnesses: { id: string; verified: string; sources: string[] }[] };

  // Fourteen from note AP section 4, and four lane Q verified in wave 4 (kilo,
  // codebuff, oh-my-pi, continue; folded in by integration w4).
  it("lists the fourteen harnesses of note AP section 4 and wave 4's four, with unique ids", () => {
    const ids = presets.harnesses.map((h) => h.id);
    expect(ids).toHaveLength(18);
    expect(new Set(ids).size).toBe(18);
    for (const id of ["kilo", "codebuff", "oh-my-pi", "continue"]) expect(ids).toContain(id);
    const planned = (presets as unknown as { planned: { id: string }[] }).planned.map((p) => p.id);
    expect(new Set([...ids, ...planned]).size).toBe(29);
    for (const id of ["claude-code", "codex", "pi", "opencode", "gemini"]) expect(ids).toContain(id);
  });

  it("every harness id fits the policy file's harness pattern and names a source", () => {
    for (const h of presets.harnesses) {
      expect(h.id).toMatch(/^[a-z0-9][a-z0-9-]{0,63}$/);
      expect(h.sources.length).toBeGreaterThan(0);
    }
  });
});

describe("daemon exchange", () => {
  it("every non-comment line has a direction marker and parses as JSON", () => {
    const text = readFileSync(join(here, "fixtures/daemon/exchange.jsonl"), "utf8");
    const lines = text.split("\n").filter((l) => l && !l.startsWith("#"));
    expect(lines.length).toBeGreaterThan(10);
    for (const l of lines) {
      expect(["> ", "< "]).toContain(l.slice(0, 2));
      expect(() => JSON.parse(l.slice(2))).not.toThrow();
    }
  });
});

// Integration w1: the repository is its own marketplace for derm's plugins, so
// `claude plugin install derm@derm` and `codex plugin add derm@derm` work from a
// clone (run with Claude Code 2.1.311 and Codex 0.163.0 on 27 Oct; Claude
// Code's `plugin validate` passed). The id must stay derm@derm: the managed
// settings fragment and Codex's hook trust keys name it.
describe("derm's own marketplaces", () => {
  const root = join(here, "..");
  const claude = JSON.parse(readFileSync(join(root, ".claude-plugin", "marketplace.json"), "utf8")) as { name: string; plugins: { name: string; source: string }[] };
  const codex = JSON.parse(readFileSync(join(root, ".agents", "plugins", "marketplace.json"), "utf8")) as { name: string; plugins: { name: string; source: { source: string; path: string } }[] };
  it("Claude Code's names derm and points at the Claude Code plugin", () => {
    expect(check("shapes/marketplace.schema.json", claude)).toEqual([]);
    expect(claude.name).toBe("derm");
    expect(claude.plugins).toEqual([expect.objectContaining({ name: "derm", source: "./packages/derm-claude-plugin" })]);
    const manifest = JSON.parse(readFileSync(join(root, "packages", "derm-claude-plugin", ".claude-plugin", "plugin.json"), "utf8")) as { name: string };
    expect(manifest.name).toBe("derm");
  });
  it("Codex's names derm and points at the Codex plugin", () => {
    expect(codex.name).toBe("derm");
    expect(codex.plugins).toEqual([{ name: "derm", source: { source: "local", path: "./packages/derm-codex-plugin" } }]);
    const manifest = JSON.parse(readFileSync(join(root, "packages", "derm-codex-plugin", ".codex-plugin", "plugin.json"), "utf8")) as { name: string };
    expect(manifest.name).toBe("derm");
  });
  it("the managed settings fragment enables exactly derm@derm", () => {
    const frag = readFileSync(join(root, "packages", "derm-claude-plugin", "managed-settings.fragment.json"), "utf8");
    expect(frag).toContain('"derm@derm"');
  });
});

// Integration w1: the coverage fields lane J's `derm status` reads (note AQ section 4).
describe("harness coverage", () => {
  type Row = { id: string; coverage: { tier: string | null; orcaId: string | null; gate: { status: string } } };
  const data = loadPresetTable() as unknown as { harnesses: Row[]; planned: Row[] };
  it("the assembled table follows harness-presets.schema.json", () => {
    expect(check("harness-presets.schema.json", data)).toEqual([]);
  });
  it("covers Orca's 27 agents with note AQ's tiers: 24 G, 2 A, 1 O", () => {
    const orca = [...data.harnesses, ...data.planned].filter((r) => r.coverage.orcaId !== null);
    expect(orca).toHaveLength(27);
    expect(new Set(orca.map((r) => r.coverage.orcaId)).size).toBe(27);
    const tiers = { G: 0, A: 0, O: 0 } as Record<string, number>;
    for (const r of orca) tiers[r.coverage.tier ?? "none"] = (tiers[r.coverage.tier ?? "none"] ?? 0) + 1;
    expect(tiers).toEqual({ G: 24, A: 2, O: 1 });
  });
  it("marks built the four wave 1 adapters, wave 2's five and wave 4's sixteen (integration w4)", () => {
    const built = [...data.harnesses, ...data.planned].filter((r) => r.coverage.gate.status === "built").map((r) => r.id).sort();
    expect(built).toEqual([
      "amp", "antigravity", "auggie", "claude-code", "cline", "codex", "command-code", "copilot-cli", "crush", "cursor",
      "droid", "gemini", "goose", "grok", "hermes", "kilo", "kimi", "kiro", "mistral-vibe", "oh-my-pi", "openclaude",
      "openclaw", "opencode", "pi", "qwen-code",
    ]);
  });
});

// Integration w2: the hook dialects of wave 4's agents (contracts/hook-dialects.md).
describe("hook dialect fixtures", () => {
  const dir = join(here, "fixtures", "hook-dialects");
  const table = loadPresetTable();
  const ids = new Set([...table.harnesses, ...table.planned].map((r) => r.id as string));
  const agents = readdirSync(dir, { withFileTypes: true }).filter((d) => d.isDirectory()).map((d) => d.name).sort();
  it("covers the sixteen agents of lanes L, N and P, each a preset id", () => {
    expect(agents).toEqual(
      ["amp", "antigravity", "auggie", "cline", "command-code", "copilot-cli", "crush", "cursor", "droid", "goose", "grok", "kimi", "kiro", "mistral-vibe", "openclaude", "qwen-code"],
    );
    for (const a of agents) expect(ids.has(a)).toBe(true);
  });
  it("every fixture parses and every file names its source and mark", () => {
    for (const a of agents) {
      const files = readdirSync(join(dir, a)).sort();
      expect(files).toContain("sources.json");
      const sources = JSON.parse(readFileSync(join(dir, a, "sources.json"), "utf8")) as {
        agent: string;
        versionRead: string;
        files: Record<string, { from: string; source: string; mark: string }>;
      };
      expect((sources as { presetId?: string }).presetId).toBe(a);
      expect(sources.versionRead.length).toBeGreaterThan(0);
      for (const f of files) {
        if (f === "sources.json") continue;
        const text = readFileSync(join(dir, a, f), "utf8");
        if (f.endsWith(".json")) expect(() => JSON.parse(text), `${a}/${f}`).not.toThrow();
        const meta = sources.files[f];
        expect(meta, `${a}/${f} is listed in sources.json`).toBeDefined();
        expect(["verbatim", "built-from-fields"]).toContain(meta?.from);
        expect(["V", "I", "NF"]).toContain(meta?.mark);
        expect(meta?.source.length ?? 0).toBeGreaterThan(0);
        expect(text, `${a}/${f} holds no key-like string`).not.toMatch(/\b(sk|ghp|hf|xox[bp])[-_][A-Za-z0-9]{16,}/);
      }
    }
  });
});

// The wave 5 base: wave 5's contracts and their first fixtures
// (events.md section 5, policy.md section 6, cu-tool.schema.json).
describe("wave 5 contracts", () => {
  it("every wave 5 record example validates", () => {
    for (const f of ["fixtures/tap/records.json", "fixtures/tap/anthropic.expected.json", "fixtures/tap/openai-responses.expected.json", "fixtures/installs/records.json"]) {
      expect([f, check("wave5-records.schema.json", read(f))]).toEqual([f, []]);
    }
  });

  it("refuses a tap record from the wrong source, a header in a detail, and a candidate set with no candidate", () => {
    const [call] = read("fixtures/tap/anthropic.expected.json") as Record<string, unknown>[];
    expect(check("wave5-records.schema.json", [{ ...call, source: "adapter" }])).not.toEqual([]);
    const detail = (call as { detail: Record<string, unknown> }).detail;
    expect(check("wave5-records.schema.json", [{ ...call, detail: { ...detail, authorization: "Bearer x" } }])).not.toEqual([]);
    const join = (read("fixtures/tap/records.json") as { kind: string; detail: Record<string, unknown> }[]).find((r) => r.kind === "join.candidates")!;
    expect(check("wave5-records.schema.json", [{ ...join, detail: { ...join.detail, candidates: [] } }])).not.toEqual([]);
  });

  it("the tap fixtures' hashes are the canonical JSON the README names", () => {
    const canon = (v: unknown): string =>
      Array.isArray(v) ? `[${v.map(canon).join(",")}]` : v !== null && typeof v === "object" ? `{${Object.keys(v).sort().map((k) => `${JSON.stringify(k)}:${canon((v as Record<string, unknown>)[k])}`).join(",")}}` : JSON.stringify(v);
    const sha = (t: string) => createHash("sha256").update(t, "utf8").digest("hex");
    const a = read("fixtures/tap/anthropic.response.json") as { content: { type: string; input?: unknown }[] };
    const [ae] = read("fixtures/tap/anthropic.expected.json") as { detail: { argsSha256: string; resultSha256: string } }[];
    expect(ae!.detail.argsSha256).toBe(sha(canon(a.content.find((b) => b.type === "tool_use")!.input)));
    const an = read("fixtures/tap/anthropic.next-request.json") as { messages: { content: unknown }[] };
    const result = (an.messages[2]!.content as { content: string }[])[0]!.content;
    expect(ae!.detail.resultSha256).toBe(sha(result));
    const o = read("fixtures/tap/openai-responses.response.json") as { output: { arguments: string }[] };
    const [oe] = read("fixtures/tap/openai-responses.expected.json") as { detail: { argsSha256: string } }[];
    expect(oe!.detail.argsSha256).toBe(sha(canon(JSON.parse(o.output[0]!.arguments))));
  });

  it("run.start's wave 5 fields and the settings example validate", () => {
    const ajv = validator();
    const runStart = ajv.getSchema(base + "wave5-records.schema.json#/$defs/runStartWave5")!;
    expect(runStart(read("fixtures/tap/runstart.example.json"))).toBe(true);
    expect(runStart({ boundaryChoice: { chosen: "none", named: false, reasons: [], answeredBy: "maybe", preAnswer: null } })).toBe(false);
    // Lane T's request T-1: an automatic pick, and srt's refusal of io_uring.
    expect(runStart({ boundaryChoice: { chosen: "srt", named: false, reasons: [{ boundary: "sbx", why: "sbx is installed and not signed in to Docker", install: "sbx login" }], answeredBy: "default", preAnswer: null }, ioUring: "blocked" })).toBe(true);
    expect(runStart({ ioUring: "unknown" })).toBe(false);
    expect(check("settings.schema.json", read("fixtures/tap/settings.example.json"))).toEqual([]);
    expect(check("settings.schema.json", { version: 1, content: { on: true } })).not.toEqual([]);
    expect(check("settings.schema.json", { version: 1, content: { on: true, retentionDays: 8 } })).not.toEqual([]);
    expect(check("settings.schema.json", { version: 1, boundary: { preAnswer: "yes" } })).not.toEqual([]);
    // Lane S's request 6 (case 113): confirmed upstreams, as the tap's reader takes them.
    expect(check("settings.schema.json", { version: 1, tap: { upstreams: { box: { base: "http://100.64.0.2:8080/v1", local: true }, gw: { base: "https://gw.example.com" } } } })).toEqual([]);
    for (const bad of [
      { anthropic: { base: "https://evil.example" } },
      { Box: { base: "https://box.lan" } },
      { box: { base: "http://box.lan:8080" } },
      { box: { base: "https://u:p@box.lan" } },
      { box: { base: "https://box.lan/?x" } },
      { box: { local: true } },
    ]) expect(check("settings.schema.json", { version: 1, tap: { upstreams: bad } }), JSON.stringify(bad)).not.toEqual([]);
  });

  it("the computer_use input schema takes Hermes's actions and refuses an unknown field", () => {
    expect(check("cu-tool.schema.json", { action: "capture", mode: "som", app: "TextEdit" })).toEqual([]);
    expect(check("cu-tool.schema.json", { action: "click", element: 3, delivery_mode: "background" })).toEqual([]);
    expect(check("cu-tool.schema.json", { action: "shell", text: "rm -rf /" })).not.toEqual([]);
    expect(check("cu-tool.schema.json", { action: "click", approve: true })).not.toEqual([]);
    expect(check("cu-tool.schema.json", {})).not.toEqual([]);
  });

  it("the install cases are well formed", () => {
    const { cases } = read("fixtures/installs/cases.json") as { cases: { id: number; text: string; expect: { install: boolean; manager?: string; form?: string; packages?: { name: string; version: string | null }[]; why?: string } }[] };
    expect(new Set(cases.map((c) => c.id)).size).toBe(cases.length);
    const installs = cases.filter((c) => c.expect.install);
    expect(installs.length).toBeGreaterThanOrEqual(20);
    for (const c of installs) {
      expect(["add", "run"]).toContain(c.expect.form);
      expect(c.expect.packages!.length).toBeGreaterThan(0);
    }
    for (const c of cases.filter((x) => !x.expect.install)) expect(c.expect.why).toBeTruthy();
    for (const form of ["npx ", "uvx ", "bunx ", "pnpm dlx ", "yarn dlx "]) {
      expect(installs.some((c) => c.text.startsWith(form) && c.expect.form === "run")).toBe(true);
    }
  });
});

// The wave 5 base: the preset table's sibling tables (presets/wave5/).
describe("wave 5 preset tables", () => {
  const blank = (): PresetTable => ({ version: 1, harnesses: [{ id: "a" }], planned: [{ id: "b" }] });
  it("merge a value into its row, as presets.rs does", () => {
    const t = blank();
    mergeWave5(t, [{ field: "tap", text: JSON.stringify({ field: "tap", rows: { a: { via: "env", name: "ANTHROPIC_BASE_URL", api: ["anthropic-messages"], verifiedAt: "2026-11-04" } } }) }, { field: "executables", text: JSON.stringify({ field: "executables", rows: { b: ["agent-b"] } }) }]);
    expect((t.harnesses[0] as { tap: { name: string } }).tap.name).toBe("ANTHROPIC_BASE_URL");
    expect(t.planned[0]).toEqual({ id: "b", executables: ["agent-b"] });
  });
  it("refuse an unknown id, a row that sets the field, a misnamed table and a bad value", () => {
    expect(() => mergeWave5(blank(), [{ field: "tap", text: JSON.stringify({ field: "tap", rows: { zzz: null } }) }])).toThrow(/does not/);
    const owned = blank();
    owned.harnesses[0]!.tap = null;
    expect(() => mergeWave5(owned, [{ field: "tap", text: JSON.stringify({ field: "tap", rows: { a: null } }) }])).toThrow(/owns/);
    expect(() => mergeWave5(blank(), [{ field: "tap", text: JSON.stringify({ field: "kit", rows: {} }) }])).toThrow(/its field/);
    expect(() => mergeWave5(blank(), [{ field: "executables", text: JSON.stringify({ field: "executables", rows: { a: "x" } }) }])).toThrow(/not a executables/);
  });
  it("a filled row validates, and a tap that names a lowercase variable does not", () => {
    const t = loadPresetTable();
    const row = { ...t.harnesses[0]!, tap: { via: "env", name: "ANTHROPIC_BASE_URL", api: ["anthropic-messages"], verifiedAt: "2026-11-04" }, kit: { name: "claude", from: "sbx", verifiedAt: "2026-11-04" }, executables: ["claude"] };
    expect(check("harness-presets.schema.json", { ...t, harnesses: [row, ...t.harnesses.slice(1)] })).toEqual([]);
    const bad = { ...row, tap: { ...row.tap, name: "anthropic_base_url" } };
    expect(check("harness-presets.schema.json", { ...t, harnesses: [bad, ...t.harnesses.slice(1)] })).not.toEqual([]);
  });
});
