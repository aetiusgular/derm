// T4.4: a takedown from the report to the mirror's output (the T4 gate,
// toolkit plan section 6). A scratch copy of the catalog; nothing here touches
// the repository's own catalog or log.
import { cpSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { exportSet } from "../export/index.ts";
import { FakeRegistry } from "../mirror/fake-registry.ts";
import { pull } from "../mirror/pull.ts";
import { OFFICIAL_KEY, type ServerRecord } from "../mirror/registry.ts";
import { Store } from "../mirror/store.ts";
import { CATALOG_DIR, catalogHasErrors, loadBrands, loadCatalog, validateCatalog } from "../validate/index.ts";
import { getMeta } from "../validate/types.ts";
import { LOG_HEADER, TAKEDOWN_LOG, takedown } from "./takedown.ts";

const dirs: string[] = [];
function scratch(): { catalog: string; log: string } {
  const root = mkdtempSync(join(tmpdir(), "derm-takedown-"));
  dirs.push(root);
  const catalog = join(root, "catalog");
  cpSync(CATALOG_DIR, catalog, { recursive: true });
  const log = join(root, "TAKEDOWNS.md");
  writeFileSync(log, LOG_HEADER);
  return { catalog, log };
}
afterEach(() => {
  for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true });
});

const REPORT = "https://github.com/aetiusgular/derm/issues/7";
const when = { now: () => new Date("2026-11-03T08:00:00Z") };

describe("takedown", () => {
  it("flips only the status, keeps every other field, and logs one line", () => {
    const { catalog, log } = scratch();
    const before = loadCatalog(catalog).entries.find((e) => e.id === "exa")!;
    const r = takedown({ id: "exa", reason: "the endpoint serves malware (report verified)", report: REPORT, catalogDir: catalog, logPath: log, ...when });
    const after = loadCatalog(catalog).entries.find((e) => e.id === "exa")!;
    expect(getMeta(after.kind, after.data)?.status).toBe("deleted");
    const strip = (d: Record<string, unknown>) => {
      const c = structuredClone(d);
      (getMeta("server", c) as { status: string }).status = "x";
      return c;
    };
    expect(strip(after.data)).toEqual(strip(before.data));
    expect(r.diff).toEqual([`- "status": "active"`, `+ "status": "deleted"`]);
    const lines = readFileSync(log, "utf8").trimEnd().split("\n");
    expect(lines.at(-1)).toBe(`| 2026-11-03 | exa | ${before.data["name"]} | active | the endpoint serves malware (report verified) | [#7](${REPORT}) |`);
    // The catalog still validates: a deleted entry is a valid entry.
    const v = validateCatalog(loadCatalog(catalog), loadBrands(catalog));
    expect(catalogHasErrors(v)).toBe(false);
  });

  it("refuses an unknown id, a second takedown, and a reason or report that could break the log", () => {
    const { catalog, log } = scratch();
    const base = { catalogDir: catalog, logPath: log, ...when };
    expect(() => takedown({ ...base, id: "no-such", reason: "x", report: REPORT })).toThrow(/no catalog entry/);
    expect(() => takedown({ ...base, id: "exa", reason: "a | b", report: REPORT })).toThrow(/reason/);
    expect(() => takedown({ ...base, id: "exa", reason: "two\nlines", report: REPORT })).toThrow(/reason/);
    expect(() => takedown({ ...base, id: "exa", reason: "", report: REPORT })).toThrow(/reason/);
    expect(() => takedown({ ...base, id: "exa", reason: "ok", report: "https://evil.example/issues/1" })).toThrow(/report/);
    expect(() => takedown({ ...base, id: "exa", reason: "ok", report: "#7)](javascript:x" })).toThrow(/report/);
    takedown({ ...base, id: "exa", reason: "ok", report: "#7" });
    expect(() => takedown({ ...base, id: "exa", reason: "ok", report: "#7" })).toThrow(/already deleted/);
    expect(readFileSync(log, "utf8").trimEnd().split("\n").filter((l) => l.startsWith("| 2026")).length).toBe(1);
  });

  it("takes a privately sent report without naming its sender", () => {
    const { catalog, log } = scratch();
    takedown({ id: "context7", reason: "trademark complaint, by email", report: "private", catalogDir: catalog, logPath: log, ...when });
    expect(readFileSync(log, "utf8")).toContain("| trademark complaint, by email | sent privately |");
  });

  it("refuses to rewrite a manifest whose formatting it would change", () => {
    const { catalog, log } = scratch();
    const f = join(catalog, "exa", "server.json");
    writeFileSync(f, JSON.stringify(JSON.parse(readFileSync(f, "utf8"))) + "\n");
    expect(() => takedown({ id: "exa", reason: "ok", report: "#7", catalogDir: catalog, logPath: log, ...when })).toThrow(/formatting/);
  });
});

describe("a takedown end to end (the T4 gate)", () => {
  it("leaves the entry out of every export, keeps it with include_deleted, and the mirror sees it deleted", async () => {
    const { catalog, log } = scratch();
    takedown({ id: "exa", reason: "end-to-end check", report: "#1", catalogDir: catalog, logPath: log, ...when });
    const files = exportSet(loadCatalog(catalog), "tony-connectors", { sha: "a".repeat(40), now: "2026-11-03T08:00:00Z" });
    const text = (p: string) => files.find((f) => f.path === `tony-connectors/${p}`)!.content;
    // Installers never see it: not by id, registry name or endpoint host.
    const named = (s: string) => /"exa"|aetiusgular\/exa"|mcp\.exa\.ai/.test(s);
    expect(named(text("claude/.claude-plugin/marketplace.json"))).toBe(false);
    expect(files.some((f) => f.path.startsWith("tony-connectors/pi/exa/") || f.path.startsWith("tony-connectors/claude/plugins/exa/"))).toBe(false);
    expect(named(text("pi/mcp.json"))).toBe(false);
    expect(named(text("docker/profile.json"))).toBe(false);
    expect(named(text("toolhive/registry.json"))).toBe(false);
    // Before the takedown the same exports did name it (the check can fail).
    const beforeFiles = exportSet(loadCatalog(CATALOG_DIR), "tony-connectors", { sha: "a".repeat(40), now: "2026-11-03T08:00:00Z" });
    for (const p of ["claude/.claude-plugin/marketplace.json", "pi/mcp.json", "docker/profile.json", "toolhive/registry.json"]) {
      expect(named(beforeFiles.find((f) => f.path === `tony-connectors/${p}`)!.content), p).toBe(true);
    }
    // The registry list, as the official one: out by default, in with include_deleted.
    const def = JSON.parse(text("registry.json")) as { servers: ServerRecord[] };
    expect(def.servers.map((s) => s.server.name)).not.toContain("io.github.aetiusgular/exa");
    const all = JSON.parse(text("registry-include-deleted.json")) as { servers: ServerRecord[]; metadata: { count: number } };
    const gone = all.servers.find((s) => s.server.name === "io.github.aetiusgular/exa")!;
    expect(gone._meta[OFFICIAL_KEY].status).toBe("deleted");
    expect(all.metadata.count).toBe(def.servers.length + 1);
    // The mirror, pulling a registry that holds the takedown, keeps the
    // server's metadata and records it deleted.
    const reg = new FakeRegistry();
    for (const s of all.servers) reg.rows.push({ server: s.server, official: { ...s._meta[OFFICIAL_KEY] } });
    const out = mkdtempSync(join(tmpdir(), "derm-takedown-mirror-"));
    dirs.push(out);
    const report = await pull({ out, client: { baseUrl: "https://registry.test", fetchImpl: reg.fetch, log: () => {} }, probe: false });
    expect(new URL(reg.calls[0]!).searchParams.get("include_deleted")).toBe("true");
    expect(report.servers).toBe(all.servers.length);
    const store = new Store(out);
    const v = store.versions("io.github.aetiusgular/exa");
    expect(v[0]?._meta[OFFICIAL_KEY].status).toBe("deleted");
    expect(v[0]?.server.description).toBe(gone.server.description);
    const index = store.read("index.json") as { servers: Record<string, { status: string }> };
    expect(index.servers["io.github.aetiusgular/exa"]?.status).toBe("deleted");
    expect(store.state("https://registry.test").counts?.deleted).toBe(1);
  });
});

describe("library/TAKEDOWNS.md", () => {
  it("starts with the header the command writes under, and holds only well-formed rows", () => {
    const text = readFileSync(TAKEDOWN_LOG, "utf8");
    expect(text.startsWith(LOG_HEADER)).toBe(true);
    for (const row of text.slice(LOG_HEADER.length).split("\n").filter(Boolean)) {
      expect(row).toMatch(/^\| \d{4}-\d{2}-\d{2} \| [a-z0-9-]+ \| [^|]+ \| (active|deprecated) \| [^|]+ \| (sent privately|\[#\d+\]\(https:\/\/github\.com\/aetiusgular\/(derm|tk)\/issues\/\d+\)) \|$/);
    }
  });
});
