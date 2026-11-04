import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterAll, describe, expect, it } from "vitest";
import { crushServerNames, crushrcServerNames, jsonServerNames, projectFolders } from "./crushServers.ts";
import { crushMcpName } from "./dialects/crush.ts";

const root = mkdtempSync(path.join(tmpdir(), "derm-crush-"));
afterAll(() => rmSync(root, { recursive: true, force: true }));

function tree(files: Record<string, string>): string {
  const base = mkdtempSync(path.join(root, "t-"));
  for (const [rel, text] of Object.entries(files)) {
    const f = path.join(base, rel);
    mkdirSync(path.dirname(f), { recursive: true });
    writeFileSync(f, text);
  }
  return base;
}

describe("Crush's configured MCP server names", () => {
  it("reads the mcp keys of a JSON config", () => {
    expect(jsonServerNames(JSON.stringify({ mcp: { exa: {}, "exa_evil": {} } }))).toEqual(["exa", "exa_evil"]);
    expect(jsonServerNames("{}")).toEqual([]);
    expect(jsonServerNames("{ not json")).toBeNull();
    expect(jsonServerNames(JSON.stringify({ mcp: ["exa"] }))).toBeNull();
  });

  it("reads mcp add lines from a plain crushrc and refuses anything it cannot read statically", () => {
    expect(crushrcServerNames("# comment\nmcp add exa --type http --url https://mcp.exa.ai/mcp\nmcp add 'my server' --type stdio --command /bin/x\nprovider add x\n")).toEqual(["exa", "my server"]);
    for (const bad of [
      "mcp add $NAME --type stdio",
      "mcp add `echo x`",
      'mcp add "ex$a"',
      "mcp add exa; mcp add other",
      "if true; then mcp add x; fi",
      "source ~/other",
      ". ~/other",
      "eval mcp add x",
      "mcp add x\\\n --type stdio",
      "mcp add ex* --type stdio",
      "mcp add {a,b}",
      "mcp add x > /tmp/y",
      "f() { mcp add x; }",
      "export X=1",
    ]) {
      expect(crushrcServerNames(bad), bad).toBeNull();
    }
    expect(crushrcServerNames("mcp add")).toBeNull();
  });

  it("walks from the working folder to the git root, and only the working folder without one", () => {
    const base = tree({ "repo/.git/HEAD": "x", "repo/a/b/.keep": "" });
    expect(projectFolders(path.join(base, "repo", "a", "b"))).toEqual([path.join(base, "repo", "a", "b"), path.join(base, "repo", "a"), path.join(base, "repo")]);
    const loose = tree({ "x/y/.keep": "" });
    // No .git anywhere up to / in a temp folder: the folder alone.
    expect(projectFolders(path.join(loose, "x", "y"))).toEqual([path.join(loose, "x", "y")]);
  });

  it("collects the global, data and project files Crush loads", () => {
    const home = tree({
      ".config/crush/crush.json": JSON.stringify({ mcp: { exa: {} } }),
      ".config/crush/crushrc": "mcp add github --type http --url https://x\n",
      ".local/share/crush/crush.json": JSON.stringify({ mcp: { data_one: {} } }),
      "proj/.git/HEAD": "x",
      "proj/.crush.json": JSON.stringify({ mcp: { exa_evil: {} } }),
      "proj/sub/crushrc": "mcp add sub_server --type stdio --command /bin/true\n",
    });
    const got = crushServerNames({ HOME: home }, path.join(home, "proj", "sub"), home);
    expect(got.complete).toBe(true);
    expect(got.names.sort()).toEqual(["data_one", "exa", "exa_evil", "github", "sub_server"]);
  });

  it("follows CRUSH_GLOBAL_CONFIG, CRUSH_GLOBAL_DATA and XDG folders", () => {
    const home = tree({
      "elsewhere/crush.json": JSON.stringify({ mcp: { moved: {} } }),
      "data/crush.json": JSON.stringify({ mcp: { moved_data: {} } }),
      "xdg/crush/crush.json": JSON.stringify({ mcp: { xdg_one: {} } }),
      "w/.keep": "",
    });
    expect(crushServerNames({ CRUSH_GLOBAL_CONFIG: path.join(home, "elsewhere"), CRUSH_GLOBAL_DATA: path.join(home, "data") }, path.join(home, "w"), home).names.sort()).toEqual(["moved", "moved_data"]);
    expect(crushServerNames({ XDG_CONFIG_HOME: path.join(home, "xdg") }, path.join(home, "w"), home).names).toEqual(["xdg_one"]);
  });

  it("is incomplete when a file cannot be read whole, or with no cwd", () => {
    const home = tree({ ".config/crush/crush.json": "{ broken", "w/.keep": "" });
    expect(crushServerNames({}, path.join(home, "w"), home).complete).toBe(false);
    const rc = tree({ ".config/crush/crushrc": "mcp add $X\n", "w/.keep": "" });
    const r = crushServerNames({}, path.join(rc, "w"), rc);
    expect(r.complete).toBe(false);
    expect(r.why).toContain("crushrc");
    expect(crushServerNames({}, undefined, rc).complete).toBe(false);
    expect(crushServerNames({}, "relative/dir", rc).complete).toBe(false);
  });
});

describe("Crush MCP names to the core's form (W2-R1 for single underscores)", () => {
  const listed = (names: string[], complete = true) => ({ names, complete });

  it("a name that can split one way needs no list", () => {
    expect(crushMcpName("mcp_exa_search", listed([], false))).toEqual({ tool: "mcp__exa__search" });
    expect(crushMcpName("bash", listed([]))).toEqual({ tool: "bash" });
  });

  it("splits at the one configured server that fits", () => {
    expect(crushMcpName("mcp_exa_web_search_exa", listed(["exa", "github"]))).toEqual({ tool: "mcp__exa__web_search_exa" });
    expect(crushMcpName("mcp_exa_evil_t", listed(["exa_evil"]))).toEqual({ tool: "mcp__exa_evil__t" });
  });

  it("asks when two servers fit, when none does, or when the list is incomplete", () => {
    const two = crushMcpName("mcp_exa_evil_t", listed(["exa", "exa_evil"]));
    expect(two.tool).toBe("mcp_exa_evil_t");
    expect(two.ambiguous).toMatch(/more than one/);
    expect(crushMcpName("mcp_exa_evil_t", listed(["github"])).ambiguous).toMatch(/no configured/);
    expect(crushMcpName("mcp_exa_evil_t", { names: ["exa"], complete: false, why: "a crushrc derm cannot read statically (crushrc)" }).ambiguous).toMatch(/crushrc/);
  });
});
