// Box test w1, BX1: DERM_LIBRARY_ONLINE=1 and DERM_LIBRARY_SKILLS_REF=1 changed
// nothing, because the validate path never called the two checks. These run
// the real command line and the exported pass.
import { execFile } from "node:child_process";
import { chmodSync, copyFileSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { delimiter, isAbsolute, join, resolve } from "node:path";
import { promisify } from "node:util";
import { describe, expect, it } from "vitest";
import { CATALOG_DIR, loadCatalog, optInChecks } from "./index.ts";

const run = promisify(execFile);
const CLI = resolve(import.meta.dirname, "../cli.ts");

describe("opt-in checks in the validate path", () => {
  it("node library/cli.ts validate runs skills-ref on every skill when DERM_LIBRARY_SKILLS_REF=1", async () => {
    const bin = mkdtempSync(join(tmpdir(), "derm-skillsref-"));
    const seen = join(bin, "seen");
    const env: NodeJS.ProcessEnv = { ...process.env, PATH: `${bin}${delimiter}${process.env["PATH"]}`, DERM_LIBRARY_SKILLS_REF: "1" };
    if (process.platform === "win32") {
      // Windows starts only a program file from PATH here: libuv tries the
      // name with `.com` and `.exe`, never a script with no extension (a
      // pip install there is `skills-ref.exe`). The fake is this node,
      // copied under that name, with a preload that acts only in the copy:
      // records the folder, fails it with one finding.
      copyFileSync(process.execPath, join(bin, "skills-ref.exe"));
      const pre = join(bin, "fake-skills-ref.cjs");
      writeFileSync(pre, `if (/skills-ref\\.exe$/i.test(process.execPath)) { require("fs").appendFileSync(${JSON.stringify(seen)}, process.argv[2] + "\\n"); process.stderr.write("Validation failed for " + process.argv[2] + ":\\n  - fake finding\\n"); process.exit(1); }\n`);
      env["NODE_OPTIONS"] = `--require ${JSON.stringify(pre)}`;
    } else {
      // A fake skills-ref: records each folder, fails each with one finding.
      writeFileSync(join(bin, "skills-ref"), `#!/bin/sh\necho "$2" >> '${seen}'\necho "Validation failed for $2:" >&2\necho "  - fake finding" >&2\nexit 1\n`);
      chmodSync(join(bin, "skills-ref"), 0o755);
    }
    delete env["DERM_LIBRARY_ONLINE"];
    const r = await run(process.execPath, [CLI, "validate"], { env }).then(
      (x) => ({ code: 0, out: x.stdout }),
      (e: { code: number; stdout: string }) => ({ code: e.code, out: e.stdout }),
    );
    const skills = loadCatalog(CATALOG_DIR).entries.filter((e) => e.kind === "skill" && e.skillMd);
    expect(skills.length).toBeGreaterThan(0);
    expect(r.out.match(/\[skill\/skills-ref\] fake finding/g)?.length).toBe(skills.length);
    expect(r.code).toBe(1);
  });

  it("posts every server to the registry's validate only with DERM_LIBRARY_ONLINE=1", async () => {
    const catalog = loadCatalog(CATALOG_DIR);
    const servers = catalog.entries.filter((e) => e.kind === "server");
    const posted: string[] = [];
    const fetchImpl = (async (_url: string, init: { body: string }) => {
      posted.push((JSON.parse(init.body) as { name: string }).name);
      return new Response(JSON.stringify({ valid: false, issues: [{ type: "semantic", path: "", message: "deprecated", severity: "warning", reference: "schema-version-deprecated" }] }), { status: 200 });
    }) as unknown as typeof fetch;
    delete process.env["DERM_LIBRARY_ONLINE"];
    expect((await optInChecks(catalog, { fetchImpl })).size).toBe(0);
    expect(posted).toEqual([]);
    process.env["DERM_LIBRARY_ONLINE"] = "1";
    try {
      const found = await optInChecks(catalog, { fetchImpl });
      expect(posted.length).toBe(servers.length);
      for (const s of servers) expect(found.get(s.id)?.[0]?.rule).toBe("upstream/online/schema-version-deprecated");
    } finally {
      delete process.env["DERM_LIBRARY_ONLINE"];
    }
  });

  it("hands skills-ref an absolute folder, so the caller's working folder and a leading dash do not matter", async () => {
    // Fix pass security review, R7.
    const seen: string[][] = [];
    const exec = (async (_f: string, args: string[]) => {
      seen.push(args);
      return { stdout: "", stderr: "" };
    }) as never;
    process.env["DERM_LIBRARY_SKILLS_REF"] = "1";
    try {
      await optInChecks(loadCatalog(CATALOG_DIR), { exec });
    } finally {
      delete process.env["DERM_LIBRARY_SKILLS_REF"];
    }
    expect(seen.length).toBeGreaterThan(0);
    for (const a of seen) {
      expect(a[0]).toBe("validate");
      expect(isAbsolute(a[1] ?? "")).toBe(true);
    }
  });
});
