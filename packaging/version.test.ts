// Every file that states the release's version states the same one: the
// workspace's Cargo.toml (which the three binaries print with --version), the
// .deb's package, the npm packages that ship, the plugin manifests, and the
// emitter's OpenTelemetry scope. The release workflow checks a tag against
// the workspace version (.github/workflows/release.yml, "Version").
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { SCOPE } from "../packages/derm-pi/src/otlp.ts";

const root = new URL("../", import.meta.url);
const text = (p: string) => readFileSync(new URL(p, root), "utf8");
const json = (p: string) => JSON.parse(text(p)) as { version?: string };

function cargoVersion(p: string, table: string): string | undefined {
  const lines = text(p).split("\n");
  let inTable = false;
  for (const line of lines) {
    const t = line.trim();
    if (t.startsWith("[")) inTable = t === `[${table}]`;
    else if (inTable) {
      const m = /^version\s*=\s*"([^"]+)"/.exec(t);
      if (m) return m[1];
    }
  }
  return undefined;
}

const SHIPPING = [
  "derm-pi",
  "derm-claude-plugin",
  "derm-codex-plugin",
  "derm-opencode-plugin",
  "derm-gemini-extension",
  "derm-hermes-plugin",
  "derm-kilo-plugin",
  "derm-openclaw-plugin",
];
const MANIFESTS = [
  "packages/derm-claude-plugin/.claude-plugin/plugin.json",
  "packages/derm-codex-plugin/.codex-plugin/plugin.json",
  "packages/derm-gemini-extension/gemini-extension.json",
];

describe("one release version", () => {
  const release = cargoVersion("Cargo.toml", "workspace.package");

  it("the workspace states one", () => {
    expect(release).toMatch(/^\d+\.\d+\.\d+(-[0-9A-Za-z.]+)?$/);
  });

  it("the .deb package states it", () => {
    expect(cargoVersion("packaging/deb/Cargo.toml", "package")).toBe(release);
  });

  it.each(SHIPPING)("packages/%s/package.json states it", (p) => {
    expect(json(`packages/${p}/package.json`).version).toBe(release);
  });

  it.each(MANIFESTS)("%s states it", (p) => {
    expect(json(p).version).toBe(release);
  });

  it("the lock file records it for each shipping package", () => {
    const lock = JSON.parse(text("package-lock.json")) as { packages: Record<string, { version?: string }> };
    for (const p of SHIPPING) expect(lock.packages[`packages/${p}`]?.version, p).toBe(release);
  });

  it("Pi's emitter names it as its scope version", () => {
    expect(SCOPE.version).toBe(release);
  });
});
