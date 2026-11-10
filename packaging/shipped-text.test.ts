// The text a release user reads inside the archives (release check RC2, RC3,
// RC5): the files release.yml and packaging/macos/build-zip.sh copy in, and
// the release notes. Build-session notes and "not published yet" lines are
// true of a branch, not of a release.
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

const root = new URL("../", import.meta.url);
const text = (p: string) => readFileSync(new URL(p, root), "utf8");

// Copied into the archives beside the binaries.
const UNITS = [
  "crates/derm-daemon/units/derm-daemon.service",
  "crates/derm-daemon/units/io.github.aetiusgular.derm.daemon.plist",
  "packaging/deb/derm-daemon.service",
  "crates/derm-audit-linux/units/derm-audit-feed.service",
  "packaging/deb/derm-audit-feed.service",
];
// Read by a release user; the README is also in the archives. The README's
// open items name a wave 4 lane as their owner on purpose, so the build-note
// check below runs on the units only.
const PAGES = [
  "README.md",
  "docs/release-notes.md",
  "docs/install/macos.md",
  "docs/install/linux.md",
  "docs/install/agents.md",
];

// Phrases found in a v0.1.0 archive by the release check.
const BUILD_NOTES = [/\blane [A-R]\b/i, /not run in a build session/i, /the (box|Mac) test installs it/i];
const UNPUBLISHED = [
  /is being prepared on/i,
  /nothing is published yet/i,
  /once the tap .* is published/i,
  /once the tap is up/i,
];

describe("shipped text is written for a release user", () => {
  it.each(UNITS)("%s carries no build-session note", (p) => {
    const t = text(p);
    for (const re of [...BUILD_NOTES, ...UNPUBLISHED]) expect(t, `${p}: ${re}`).not.toMatch(re);
  });

  it.each(PAGES)("%s says what is published", (p) => {
    const t = text(p);
    for (const re of UNPUBLISHED) expect(t, `${p}: ${re}`).not.toMatch(re);
  });

  it("the install pages unpack the zip by its own folder", () => {
    const mac = text("docs/install/macos.md");
    expect(mac).toMatch(/cd derm-<version>-macos/);
    expect(mac).not.toMatch(/unzip derm-<version>-macos\.zip -d derm\b/);
  });
});

describe("the macOS zip has one top folder (RC5)", () => {
  const script = text("packaging/macos/build-zip.sh");

  it("stages under derm-<version>-macos/", () => {
    expect(script).toMatch(/stage=\$stage_root\/derm-\$version-macos/);
  });

  it("zips that folder with --keepParent, as Apple's notarization docs do", () => {
    expect(script).toMatch(/ditto -c -k --norsrc --noextattr --keepParent "derm-\$version-macos"/);
  });
});

// Release recheck RC8: with no policy file every call asks, and where an ask
// goes is each preset row's `coverage.ask`. The install page says so before
// the table, for every built adapter, in the same split as the rows.
describe("the agents page says what happens with no policy (RC8)", () => {
  const page = text("docs/install/agents.md");
  const presets = new URL("crates/derm-cli/src/connect/presets/", root);
  const index = JSON.parse(readFileSync(new URL("index.json", presets), "utf8"));
  const ids: string[] = [...index.harnesses, ...index.planned];
  // The agents' names as this page writes them.
  const NAMES: Record<string, string> = {
    "claude-code": "Claude Code",
    codex: "Codex",
    pi: "Pi",
    "oh-my-pi": "oh-my-pi",
    opencode: "OpenCode",
    kilo: "Kilo Code",
    gemini: "Gemini CLI",
    hermes: "Hermes Agent",
    openclaw: "OpenClaw",
    // Wave 4 (integration w4): lanes L, N and P.
    openclaude: "OpenClaude",
    "qwen-code": "Qwen Code",
    droid: "Droid",
    "command-code": "Command Code",
    kimi: "Kimi Code",
    auggie: "Auggie",
    "copilot-cli": "GitHub Copilot CLI",
    grok: "Grok Build",
    cursor: "Cursor",
    antigravity: "Antigravity CLI",
    goose: "goose",
    "mistral-vibe": "Mistral Vibe",
    crush: "Crush",
    kiro: "Kiro CLI",
    amp: "Amp",
    cline: "Cline CLI",
  };
  const sentence = page.match(
    /With no `~\/\.derm\/policy\.json` every call not on the reject list asks: (.*?) then prompt before every tool call, and (.*?) deny every tool call unless/,
  );
  const listed = (clause: string) => clause.split(/, | and /).map((s) => s.trim()).sort();
  const rows = ids.map((id) => JSON.parse(readFileSync(new URL(`${id}.json`, presets), "utf8")));
  const built = rows.filter((r) => r.coverage?.gate?.status === "built");

  it("says it before the install table", () => {
    expect(sentence, "the no-policy sentence").not.toBeNull();
    expect(page.indexOf(sentence![0])).toBeLessThan(page.indexOf("| Agent | Install |"));
  });

  it("knows every built adapter's ask route", () => {
    for (const r of built) {
      expect(NAMES[r.id], `${r.id} is built: give it a name on this page`).toBeDefined();
      expect(["own-prompt", "approver-or-deny"], r.id).toContain(r.coverage.ask);
    }
  });

  it("lists exactly the built adapters, each in its route's clause", () => {
    const by = (ask: string) => built.filter((r) => r.coverage.ask === ask).map((r) => NAMES[r.id]).sort();
    expect(listed(sentence![1])).toEqual(by("own-prompt"));
    expect(listed(sentence![2])).toEqual(by("approver-or-deny"));
  });
});
