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
