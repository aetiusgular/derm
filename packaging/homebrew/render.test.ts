import { describe, expect, it } from "vitest";
// @ts-expect-error plain .mjs without types
import { parseSums, render } from "./render.mjs";

const mac = "a".repeat(64);
const lin = "b".repeat(64);
const deb = "c".repeat(64);
const sums = [
  `${lin}  derm-0.1.0-x86_64-unknown-linux-musl.tar.gz`,
  `${deb}  derm_0.1.0_amd64.deb`,
  `${mac}  derm-0.1.0-macos.zip`,
  "",
].join("\n");

describe("homebrew formula", () => {
  it("fills the version and both hashes, nothing left over", () => {
    const f = render("0.1.0", sums);
    // brew audit --strict: the version is scanned from the URL; a version line is redundant.
    expect(f).not.toMatch(/^  version /m);
    // The universal zip under both on_arm and on_intel (brew style's ComponentsOrder).
    expect(f.split(`releases/download/v0.1.0/derm-0.1.0-macos.zip"\n      sha256 "${mac}"`).length - 1).toBe(2);
    expect(f).toContain(`derm-0.1.0-x86_64-unknown-linux-musl.tar.gz"\n      sha256 "${lin}"`);
    expect(f).not.toMatch(/@[A-Z0-9_]+@/);
    expect(f).not.toContain(deb);
  });

  it("refuses a missing file, a bad line, a duplicate and an odd version", () => {
    expect(() => render("0.1.0", sums.replace(/^.*macos\.zip$/m, ""))).toThrow(/no derm-0.1.0-macos.zip/);
    expect(() => render("0.1.0", `${sums}xyz  thing\n`)).toThrow(/malformed/);
    expect(() => parseSums(`${mac}  a\n${mac}  a\n`)).toThrow(/twice/);
    for (const v of ["v0.1.0", "0.1", '0.1.0"; system "x', "0.1.0/../x"]) {
      expect(() => render(v, sums)).toThrow(/not x.y.z/);
    }
  });

  it("tests the install with --version, which exits 0 (--help exits 2)", () => {
    const f = render("0.1.0", sums);
    expect(f).toContain('assert_equal "derm #{version}", shell_output("#{bin}/derm --version").strip');
    expect(f).not.toContain("--help");
  });

  it("refuses a template placeholder it does not know", () => {
    expect(() => render("0.1.0", sums, 'x "@VERSION@" "@OTHER@"')).toThrow(/@OTHER@ not filled/);
  });
});
