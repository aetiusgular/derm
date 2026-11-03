// packaging/check-dist.mjs against artifacts built here with dpkg-deb, a good
// pair and the faults it must refuse.
import { execFileSync, spawnSync } from "node:child_process";
import { chmodSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, it } from "vitest";

const CHECK = join(dirname(fileURLToPath(import.meta.url)), "check-dist.mjs");
const UNIT = "[Service]\nExecStart=/usr/bin/derm-daemon --foreground\n";
const dirs: string[] = [];
afterEach(() => {
  for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true });
});

function put(path: string, text: string, mode = 0o644): void {
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, text);
  chmodSync(path, mode);
}

function dist(o: { postinst?: boolean; unit?: string; extra?: boolean } = {}): string {
  const root = mkdtempSync(join(tmpdir(), "derm-dist-"));
  dirs.push(root);
  const out = join(root, "dist");
  mkdirSync(out);
  const name = "derm-0.1.0-x86_64-unknown-linux-musl";
  const stage = join(root, name);
  for (const b of ["derm", "derm-daemon", "derm-audit-feed"]) put(join(stage, b), "#!/bin/sh\n", 0o755);
  for (const d of ["LICENSE", "NOTICE", "README.md"]) put(join(stage, d), d);
  put(join(stage, "derm-daemon.service"), UNIT);
  if (o.extra) put(join(stage, "stray.txt"), "x");
  execFileSync("tar", ["-C", root, "--owner=0", "--group=0", "-czf", join(out, `${name}.tar.gz`), name]);
  const pkg = join(root, "pkg");
  put(join(pkg, "DEBIAN", "control"), "Package: derm\nVersion: 0.1.0\nArchitecture: amd64\nMaintainer: t <t@example.com>\nDescription: test\n");
  if (o.postinst) put(join(pkg, "DEBIAN", "postinst"), "#!/bin/sh\nsystemctl --global enable derm-daemon\n", 0o755);
  // derm-daemon is 2 MB in a real build: bigger than a default pipe buffer.
  for (const b of ["derm", "derm-daemon", "derm-audit-feed"]) put(join(pkg, "usr/bin", b), `#!/bin/sh\n#${b === "derm-daemon" ? "x".repeat(2_000_000) : ""}\n`, 0o755);
  put(join(pkg, "usr/lib/systemd/user/derm-daemon.service"), o.unit ?? UNIT);
  execFileSync("dpkg-deb", ["--root-owner-group", "--build", pkg, join(out, "derm_0.1.0_amd64.deb")], { stdio: "ignore" });
  return out;
}

function check(d: string): { code: number | null; text: string } {
  const r = spawnSync(process.execPath, [CHECK, d], { encoding: "utf8" });
  return { code: r.status, text: r.stdout + r.stderr };
}

const hasDpkg = spawnSync("dpkg-deb", ["--version"]).status === 0;

describe.skipIf(!hasDpkg)("check-dist", () => {
  it("passes a tarball and a .deb as the release builds them", () => {
    const r = check(dist());
    expect(r.code, r.text).toBe(0);
  });

  it("refuses a .deb with a maintainer script", () => {
    const r = check(dist({ postinst: true }));
    expect(r.code).toBe(1);
    expect(r.text).toContain("maintainer scripts postinst");
  });

  it("refuses a unit that starts another program", () => {
    const r = check(dist({ unit: "[Service]\nExecStart=%h/.local/bin/derm-daemon --foreground\n" }));
    expect(r.code).toBe(1);
    expect(r.text).toContain("does not start /usr/bin/derm-daemon");
  });

  it("refuses an extra file in the tarball", () => {
    const r = check(dist({ extra: true }));
    expect(r.code).toBe(1);
    expect(r.text).toContain("extra files: stray.txt");
  });
});
