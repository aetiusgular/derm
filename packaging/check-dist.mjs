// Checks the Linux release artifacts in a folder before they are hashed
// (.github/workflows/release.yml). Exit 1 with a reason on the first problem.
//
//   node packaging/check-dist.mjs <dist>
//
// The tarball holds the three binaries (mode 0755), LICENSE, NOTICE, README.md
// and the user unit, under one top folder. The .deb holds the binaries in
// /usr/bin, the user unit in /usr/lib/systemd/user/ starting /usr/bin/
// derm-daemon, and no maintainer script: nothing runs or is enabled on
// install (plans/parallel_build_tk.md, section 7b, release step 3).
import { execFileSync } from "node:child_process";
import { mkdtempSync, readdirSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const BINARIES = ["derm", "derm-daemon", "derm-audit-feed"];
const DOCS = ["LICENSE", "NOTICE", "README.md", "derm-daemon.service"];

function fail(why) {
  console.error(`check-dist: ${why}`);
  process.exit(1);
}

const dist = process.argv[2];
if (!dist) fail("usage: node packaging/check-dist.mjs <dist>");
const files = readdirSync(dist);
const tars = files.filter((f) => f.endsWith(".tar.gz"));
const debs = files.filter((f) => f.endsWith(".deb"));
if (tars.length !== 1) fail(`expected one .tar.gz, found ${tars.length}`);
if (debs.length !== 1) fail(`expected one .deb, found ${debs.length}`);

// The tarball: names, modes and nothing else.
const tar = tars[0];
const top = tar.replace(/\.tar\.gz$/, "");
const listing = execFileSync("tar", ["-tvzf", join(dist, tar)], { encoding: "utf8" }).trim().split("\n");
const seen = new Map();
for (const line of listing) {
  const parts = line.trim().split(/\s+/);
  const mode = parts[0];
  const name = parts.at(-1);
  if (name === `${top}/`) continue;
  if (!name.startsWith(`${top}/`) || name.slice(top.length + 1).includes("/")) fail(`${tar}: unexpected path ${name}`);
  seen.set(name.slice(top.length + 1), mode);
}
for (const b of BINARIES) if (seen.get(b) !== "-rwxr-xr-x") fail(`${tar}: ${b} missing or not 0755 (${seen.get(b)})`);
for (const d of DOCS) if (seen.get(d) !== "-rw-r--r--") fail(`${tar}: ${d} missing or not 0644 (${seen.get(d)})`);
if (seen.size !== BINARIES.length + DOCS.length) fail(`${tar}: extra files: ${[...seen.keys()].filter((k) => !BINARIES.includes(k) && !DOCS.includes(k)).join(", ")}`);

// The .deb: its control members and its files.
const deb = join(dist, debs[0]);
const ctl = mkdtempSync(join(tmpdir(), "derm-deb-"));
try {
  execFileSync("dpkg-deb", ["-e", deb, ctl]);
  const members = readdirSync(ctl).sort();
  const scripts = members.filter((m) => ["preinst", "postinst", "prerm", "postrm", "config", "templates", "triggers"].includes(m));
  if (scripts.length) fail(`${debs[0]}: maintainer scripts ${scripts.join(", ")}`);
  const contents = execFileSync("dpkg-deb", ["-c", deb], { encoding: "utf8" });
  for (const b of BINARIES) if (!new RegExp(`^-rwxr-xr-x .* \\./usr/bin/${b}$`, "m").test(contents)) fail(`${debs[0]}: /usr/bin/${b} missing or not 0755`);
  if (!/ \.\/usr\/lib\/systemd\/user\/derm-daemon\.service$/m.test(contents)) fail(`${debs[0]}: the user unit is missing`);
  if (/ \.\/(etc|lib\/systemd\/system|usr\/lib\/systemd\/system)\//m.test(contents)) fail(`${debs[0]}: installs into /etc or a system unit folder`);
  // Extracted to a folder: the binaries are megabytes, past a pipe buffer.
  const x = mkdtempSync(join(tmpdir(), "derm-deb-x-"));
  try {
    execFileSync("dpkg-deb", ["-x", deb, x]);
    const text = readFileSync(join(x, "usr/lib/systemd/user/derm-daemon.service"), "utf8");
    if (!/^ExecStart=\/usr\/bin\/derm-daemon --foreground$/m.test(text)) fail(`${debs[0]}: the unit does not start /usr/bin/derm-daemon`);
  } finally {
    rmSync(x, { recursive: true, force: true });
  }
} finally {
  rmSync(ctl, { recursive: true, force: true });
}
console.log(`check-dist: ${tar} and ${debs[0]} look right`);
