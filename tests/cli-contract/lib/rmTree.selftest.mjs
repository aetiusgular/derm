// node tests/cli-contract/lib/rmTree.selftest.mjs
// Box test, 19 Nov 2026: every Mistral Vibe check ended in EACCES when the
// runner was not root. Vibe 3.1.1 keeps its plugin packages under the scratch
// HOME as read-only folders (0500, `.vibe/logs/session/plugins/packages/`),
// and rmSync cannot empty a folder its owner may not write. Root can, which
// is why the cloud runs (as root) never showed it. Run as a normal user.
import { chmodSync, existsSync, mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { rmTree } from "./rmTree.mjs";

const check = (what, got, want) => {
  if (got !== want) {
    console.error(`FAIL ${what}: ${got}, wanted ${want}`);
    process.exitCode = 1;
  } else console.log(`ok ${what}`);
};

function vibeLike() {
  const root = mkdtempSync(path.join(tmpdir(), "rmtree-"));
  const pkg = path.join(root, "home", ".vibe", "logs", "session", "plugins", "packages", "4d", "4df3");
  mkdirSync(path.join(pkg, "skills", "vibe"), { recursive: true });
  writeFileSync(path.join(pkg, "skills", "vibe", "SKILL.md"), "x");
  // A link out of the tree: rmTree must not change what it points at.
  const outside = mkdtempSync(path.join(tmpdir(), "rmtree-out-"));
  chmodSync(outside, 0o500);
  symlinkSync(outside, path.join(pkg, "skills", "out"));
  for (const d of [path.join(pkg, "skills", "vibe"), path.join(pkg, "skills"), pkg]) chmodSync(d, 0o500);
  return { root, outside };
}

if (process.getuid?.() === 0) {
  console.log("skip: root may remove any folder, so this shows nothing as root");
} else {
  const a = vibeLike();
  let plain = "removed";
  try {
    rmSync(a.root, { recursive: true, force: true });
  } catch (e) {
    plain = e.code;
  }
  check("rmSync on a tree with 0500 folders", plain, "EACCES");
  rmTree(a.root);
  check("rmTree removes it", existsSync(a.root), false);
  const b = vibeLike();
  rmTree(b.root);
  check("rmTree leaves a linked folder outside the tree as it was", existsSync(b.outside), true);
  check("and its mode unchanged", (await import("node:fs")).statSync(b.outside).mode & 0o777, 0o500);
  for (const o of [a.outside, b.outside]) {
    chmodSync(o, 0o700);
    rmSync(o, { recursive: true, force: true });
  }
}
