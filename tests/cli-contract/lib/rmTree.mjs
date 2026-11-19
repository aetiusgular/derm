// Removes a check's scratch folder, including folders an agent left
// read-only. Mistral Vibe 3.1.1 keeps its plugin packages as 0500 folders
// under the scratch HOME, and rmSync cannot empty those unless the runner is
// root (rmTree.selftest.mjs). Each folder in the tree is first given owner
// write and search; links are not followed, so nothing outside the tree
// changes.
import { chmodSync, lstatSync, readdirSync, rmSync } from "node:fs";
import path from "node:path";

export function rmTree(dir) {
  const open = (d) => {
    let st;
    try {
      st = lstatSync(d);
    } catch {
      return;
    }
    if (!st.isDirectory()) return;
    if ((st.mode & 0o700) !== 0o700) {
      try {
        chmodSync(d, (st.mode & 0o7777) | 0o700);
      } catch {
        return;
      }
    }
    let names = [];
    try {
      names = readdirSync(d);
    } catch {
      return;
    }
    for (const n of names) open(path.join(d, n));
  };
  open(dir);
  rmSync(dir, { recursive: true, force: true });
}
