// File modes for derm-pi's tests on every system (note BF section 4.3).
//
// On Windows Node's chmod sets only the read-only bit, and a stat's mode is
// made up from it ("On Windows, only the write permission can be
// manipulated", @types/node fs.d.ts; libuv `src/win/fs.c`). derm's Rust
// checks, which decide for derm-pi through `derm gate serve`, read the access
// list there. So a test that loosens a file says it here: the mode as asked
// everywhere, and on Windows, when the mode lets others write, Everyone is
// also granted write in the access list (`icacls /grant *S-1-1-0`, as
// crates/derm-cli/src/run/mod.rs's `fpw_s2_*` test does). A folder's grant
// is not inherited, as a Unix folder's mode is not its files'. Linux and
// macOS get the same chmod as before and nothing else.
import { execFileSync } from "node:child_process";
import { chmodSync, statSync } from "node:fs";

export const WIN = process.platform === "win32";

/** `chmod p mode`; on Windows, a mode others may write also lets Everyone write `p`. */
export function setMode(p: string, mode: number): void {
  chmodSync(p, mode);
  if (WIN && (mode & 0o022) !== 0) {
    const grant = statSync(p).isDirectory() ? "*S-1-1-0:(M)" : "*S-1-1-0:(W)";
    execFileSync("icacls", [p, "/grant", grant], { stdio: "ignore" });
  }
}

/**
 * Windows only: the access list's entries, as icacls prints them, one per
 * principal (`NAME:(rights)`). derm's private files carry exactly one, the
 * user's full control (derm-core `user_only_sddl`: `D:P(A;;FA;;;<user>)`).
 */
export function accessEntries(p: string): string[] {
  const out = execFileSync("icacls", [p], { encoding: "utf8" });
  const lines = out.split(/\r?\n/).filter((l) => l.trim() && !/^Successfully processed/i.test(l.trim()));
  // The first line starts with the path; the rest are indented entries.
  return lines.map((l, i) => (i === 0 ? l.slice(p.length) : l).trim()).filter(Boolean);
}

/** Windows only: this process's user as icacls names it (`DOMAIN\user`). */
export function whoami(): string {
  return execFileSync("whoami", { encoding: "utf8" }).trim();
}
