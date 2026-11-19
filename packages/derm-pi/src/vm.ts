// derm's sbx VM, as derm-pi tells it (17 Nov 2026): the gate's rule
// (crates/derm-cli/src/gate/daemon.rs, SBX_HOST and VM_MARKER), ported from
// the TypeScript hook core's daemon.ts, which was deleted on 19 Nov 2026;
// test/vm.test.ts holds the path and host equal to the gate's.
//
// In the VM the daemon is on the host, at http://host.docker.internal:<port>
// (`derm run` names it in DERM_OTLP_ENDPOINT and opens that port for the
// sandbox alone). The emitter may post there only when all of these hold:
// - the marker derm's kit writes as root is in place. A project can set every
//   variable below, so the variables alone would let a project on a host send
//   the chat's records to a listener of its own; the marker is something it
//   cannot make.
// - DERM_BOUNDARY=sbx and DERM_OTLP_ENDPOINT a plain
//   http://host.docker.internal:<port> with no user, path, query or fragment.
// - no file where a daemon socket would be: where there is one, this is a
//   host with a daemon and the loopback rule stands.
// - the process is not root.

import { lstatSync } from "node:fs";
import { platform, userInfo } from "node:os";
import path from "node:path";

export const SBX_HOST = "host.docker.internal";
export const VM_MARKER = "/opt/derm-kit/sbx-vm";

type Stat = { uid: number; mode: number; nlink: number; isFile(): boolean; isDirectory(): boolean };

/** Why the VM marker does not hold, or undefined when it does. */
export function vmMarker(file: string = VM_MARKER, system: NodeJS.Platform = platform(), stat: (p: string) => Stat = lstatSync): string | undefined {
  if (system !== "linux") return "the VM route is only for derm's sbx VM, which is Linux";
  try {
    const f = stat(file);
    if (!f.isFile() || f.nlink !== 1) return "the VM marker is not a plain file";
    if (f.uid !== 0 || (f.mode & 0o022) !== 0) return "the VM marker is not root's alone";
    const d = stat(path.dirname(file));
    if (!d.isDirectory() || d.uid !== 0 || (d.mode & 0o022) !== 0) return "the VM marker's folder is not root's alone";
    return undefined;
  } catch {
    return "no VM marker (derm's sbx kit was not installed here)";
  }
}

/** Where a daemon socket would be on this machine, whatever the variables say. */
export function socketCandidates(env: NodeJS.ProcessEnv): string[] {
  const out = new Set<string>();
  const named = env.DERM_DAEMON_SOCKET;
  if (named && named.trim() !== "") out.add(named);
  const under = (home: string | undefined) => {
    if (home && path.isAbsolute(home)) out.add(path.join(home, ".derm", "run", "derm", "daemon.sock"));
  };
  under(env.HOME);
  // HOME can be moved by a project's env; the password database's home cannot.
  try {
    under(userInfo().homedir);
  } catch {
    // No entry for this uid: the other candidates stand.
  }
  const runtime = env.XDG_RUNTIME_DIR;
  if (runtime && runtime.trim() !== "") out.add(path.join(runtime, "derm", "daemon.sock"));
  if (typeof process.getuid === "function") out.add(path.join("/run/user", String(process.getuid()), "derm", "daemon.sock"));
  return [...out];
}

/** True when this process is in derm's sbx VM and its endpoint is the host's daemon port. */
export function vmLogs(
  env: NodeJS.ProcessEnv = process.env,
  marker: () => string | undefined = vmMarker,
  uid: number | undefined = process.getuid?.(),
  candidates: () => string[] = () => socketCandidates(env),
): boolean {
  if (env.DERM_BOUNDARY?.trim() !== "sbx") return false;
  if (uid === 0) return false;
  const raw = env.DERM_OTLP_ENDPOINT?.trim();
  if (!raw) return false;
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    return false;
  }
  if (url.protocol !== "http:" || url.hostname !== SBX_HOST || url.port === "") return false;
  if (url.username !== "" || url.password !== "" || url.search !== "" || url.hash !== "") return false;
  if (url.pathname !== "/" && url.pathname !== "") return false;
  if (marker() !== undefined) return false;
  for (const sock of candidates()) {
    try {
      lstatSync(sock);
      return false;
    } catch (e) {
      if ((e as NodeJS.ErrnoException)?.code !== "ENOENT") return false;
    }
  }
  return true;
}
