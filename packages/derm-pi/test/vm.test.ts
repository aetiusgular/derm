// derm-pi's emitter in derm's sbx VM. Until 17 Nov 2026 the emitter posted to
// a loopback address only, so under `derm run --boundary sbx` Pi's records
// never left the VM: the daemon is on the host, at
// http://host.docker.internal:<port>. The emitter now takes that address
// too, and only where derm's gate takes its own VM route
// (crates/derm-cli/src/gate/daemon.rs, SBX_HOST and VM_MARKER; until 19 Nov
// 2026 also the TypeScript hook core's daemon.ts, now deleted):
// the root-owned marker derm's kit writes, DERM_BOUNDARY=sbx, a plain
// http://host.docker.internal:<port>, no daemon socket on this machine, not
// root. Anywhere else the rule is loopback only, as before.

import { describe, expect, it } from "vitest";
import { logsUrl } from "../src/otlp.ts";
import { SBX_HOST, VM_MARKER, vmLogs, vmMarker } from "../src/vm.ts";
import { readFileSync } from "node:fs";

// The gate's own constants, read from its source.
const GATE_DAEMON = readFileSync(new URL("../../../crates/derm-cli/src/gate/daemon.rs", import.meta.url), "utf8");
const rustConst = (name: string) => new RegExp(`pub const ${name}: &str = "([^"]*)";`).exec(GATE_DAEMON)?.[1];

const ENDPOINT = "http://host.docker.internal:46659";
const ENV = { DERM_BOUNDARY: "sbx", DERM_OTLP_ENDPOINT: ENDPOINT };
const holds = (): string | undefined => undefined;
const none = () => [] as string[];

type St = { uid: number; mode: number; nlink: number; isFile(): boolean; isDirectory(): boolean };
const fakeStat = (over: { file?: Partial<St>; dir?: Partial<St> }) => (p: string): St => {
  const file: St = { uid: 0, mode: 0o100644, nlink: 1, isFile: () => true, isDirectory: () => false, ...over.file };
  const dir: St = { uid: 0, mode: 0o040755, nlink: 2, isFile: () => false, isDirectory: () => true, ...over.dir };
  return p.endsWith("sbx-vm") ? file : dir;
};

describe("the VM marker, as derm's gate reads it", () => {
  it("is the same path and host", () => {
    expect(VM_MARKER).toBe(rustConst("VM_MARKER"));
    expect(SBX_HOST).toBe(rustConst("SBX_HOST"));
  });

  // The answers the deleted TypeScript core gave for each (its tests at
  // f75328d), and derm's gate gives (gate/daemon.rs vm_marker).
  it.each([
    ["root's plain file in root's folder", {}, "linux", true],
    ["on macOS", {}, "darwin", false],
    ["on Windows", {}, "win32", false],
    ["the agent's own file", { file: { uid: 1000 } }, "linux", false],
    ["a file others can write", { file: { mode: 0o100666 } }, "linux", false],
    ["a file with a second link", { file: { nlink: 2 } }, "linux", false],
    ["not a file", { file: { isFile: () => false } }, "linux", false],
    ["a folder that is the agent's", { dir: { uid: 1000 } }, "linux", false],
    ["a folder others can write", { dir: { mode: 0o040777 } }, "linux", false],
  ] as const)("%s: holds %s", (_name, over, system, holds) => {
    const st = fakeStat(over as { file?: Partial<St>; dir?: Partial<St> });
    expect(vmMarker(VM_MARKER, system, st) === undefined).toBe(holds);
  });

  it("holds only for root's plain file in root's folder on Linux", () => {
    expect(vmMarker(VM_MARKER, "linux", fakeStat({}))).toBeUndefined();
    expect(vmMarker(VM_MARKER, "darwin", fakeStat({}))).toBeDefined();
    expect(vmMarker(VM_MARKER, "linux", fakeStat({ file: { uid: 1000 } }))).toBeDefined();
    expect(
      vmMarker(VM_MARKER, "linux", () => {
        throw new Error("ENOENT");
      }),
    ).toMatch(/no VM marker/);
  });
});

describe("the emitter's VM route", () => {
  it("is taken in derm's VM", () => {
    expect(vmLogs(ENV, holds, 1000, none)).toBe(true);
    expect(logsUrl(ENDPOINT, true)).toEqual({ url: `${ENDPOINT}/v1/logs` });
  });

  it.each([
    ["no marker", ENV, (): string | undefined => "no VM marker", 1000, none],
    ["another boundary", { ...ENV, DERM_BOUNDARY: "srt" }, holds, 1000, none],
    ["no boundary named", { DERM_OTLP_ENDPOINT: ENDPOINT }, holds, 1000, none],
    ["root", ENV, holds, 0, none],
    ["a daemon socket on this machine", ENV, holds, 1000, () => [process.execPath]],
    ["another host", { ...ENV, DERM_OTLP_ENDPOINT: "http://evil.example:46659" }, holds, 1000, none],
    ["https", { ...ENV, DERM_OTLP_ENDPOINT: "https://host.docker.internal:46659" }, holds, 1000, none],
    ["no port", { ...ENV, DERM_OTLP_ENDPOINT: "http://host.docker.internal" }, holds, 1000, none],
    ["a path", { ...ENV, DERM_OTLP_ENDPOINT: `${ENDPOINT}/x` }, holds, 1000, none],
    ["a user", { ...ENV, DERM_OTLP_ENDPOINT: "http://u@host.docker.internal:46659" }, holds, 1000, none],
    ["a query", { ...ENV, DERM_OTLP_ENDPOINT: `${ENDPOINT}?a=1` }, holds, 1000, none],
    ["no endpoint", { DERM_BOUNDARY: "sbx" }, holds, 1000, none],
  ] as const)("is not taken with %s", (_name, env, marker, uid, candidates) => {
    expect(vmLogs(env as NodeJS.ProcessEnv, marker, uid, candidates as () => string[])).toBe(false);
  });

  it("outside the VM the host name is refused as before, and loopback is unchanged", () => {
    expect(logsUrl(ENDPOINT)).toEqual({ refused: "endpoint is not loopback" });
    expect(logsUrl(ENDPOINT, false)).toEqual({ refused: "endpoint is not loopback" });
    expect(logsUrl("http://127.0.0.1:4318", false)).toEqual({ url: "http://127.0.0.1:4318/v1/logs" });
    // The VM's yes is for that one host over http, nothing wider.
    expect(logsUrl("http://evil.example:46659", true)).toEqual({ refused: "endpoint is not loopback" });
    expect(logsUrl("https://host.docker.internal:46659", true)).toEqual({ refused: "endpoint is not loopback" });
    expect(logsUrl("http://127.0.0.1:4318", true)).toEqual({ url: "http://127.0.0.1:4318/v1/logs" });
  });
});
