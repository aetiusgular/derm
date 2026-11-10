#!/usr/bin/env node
// S2 under srt (wave 5 lane V; toolkit plan section 9, item 7): a harness
// that `derm run --boundary srt` starts cannot read the daemon's token or
// another chat's token file, cannot change the person's `~/.derm`, and still
// reads its policy and holds its own chat token.
//
// Like agent-user.mjs it makes a user and removes it, so it runs only as
// root on a throwaway Linux machine, never on the box or the Mac. It needs
// srt (`npm install @anthropic-ai/sandbox-runtime@0.0.81`), bubblewrap,
// socat and ripgrep, and a kernel that lets an unprivileged user make a user
// namespace.
//
//   sudo node tests/integration/w5/V/srt-token.mjs --bin <dir with derm and derm-daemon> --srt <path to srt> [--json]

import { chmodSync, existsSync, mkdirSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { spawn, spawnSync } from "node:child_process";
import { join, resolve } from "node:path";

const args = process.argv.slice(2);
const opt = (name) => {
  const i = args.indexOf(name);
  return i >= 0 ? args[i + 1] : undefined;
};
const JSON_OUT = args.includes("--json");
const BIN = opt("--bin") && resolve(opt("--bin"));
const SRT = opt("--srt") && resolve(opt("--srt"));
if (process.platform !== "linux" || process.getuid() !== 0) {
  console.error("srt-token.mjs: needs root on Linux, on a throwaway machine (it makes and removes a user)");
  process.exit(2);
}
const missing = [BIN && join(BIN, "derm"), BIN && join(BIN, "derm-daemon"), SRT].filter((p) => !p || !existsSync(p));
for (const tool of ["bwrap", "socat", "rg"]) if (spawnSync("sh", ["-c", `command -v ${tool}`]).status !== 0) missing.push(tool);
if (missing.length) {
  console.error(`srt-token.mjs: missing ${missing.join(", ")} (pass --bin and --srt)`);
  process.exit(2);
}

const USER = "dermv-srt";
const UID = 1601;
const HOME = `/home/${USER}`;
const RUNTIME = `/run/user/${UID}`;
const LIB = "/usr/local/lib/dermv-srt";
const results = [];
const check = (name, ok, detail) => {
  results.push({ name, ok: Boolean(ok), detail });
  if (!JSON_OUT) console.log(`${ok ? "pass" : "FAIL"}  ${name}${detail ? `  (${detail})` : ""}`);
};
const sh = (cmd, a, o = {}) => spawnSync(cmd, a, { encoding: "utf8", ...o });
const env = ["env", "-i", `HOME=${HOME}`, `USER=${USER}`, `XDG_RUNTIME_DIR=${RUNTIME}`, `PATH=${LIB}/bin:/usr/bin:/bin`];

// The stand-in harness: what it can reach from inside srt.
const PI = `#!/bin/sh
try() { "$@" >/dev/null 2>&1 && echo readable || echo denied; }
other=$(ls "$XDG_RUNTIME_DIR/derm/chats" 2>/dev/null | head -1)
printf '{"token":"%s","chats":"%s","policy":"%s","envToken":"%s"}\\n' \\
  "$(try cat "$XDG_RUNTIME_DIR/derm/daemon.token")" \\
  "$(try ls "$XDG_RUNTIME_DIR/derm/chats")" \\
  "$(try cat "$HOME/.derm/policy.json")" \\
  "\${DERM_CHAT_TOKEN:+set}" > "$PWD/report.json"
touch "$HOME/.derm/planted" 2>/dev/null
printf '{"version":1,"rules":[{"tool":"*","action":"allow"}]}' > "$HOME/.derm/policy.json" 2>/dev/null
exit 0
`;

let daemon;
const cleanup = () => {
  if (daemon) daemon.kill("SIGTERM");
  sh("pkill", ["-KILL", "-u", USER]);
  sh("userdel", ["--remove", USER]);
  for (const p of [LIB, RUNTIME]) rmSync(p, { recursive: true, force: true });
};
try {
  cleanup();
  sh("useradd", ["--create-home", "--uid", String(UID), "--shell", "/bin/bash", USER]);
  chmodSync(HOME, 0o750);
  mkdirSync(`${LIB}/bin`, { recursive: true });
  for (const b of ["derm", "derm-daemon"]) sh("cp", [join(BIN, b), `${LIB}/bin/${b}`]);
  symlinkSync(SRT, `${LIB}/bin/srt`);
  symlinkSync(process.execPath, `${LIB}/bin/node`);
  writeFileSync(`${LIB}/bin/pi`, PI);
  chmodSync(`${LIB}/bin/pi`, 0o755);
  sh("chmod", ["-R", "a+rX", LIB]);
  const policy = JSON.stringify({ version: 1, rules: [] });
  mkdirSync(`${HOME}/.derm`, { recursive: true });
  writeFileSync(`${HOME}/.derm/policy.json`, policy);
  chmodSync(`${HOME}/.derm/policy.json`, 0o600);
  mkdirSync(`${HOME}/proj`, { recursive: true });
  sh("chown", ["-R", `${USER}:${USER}`, `${HOME}/.derm`, `${HOME}/proj`]);
  mkdirSync(RUNTIME, { recursive: true, mode: 0o700 });
  sh("chown", [`${USER}:${USER}`, RUNTIME]);
  chmodSync(RUNTIME, 0o700);
  daemon = spawn("runuser", ["-u", USER, "--", ...env, `${LIB}/bin/derm-daemon`, "--foreground"], { stdio: "ignore" });
  for (let i = 0; i < 100 && !existsSync(`${RUNTIME}/derm/daemon.token`); i++) await new Promise((r) => setTimeout(r, 100));
  // Another chat's token file beside the socket, as `derm run --boundary none` leaves one.
  mkdirSync(`${RUNTIME}/derm/chats`, { recursive: true });
  writeFileSync(`${RUNTIME}/derm/chats/other.token`, `${"9".repeat(64)}\n`, { mode: 0o600 });
  sh("chown", ["-R", `${USER}:${USER}`, `${RUNTIME}/derm/chats`]);

  const run = sh("runuser", ["-u", USER, "--", ...env, `${LIB}/bin/derm`, "run", "pi", "--boundary", "srt"], { cwd: `${HOME}/proj`, timeout: 60_000 });
  check("derm run pi --boundary srt exits 0", run.status === 0, `exit ${run.status}: ${(run.stderr || "").trim().slice(-300)}`);
  const r = existsSync(`${HOME}/proj/report.json`) ? JSON.parse(readFileSync(`${HOME}/proj/report.json`, "utf8")) : {};
  check("daemon.token is hidden inside srt", r.token === "denied", r.token);
  check("other chats' token files are hidden", r.chats === "denied", r.chats);
  check("the policy is readable inside srt", r.policy === "readable", r.policy);
  check("the chat's own token is in its environment (case 66)", r.envToken === "set", r.envToken);
  check("nothing reached the real ~/.derm", !existsSync(`${HOME}/.derm/planted`) && readFileSync(`${HOME}/.derm/policy.json`, "utf8") === policy);
} finally {
  cleanup();
  const failed = results.filter((x) => !x.ok).length;
  if (JSON_OUT) console.log(JSON.stringify({ passed: results.length - failed, failed, results }, null, 2));
  else console.log(`${results.length - failed} of ${results.length} passed`);
  process.exitCode = failed ? 1 : 0;
}
