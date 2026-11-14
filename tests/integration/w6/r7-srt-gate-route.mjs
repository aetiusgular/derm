#!/usr/bin/env node
// R7 (case 270), Tony's option 1 of 14 Nov 2026, end to end on Linux with the
// real daemon and the real srt: a gate inside derm's srt chat sends its
// records to the daemon's HTTP port through srt's own proxy (srt refuses
// every `socket(AF_UNIX)` there), never to srt's tmpfs over `~/.derm`, and a
// record it cannot post denies the call.
//
// Each case runs `derm hook claude-code pre` inside `derm run --boundary srt`
// on a Claude Code PreToolUse input for an allowed Bash call:
//   route     the record reaches the daemon; nothing is left in a light log;
//             the route file is gone after the chat
//   token     a token the daemon does not know: denied
//   chat      another DERM_CHAT_ID (no route file of that name): denied
//   proxy     a proxy at another port than srt's: denied
//   planted   the route folder moved away and a file of the agent's own put
//             in its place on srt's tmpfs: denied
//   symlink   the route folder replaced by a link to a folder of the chat's
//             (another device), a file there naming a listener the agent
//             runs in the sandbox as proxy and daemon: denied, and nothing
//             reaches the listener (fix pass 2's review, FP2-R1)
//
//   node tests/integration/w6/r7-srt-gate-route.mjs --bin target/debug --srt /tmp/cli/node_modules/.bin/srt
//
// Needs srt 0.0.82 with bubblewrap, socat and ripgrep in /usr/bin, and Node
// 22.18 or later. Everything runs under a fresh folder in /var/tmp (HOME,
// XDG_RUNTIME_DIR, XDG_DATA_HOME), removed at the end. Run on 14 Nov 2026 by
// integration w6's fix pass 2 as root and as a plain user: every case; with the
// build at `aad4e65` the first case allows the call and the daemon gets no
// record (the light log went into srt's tmpfs), and every other case allows.

import { spawn } from "node:child_process";
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..", "..");
const args = process.argv.slice(2);
const opt = (name, dflt) => {
  const i = args.indexOf(name);
  return i >= 0 && args[i + 1] ? args[i + 1] : dflt;
};
const BIN = resolve(ROOT, opt("--bin", "target/release"));
const SRT = opt("--srt", "/tmp/cli/node_modules/.bin/srt");
const DERM = join(BIN, "derm");
const DAEMON = join(BIN, "derm-daemon");
const missing = [DERM, DAEMON, SRT, "/usr/bin/bwrap", "/usr/bin/socat", "/usr/bin/rg"].filter((b) => !existsSync(b));
if (process.platform !== "linux" || missing.length) {
  console.log(`skip: ${process.platform !== "linux" ? "Linux only" : `missing ${missing.join(", ")}`}`);
  process.exit(0);
}

const results = [];
const check = (name, ok, detail) => {
  results.push({ name, ok: Boolean(ok) });
  console.log(`${ok ? "pass" : "FAIL"}  ${name}${detail ? `  (${detail})` : ""}`);
};
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// Not under /tmp: srt lets a chat write /tmp, so a HOME there would not show
// the boundary.
const top = mkdtempSync(join(existsSync("/var/tmp") ? "/var/tmp" : "/tmp", "derm-int-r7-"));
const HOME = join(top, "home");
const RUN = join(top, "run");
const DATA = join(top, "data");
const WORK = join(HOME, "work");
const TOOLS = join(top, "bin");
for (const d of [HOME, RUN, DATA, WORK, TOOLS, join(HOME, ".derm")]) mkdirSync(d, { recursive: true, mode: 0o700 });
chmodSync(RUN, 0o700);
for (const [name, target] of [["derm", DERM], ["srt", SRT]]) {
  writeFileSync(join(TOOLS, name), `#!/bin/sh\nexec '${target}' "$@"\n`);
  chmodSync(join(TOOLS, name), 0o755);
}
const PATH = [TOOLS, dirname(process.execPath), "/usr/local/bin", "/usr/bin", "/bin"].join(":");
const env = { PATH, HOME, XDG_RUNTIME_DIR: RUN, XDG_DATA_HOME: DATA, LANG: "C.UTF-8" };
writeFileSync(join(HOME, ".derm", "policy.json"), JSON.stringify({ version: 1, rules: [{ tool: "bash", action: "allow" }] }));
chmodSync(join(HOME, ".derm", "policy.json"), 0o600);

// A listener the agent could run in the sandbox: it answers a CONNECT and
// then any request with ok, and notes that it heard one.
const listener = join(top, "listener.mjs");
writeFileSync(
  listener,
  `import net from "node:net";
import { appendFileSync } from "node:fs";
const out = process.argv[2];
const srv = net.createServer((c) => {
  let buf = "", tunneled = false;
  c.on("data", (d) => {
    buf += d.toString("latin1");
    if (!tunneled && buf.includes("\\r\\n\\r\\n")) { appendFileSync(out, "connect\\n"); buf = buf.split("\\r\\n\\r\\n").slice(1).join("\\r\\n\\r\\n"); tunneled = true; c.write("HTTP/1.1 200 OK\\r\\n\\r\\n"); }
    if (tunneled && buf.includes("\\r\\n\\r\\n")) { appendFileSync(out, "request\\n"); const b = '{"ok":true}'; c.end("HTTP/1.1 200 OK\\r\\nContent-Type: application/json\\r\\nContent-Length: " + b.length + "\\r\\n\\r\\n" + b); }
  });
});
srv.listen(4444, "127.0.0.1");
setTimeout(() => process.exit(0), 8000);
`,
);

// The probe the chat runs: one hook call per case, its answer on a line.
const probe = join(top, "probe.sh");
writeFileSync(
  probe,
  `#!/bin/bash
input() { printf '{"session_id":"s","transcript_path":"/x","cwd":"%s","hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"echo hi"},"tool_use_id":"%s"}' "$PWD" "$1"; }
hook() { local id=$1; shift; echo "CASE $id $(input "$id" | env "$@" derm hook claude-code pre | tr -d '\\n')"; }
hook toolu_r7_route A=1
hook toolu_r7_token DERM_CHAT_TOKEN=${"0".repeat(64)}
hook toolu_r7_chat DERM_CHAT_ID=derm-000000000000
hook toolu_r7_proxy HTTPS_PROXY=http://localhost:4444 HTTP_PROXY=http://localhost:4444 ALL_PROXY= https_proxy= http_proxy= all_proxy=
r="$HOME/.derm/run/routes"
mv "$r" "$HOME/.derm/run/moved" && mkdir -p "$r" && printf '{"daemonPort":1,"proxyPort":3128}' > "$r/$DERM_CHAT_ID.json" && chmod 600 "$r/$DERM_CHAT_ID.json"
hook toolu_r7_planted A=1
rm -rf "$r"; mkdir -p "$PWD/elsewhere" && ln -s "$PWD/elsewhere" "$r"
printf '{"daemonPort":7777,"proxyPort":4444}' > "$PWD/elsewhere/$DERM_CHAT_ID.json" && chmod 600 "$PWD/elsewhere/$DERM_CHAT_ID.json"
node "${listener}" "$PWD/heard" & sleep 0.7
hook toolu_r7_symlink HTTPS_PROXY=http://127.0.0.1:4444 HTTP_PROXY= ALL_PROXY= https_proxy= http_proxy= all_proxy=
echo "HEARD $(test -s "$PWD/heard" && echo yes || echo no)"
echo "LIGHT $(ls "$HOME/.derm/local" 2>/dev/null | wc -l)"
`,
);
chmodSync(probe, 0o755);

const daemon = spawn(DAEMON, ["--foreground"], { env, stdio: ["ignore", "ignore", "pipe"] });
let daemonErr = "";
daemon.stderr.on("data", (d) => (daemonErr += d));
const cleanup = () => {
  try {
    daemon.kill("SIGTERM");
  } catch {}
  rmSync(top, { recursive: true, force: true });
};

try {
  for (let i = 0; i < 100 && !existsSync(join(RUN, "derm", "otlp.endpoint")); i++) await sleep(100);
  const run = await new Promise((done) => {
    const ch = spawn(DERM, ["run", "--boundary", "srt", "--", probe], { env, cwd: WORK, stdio: ["ignore", "pipe", "pipe"] });
    let out = "";
    let err = "";
    ch.stdout.on("data", (d) => (out += d));
    ch.stderr.on("data", (d) => (err += d));
    ch.on("exit", (code) => done({ code, out, err }));
  });
  const answer = (id) => (run.out.match(new RegExp(`CASE ${id} (.*)`)) ?? [])[1] ?? "";
  const decision = (id) => (answer(id).match(/"permissionDecision":"(\w+)"/) ?? [])[1] ?? "none";
  await sleep(500);
  const logs = readdirSync(join(DATA, "derm", "activity")).map((f) => readFileSync(join(DATA, "derm", "activity", f), "utf8")).join("");
  const kept = (id) => logs.includes(`"toolUseId":"${id}"`);
  check("the route note is on the start line", /sends its records to the daemon's port through srt's proxy/.test(run.err), run.err.split("\n").find((l) => /srt/.test(l))?.slice(0, 120));
  check("route: the record reaches the daemon, the call runs", decision("toolu_r7_route") === "allow" && kept("toolu_r7_route"), `${decision("toolu_r7_route")}, kept ${kept("toolu_r7_route")}`);
  for (const id of ["token", "chat", "proxy", "planted", "symlink"]) {
    const d = decision(`toolu_r7_${id}`);
    check(`${id}: a record not posted denies the call`, d === "deny", `${d}: ${answer(`toolu_r7_${id}`).slice(0, 160)}`);
  }
  check("symlink: nothing reached the agent's listener", /HEARD no/.test(run.out), (run.out.match(/HEARD \w+/) ?? [])[0]);
  const light = Number((run.out.match(/LIGHT (\d+)/) ?? [])[1] ?? -1);
  check("no light log in the sandbox", light === 0, `${light}`);
  check("no light log on the host", !existsSync(join(HOME, ".derm", "local")) || readdirSync(join(HOME, ".derm", "local")).length === 0);
  const routes = join(HOME, ".derm", "run", "routes");
  check("the route file is gone after the chat", !existsSync(routes) || readdirSync(routes).length === 0);
} finally {
  cleanup();
}
const failed = results.filter((r) => !r.ok).length;
console.log(`${results.length - failed} of ${results.length} passed`);
if (daemonErr.trim() && failed) console.error(daemonErr.slice(-1500));
process.exit(failed ? 1 : 0);
