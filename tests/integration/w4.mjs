#!/usr/bin/env node
// Every harness `derm run` starts, against lane B's real daemon (fix pass 1
// for the Mac test w4, MW4-6). `derm run`'s own tests use a fake daemon that
// accepts any harness id, so the real daemon's refusal of 9 of the 21
// agents, and of an unknown program (case 80), showed only on the Mac.
//
// For each preset row that names a command (`crates/derm-cli/src/connect/
// presets/<id>.json`, `cli`), a stand-in of that name prints the variables
// derm gives it and exits; `derm run <id> --boundary none -- --version` must
// start it with a chat token, and the daemon must hold that chat's
// `run.start` under the row's id. Then the same for a program no row names.
// Nothing here runs a real agent or reaches the network.
//
//   node tests/integration/w4.mjs [--bin target/release] [--json]
//
// Needs Node 22.18 or later. Everything runs under a fresh temp folder
// (HOME, XDG_RUNTIME_DIR, XDG_DATA_HOME), removed at the end.

import { spawn } from "node:child_process";
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import net from "node:net";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");
const args = process.argv.slice(2);
const opt = (name, dflt) => {
  const i = args.indexOf(name);
  return i >= 0 && args[i + 1] ? args[i + 1] : dflt;
};
const BIN = resolve(ROOT, opt("--bin", "target/release"));
const JSON_OUT = args.includes("--json");
const DERM = join(BIN, "derm");
const DAEMON = join(BIN, "derm-daemon");
for (const b of [DERM, DAEMON]) {
  if (!existsSync(b)) {
    console.error(`missing ${b}: run cargo build --release first, or pass --bin`);
    process.exit(2);
  }
}

const results = [];
function check(name, ok, detail) {
  results.push({ name, ok: Boolean(ok), detail });
  if (!JSON_OUT) console.log(`${ok ? "pass" : "FAIL"}  ${name}${detail ? `  (${detail})` : ""}`);
}
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

const top = mkdtempSync(join(tmpdir(), "derm-int-w4-"));
const HOME = join(top, "home");
const RUN = join(top, "run");
const DATA = join(top, "data");
const WORK = join(HOME, "work");
const FAKEBIN = join(top, "bin");
for (const d of [HOME, RUN, DATA, WORK, FAKEBIN]) mkdirSync(d, { recursive: true, mode: 0o700 });
chmodSync(RUN, 0o700);
const SOCK = join(RUN, "derm", "daemon.sock");
// The stand-ins first; the system folders after them, for `env` and `node`.
const PATH = [FAKEBIN, dirname(process.execPath), "/usr/local/bin", "/usr/bin", "/bin"].join(":");
const baseEnv = { PATH, HOME, XDG_RUNTIME_DIR: RUN, XDG_DATA_HOME: DATA, LANG: "C.UTF-8" };

// ------------------------------------------------------------ the rows

const presetDir = join(ROOT, "crates/derm-cli/src/connect/presets");
const index = JSON.parse(readFileSync(join(presetDir, "index.json"), "utf8"));
const rows = [...index.harnesses, ...index.planned].map((id) => JSON.parse(readFileSync(join(presetDir, `${id}.json`), "utf8")));
// Rows `derm run` does not start, by their own words in run/harness.rs
// (NOT_RUN): Zed's command opens the editor; Codebuff and Continue have no
// gate and run as unknown programs.
const NOT_RUN = new Set(["zed", "codebuff", "continue"]);
const runnable = rows.filter((r) => typeof r.cli === "string" && r.cli !== "TODO" && !NOT_RUN.has(r.id));

const standIn = (name) => {
  const p = join(FAKEBIN, name);
  writeFileSync(p, `#!/bin/sh\necho "STANDIN ${name} DERM_HARNESS=$DERM_HARNESS TOKEN=\${DERM_CHAT_TOKEN:+set}"\nexit 0\n`);
  chmodSync(p, 0o755);
};
for (const r of runnable) standIn(r.cli);
standIn("derm-w4-unknown-agent");
// Cline's gate needs lane P's responder beside it (derm run, Launch::Cline):
// a stand-in that waits until derm run stops it.
{
  const p = join(FAKEBIN, "derm-cline-responder");
  writeFileSync(p, "#!/usr/bin/env node\nsetTimeout(() => {}, 60000);\n");
  chmodSync(p, 0o755);
}

// ------------------------------------------------------------ daemon

const daemon = spawn(DAEMON, ["--foreground"], { env: baseEnv, stdio: ["ignore", "ignore", "pipe"] });
let daemonErr = "";
daemon.stderr.on("data", (d) => (daemonErr += d));
function cleanup() {
  try {
    daemon.kill("SIGTERM");
  } catch {}
  rmSync(top, { recursive: true, force: true });
}

// A daemon-scope tail that keeps every event it is sent.
function openTail(token, events) {
  return new Promise((resolveTail, rejectTail) => {
    const sock = net.createConnection({ path: SOCK });
    let buf = "";
    let replies = 0;
    sock.on("data", (c) => {
      buf += c;
      let i;
      while ((i = buf.indexOf("\n")) >= 0) {
        const line = buf.slice(0, i);
        buf = buf.slice(i + 1);
        if (!line.trim()) continue;
        const msg = JSON.parse(line);
        if (msg.event) {
          events.push(msg.event);
          continue;
        }
        replies += 1;
        if (replies === 2) resolveTail({ ok: msg.ok === true, close: () => sock.destroy() });
      }
    });
    sock.on("error", rejectTail);
    sock.on("connect", () => {
      sock.write(`${JSON.stringify({ op: "hello", token, client: "w4 tail" })}\n`);
      sock.write(`${JSON.stringify({ op: "tail" })}\n`);
    });
  });
}

function runDerm(argv) {
  return new Promise((resolveRun) => {
    const child = spawn(DERM, ["run", ...argv], { env: baseEnv, cwd: WORK, stdio: ["ignore", "pipe", "pipe"] });
    let out = "";
    let err = "";
    child.stdout.on("data", (d) => (out += d));
    child.stderr.on("data", (d) => (err += d));
    const timer = setTimeout(() => child.kill("SIGKILL"), 60_000);
    child.on("close", (code) => {
      clearTimeout(timer);
      resolveRun({ code, out, err });
    });
  });
}

let failed = false;
try {
  const deadline = Date.now() + 10_000;
  while (!existsSync(SOCK) && Date.now() < deadline) await sleep(50);
  check("daemon started", existsSync(SOCK), daemonErr.trim().slice(0, 200));
  const tokenFile = join(dirname(SOCK), "daemon.token");
  while (!existsSync(tokenFile) && Date.now() < deadline) await sleep(50);
  const daemonToken = readFileSync(tokenFile, "utf8").trim();
  const events = [];
  const tail = await openTail(daemonToken, events);
  check("daemon-scope tail opens", tail.ok);

  const cases = runnable.map((r) => ({ id: r.id, argv: [r.id, "--boundary", "none", "--chat", `w4-${r.id}`, "--", "--version"], chat: `w4-${r.id}` }));
  cases.push({ id: "other", argv: ["--boundary", "none", "--chat", "w4-other", "--", "derm-w4-unknown-agent", "--version"], chat: "w4-other" });
  for (const c of cases) {
    const r = await runDerm(c.argv);
    const started = r.code === 0 && r.out.includes(`DERM_HARNESS=${c.id} TOKEN=set`);
    check(`derm run starts ${c.id} with a chat token`, started, started ? "" : `exit ${r.code}: ${(r.err || r.out).trim().split("\n").slice(-2).join(" | ").slice(0, 240)}`);
  }
  // What the daemon recorded: each chat's run.start under its row's id.
  await sleep(500);
  tail.close();
  const starts = new Map(events.filter((e) => e.kind === "run.start").map((e) => [e.chatId ?? e.chat_id, e.harness]));
  for (const c of cases) {
    const h = starts.get(c.chat);
    check(`the daemon holds ${c.chat}'s run.start under ${c.id}`, h === c.id, h === undefined ? "no run.start" : `harness ${h}`);
  }
  // Nothing else is minted for: an id the table does not have is refused.
  const bad = await runDerm(["no-such-agent", "--boundary", "none", "--", "--version"]);
  check("an id no row names is refused before anything starts", bad.code !== 0 && !bad.out.includes("STANDIN"), `exit ${bad.code}`);
} catch (e) {
  check("ran to the end", false, String(e?.stack ?? e).slice(0, 300));
} finally {
  cleanup();
}
failed = results.some((r) => !r.ok);
if (JSON_OUT) console.log(JSON.stringify({ results }, null, 1));
else console.log(`${results.filter((r) => r.ok).length} of ${results.length} passed`);
process.exit(failed ? 1 : 0);
