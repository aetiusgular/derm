// Fix pass 6 (integration w6; note BE section 1.5, option (e), Tony's call of
// 15 Nov 2026): `derm run claude-code` registers derm's own gate in its last
// `--settings` block, by derm's absolute path, in exec form with
// `onFailure: "block"`, and turns derm's plugin off for the chat. Run against
// the real Claude Code and the real daemon, with the fake Messages server:
//
//   run-claude-gate-settings      no plugin installed: the denied Bash call
//                                 never runs, Claude Code sees derm's reason,
//                                 and the daemon holds one approval record
//                                 for it; the OTel export still reaches the
//                                 daemon (the helper rides in the same block)
//   run-claude-gate-plugin-off    derm's plugin installed at user scope from
//                                 this repository: still one approval record
//                                 per call, so the plugin did not gate too
//
//   cargo build --release -p derm-cli -p derm-daemon
//   DERM_BIN=target/release/derm node tests/cli-contract/run.mjs --claude /tmp/cli/node_modules/.bin/claude \
//     --only run-claude-gate-settings,run-claude-gate-plugin-off
//
// Linux and macOS (the daemon's socket); Windows runs the same block by the
// Windows test. Everything under a fresh folder (HOME, XDG_RUNTIME_DIR,
// XDG_DATA_HOME), removed at the end.

import { spawn, spawnSync } from "node:child_process";
import { cpSync, existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { startFakeMessages, textBlock, toolUse } from "../../lib/fakeMessages.mjs";
import { dermBin } from "../../lib/dermBin.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(HERE, "..", "..", "..", "..");
const PLUGIN = path.join(ROOT, "packages", "derm-claude-plugin");
const DERM = dermBin() ? realpathSync(dermBin()) : undefined;
const DAEMON = DERM ? path.join(path.dirname(DERM), "derm-daemon") : undefined;
const DUMMY_KEY = "sk-ant-api03-contract-test-dummy-key-not-real";
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function needs() {
  if (!DERM) return "no derm binary (DERM_BIN, target/release, target/debug)";
  if (!existsSync(DAEMON)) return `no derm-daemon beside ${DERM}`;
  if (process.platform === "win32") return "the daemon's socket is Unix here; the Windows test runs this on the box";
  return null;
}

function box(name) {
  const base = process.env.CLI_CONTRACT_TMP ?? (existsSync("/var/tmp") ? "/var/tmp" : tmpdir());
  const root = mkdtempSync(path.join(base, `rg6-${name}-`));
  const d = { root, home: path.join(root, "home"), work: path.join(root, "home", "work"), run: path.join(root, "run"), data: path.join(root, "data"), bin: path.join(root, "bin") };
  for (const x of [d.home, d.work, d.run, d.data, d.bin, path.join(d.home, ".derm"), path.join(d.home, ".local", "bin")]) mkdirSync(x, { recursive: true, mode: 0o700 });
  writeFileSync(path.join(d.home, ".derm", "policy.json"), JSON.stringify({ version: 1, rules: [{ tool: "bash", action: "deny" }] }), { mode: 0o600 });
  return d;
}

function run(bin, args, { env, cwd, seconds = 150 }) {
  return new Promise((resolve) => {
    const ch = spawn(bin, args, { env, cwd, stdio: ["ignore", "pipe", "pipe"], detached: true });
    let out = "";
    let err = "";
    ch.stdout.on("data", (x) => (out += x));
    ch.stderr.on("data", (x) => (err += x));
    const t = setTimeout(() => {
      try {
        process.kill(-ch.pid, "SIGKILL");
      } catch {}
    }, seconds * 1000);
    ch.on("close", (code) => {
      clearTimeout(t);
      resolve({ code, out, err });
    });
  });
}

async function turn(claudePath, { plugin }) {
  const d = box(plugin ? "plugin" : "settings");
  const env = {
    PATH: [d.bin, path.dirname(process.execPath), "/usr/local/bin", "/usr/bin", "/bin"].join(":"),
    HOME: d.home,
    XDG_RUNTIME_DIR: d.run,
    XDG_DATA_HOME: d.data,
    LANG: "C.UTF-8",
    NO_COLOR: "1",
    DISABLE_AUTOUPDATER: "1",
    DISABLE_TELEMETRY: "1",
    CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC: "1",
  };
  spawnSync("ln", ["-s", claudePath, path.join(d.bin, "claude")]);
  // The plugin's launcher runs derm from ~/.local/bin.
  cpSync(DERM, path.join(d.home, ".local", "bin", "derm"));
  let installed = null;
  if (plugin) {
    const add = spawnSync(claudePath, ["plugin", "marketplace", "add", ROOT], { env, cwd: d.work, encoding: "utf8", timeout: 120000 });
    const inst = spawnSync(claudePath, ["plugin", "install", "derm@derm", "--scope", "user"], { env, cwd: d.work, encoding: "utf8", timeout: 120000 });
    installed = `${add.status}/${inst.status}: ${(add.stderr + inst.stdout + inst.stderr).trim().slice(-200)}`;
  }
  const daemon = spawn(DAEMON, ["--foreground"], { env, stdio: ["ignore", "ignore", "pipe"] });
  const outside = path.join(d.work, "made-by-bash.txt");
  const fake = await startFakeMessages({
    script: (b) =>
      JSON.stringify(b.messages ?? []).includes("tool_result")
        ? [textBlock("done")]
        : [toolUse("Bash", { command: `echo x > ${outside}`, description: "write" }, "toolu_rg6")],
  });
  let r;
  try {
    for (let i = 0; i < 100 && !existsSync(path.join(d.run, "derm", "otlp.endpoint")); i++) await sleep(100);
    r = await run(
      DERM,
      ["run", "claude-code", "--boundary", "none", "--no-tap", "--", "-p", "go", "--model", "claude-sonnet-4-5", "--output-format", "json"],
      { env: { ...env, ANTHROPIC_BASE_URL: fake.baseUrl, ANTHROPIC_API_KEY: DUMMY_KEY }, cwd: d.work },
    );
    await sleep(6000); // Claude Code exports its logs every few seconds.
  } finally {
    await fake.close();
    daemon.kill("SIGTERM");
  }
  const results = [];
  for (const q of fake.requests) {
    for (const m of q.body?.messages ?? []) {
      for (const c of Array.isArray(m.content) ? m.content : []) {
        if (c?.type === "tool_result" && c.tool_use_id === "toolu_rg6") results.push(typeof c.content === "string" ? c.content : JSON.stringify(c.content));
      }
    }
  }
  // The daemon's log: under XDG_DATA_HOME on Linux, under the home's
  // Application Support on macOS, where it does not read that variable (the
  // Mac run after eval pass 1's fixes: both checks failed with "approval
  // records: []" while the deny itself held, because only the first was read).
  const logDir = [path.join(d.data, "derm", "activity"), path.join(d.home, "Library", "Application Support", "derm", "activity")].find((p) => existsSync(p));
  const lines = logDir
    ? readdirSync(logDir)
        .flatMap((f) => readFileSync(path.join(logDir, f), "utf8").split("\n"))
        .filter(Boolean)
        .map((l) => {
          try {
            return JSON.parse(l);
          } catch {
            return null;
          }
        })
        .filter(Boolean)
        .map((l) => l.event ?? l)
    : [];
  const approvals = lines.filter((e) => e.kind === "approval" && e.detail?.toolUseId === "toolu_rg6");
  const otel = lines.filter((e) => e.source === "otel").length;
  const out = {
    exit: r.code,
    ran: existsSync(outside),
    result: results.join(" | ").slice(0, 300),
    approvals: approvals.map((a) => a.detail?.decision),
    otel,
    installed,
    note: (r.err.split("\n").find((l) => /plugin is off/.test(l)) ?? "").slice(0, 160),
    stderrTail: r.err.slice(-400),
  };
  if (!process.env.KEEP_RG6) rmSync(d.root, { recursive: true, force: true });
  return out;
}

function verdict(t, { plugin }) {
  const ok = !t.ran && /derm/.test(t.result) && t.approvals.length === 1 && t.approvals[0] === "deny" && t.otel > 0 && t.note !== "" && (!plugin || /^0\/0/.test(t.installed ?? ""));
  return {
    status: ok ? "pass" : "fail",
    finding: `exit ${t.exit}; the Bash call ran: ${t.ran}; its result: ${t.result}; approval records: ${JSON.stringify(t.approvals)}; otel records: ${t.otel}; plugin: ${t.installed ?? "none"}; start line: ${t.note || "(none)"}${ok ? "" : `; stderr: ${t.stderrTail}`}`,
  };
}

export const checks = [
  {
    id: "run-claude-gate-settings",
    title: "fix pass 6: derm run claude-code gates through its own --settings block, by derm's absolute path, with no plugin installed; one approval record; OTel still reaches the daemon",
    harness: "claude",
    async run({ claudePath }) {
      const n = needs();
      if (n) return { status: "skip", finding: n };
      return verdict(await turn(claudePath, { plugin: false }), { plugin: false });
    },
  },
  {
    id: "run-claude-gate-plugin-off",
    title: "fix pass 6: with derm's plugin installed at user scope, derm run turns it off for the chat, so a call is gated once",
    harness: "claude",
    async run({ claudePath }) {
      const n = needs();
      if (n) return { status: "skip", finding: n };
      return verdict(await turn(claudePath, { plugin: true }), { plugin: true });
    },
  },
];
