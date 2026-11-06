// Lane U (wave 5): the one computer_use tool, end to end, with a real CLI.
//
// A real derm-daemon (a debug build: only a debug build takes
// DERM_CUA_DRIVER) runs in a throwaway home with computerUse.on in
// ~/.derm/settings.json. Computer use runs on Linux through the daemon's
// own runtime (crates/derm-daemon/src/computer_use/direct.rs), with a
// stand-in for `cua-driver mcp --direct` at cua-driver-rs 0.38.0 (the real
// driver was not run in the cloud; the lane's status doc). A program named
// `calc` (a copy of `sleep`) runs as the app. The real CLI starts derm's
// relay (`derm-daemon cu-mcp`) as an MCP server with a chat token the
// daemon minted; the fake model asks for capture(app="calc"), then a click,
// then stops. A test approver on the daemon's socket answers the card yes.
//
// Pass: the CLI listed one tool, computer_use, with the contract's input
// schema; the card reached the approver once, for exe.calc, under the
// grant tool; the driver started bounded with the program's executable in
// its manifest; the capture's result reached the model with its image; the
// click reached the driver at the element with the capture's token; every
// cu.action record validates against contracts/wave5-records.schema.json
// and holds no image or typed text.
//
//   cargo build -p derm-daemon
//   node tests/cli-contract/run.mjs --claude <path> --only cu-tool-claude
//
// The daemon is DERM_DAEMON_DEBUG, else target/debug/derm-daemon.

import { spawn } from "node:child_process";
import { chmodSync, copyFileSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { Ajv2020 } from "ajv/dist/2020.js";
import { ClaudeSession } from "../../lib/claudeDriver.mjs";
import { makeTempDirs } from "../../lib/codexDriver.mjs";
import { startFakeMessages, textBlock, toolUse } from "../../lib/fakeMessages.mjs";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../../..");
const TOOL = "mcp__derm_cu__computer_use";
const PNG = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg==";
const TYPED = "derm-cu-typed-marker";

const FAKE_DRIVER = `#!/bin/sh
dir="$(dirname "$0")"
log="$dir/driver.log"
say() { printf '%s\\n' "$*" >> "$log"; }
[ "$*" = "mcp --direct" ] || { say "bad args: $*"; exit 64; }
[ "$CUA_DRIVER_PERMISSION_MODE" = bounded ] || { say "not bounded"; exit 65; }
[ "$CUA_DRIVER_CAPABILITY_MANIFEST_APPROVED" = 1 ] || { say "not approved"; exit 65; }
[ -f "$CUA_DRIVER_CAPABILITY_MANIFEST_FILE" ] || { say "no manifest"; exit 65; }
[ -z "$CUA_DRIVER_DANGEROUSLY_BYPASS_APPROVALS" ] || { say bypass; exit 65; }
cp "$CUA_DRIVER_CAPABILITY_MANIFEST_FILE" "$dir/read-manifest.yaml"
say start
while IFS= read -r line; do
  id=$(printf '%s' "$line" | sed -n 's/.*"id":\\([0-9][0-9]*\\).*/\\1/p')
  [ -z "$id" ] && continue
  case "$line" in
    *'"initialize"'*) printf '{"jsonrpc":"2.0","id":%s,"result":{"protocolVersion":"2025-06-18","capabilities":{"tools":{}},"serverInfo":{"name":"fake"}}}\\n' "$id" ;;
    # cua-driver-rs 0.38.0: a listing with no pid is a whole-display
    # observation, which derm's manifest refuses (box test w5, BW5-19); with
    # a pid it lists that process's windows (fix pass 1).
    *'"list_windows"'*)
      pid=$(printf '%s' "$line" | sed -n 's/.*"pid":\\([0-9][0-9]*\\).*/\\1/p')
      if [ -z "$pid" ]; then
        say "refused display"
        printf '{"jsonrpc":"2.0","id":%s,"result":{"isError":true,"content":[{"type":"text","text":"desktop display observation is outside the capability manifest"}]}}\\n' "$id"
      else
        say "call list_windows pid=$pid"
        printf '{"jsonrpc":"2.0","id":%s,"result":{"content":[{"type":"text","text":"1"}],"structuredContent":{"windows":[{"app_name":"calc","pid":%s,"window_id":7,"z_index":1,"title":"calc"}]}}}\\n' "$id" "$pid"
      fi ;;
    *'"get_window_state"'*) say "call get_window_state"; printf '{"jsonrpc":"2.0","id":%s,"result":{"content":[{"type":"text","text":"calc"},{"type":"image","data":"${PNG}","mimeType":"image/png"}],"structuredContent":{"window_title":"calc","elements":[{"element_index":1,"role":"button","label":"seven","frame":{"x":1,"y":1,"w":9,"h":9},"element_token":"s9:1"}]}}}\\n' "$id" ;;
    *'"click"'*) say "call $line"; printf '{"jsonrpc":"2.0","id":%s,"result":{"content":[{"type":"text","text":"clicked"}],"structuredContent":{"effect":"confirmed"}}}\\n' "$id" ;;
    *) say "call other"; printf '{"jsonrpc":"2.0","id":%s,"result":{"content":[{"type":"text","text":"ok"}]}}\\n' "$id" ;;
  esac
done
say eof
`;

function daemonBin() {
  for (const p of [process.env.DERM_DAEMON_DEBUG, path.join(ROOT, "target/debug/derm-daemon")]) {
    if (p && existsSync(p)) return p;
  }
  return null;
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
async function until(fn, ms, step = 50) {
  const end = Date.now() + ms;
  while (Date.now() < end) {
    const v = fn();
    if (v) return v;
    await sleep(step);
  }
  return fn();
}

/** A JSON-lines socket client: replies in order, pushes to `onPush`. */
class Conn {
  constructor(sock, onPush) {
    this.waiters = [];
    this.sock = net.createConnection({ path: sock });
    let buf = "";
    this.sock.on("data", (c) => {
      buf += c;
      let i;
      while ((i = buf.indexOf("\n")) >= 0) {
        const line = buf.slice(0, i);
        buf = buf.slice(i + 1);
        if (!line.trim()) continue;
        const msg = JSON.parse(line);
        if (msg.event || msg.approve) {
          onPush?.(msg, this);
          continue;
        }
        this.waiters.shift()?.(msg);
      }
    });
    this.sock.on("error", () => {});
  }
  ready() {
    return new Promise((r, j) => {
      this.sock.once("connect", r);
      this.sock.once("error", j);
    });
  }
  send(obj) {
    return new Promise((r) => {
      this.waiters.push(r);
      this.sock.write(`${JSON.stringify(obj)}\n`);
    });
  }
  close() {
    this.sock.destroy();
  }
}

let validate;
function schemaErrors(records) {
  if (!validate) {
    const ajv = new Ajv2020({ allErrors: true, strict: false, validateFormats: false });
    validate = ajv.compile(JSON.parse(readFileSync(path.join(ROOT, "contracts/wave5-records.schema.json"), "utf8")));
  }
  return validate(records) ? [] : validate.errors.map((e) => `${e.instancePath} ${e.message}`);
}

function toolResults(body) {
  const out = [];
  for (const m of body?.messages ?? []) {
    if (!Array.isArray(m.content)) continue;
    for (const b of m.content) if (b.type === "tool_result") out.push(b);
  }
  return out;
}

async function claudeToolCheck({ claudePath }) {
  const bin = daemonBin();
  if (!bin) return { status: "skip", finding: "no debug derm-daemon (cargo build -p derm-daemon, or DERM_DAEMON_DEBUG)" };
  const top = mkdtempSync(path.join(os.tmpdir(), "derm-cu-u-"));
  const HOME = path.join(top, "home");
  const RUN = path.join(top, "run");
  const DATA = path.join(top, "data");
  const BIN = path.join(top, "bin");
  for (const d of [HOME, RUN, DATA, BIN, path.join(HOME, ".derm")]) mkdirSync(d, { recursive: true, mode: 0o700 });
  chmodSync(RUN, 0o700);
  writeFileSync(path.join(HOME, ".derm", "settings.json"), JSON.stringify({ version: 1, computerUse: { on: true } }), { mode: 0o600 });
  const driver = path.join(BIN, "cua-driver");
  writeFileSync(driver, FAKE_DRIVER, { mode: 0o755 });
  // The app: a copy of sleep named calc, running as us.
  const calc = path.join(BIN, "calc");
  copyFileSync("/bin/sleep", calc);
  chmodSync(calc, 0o755);
  const app = spawn(calc, ["300"], { stdio: "ignore" });
  const SOCK = path.join(RUN, "derm", "daemon.sock");
  const daemon = spawn(bin, ["--foreground"], {
    env: { PATH: process.env.PATH, HOME, XDG_RUNTIME_DIR: RUN, XDG_DATA_HOME: DATA, LANG: "C.UTF-8", DERM_CUA_DRIVER: driver, DISPLAY: ":99" },
    stdio: ["ignore", "ignore", "pipe"],
  });
  let daemonErr = "";
  daemon.stderr.on("data", (d) => (daemonErr = (daemonErr + d).slice(-4000)));
  let fake;
  let s;
  const conns = [];
  try {
    await until(() => existsSync(SOCK) && existsSync(path.join(RUN, "derm", "cu.endpoint")), 15000);
    if (!existsSync(path.join(RUN, "derm", "cu.endpoint"))) {
      return { status: "fail", finding: `computer use did not start with computerUse.on: ${daemonErr.slice(-400)}` };
    }
    const daemonToken = readFileSync(path.join(RUN, "derm", "daemon.token"), "utf8").trim();
    const admin = new Conn(SOCK);
    conns.push(admin);
    await admin.ready();
    await admin.send({ op: "hello", token: daemonToken, client: "cu-check" });
    const chat = "cu-u-1";
    const mint = await admin.send({ op: "token.mint", chat, harness: "claude-code" });
    // The chat runs under srt, so a yes needs no person check (lane V).
    await admin.send({
      op: "event",
      event: { id: "cu-u-start", at: 0, chatId: chat, harness: "claude-code", source: "run", kind: "run.start", summary: "", detail: { boundary: "srt" }, pid: app.pid },
    });
    const records = [];
    const tail = new Conn(SOCK, (msg) => {
      if (msg.event?.kind === "cu.action") records.push(msg.event);
    });
    conns.push(tail);
    await tail.ready();
    await tail.send({ op: "hello", token: daemonToken, client: "cu-check-tail" });
    await tail.send({ op: "tail", chat });
    const cards = [];
    const approver = new Conn(SOCK, (msg, c) => {
      if (!msg.approve) return;
      cards.push(msg.approve);
      c.sock.write(`${JSON.stringify({ op: "answer", id: msg.approve.id, answer: "yes", chat: msg.approve.chat })}\n`);
    });
    conns.push(approver);
    await approver.ready();
    await approver.send({ op: "hello", token: daemonToken, client: "cu-check-approver" });
    const registered = await approver.send({ op: "approver" });
    if (!registered.ok) return { status: "fail", finding: `the test approver was refused: ${JSON.stringify(registered)}` };

    let listed = null;
    let seenTools = [];
    fake = await startFakeMessages({
      script: (body) => {
        const tools = body?.tools ?? [];
        const ours = tools.find((t) => t.name === TOOL);
        if (!ours) {
          seenTools = tools.map((t) => t.name);
          return [textBlock("no computer_use tool")];
        }
        listed = listed ?? { names: tools.filter((t) => t.name.startsWith("mcp__derm_cu__")).map((t) => t.name), schema: ours.input_schema };
        const results = toolResults(body);
        if (results.length === 0) return [toolUse(TOOL, { action: "capture", app: "calc" })];
        if (results.length === 1) return [toolUse(TOOL, { action: "click", element: 1 })];
        if (results.length === 2) return [toolUse(TOOL, { action: "type", text: `sudo rm -rf ${TYPED}` })];
        return [textBlock("done")];
      },
    });
    const dirs = makeTempDirs("cu-u-claude-");
    const config = JSON.stringify({ mcpServers: { derm_cu: { type: "stdio", command: bin, args: ["cu-mcp"] } } });
    s = new ClaudeSession({
      claudePath,
      dirs,
      baseUrl: fake.baseUrl,
      args: ["--mcp-config", config],
      // Every tool in the request, not behind tool search (the measurement
      // session's switch), so the fake model can call it on the first turn.
      env: { DERM_CHAT_TOKEN: mint.token, DERM_DAEMON_SOCKET: SOCK, XDG_RUNTIME_DIR: RUN, ENABLE_TOOL_SEARCH: "false" },
    });
    await s.send("use the calculator", 150000);
    await until(() => records.length >= 3, 5000);

    const problems = [];
    const contract = JSON.parse(readFileSync(path.join(ROOT, "contracts/cu-tool.schema.json"), "utf8"));
    if (!listed) problems.push(`the model never saw ${TOOL}; it saw ${seenTools.length} tools: ${seenTools.filter((n) => /mcp|derm|Search/i.test(n)).join(", ") || "none from MCP"}`);
    else {
      if (JSON.stringify(listed.names) !== JSON.stringify([TOOL])) problems.push(`tools from derm_cu: ${listed.names.join(", ")}`);
      if (JSON.stringify(Object.keys(listed.schema?.properties ?? {}).sort()) !== JSON.stringify(Object.keys(contract.properties).sort())) problems.push("the input schema's properties differ from the contract");
    }
    if (cards.length !== 1) problems.push(`${cards.length} cards (want 1)`);
    else if (cards[0].tool !== "computer-use/grant-app" || !/calc/.test(cards[0].summary ?? "")) problems.push(`card: ${JSON.stringify(cards[0]).slice(0, 300)}`);
    const manifest = existsSync(path.join(BIN, "read-manifest.yaml")) ? readFileSync(path.join(BIN, "read-manifest.yaml"), "utf8") : "";
    if (!manifest.includes(`- executable: "${calc}"`) || manifest.includes("bundle_id")) problems.push(`manifest: ${manifest.slice(0, 300)}`);
    const log = existsSync(path.join(BIN, "driver.log")) ? readFileSync(path.join(BIN, "driver.log"), "utf8") : "";
    if (/bad args|not bounded|bypass|not approved/.test(log)) problems.push(`driver: ${log.slice(0, 300)}`);
    const click = log.split("\n").find((l) => l.includes('"click"'));
    if (!click || !click.includes('"element_index":1') || !click.includes('"element_token":"s9:1"') || !click.includes('"window_id":7')) problems.push(`click sent: ${click ?? "none"}`);
    if (log.includes(TYPED)) problems.push("the blocked text reached the driver");
    const second = fake.turnRequests().map((r) => toolResults(r.body)).find((t) => t.length >= 1);
    const captureResult = second?.[0];
    const content = Array.isArray(captureResult?.content) ? captureResult.content : [];
    if (!content.some((b) => b.type === "image")) problems.push(`the capture reached the model without its image: ${String(JSON.stringify(captureResult) ?? "no tool result").slice(0, 300)}`);
    if (!content.some((b) => b.type === "text" && /"elements"/.test(b.text ?? ""))) problems.push("the capture's elements did not reach the model");
    const kinds = records.map((r) => `${r.detail.action}:${r.detail.verdict}`);
    if (JSON.stringify(kinds) !== JSON.stringify(["capture:ok", "click:ok", "type:blocked"])) problems.push(`records: ${kinds.join(", ")}`);
    const errors = schemaErrors(records);
    if (errors.length) problems.push(`schema: ${errors.slice(0, 3).join("; ")}`);
    const recordText = JSON.stringify(records);
    if (recordText.includes(PNG) || recordText.includes(TYPED)) problems.push("a record holds the image or the typed text");
    return {
      status: problems.length ? "fail" : "pass",
      finding: problems.length
        ? problems.join(" | ")
        : `Claude Code listed one tool (computer_use), the card went to the approver once (${cards[0].tool}), the driver started bounded with ${calc} as the app, the capture reached the model with its image, the click carried the capture's element token, the blocked text was stopped before the driver, and ${records.length} cu.action records validate.`,
      seen: { cards: cards.length, records: kinds },
    };
  } finally {
    try {
      await s?.close();
    } catch {}
    await fake?.close?.();
    for (const c of conns) c.close();
    try {
      daemon.kill("SIGTERM");
    } catch {}
    try {
      app.kill("SIGKILL");
    } catch {}
    await sleep(200);
    rmSync(top, { recursive: true, force: true });
  }
}

export const checks = [
  {
    id: "cu-tool-claude",
    title: "Claude Code drives one app through derm's computer_use: one tool, one card, bounded driver, records",
    harness: "claude",
    run: claudeToolCheck,
  },
];
