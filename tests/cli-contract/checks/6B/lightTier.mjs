// Lane 6B (wave 6): the light tier against the real Claude Code. No derm run,
// no daemon, no chat token: derm's Rust hook (`derm hook claude-code pre` and
// `post`, by derm's absolute path, case 227) registered in Claude Code's user
// settings, `claude -p` against the fake Messages server. Every decision and
// result must land in `<home>/.derm/local/<session>.jsonl` as chain v2 lines
// (contracts/events.md section 6.4), chained in order, verified here by a
// second implementation of the hash (sorted keys, as serde_json without
// `preserve_order` writes them; the base's Python one is held to the Rust one
// by `the_contract_fixtures_are_this_modules_output`).
//
// run.mjs loads lane folders by `/^(?:[A-Z]|5b[A-F])$/`, so until integration
// adds wave 6's names this folder runs on its own:
//   DERM_BIN=target/debug/derm node tests/cli-contract/checks/6B/lightTier.mjs --claude <claude>
// (a check whose CLI is not given is skipped).

import { createHash } from "node:crypto";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { startFakeMessages, textBlock, toolUse } from "../../lib/fakeMessages.mjs";
import { spawnGroup, stopGroup } from "../../lib/procs.mjs";
import { dermBin } from "../../lib/dermBin.mjs";

const GENESIS = "0".repeat(64);

/** serde_json's text of a value with every object's keys sorted. */
function canonical(v) {
  if (Array.isArray(v)) return `[${v.map(canonical).join(",")}]`;
  if (v && typeof v === "object") {
    return `{${Object.keys(v)
      .sort()
      .map((k) => `${JSON.stringify(k)}:${canonical(v[k])}`)
      .join(",")}}`;
  }
  return JSON.stringify(v);
}

/** Chain v2's rule for `lines` from genesis; the kinds, or why it broke. */
export function verifyChainV2(lines) {
  let prev = GENESIS;
  const kinds = [];
  for (const [i, text] of lines.entries()) {
    let l;
    try {
      l = JSON.parse(text);
    } catch {
      return { ok: false, why: `line ${i + 1}: not JSON` };
    }
    const keys = Object.keys(l).sort().join(",");
    if (keys !== "hash,kind,prev,record,seq,v" || l.v !== 2) return { ok: false, why: `line ${i + 1}: not a chain v2 line (${keys})` };
    if (l.seq !== i) return { ok: false, why: `line ${i + 1}: seq ${l.seq}` };
    if (l.prev !== prev) return { ok: false, why: `line ${i + 1}: prev does not match` };
    const h = createHash("sha256").update(`derm-chain-v2\n${l.seq}\n${l.prev}\n${l.kind}\n${canonical(l.record)}`).digest("hex");
    if (h !== l.hash) return { ok: false, why: `line ${i + 1}: hash does not match` };
    if (l.record.kind !== l.kind) return { ok: false, why: `line ${i + 1}: kind ${l.kind} against the record's ${l.record.kind}` };
    prev = l.hash;
    kinds.push(l.kind);
  }
  return { ok: true, kinds, records: lines.map((t) => JSON.parse(t).record) };
}

/** One `claude -p` turn whose model calls Bash with each of `commands` in one message. */
async function turn(claude, commands) {
  const derm = dermBin();
  if (!derm) return { skip: "no derm build (cargo build -p derm-cli, or DERM_BIN)" };
  const fake = await startFakeMessages({
    script: (body) =>
      JSON.stringify(body.messages ?? []).includes("tool_result")
        ? [textBlock("done")]
        : commands.map((c, n) => toolUse("Bash", { command: c, description: `step ${n}` })),
  });
  const root = mkdtempSync(path.join(process.env.CLI_CONTRACT_TMP ?? tmpdir(), "6b-light-"));
  const home = path.join(root, "home");
  const work = path.join(root, "work");
  const config = path.join(root, "claude-config");
  for (const d of [home, work, config]) mkdirSync(d, { recursive: true });
  // The policy outside the work folder, 0600 (case 226).
  const policy = path.join(root, "policy.json");
  writeFileSync(policy, JSON.stringify({ version: 1, rules: [{ tool: "bash", action: "allow" }] }), { mode: 0o600 });
  const gate = (event) => ({ type: "command", command: `"${derm}" hook claude-code ${event}`, timeout: 120 });
  writeFileSync(
    path.join(config, "settings.json"),
    JSON.stringify({
      hooks: {
        PreToolUse: [{ matcher: "*", hooks: [gate("pre")] }],
        PostToolUse: [{ matcher: "*", hooks: [gate("post")] }],
      },
    }),
  );
  const env = {
    PATH: [path.dirname(process.execPath), "/usr/local/bin", "/usr/bin", "/bin"].join(":"),
    HOME: home,
    CLAUDE_CONFIG_DIR: config,
    ANTHROPIC_BASE_URL: fake.baseUrl,
    ANTHROPIC_API_KEY: "sk-ant-api03-contract-test-dummy-key-not-real",
    CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC: "1",
    DISABLE_AUTOUPDATER: "1",
    DERM_POLICY: policy,
    // A daemon socket that is not there: the light tier, as on a machine
    // with derm installed and no daemon running.
    DERM_DAEMON_SOCKET: path.join(root, "absent.sock"),
  };
  const child = spawnGroup(claude, ["-p", "run the steps", "--output-format", "json", "--model", "claude-sonnet-4-5"], { env, cwd: work, stdio: ["ignore", "pipe", "pipe"] });
  let out = "";
  let err = "";
  child.stdout.on("data", (d) => (out += d));
  child.stderr.on("data", (d) => (err += d));
  const code = await new Promise((resolve) => {
    const timer = setTimeout(() => stopGroup(child).then(() => resolve("timeout")), 150_000);
    child.on("exit", (c) => {
      clearTimeout(timer);
      resolve(c);
    });
  });
  await stopGroup(child);
  let session = null;
  try {
    session = JSON.parse(out.trim().split("\n").pop()).session_id ?? null;
  } catch {}
  const log = session ? path.join(home, ".derm", "local", `${session}.jsonl`) : null;
  const text = log && existsSync(log) ? readFileSync(log, "utf8") : "";
  const ran = commands.map((_c, n) => existsSync(path.join(work, `ran${n}.txt`)));
  await fake.close();
  rmSync(root, { recursive: true, force: true });
  return { code, err, session, lines: text.split("\n").filter((l) => l.length > 0), endsWithNewline: text.endsWith("\n"), ran };
}

export const checks = [
  {
    id: "light-tier-claude-log",
    title: "Claude Code with derm's hook and no daemon leaves a chain v2 log per chat",
    harness: "claude",
    async run({ claudePath }) {
      const t = await turn(claudePath, ["echo one > ran0.txt"]);
      if (t.skip) return { status: "skip", finding: t.skip };
      if (t.code !== 0) return { status: "error", finding: `claude exited ${t.code}: ${t.err.slice(-300)}` };
      if (!t.ran[0]) return { status: "fail", finding: "the allowed Bash call did not run" };
      const v = verifyChainV2(t.lines);
      if (!v.ok) return { status: "fail", finding: `the log does not verify: ${v.why}` };
      if (v.kinds.join(",") !== "approval,tool.call") return { status: "fail", finding: `kinds ${v.kinds.join(",")}` };
      const bad = v.records.find((r) => r.chatId !== t.session || r.harness !== "claude-code" || r.detail?.trust !== "client");
      if (bad) return { status: "fail", finding: `a record names another chat or harness: ${JSON.stringify(bad).slice(0, 200)}` };
      if (!t.endsWithNewline) return { status: "fail", finding: "the log does not end with a newline" };
      return { status: "pass", finding: `session ${t.session}: approval then tool.call, chained from genesis` };
    },
  },
  {
    id: "light-tier-claude-parallel",
    title: "Three Bash calls in one message: every hook's line is whole and chained",
    harness: "claude",
    async run({ claudePath }) {
      const t = await turn(claudePath, ["echo a > ran0.txt", "echo b > ran1.txt", "echo c > ran2.txt"]);
      if (t.skip) return { status: "skip", finding: t.skip };
      if (t.code !== 0) return { status: "error", finding: `claude exited ${t.code}: ${t.err.slice(-300)}` };
      const v = verifyChainV2(t.lines);
      if (!v.ok) return { status: "fail", finding: `the log does not verify: ${v.why}` };
      const approvals = v.kinds.filter((k) => k === "approval").length;
      const results = v.kinds.filter((k) => k === "tool.call").length;
      const ran = t.ran.filter(Boolean).length;
      if (approvals !== 3 || results !== ran) return { status: "fail", finding: `${approvals} approvals and ${results} results for ${ran} calls that ran: ${v.kinds.join(",")}` };
      return { status: "pass", finding: `${t.lines.length} lines (${v.kinds.join(",")}), chained` };
    },
  },
];

// On its own: `node lightTier.mjs --claude <path>`.
if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const i = process.argv.indexOf("--claude");
  const claudePath = i > 0 ? process.argv[i + 1] : null;
  let failed = 0;
  for (const c of checks) {
    if (!claudePath) {
      console.log(`${c.id}: skip (no --claude)`);
      continue;
    }
    let r;
    try {
      r = await c.run({ claudePath });
    } catch (e) {
      r = { status: "error", finding: String(e?.stack ?? e) };
    }
    if (r.status === "fail" || r.status === "error") failed++;
    console.log(`${c.id}: ${r.status}: ${r.finding}`);
  }
  process.exit(failed ? 1 : 0);
}
