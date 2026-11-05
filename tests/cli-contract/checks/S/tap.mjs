// Lane S (wave 5): the model tap between a real CLI and a fake model server.
//
// Each check starts `tap_dev` (crates/derm-tap/examples/tap_dev.rs: the
// server the daemon runs, writing its records to a file), asks it for the
// launch shape `derm run` would add for the harness (derm_tap::launch, from
// the row in crates/derm-cli/src/connect/presets/wave5/tap.json), starts the
// real CLI with that shape against the fake server, and reads what the tap
// recorded. Pass: the model's tool call is recorded under the id the CLI
// used, joined to the result the CLI sent back, with the paths it named;
// every record validates against contracts/wave5-records.schema.json; no
// record holds the key, the prompt or the tool's output; the fake saw the
// requests at the provider's own paths, with no route on them.
//
//   cargo build -p derm-tap --example tap_dev
//   node tests/cli-contract/run.mjs --claude <path> --codex <path> \
//     --cli gemini=<path> --only tap-claude,tap-codex,tap-gemini
//
// The binary is DERM_TAP_DEV, else target/debug/examples/tap_dev, else
// target/release/examples/tap_dev. No network: every upstream is loopback.

import { spawn, execFileSync } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import path from "node:path";
import readline from "node:readline";
import { fileURLToPath } from "node:url";
import { Ajv2020 } from "ajv/dist/2020.js";
import { ClaudeSession, DUMMY_KEY, writeProjectFile } from "../../lib/claudeDriver.mjs";
import { isolatedEnv, makeTempDirs } from "../../lib/codexDriver.mjs";
import { startFakeMessages, textBlock, toolUse } from "../../lib/fakeMessages.mjs";
import { call, startFakeResponses, text as rText } from "../../lib/fakeResponses.mjs";
import { functionCall, functionResponses, startFakeGemini, text as gText } from "../../lib/fakeGemini.mjs";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../../..");
const MARK = "derm-tap-output-marker";
const PROMPT = "derm-tap-prompt-marker";

function tapBin() {
  for (const p of [process.env.DERM_TAP_DEV, path.join(ROOT, "target/debug/examples/tap_dev"), path.join(ROOT, "target/release/examples/tap_dev")]) {
    if (p && existsSync(p)) return p;
  }
  return null;
}

function row(harness) {
  const t = JSON.parse(readFileSync(path.join(ROOT, "crates/derm-cli/src/connect/presets/wave5/tap.json"), "utf8"));
  return t.rows[harness];
}

/** Canonical JSON: keys sorted, no spaces (record.rs `canonical`). */
function canonical(v) {
  if (Array.isArray(v)) return `[${v.map(canonical).join(",")}]`;
  if (v && typeof v === "object") return `{${Object.keys(v).sort().map((k) => `${JSON.stringify(k)}:${canonical(v[k])}`).join(",")}}`;
  return JSON.stringify(v);
}
const sha = (s) => createHash("sha256").update(s).digest("hex");
const resultHash = (v) => sha(typeof v === "string" ? v : canonical(v));

let validate;
function schemaErrors(records) {
  if (!validate) {
    const ajv = new Ajv2020({ allErrors: true, strict: false, validateFormats: false });
    validate = ajv.compile(JSON.parse(readFileSync(path.join(ROOT, "contracts/wave5-records.schema.json"), "utf8")));
  }
  return validate(records) ? [] : validate.errors.map((e) => `${e.instancePath} ${e.message}`);
}

async function startTap({ harness, upstreams, dir }) {
  const bin = tapBin();
  const token = randomBytes(32).toString("hex");
  const records = path.join(dir, "records.jsonl");
  const args = ["--token", token, "--chat", "chat-s", "--harness", harness, "--records", records, "--row", JSON.stringify(row(harness))];
  for (const [k, v] of Object.entries(upstreams)) args.push("--upstream", `${k}=${v}`);
  const child = spawn(bin, args, { stdio: ["pipe", "pipe", "pipe"] });
  const lines = readline.createInterface({ input: child.stdout });
  const got = [];
  await new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error("tap_dev did not start")), 15000);
    lines.on("line", (l) => {
      got.push(l);
      if (got.length === 2) {
        clearTimeout(timer);
        resolve();
      }
    });
    child.on("exit", (c) => reject(new Error(`tap_dev exited ${c}`)));
  });
  return {
    endpoint: got[0].replace(/^listening /, ""),
    launch: JSON.parse(got[1]),
    records: () => (existsSync(records) ? readFileSync(records, "utf8").split("\n").filter(Boolean).map((l) => JSON.parse(l)) : []),
    stop: () => {
      child.stdin.end();
      setTimeout(() => child.kill("SIGKILL"), 2000).unref();
    },
  };
}

/** The common part of every check's verdict. */
function judge({ records, callId, tool, resultValue, path: named, fakeUrls, secrets }) {
  const calls = records.filter((r) => r.kind === "tap.call" && r.detail.callId === callId);
  const first = calls[0];
  const joined = calls.find((r) => r.detail.resultSha256);
  const requests = records.filter((r) => r.kind === "tap.request");
  const errors = schemaErrors(records);
  const text = JSON.stringify(records);
  const leaked = secrets.filter((s) => text.includes(s));
  const routed = fakeUrls.filter((u) => u.includes("/r/") || u.includes("openai-auto"));
  const facts = {
    requests: requests.length,
    callRecorded: Boolean(first) && first.detail.tool === tool,
    joined: Boolean(joined) && (resultValue === undefined || joined.detail.resultSha256 === resultHash(resultValue)),
    pathsNamed: named ? Boolean(first?.detail.paths?.includes(named)) : true,
    sameId: calls.every((c) => c.id === `tap-chat-s-${callId}`),
    schemaErrors: errors.slice(0, 3),
    leaked,
    routeReachedUpstream: routed,
  };
  const ok = facts.requests > 0 && facts.callRecorded && facts.joined && facts.pathsNamed && facts.sameId && errors.length === 0 && leaked.length === 0 && routed.length === 0;
  return { ok, facts };
}

export const checks = [
  {
    id: "tap-claude",
    title: "Claude Code through the tap: a Read call recorded, joined to its result, with its path",
    harness: "claude",
    async run({ binPath }) {
      if (!tapBin()) return { status: "skip", finding: "no tap_dev binary (cargo build -p derm-tap --example tap_dev)" };
      const dirs = makeTempDirs("tap-c-");
      const file = writeProjectFile(dirs, "README.md", `# ${MARK}\n`);
      const fake = await startFakeMessages({
        script: (body, n, reqs) => {
          const turns = reqs.filter((r) => r.kind === "messages" && !r.side).length;
          return turns === 1 ? [toolUse("Read", { file_path: file }, "toolu_dermtap000001")] : [textBlock("done")];
        },
      });
      const tap = await startTap({ harness: "claude-code", upstreams: { anthropic: fake.baseUrl }, dir: dirs.root });
      const [name, value] = tap.launch.env[0];
      let session;
      try {
        session = new ClaudeSession({ claudePath: binPath, dirs, baseUrl: value });
        await session.send(`${PROMPT} read the readme`);
        await new Promise((r) => setTimeout(r, 300));
        const records = tap.records();
        const back = fake.requests
          .flatMap((r) => r.body?.messages ?? [])
          .flatMap((m) => (Array.isArray(m.content) ? m.content : []))
          .find((b) => b.type === "tool_result" && b.tool_use_id === "toolu_dermtap000001");
        const { ok, facts } = judge({
          records,
          callId: "toolu_dermtap000001",
          tool: "Read",
          resultValue: back?.content,
          path: file,
          fakeUrls: fake.requests.map((r) => r.url),
          secrets: [DUMMY_KEY, PROMPT, MARK],
        });
        const paths = [...new Set(fake.requests.map((r) => r.url.split("?")[0]))];
        return {
          status: ok && name === "ANTHROPIC_BASE_URL" ? "pass" : "fail",
          finding: `${name} with the route in its path; the fake saw ${JSON.stringify(paths)}; ${JSON.stringify(facts)}${ok ? "" : ` stderr: ${session.stderr.slice(-300)}`}`,
        };
      } finally {
        await session?.close();
        tap.stop();
        await fake.close();
        if (!process.env.CLI_CONTRACT_KEEP) rmSync(dirs.root, { recursive: true, force: true });
      }
    },
  },
  {
    id: "tap-codex",
    title: "Codex through the tap: a custom provider, HTTP only, the route in a header; an exec_command call joined",
    harness: "codex",
    async run({ binPath }) {
      if (!tapBin()) return { status: "skip", finding: "no tap_dev binary (cargo build -p derm-tap --example tap_dev)" };
      const dirs = makeTempDirs("tap-x-");
      const fake = await startFakeResponses({
        script: (body, n) => (n === 0 ? [call("exec_command", { cmd: `echo ${MARK}` }, "call_dermtap01")] : [rText("done")]),
      });
      const tap = await startTap({ harness: "codex", upstreams: { openai: `${fake.baseUrl}/v1`, chatgpt: `${fake.baseUrl}/v1` }, dir: dirs.root });
      const key = "sk-derm-tap-contract-dummy";
      writeFileSync(
        path.join(dirs.codexHome, "config.toml"),
        ['model = "fake-model"', "model_context_window = 16384", "", "[analytics]", "enabled = false", "", "[otel]", 'exporter = "none"', 'metrics_exporter = "none"', ""].join("\n"),
      );
      const env = isolatedEnv({ home: dirs.home, extra: { CODEX_HOME: dirs.codexHome, ...Object.fromEntries(tap.launch.env) } });
      try {
        execFileSync(binPath, ["login", "--with-api-key"], { env, input: `${key}\n`, encoding: "utf8", timeout: 60000 });
        const r = await new Promise((resolve) => {
          const child = spawn(binPath, ["exec", ...tap.launch.args, "--skip-git-repo-check", "--json", "-s", "workspace-write", "-c", 'approval_policy="never"', `${PROMPT} go`], { cwd: dirs.work, env, stdio: ["ignore", "ignore", "pipe"], detached: true });
          let err = "";
          child.stderr.on("data", (d) => (err += d));
          // Codex's npm shim forwards signals only to its own child, so the
          // group goes (lib/procs.mjs's reason).
          const timer = setTimeout(() => {
            try {
              process.kill(-child.pid, "SIGKILL");
            } catch {}
          }, 120000);
          child.on("exit", (code) => {
            clearTimeout(timer);
            resolve({ code, err });
          });
        });
        await new Promise((res) => setTimeout(res, 300));
        const records = tap.records();
        const out = fake.requests.flatMap((q) => q.body?.input ?? []).find((i) => i.type === "function_call_output" && i.call_id === "call_dermtap01");
        const { ok, facts } = judge({
          records,
          callId: "call_dermtap01",
          tool: "exec_command",
          resultValue: out?.output,
          fakeUrls: fake.requests.map((q) => q.url),
          secrets: [key, PROMPT, MARK],
        });
        const routeHeaders = fake.requests.filter((q) => q.headers?.["x-derm-tap-route"]).length;
        const argvHoldsRoute = tap.launch.args.some((a) => a.includes(tap.launch.env[0][1]));
        const pass = ok && r.code === 0 && routeHeaders === 0 && !argvHoldsRoute;
        return {
          status: pass ? "pass" : "fail",
          finding: `exit ${r.code}; ${tap.launch.args.length / 2} -c flags, none holding the route: ${!argvHoldsRoute}; route header forwarded upstream ${routeHeaders} time(s); ${JSON.stringify(facts)}${pass ? "" : ` stderr: ${r.err.slice(-400)}`}`,
        };
      } finally {
        tap.stop();
        await fake.close();
        if (!process.env.CLI_CONTRACT_KEEP) rmSync(dirs.root, { recursive: true, force: true });
      }
    },
  },
  {
    id: "tap-gemini",
    title: "Gemini CLI through the tap: a run_shell_command call with no id, joined to its functionResponse by name",
    harness: "gemini",
    async run({ binPath }) {
      if (!tapBin()) return { status: "skip", finding: "no tap_dev binary (cargo build -p derm-tap --example tap_dev)" };
      const dirs = makeTempDirs("tap-g-");
      const fake = await startFakeGemini({
        script: (body, n) => (n === 0 ? [functionCall("run_shell_command", { command: `echo ${MARK}` })] : [gText("done")]),
      });
      const tap = await startTap({ harness: "gemini", upstreams: { gemini: fake.baseUrl }, dir: dirs.root });
      mkdirSync(path.join(dirs.home, ".gemini"), { recursive: true });
      writeFileSync(path.join(dirs.home, ".gemini", "settings.json"), JSON.stringify({ security: { auth: { selectedType: "gemini-api-key" } } }));
      const env = {
        PATH: process.env.PATH,
        HOME: dirs.home,
        GEMINI_API_KEY: "fake-gemini-key-derm-tap",
        GEMINI_CLI_TRUST_WORKSPACE: "true",
        GEMINI_CLI_NO_RELAUNCH: "true",
        NO_COLOR: "1",
        ...Object.fromEntries(tap.launch.env),
      };
      try {
        const r = await new Promise((resolve) => {
          const child = spawn(binPath, ["-p", `${PROMPT} run the step`, "--approval-mode", "yolo", "--output-format", "json"], { cwd: dirs.work, env, stdio: ["ignore", "pipe", "pipe"] });
          let err = "";
          child.stderr.on("data", (d) => (err += d));
          const timer = setTimeout(() => child.kill("SIGKILL"), 120000);
          child.on("close", (code) => {
            clearTimeout(timer);
            resolve({ code, err });
          });
        });
        await new Promise((res) => setTimeout(res, 300));
        const records = tap.records();
        const call0 = records.find((x) => x.kind === "tap.call" && x.detail.tool === "run_shell_command");
        const fr = fake.turnRequests().flatMap((t) => functionResponses(t.body)).find((f) => f.name === "run_shell_command");
        const { ok, facts } = judge({
          records,
          callId: call0?.detail.callId ?? "none",
          tool: "run_shell_command",
          resultValue: fr?.response,
          fakeUrls: fake.requests.map((q) => q.url),
          secrets: ["fake-gemini-key-derm-tap", PROMPT, MARK],
        });
        return {
          status: ok && r.code === 0 ? "pass" : "fail",
          finding: `exit ${r.code}; call id ${call0?.detail.callId}; ${JSON.stringify(facts)}${ok ? "" : ` stderr: ${r.err.slice(-300)}`}`,
        };
      } finally {
        tap.stop();
        await fake.close();
        if (!process.env.CLI_CONTRACT_KEEP) rmSync(dirs.root, { recursive: true, force: true });
      }
    },
  },
];
