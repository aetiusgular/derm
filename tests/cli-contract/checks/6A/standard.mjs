// Wave 6 lane 6A: the Standard tier against the real CLIs (contracts/sandbox.md).
//
// Each check runs `derm run <harness> --boundary none --tier standard` with
// the real Claude Code 2.1.322 or Codex 0.167.2 against the fake model
// servers, the model asking for three commands: a read of a file under
// ~/.ssh (derm denies its reads), a write outside the chat's folder, and a
// write inside it (and for Codex a request to a loopback port). Passing means the effect, not the text: the denied read
// gets nothing, the outside write never reaches the host, the inside write
// does. A control run of the same turn with no tier shows the probe would
// have worked (rules section 9 item 12; note AZ A10: Codex takes an unknown
// profile key with no word). Two more checks show the refusals happen
// before anything starts, with a stand-in that leaves a mark if derm starts
// it.
//
//   cargo build -p derm-cli
//   npm install --prefix /tmp/cli @anthropic-ai/claude-code@2.1.322 @openai/codex@0.167.2
//   apt-get install bubblewrap socat     # both CLIs' Linux sandboxes
//   DERM_BIN=<target>/debug/derm node tests/cli-contract/run.mjs \
//     --claude /tmp/cli/node_modules/.bin/claude --codex /tmp/cli/node_modules/.bin/codex \
//     --only standard-claude-holds,standard-claude-refuses-a-widening-user-file,standard-codex-holds,standard-codex-refuses-a-layer-naming-its-profile
//
// No account and no network but loopback: `--no-daemon --no-tap`, each CLI
// pointed at its fake by its own variables or `-c` pairs.

import { spawn } from "node:child_process";
import { chmodSync, existsSync, mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { startFakeMessages, toolUse, textBlock } from "../../lib/fakeMessages.mjs";
import { startFakeResponses, call, text, callOutputs } from "../../lib/fakeResponses.mjs";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../../..");
const SECRET = "s3cret-6a-not-a-key";
const DUMMY_KEY = "sk-ant-api03-contract-test-dummy-key-not-real";

function dermBin() {
  for (const p of [process.env.DERM_BIN, path.join(ROOT, "target/release/derm"), path.join(ROOT, "target/debug/derm")]) {
    if (p && existsSync(p)) return p;
  }
  return null;
}

function needs() {
  if (!dermBin()) return "no derm binary (DERM_BIN, target/release, target/debug)";
  if (process.platform === "linux" && !["bwrap", "socat"].every((t) => existsSync(`/usr/bin/${t}`))) {
    return "bubblewrap and socat are not in /usr/bin (both CLIs' Linux sandboxes need them)";
  }
  if (process.platform !== "linux" && process.platform !== "darwin") return "the Standard tier is built for Linux and macOS";
  return null;
}

/** A throwaway HOME (with a secret under ~/.ssh), a chat folder and a bin
 *  folder, outside /tmp where the folder's own write rules may differ. */
function box(name) {
  const base = process.env.CLI_CONTRACT_TMP ?? (existsSync("/var/tmp") ? "/var/tmp" : tmpdir());
  const root = mkdtempSync(path.join(base, `std6a-${name}-`));
  const dirs = { root, home: path.join(root, "home"), work: path.join(root, "work"), bin: path.join(root, "bin") };
  for (const d of [dirs.home, dirs.work, dirs.bin, path.join(dirs.home, ".ssh")]) mkdirSync(d, { recursive: true });
  writeFileSync(path.join(dirs.home, ".ssh", "id_test"), `${SECRET}\n`);
  return dirs;
}

function done(dirs, result) {
  if (!process.env.KEEP_STD6A) rmSync(dirs.root, { recursive: true, force: true });
  return result;
}

function derm(dirs, args, { program, cli, env = {}, timeoutMs = 150000 }) {
  symlinkSync(cli, path.join(dirs.bin, program));
  const PATH = [dirs.bin, path.dirname(process.execPath), "/usr/bin", "/bin"].join(":");
  return new Promise((resolve) => {
    const ch = spawn(dermBin(), ["run", ...args], {
      cwd: dirs.work,
      env: { PATH, HOME: dirs.home, LANG: "C.UTF-8", NO_COLOR: "1", DO_NOT_TRACK: "1", ...env },
      stdio: ["ignore", "pipe", "pipe"],
      detached: true,
    });
    let out = "";
    let err = "";
    ch.stdout.on("data", (d) => (out += d));
    ch.stderr.on("data", (d) => (err += d));
    const timer = setTimeout(() => {
      try {
        process.kill(-ch.pid, "SIGKILL");
      } catch {}
    }, timeoutMs);
    ch.on("exit", (code) => {
      clearTimeout(timer);
      try {
        process.kill(-ch.pid, "SIGKILL");
      } catch {}
      resolve({ code, out, err });
    });
  });
}

/** A stand-in for the harness that leaves a mark if derm starts it. */
function standIn(dirs) {
  const marker = path.join(dirs.root, "started");
  const p = path.join(dirs.root, "stand-in");
  writeFileSync(p, `#!/bin/sh\ntouch '${marker}'\n`);
  chmodSync(p, 0o755);
  return { p, marker };
}

// --- Claude Code ---------------------------------------------------------------------------

async function claudeTurn(dirs, claudePath, tierArgs) {
  const outside = path.join(dirs.root, "outside-the-chat");
  const fake = await startFakeMessages({
    script: (b) =>
      JSON.stringify(b.messages ?? []).includes("tool_result")
        ? [textBlock("done")]
        : [
            toolUse("Bash", { command: `cat ${dirs.home}/.ssh/id_test`, description: "read" }, "toolu_read"),
            toolUse("Bash", { command: `echo x > ${outside}`, description: "outside" }, "toolu_out"),
            toolUse("Bash", { command: "echo y > inside.txt", description: "inside" }, "toolu_in"),
          ],
  });
  let r;
  try {
    r = await derm(
      dirs,
      ["claude-code", "--boundary", "none", ...tierArgs, "--no-daemon", "--no-tap", "--", "-p", "go", "--allowedTools", "Bash", "--model", "claude-sonnet-4-5", "--output-format", "json"],
      {
        program: "claude",
        cli: claudePath,
        env: {
          ANTHROPIC_BASE_URL: fake.baseUrl,
          ANTHROPIC_API_KEY: DUMMY_KEY,
          CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC: "1",
          DISABLE_AUTOUPDATER: "1",
          DISABLE_TELEMETRY: "1",
        },
      },
    );
  } finally {
    await fake.close();
  }
  const results = {};
  for (const q of fake.requests) {
    for (const m of q.body?.messages ?? []) {
      for (const c of Array.isArray(m.content) ? m.content : []) {
        if (c?.type === "tool_result") results[c.tool_use_id] = (typeof c.content === "string" ? c.content : JSON.stringify(c.content)).slice(0, 300);
      }
    }
  }
  return {
    exit: r.code,
    secretRead: (results.toolu_read ?? "").includes(SECRET),
    outsideOnHost: existsSync(outside),
    insideOnHost: existsSync(path.join(dirs.work, "inside.txt")),
    ran: Object.keys(results).length,
    results,
    stderrTail: r.err.slice(-500),
  };
}

// --- Codex -------------------------------------------------------------------------------------

async function codexTurn(dirs, codexPath, tierArgs, extra = []) {
  const outside = path.join(dirs.root, "outside-the-chat");
  // The network probe asks the fake server itself, on loopback: Codex's
  // Linux sandbox gives a command with network off its own namespace.
  let port = 0;
  const probe = () =>
    `cat ${dirs.home}/.ssh/id_test; echo read=$?; echo x > ${outside}; echo outw=$?; echo y > inside.txt; echo inw=$?; ` +
    `curl -s -m 5 -o /dev/null -w 'net=%{http_code}' http://127.0.0.1:${port}/ping; echo`;
  const fake = await startFakeResponses({ script: (b, n) => (n === 0 ? [call("exec_command", { cmd: probe() }, "c1")] : [text("done")]) });
  port = new URL(fake.baseUrl).port;
  const provider = `{name="fake_local",base_url="${fake.baseUrl}/v1",wire_api="responses",requires_openai_auth=false,supports_websockets=false,request_max_retries=0,stream_max_retries=0}`;
  mkdirSync(path.join(dirs.home, ".codex"), { recursive: true });
  let r;
  try {
    r = await derm(
      dirs,
      [
        "codex", "--boundary", "none", ...tierArgs, "--no-daemon", "--no-tap", "--",
        "exec", "--skip-git-repo-check", "--json",
        "-c", 'approval_policy="never"', "-c", 'model_provider="fake_local"', "-c", 'model="fake-model"',
        "-c", `model_providers.fake_local=${provider}`, "-c", "analytics.enabled=false", ...extra, "go",
      ],
      { program: "codex", cli: codexPath, env: { CODEX_DISABLE_UPDATE_CHECK: "1" } },
    );
  } finally {
    await fake.close();
  }
  const out = Object.assign({}, ...fake.requests.map((q) => callOutputs(q.body)));
  const o = out.c1 ?? "";
  return {
    exit: r.code,
    secretRead: o.includes(SECRET),
    outsideOnHost: existsSync(outside),
    insideOnHost: existsSync(path.join(dirs.work, "inside.txt")),
    ran: o.length > 0,
    reachedNetwork: /net=(?!000)\d{3}/.test(o),
    output: o.split("Output:").pop().trim().slice(0, 400),
    stderrTail: r.err.slice(-500),
  };
}

export const checks = [
  {
    id: "standard-claude-holds",
    title: "6A: under derm run --tier standard, Claude Code's own sandbox (derm's --settings block) denies a read of ~/.ssh and a write outside the chat's folder, and lets a write inside it through",
    harness: "claude",
    async run({ binPath }) {
      const why = needs();
      if (why) return { status: "skip", finding: why };
      const control = box("cc-control");
      const before = await claudeTurn(control, binPath, []);
      done(control, null);
      const dirs = box("cc");
      const seen = await claudeTurn(dirs, binPath, ["--tier", "standard"]);
      const meaningful = before.secretRead && before.outsideOnHost && before.insideOnHost;
      const held = seen.ran >= 3 && !seen.secretRead && !seen.outsideOnHost && seen.insideOnHost;
      const status = meaningful && held ? "pass" : "fail";
      return done(dirs, {
        status,
        finding: `control (no tier): read ${before.secretRead}, outside write ${before.outsideOnHost}, inside write ${before.insideOnHost}; Standard: read ${seen.secretRead}, outside write ${seen.outsideOnHost}, inside write ${seen.insideOnHost}`,
        seen: { control: before, standard: seen },
      });
    },
  },
  {
    id: "standard-claude-refuses-a-widening-user-file",
    title: "6A: a user settings file whose sandbox.filesystem.allowWrite would widen derm's block refuses the Standard tier before Claude Code starts",
    harness: "claude",
    async run() {
      const why = needs();
      if (why) return { status: "skip", finding: why };
      const dirs = box("cc-refuse");
      mkdirSync(path.join(dirs.home, ".claude"), { recursive: true });
      writeFileSync(path.join(dirs.home, ".claude", "settings.json"), JSON.stringify({ sandbox: { filesystem: { allowWrite: [dirs.root] } } }));
      const s = standIn(dirs);
      const r = await derm(dirs, ["claude-code", "--boundary", "none", "--tier", "standard", "--no-daemon", "--no-tap", "--", "-p", "go"], { program: "claude", cli: s.p, timeoutMs: 60000 });
      const started = existsSync(s.marker);
      const ok = r.code === 2 && !started && /allowWrite/.test(r.err);
      return done(dirs, { status: ok ? "pass" : "fail", finding: `exit ${r.code}, started ${started}; ${r.err.trim().slice(-300)}` });
    },
  },
  {
    id: "standard-claude-reaches-a-secret-host",
    title: "6A/6C (Mac test w6, MW6-4): in a brokered Standard chat, Claude Code's own proxy admits the secret's host and chains it to derm-egress, and still refuses a host off its list with its own 403",
    harness: "claude",
    async run({ binPath }) {
      const why = needs();
      if (why) return { status: "skip", finding: why };
      if (!existsSync("/usr/bin/script")) return { status: "skip", finding: "no script(1) to give `derm secret ca create` a terminal" };
      const dirs = box("cc-secret");
      // derm's CA, from a terminal (case 89: a pty passes that check), and a
      // secret whose value comes from this run's own environment.
      const ca = await new Promise((resolve) => {
        const ch = spawn("/usr/bin/script", ["-qec", `${dermBin()} secret ca create`, "/dev/null"], { env: { PATH: "/usr/bin:/bin", HOME: dirs.home }, stdio: ["ignore", "pipe", "pipe"] });
        let out = "";
        ch.stdout.on("data", (d) => (out += d));
        ch.stderr.on("data", (d) => (out += d));
        ch.on("exit", (code) => resolve({ code, out }));
      });
      if (ca.code !== 0) return done(dirs, { status: "fail", finding: `derm secret ca create: exit ${ca.code}: ${ca.out.slice(-300)}` });
      writeFileSync(path.join(dirs.home, ".derm", "secrets.json"), JSON.stringify({ version: 1, secrets: [{ id: "gh", hosts: ["api.github.com"], from: { env: "W6_FAKE_SECRET" } }] }));
      chmodSync(path.join(dirs.home, ".derm", "secrets.json"), 0o600);
      chmodSync(path.join(dirs.home, ".derm"), 0o700);
      const fake = await startFakeMessages({
        script: (b) =>
          JSON.stringify(b.messages ?? []).includes("tool_result")
            ? [textBlock("done")]
            : [
                toolUse("Bash", { command: "curl -s -m 15 -o g.out -w gh=%{http_connect}/%{http_code} https://api.github.com/zen", description: "secret host" }, "toolu_gh"),
                toolUse("Bash", { command: "curl -s -m 15 -o o.out -w other=%{http_connect}/%{http_code} https://example.org/", description: "other host" }, "toolu_other"),
              ],
      });
      let r;
      try {
        r = await derm(
          dirs,
          ["claude-code", "--boundary", "none", "--tier", "standard", "--no-daemon", "--no-tap", "--", "-p", "go", "--allowedTools", "Bash", "--model", "claude-sonnet-4-5", "--output-format", "json"],
          {
            program: "claude",
            cli: binPath,
            env: {
              ANTHROPIC_BASE_URL: fake.baseUrl,
              ANTHROPIC_API_KEY: DUMMY_KEY,
              CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC: "1",
              DISABLE_AUTOUPDATER: "1",
              DISABLE_TELEMETRY: "1",
              W6_FAKE_SECRET: "fake-value-for-the-contract-check-0000",
            },
          },
        );
      } finally {
        await fake.close();
      }
      let o = "";
      for (const q of fake.requests) {
        for (const m of q.body?.messages ?? []) {
          for (const c of Array.isArray(m.content) ? m.content : []) {
            if (c?.type === "tool_result" && (c.tool_use_id === "toolu_gh" || c.tool_use_id === "toolu_other")) o += ` ${typeof c.content === "string" ? c.content : JSON.stringify(c.content)}`;
          }
        }
      }
      // `%{http_connect}` is the CONNECT's answer from Claude Code's own
      // proxy, `%{http_code}` the request's inside the tunnel.
      const [ghConnect, ghCode] = (/gh=(\d{3})\/(\d{3})/.exec(o) ?? []).slice(1);
      const [otherConnect] = (/other=(\d{3})\/(\d{3})/.exec(o) ?? []).slice(1);
      const gh = ghConnect === undefined ? undefined : `${ghConnect}/${ghCode}`;
      const other = otherConnect;
      // The secret's host passes Claude Code's own proxy (CONNECT 200) and
      // meets derm-egress, whose leaf curl trusts through CURL_CA_BUNDLE (a
      // response came back through the tunnel); a host off the list stops at
      // Claude Code's proxy with its own 403.
      const ok = ghConnect === "200" && ghCode !== undefined && ghCode !== "000" && otherConnect === "403";
      return done(dirs, { status: ok ? "pass" : "fail", finding: `secret's host ${gh ?? "none"}, other host ${other ?? "none"}; exit ${r.code}; ${o.slice(0, 300)} ${r.err.trim().slice(-300)}` });
    },
  },
  {
    id: "standard-codex-holds",
    title: "6A: under derm run --tier standard, Codex's own sandbox (derm's profile by -c) denies a read of ~/.ssh and a write outside the chat's folder, and lets a write inside it through",
    harness: "codex",
    async run({ binPath }) {
      const why = needs();
      if (why) return { status: "skip", finding: why };
      const control = box("cx-control");
      const before = await codexTurn(control, binPath, []);
      done(control, null);
      // And with Codex's sandbox off: the network probe reaches the fake.
      const open = box("cx-open");
      const opened = await codexTurn(open, binPath, [], ["-s", "danger-full-access"]);
      done(open, null);
      const dirs = box("cx");
      const seen = await codexTurn(dirs, binPath, ["--tier", "standard"]);
      // Codex's default exec sandbox is read-only: the control shows the
      // read goes through and the writes do not, so the inside write is what
      // the profile adds.
      const meaningful = before.secretRead && !before.insideOnHost && opened.reachedNetwork;
      const held = seen.ran && !seen.secretRead && !seen.outsideOnHost && seen.insideOnHost && !seen.reachedNetwork;
      return done(dirs, {
        status: meaningful && held ? "pass" : "fail",
        finding: `control (no tier): read ${before.secretRead}, inside write ${before.insideOnHost}; sandbox off: network ${opened.reachedNetwork}; Standard: read ${seen.secretRead}, outside write ${seen.outsideOnHost}, inside write ${seen.insideOnHost}, network ${seen.reachedNetwork}`,
        seen: { control: before, open: opened, standard: seen },
      });
    },
  },
  {
    id: "standard-codex-refuses-a-layer-naming-its-profile",
    title: "6A: a trusted project's .codex/config.toml that defines [permissions.derm] (which Codex would merge into derm's profile) refuses the Standard tier before Codex starts",
    harness: "codex",
    async run() {
      const why = needs();
      if (why) return { status: "skip", finding: why };
      const dirs = box("cx-refuse");
      mkdirSync(path.join(dirs.work, ".codex"), { recursive: true });
      writeFileSync(path.join(dirs.work, ".codex", "config.toml"), `[permissions.derm.filesystem]\n${JSON.stringify(dirs.root)} = "write"\n`);
      mkdirSync(path.join(dirs.home, ".codex"), { recursive: true });
      writeFileSync(path.join(dirs.home, ".codex", "config.toml"), `[projects.${JSON.stringify(dirs.work)}]\ntrust_level = "trusted"\n`);
      const s = standIn(dirs);
      const r = await derm(dirs, ["codex", "--boundary", "none", "--tier", "standard", "--no-daemon", "--no-tap", "--", "exec", "go"], { program: "codex", cli: s.p, timeoutMs: 60000 });
      const started = existsSync(s.marker);
      const ok = r.code === 2 && !started && /permissions\.derm/.test(r.err);
      return done(dirs, { status: ok ? "pass" : "fail", finding: `exit ${r.code}, started ${started}; ${r.err.trim().slice(-300)}` });
    },
  },
];
