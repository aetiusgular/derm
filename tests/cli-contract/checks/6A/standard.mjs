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
//     --only standard-claude-holds,standard-claude-refuses-a-widening-user-file,standard-codex-holds,standard-codex-refuses-a-layer-naming-its-profile,\
//       standard-codex-keeps-tmp-to-the-chat,standard-claude-keeps-tmp-to-the-chat
//
// No account and no network but loopback: `--no-daemon --no-tap`, each CLI
// pointed at its fake by its own variables or `-c` pairs.
//
// On Ubuntu with `bwrap-userns-restrict` (or the userns sysctl at 1) derm
// refuses Claude Code's tier (BW6-1), and the Claude checks take that refusal
// as their pass; `DERM_BWRAP_DIR=/usr/local/libexec/derm-srt` puts srt's
// bubblewrap copy first on the checks' PATH so the tier runs (box test w6
// retest, BW6R-2). `node tests/cli-contract/checks/6A/standard.selftest.mjs`
// tests that reading.

import { spawn } from "node:child_process";
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, rmdirSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
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

/** The folder of a bubblewrap copy to put first on the checks' PATH
 *  (`DERM_BWRAP_DIR`, the box's `/usr/local/libexec/derm-srt`, which
 *  `docs/install/linux.md` option 1 installs), when it holds one. Box test
 *  w6 retest, BW6R-2: the checks' own PATH had `/usr/bin` first, so derm
 *  refused the tier there whatever the host offered. */
function bwrapDir(env = process.env) {
  const d = env.DERM_BWRAP_DIR;
  return d && path.isAbsolute(d) && existsSync(path.join(d, "bwrap")) ? d : null;
}

function checkPath(dirs) {
  return [dirs.bin, bwrapDir(), path.dirname(process.execPath), "/usr/bin", "/bin"].filter(Boolean).join(":");
}

/** Whether derm refuses Claude Code's tier on this host (BW6-1), read the
 *  way `contracts_w6.rs`'s `host_kills_claude_codes_commands` reads it, for
 *  the PATH the check gives derm: Ubuntu's `bwrap-userns-restrict` with
 *  `/usr/bin/bwrap` (or none) first on it, or no profile and the userns
 *  sysctl at 1. Facts are passed in for the test of this function. */
export function hostKillsClaudeCommands(PATH, facts = {}) {
  if ((facts.platform ?? process.platform) !== "linux") return false;
  const exists = facts.exists ?? existsSync;
  const read = facts.read ?? ((f) => readFileSync(f, "utf8"));
  const real = facts.real ?? ((f) => realpathSync(f));
  let sysctl = false;
  try {
    sysctl = read("/proc/sys/kernel/apparmor_restrict_unprivileged_userns").trim() === "1";
  } catch {}
  const profile = exists("/etc/apparmor.d/bwrap-userns-restrict");
  let first = null;
  for (const d of PATH.split(":")) {
    const b = path.join(d, "bwrap");
    if (exists(b)) {
      try {
        first = real(b);
      } catch {
        first = b;
      }
      break;
    }
  }
  return (profile && (first === null || first === "/usr/bin/bwrap")) || (!profile && sysctl);
}

/** On a host where derm refuses Claude Code's tier, the check's pass is
 *  that refusal: exit 2, named, nothing started (BW6-1, as the Rust test). */
async function claudeRefusal(dirs) {
  const s = standIn(dirs);
  const r = await derm(dirs, ["claude-code", "--boundary", "none", "--tier", "standard", "--no-daemon", "--no-tap", "--", "-p", "go"], { program: "claude", cli: s.p, timeoutMs: 60000 });
  const started = existsSync(s.marker);
  const ok = r.code === 2 && !started && /cannot run a command on this host/.test(r.err);
  return done(dirs, {
    status: ok ? "pass" : "fail",
    finding: `this host kills Claude Code's sandboxed commands (BW6-1), so the tier's pass is derm's refusal: exit ${r.code}, started ${started}; ${r.err.trim().slice(-300)}`,
  });
}

function derm(dirs, args, { program, cli, env = {}, timeoutMs = 150000 }) {
  symlinkSync(cli, path.join(dirs.bin, program));
  const PATH = checkPath(dirs);
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

// --- /tmp (box test w6, BW6-2) ---------------------------------------------------------------

/** The shell lines the /tmp checks run: a write to /tmp itself, and a
 *  `mktemp` (which takes TMPDIR when it is set). */
function tmpProbe(mark) {
  return {
    slash: `echo x > ${mark}; echo tmpw=$?`,
    mk: `t=$(mktemp) && echo y > "$t" && echo mk=ok; echo "td=\${TMPDIR:-unset}"`,
  };
}

function tmpMark(name) {
  return `/tmp/std6a-${name}-${process.pid}-${Date.now()}`;
}

// Codex's own workspace-write leaves empty `.agents`, `.aws`, `.codex` and
// `.git` in each writable root, /tmp included (case 248, open item 6A-5); the
// control run here would leave them, and a `.git` in /tmp breaks a later
// walk to a git root (`hook/native/tests.rs`). Those this turn made, empty,
// are removed after it.
const LITTER = [".agents", ".aws", ".codex", ".git"].map((n) => path.join("/tmp", n));

async function codexTmpTurn(dirs, codexPath, tierArgs, extra = []) {
  const before = new Set(LITTER.filter((p) => existsSync(p)));
  try {
    return await codexTmpTurnIn(dirs, codexPath, tierArgs, extra);
  } finally {
    for (const p of LITTER) {
      if (!before.has(p)) {
        try {
          rmdirSync(p);
        } catch {}
      }
    }
  }
}

async function codexTmpTurnIn(dirs, codexPath, tierArgs, extra) {
  const mark = tmpMark("cx");
  const pr = tmpProbe(mark);
  const fake = await startFakeResponses({ script: (b, n) => (n === 0 ? [call("exec_command", { cmd: `${pr.slash}; ${pr.mk}` }, "c1")] : [text("done")]) });
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
  const onHost = existsSync(mark);
  rmSync(mark, { force: true });
  const td = (o.match(/td=(\S+)/) ?? [])[1] ?? "";
  return {
    exit: r.code,
    ran: o.length > 0,
    slashTmpOnHost: onHost,
    mktempOk: /mk=ok/.test(o),
    tmpdir: td,
    tmpdirLeft: td.startsWith("/") && existsSync(td),
    output: o.split("Output:").pop().trim().slice(0, 400),
    stderrTail: r.err.slice(-500),
  };
}

async function claudeTmpTurn(dirs, claudePath, tierArgs) {
  const mark = tmpMark("cc");
  const pr = tmpProbe(mark);
  const fake = await startFakeMessages({
    script: (b) =>
      JSON.stringify(b.messages ?? []).includes("tool_result")
        ? [textBlock("done")]
        : [
            toolUse("Bash", { command: pr.slash, description: "slash tmp" }, "toolu_slash"),
            toolUse("Bash", { command: pr.mk, description: "mktemp" }, "toolu_mk"),
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
  const onHost = existsSync(mark);
  rmSync(mark, { force: true });
  const td = ((results.toolu_mk ?? "").match(/td=(\S+?)(?:\\n|"|\s|$)/) ?? [])[1] ?? "";
  return {
    exit: r.code,
    ran: Object.keys(results).length,
    slashTmpOnHost: onHost,
    mktempOk: /mk=ok/.test(results.toolu_mk ?? ""),
    tmpdir: td,
    results,
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
      if (hostKillsClaudeCommands(checkPath({ bin: "/nonexistent" }))) return claudeRefusal(box("cc-refused"));
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
      if (hostKillsClaudeCommands(checkPath({ bin: "/nonexistent" }))) return claudeRefusal(box("cc-refused"));
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
  {
    id: "standard-codex-keeps-tmp-to-the-chat",
    title: "6A (BW6-2): under derm run --tier standard, a Codex command cannot write /tmp itself, gets a TMPDIR of the chat's own that mktemp writes, and derm removes that folder after the chat",
    harness: "codex",
    async run({ binPath }) {
      const why = needs();
      if (why) return { status: "skip", finding: why };
      // Control: Codex's own workspace-write writes /tmp (its `:slash_tmp`).
      const control = box("cxt-control");
      const before = await codexTmpTurn(control, binPath, [], ["-s", "workspace-write"]);
      done(control, null);
      const dirs = box("cxt");
      const seen = await codexTmpTurn(dirs, binPath, ["--tier", "standard"]);
      const meaningful = before.ran && before.slashTmpOnHost;
      const held = seen.ran && !seen.slashTmpOnHost && seen.mktempOk && /\/derm-tmp-/.test(seen.tmpdir) && !seen.tmpdirLeft;
      return done(dirs, {
        status: meaningful && held ? "pass" : "fail",
        finding: `control (workspace-write): /tmp write ${before.slashTmpOnHost}; Standard: /tmp write ${seen.slashTmpOnHost}, mktemp ${seen.mktempOk}, TMPDIR ${seen.tmpdir || "(none)"}, left after ${seen.tmpdirLeft}`,
        seen: { control: before, standard: seen },
      });
    },
  },
  {
    id: "standard-claude-keeps-tmp-to-the-chat",
    title: "6A (BW6-2): under derm run --tier standard, a Claude Code Bash command cannot write /tmp itself, and mktemp still works",
    harness: "claude",
    async run({ binPath }) {
      const why = needs();
      if (why) return { status: "skip", finding: why };
      if (hostKillsClaudeCommands(checkPath({ bin: "/nonexistent" }))) return claudeRefusal(box("cc-refused"));
      const control = box("cct-control");
      const before = await claudeTmpTurn(control, binPath, []);
      done(control, null);
      const dirs = box("cct");
      const seen = await claudeTmpTurn(dirs, binPath, ["--tier", "standard"]);
      const meaningful = before.ran >= 2 && before.slashTmpOnHost;
      const held = seen.ran >= 2 && !seen.slashTmpOnHost && seen.mktempOk;
      return done(dirs, {
        status: meaningful && held ? "pass" : "fail",
        finding: `control (no tier): /tmp write ${before.slashTmpOnHost}; Standard: /tmp write ${seen.slashTmpOnHost}, mktemp ${seen.mktempOk}, TMPDIR ${seen.tmpdir || "(none)"}`,
        seen: { control: before, standard: seen },
      });
    },
  },
];
