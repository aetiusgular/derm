// Fix pass 8 (Mac test w5 retest 7, MW5-32): the real Codex under derm's
// srt runs its shell commands, and srt still confines them.
//
// Codex 0.163.0 starts every command inside its own sandbox: Seatbelt
// through `/usr/bin/sandbox-exec` on macOS (`sandboxing/src/seatbelt.rs:62`)
// and bubblewrap on Linux (`linux-sandbox/src/launcher.rs:222-244`). Neither
// can start inside srt 0.0.81's: macOS refuses a second Seatbelt profile
// ("sandbox-exec: sandbox_apply: Operation not permitted", retest 7, run),
// and srt's seccomp layer refuses a nested user namespace on Linux (srt
// README lines 712-715: "a nested bubblewrap ... fail[s] with EPERM"). The
// turn then ends as if the command ran. This check runs one real `codex
// exec` turn against the fake Responses server under `derm run codex
// --boundary srt` and asks:
//   - the command ran (its marker file is in the chat's folder, and its
//     output reached the model);
//   - a write to HOME outside the chat's folders was refused;
//   - a write to Codex's own config (a control file derm keeps read-only)
//     was refused.
// And that derm refuses a command line that asks for Codex's own sandbox
// under srt, before anything starts.
//
//   cargo build -p derm-cli
//   DERM_BIN=<target>/debug/derm SRT_BIN=/tmp/cli/node_modules/.bin/srt \
//     node tests/cli-contract/run.mjs --codex /tmp/cli/node_modules/.bin/codex \
//     --only boundary-srt-codex-runs-commands,boundary-srt-codex-own-sandbox-refused
//
// Linux also needs bwrap, socat and rg in /usr/bin. No account, no network
// but loopback: `--no-daemon --no-tap`, Codex pointed at the fake through its
// own config, and `--model-url` naming the fake's port for srt's proxy.

import { spawn } from "node:child_process";
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { startFakeResponses, call, text, callOutputs } from "../../lib/fakeResponses.mjs";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../../..");
const MARK = "derm-mw532-ran";

function dermBin() {
  for (const p of [process.env.DERM_BIN, path.join(ROOT, "target/release/derm"), path.join(ROOT, "target/debug/derm")]) {
    if (p && existsSync(p)) return p;
  }
  return null;
}

function srtBin() {
  for (const p of [process.env.SRT_BIN, "/tmp/cli/node_modules/.bin/srt"]) {
    if (p && existsSync(p)) return p;
  }
  return null;
}

function needs() {
  if (!dermBin()) return "no derm binary (DERM_BIN, target/release, target/debug)";
  if (!srtBin()) return "no srt (SRT_BIN, /tmp/cli/node_modules/.bin/srt)";
  if (process.platform === "linux" && !["bwrap", "socat", "rg"].every((t) => existsSync(`/usr/bin/${t}`))) {
    return "srt's Linux tools (bwrap, socat, rg) are not in /usr/bin";
  }
  return null;
}

/** A throwaway HOME, folder and bin outside /tmp (derm's srt lets a chat
 *  write /tmp, so a HOME there would not show the boundary). The folder is a
 *  git repository, as a chat's folder usually is. */
function box(name) {
  const base = process.env.CLI_CONTRACT_TMP ?? (existsSync("/var/tmp") ? "/var/tmp" : tmpdir());
  const root = mkdtempSync(path.join(base, `codex-srt-${name}-`));
  const dirs = { root, home: path.join(root, "home"), work: path.join(root, "work"), bin: path.join(root, "bin") };
  for (const d of [dirs.home, dirs.work, dirs.bin, path.join(dirs.work, ".git")]) {
    mkdirSync(d, { recursive: true });
  }
  return dirs;
}

function derm(dirs, args, { codexPath, timeoutMs = 150000 }) {
  symlinkSync(codexPath, path.join(dirs.bin, "codex"));
  symlinkSync(srtBin(), path.join(dirs.bin, "srt"));
  const PATH = [dirs.bin, path.dirname(process.execPath), "/usr/bin", "/bin"].join(":");
  return new Promise((resolve) => {
    // Its own process group, so a timeout also ends srt's and Codex's children.
    const ch = spawn(dermBin(), ["run", ...args], {
      cwd: dirs.work,
      env: { PATH, HOME: dirs.home, LANG: "C.UTF-8", NO_COLOR: "1", CODEX_DISABLE_UPDATE_CHECK: "1", DO_NOT_TRACK: "1" },
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

const done = (dirs, result) => {
  if (!process.env.KEEP_CODEX_SRT) rmSync(dirs.root, { recursive: true, force: true });
  return result;
};

export const checks = [
  {
    id: "boundary-srt-codex-runs-commands",
    title: "MW5-32: under derm's srt the real Codex runs its shell commands (its own sandbox cannot start inside srt's), and srt still confines them",
    harness: "codex",
    async run({ binPath }) {
      const why = needs();
      if (why) return { status: "skip", finding: why };
      const dirs = box("runs");
      const outside = path.join(dirs.home, "outside-the-chat");
      const control = path.join(dirs.home, ".codex", "config.toml");
      const rules = path.join(dirs.home, ".codex", "rules");
      const fake = await startFakeResponses({
        script: (body, n) =>
          n === 0
            ? [
                call("exec_command", { cmd: `echo ${MARK} > marker.txt && cat marker.txt` }, "c1"),
                call("exec_command", { cmd: `touch ${outside}` }, "c2"),
                call("exec_command", { cmd: `echo '[x]' >> ${control}` }, "c3"),
              ]
            : [text("done")],
      });
      const port = new URL(fake.baseUrl).port;
      // A fresh Codex home: no config.toml and no rules folder (the Linux
      // half: srt holds a missing denied path with /dev/null, which Codex
      // cannot read). The provider comes in with `-c`, at derm's level.
      const provider = `{name="fake_local",base_url="${fake.baseUrl}/v1",wire_api="responses",requires_openai_auth=false,supports_websockets=false,request_max_retries=0,stream_max_retries=0}`;
      let r;
      try {
        r = await derm(
          dirs,
          [
            "codex",
            "--boundary",
            "srt",
            "--no-daemon",
            "--no-tap",
            "--model-url",
            `http://127.0.0.1:${port}`,
            "--",
            "exec",
            "--skip-git-repo-check",
            "--json",
            "-c",
            'approval_policy="never"',
            "-c",
            'model_provider="fake_local"',
            "-c",
            'model="fake-model"',
            "-c",
            `model_providers.fake_local=${provider}`,
            "-c",
            "analytics.enabled=false",
            "go",
          ],
          { codexPath: binPath },
        );
      } finally {
        await fake.close();
      }
      const outputs = Object.assign({}, ...fake.requests.map((q) => callOutputs(q.body)));
      const ran = existsSync(path.join(dirs.work, "marker.txt")) && (outputs.c1 ?? "").includes(MARK);
      const confined = !existsSync(outside);
      // derm made it empty before the start (Linux), and the chat could not
      // add to it; on macOS nothing makes it, and the chat could not make it.
      const controlKept = !existsSync(control) || readFileSync(control, "utf8") === "";
      const said = /Codex's own sandbox/.test(r.err);
      // srt's hold on the missing rules folder is gone with the sandbox.
      const rulesLeft = existsSync(rules);
      const seen = {
        exit: r.code,
        ran,
        confined,
        controlKept,
        said,
        rulesLeft,
        outputs: Object.fromEntries(Object.entries(outputs).map(([k, v]) => [k, v.slice(0, 240)])),
        stderrTail: r.err.slice(-600),
      };
      if (!ran || !confined || !controlKept || !said) {
        return done(dirs, { status: "fail", finding: `ran ${ran}, outside refused ${confined}, config kept ${controlKept}, start line ${said}; ${JSON.stringify(seen).slice(0, 1400)}`, seen });
      }
      return done(dirs, {
        status: "pass",
        finding: "from a fresh Codex home (no config.toml, no rules folder), under derm's srt Codex ran its command (marker written, its output reached the model); a write to HOME and one to ~/.codex/config.toml were refused; the start line says srt is Codex's sandbox",
        seen,
      });
    },
  },
  {
    id: "boundary-srt-codex-own-sandbox-refused",
    title: "MW5-32: derm refuses Codex's own sandbox named on the command line under srt, before anything starts",
    harness: "codex",
    async run({ binPath }) {
      const why = needs();
      if (why) return { status: "skip", finding: why };
      const cases = [
        ["-s", "workspace-write", "exec", "go"],
        ["exec", "--sandbox=read-only", "go"],
        ["exec", "-c", 'sandbox_mode="workspace-write"', "go"],
        ["--approve-for-me", "exec", "go"],
      ];
      const seen = [];
      for (const words of cases) {
        const dirs = box("refused");
        const marker = path.join(dirs.work, "started");
        // A stand-in Codex that leaves a mark if derm starts it.
        const stand = path.join(dirs.root, "codex-stand-in");
        writeFileSync(stand, `#!/bin/sh\ntouch '${marker}'\n`);
        chmodSync(stand, 0o755);
        const r = await derm(dirs, ["codex", "--boundary", "srt", "--no-daemon", "--no-tap", "--", ...words], { codexPath: stand, timeoutMs: 60000 });
        seen.push({ words: words.join(" "), exit: r.code, started: existsSync(marker), err: r.err.slice(-300) });
        done(dirs, null);
      }
      const bad = seen.filter((s) => s.exit !== 2 || s.started || !/Codex's own sandbox/.test(s.err));
      return bad.length
        ? { status: "fail", finding: JSON.stringify(bad).slice(0, 1400), seen }
        : { status: "pass", finding: `refused before any start, each naming Codex's own sandbox: ${seen.map((s) => s.words).join(" | ")}`, seen };
    },
  },
];
