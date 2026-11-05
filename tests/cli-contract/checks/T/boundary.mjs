// Lane T (wave 5): `derm run` with no `--boundary`, against the real Pi
// 1.4.0 and the real srt 0.0.81, with sbx faked (sbx needs KVM and a Docker
// sign-in, neither of which a cloud workspace has; the box test and the Mac
// test run the real one). Cases 118 and 129 of the rules.
//
//   cargo build -p derm-cli
//   DERM_BIN=<target>/debug/derm SRT_BIN=/tmp/cli/node_modules/.bin/srt \
//     node tests/cli-contract/run.mjs --cli pi=/tmp/cli/node_modules/.bin/pi \
//     --only boundary-default-srt,boundary-srt-confines,boundary-sbx-signed-out,boundary-sbx-chosen,boundary-none-stops,boundary-pre-answer,boundary-terminal
//
// derm is DERM_BIN, else target/release/derm, else target/debug/derm. srt is
// SRT_BIN, else /tmp/cli/node_modules/.bin/srt; on Linux it also needs
// bwrap, socat and rg in /usr/bin. Every check runs `derm run --no-daemon`
// in a throwaway HOME and folder, with PATH holding only what the check
// puts there, node, /usr/bin and /bin. No network, no account.

import { spawnSync } from "node:child_process";
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../../..");

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

/** A throwaway HOME, working folder and bin folder, outside /tmp where it
 *  can be: derm's srt settings let a chat write /tmp, so a HOME under it
 *  would not show the boundary. */
function box(name) {
  const base = process.env.CLI_CONTRACT_TMP ?? (existsSync("/var/tmp") ? "/var/tmp" : tmpdir());
  const root = mkdtempSync(path.join(base, `boundary-${name}-`));
  const dirs = { root, home: path.join(root, "home"), work: path.join(root, "work"), bin: path.join(root, "bin") };
  for (const d of [dirs.home, dirs.work, dirs.bin]) mkdirSync(d);
  return dirs;
}

function script(dir, name, body) {
  const p = path.join(dir, name);
  writeFileSync(p, `#!/bin/sh\n${body}\n`);
  chmodSync(p, 0o755);
  return p;
}

/** A fake sbx: logs each call with the telemetry switch it saw. `ls` says
 *  "not signed in" when `signedIn` is false (sbx 0.51.0's words, the smoke
 *  test); everything else exits 0. */
function fakeSbx(dir, { signedIn }) {
  const log = path.join(dir, "..", "sbx-calls");
  script(
    dir,
    "sbx",
    `echo "$* | telemetry=\${SBX_NO_TELEMETRY:-unset}" >> '${log}'\n` +
      `case "$1" in\n` +
      `  version) echo 'sbx version v0.51.0 fake' ;;\n` +
      `  ls) ${signedIn ? "exit 0" : "echo 'error: not signed in to Docker' >&2; exit 1"} ;;\n` +
      `esac\nexit 0`,
  );
  return log;
}

function derm(dirs, args, { input = "" } = {}) {
  const PATH = [dirs.bin, path.dirname(process.execPath), "/usr/bin", "/bin"].join(":");
  const r = spawnSync(dermBin(), ["run", ...args], {
    cwd: dirs.work,
    env: { PATH, HOME: dirs.home, LANG: "C" },
    input,
    encoding: "utf8",
    timeout: 120000,
  });
  return { code: r.status, out: r.stdout ?? "", err: r.stderr ?? "" };
}

function needs({ srt = true } = {}) {
  if (!dermBin()) return "no derm binary (DERM_BIN, target/release, target/debug)";
  if (srt && !srtBin()) return "no srt (SRT_BIN, /tmp/cli/node_modules/.bin/srt)";
  if (srt && process.platform === "linux" && !["bwrap", "socat", "rg"].every((t) => existsSync(`/usr/bin/${t}`))) {
    return "srt's Linux tools (bwrap, socat, rg) are not in /usr/bin";
  }
  return null;
}

function withPi(dirs, binPath, { srt = true } = {}) {
  symlinkSync(binPath, path.join(dirs.bin, "pi"));
  if (srt) symlinkSync(srtBin(), path.join(dirs.bin, "srt"));
}

/** derm-pi registered as `derm status` reads it (`watch/register.rs`, `pi`):
 *  a local package folder whose package.json is named
 *  `@aetiusgular/derm-pi`, listed in `~/.pi/agent/settings.json`. The folder
 *  is a stand-in with no extension: `pi --version` loads none. */
function registerDermPi(dirs) {
  const pkg = path.join(dirs.root, "derm-pi");
  mkdirSync(pkg);
  writeFileSync(path.join(pkg, "package.json"), JSON.stringify({ name: "@aetiusgular/derm-pi", version: "0.0.0" }));
  const agent = path.join(dirs.home, ".pi", "agent");
  mkdirSync(agent, { recursive: true });
  writeFileSync(path.join(agent, "settings.json"), JSON.stringify({ packages: [pkg] }));
}

const done = (dirs, result) => {
  rmSync(dirs.root, { recursive: true, force: true });
  return result;
};

export const checks = [
  {
    id: "boundary-default-srt",
    title: "no --boundary, no sbx: derm picks srt and the real Pi starts under it; with derm's gate registered, srt comes before a signed-in sbx",
    harness: "pi",
    async run({ binPath, version }) {
      const why = needs();
      if (why) return { status: "skip", finding: why };
      const dirs = box("srt");
      withPi(dirs, binPath);
      const r = derm(dirs, ["pi", "--no-daemon", "--", "--version"]);
      const v = (version ?? "").split(" ").pop();
      if (r.code !== 0 || !r.out.includes(v)) {
        return done(dirs, { status: "fail", finding: `exit ${r.code}; stdout ${JSON.stringify(r.out.slice(0, 200))}; stderr ${JSON.stringify(r.err.slice(-400))}` });
      }
      if (!/no --boundary given; pi runs under srt \(sbx: sbx is not installed/.test(r.err)) {
        return done(dirs, { status: "fail", finding: `no note of the choice: ${JSON.stringify(r.err.slice(0, 300))}` });
      }
      rmSync(dirs.root, { recursive: true, force: true });
      // Phase 4, item 2 (Tony's O1 decision, the interim half): Pi with
      // derm's gate registered (its row blocks when it fails) and sbx
      // installed and signed in. derm picks srt, which keeps the gate, and
      // never calls sbx; a named --boundary sbx still picks sbx (D1).
      const gated = box("srt-gated");
      withPi(gated, binPath);
      const log = fakeSbx(gated.bin, { signedIn: true });
      registerDermPi(gated);
      const g = derm(gated, ["pi", "--no-daemon", "--", "--version"]);
      const calls = existsSync(log) ? readFileSync(log, "utf8") : "";
      if (g.code !== 0 || !g.out.includes(v) || !/no --boundary given; pi runs under srt, which keeps derm's gate/.test(g.err)) {
        return done(gated, { status: "fail", finding: `gated: exit ${g.code}; stderr ${JSON.stringify(g.err.slice(0, 400))}` });
      }
      if (calls !== "") {
        return done(gated, { status: "fail", finding: `gated: sbx was called though srt would do: ${JSON.stringify(calls)}` });
      }
      const dry = derm(gated, ["pi", "--boundary", "sbx", "--no-daemon", "--dry-run", "--", "--version"]);
      if (dry.code !== 0 || !/sbx/.test(dry.out + dry.err) || /runs under srt/.test(dry.err)) {
        return done(gated, { status: "fail", finding: `gated, --boundary sbx named: exit ${dry.code}; ${JSON.stringify((dry.out + dry.err).slice(0, 300))}` });
      }
      return done(gated, {
        status: "pass",
        finding: `srt chosen with sbx's reason; Pi ${v} answered under it. With derm-pi registered and sbx signed in: srt first, sbx never called; --boundary sbx still plans sbx`,
      });
    },
  },
  {
    id: "boundary-srt-confines",
    title: "the srt derm picked is a real boundary: a write to HOME outside the chat's folders is refused",
    harness: "pi",
    async run({ binPath }) {
      const why = needs();
      if (why) return { status: "skip", finding: why };
      const dirs = box("confine");
      withPi(dirs, binPath);
      const outside = path.join(dirs.home, "outside-the-chat");
      const inside = path.join(dirs.work, "inside-the-chat");
      const r1 = derm(dirs, ["--no-daemon", "--", "/usr/bin/touch", outside]);
      const r2 = derm(dirs, ["--no-daemon", "--", "/usr/bin/touch", inside]);
      if (!r1.err.includes("runs under srt") || !r2.err.includes("runs under srt")) {
        return done(dirs, { status: "fail", finding: `srt was not chosen: ${JSON.stringify(r1.err.slice(0, 300))}` });
      }
      if (existsSync(outside) || r1.code === 0) {
        return done(dirs, { status: "fail", finding: `touch outside the chat's folders: exit ${r1.code}, file there: ${existsSync(outside)}` });
      }
      if (!existsSync(inside) || r2.code !== 0) {
        return done(dirs, { status: "fail", finding: `touch in the working folder: exit ${r2.code}; ${r2.err.slice(-300)}` });
      }
      return done(dirs, { status: "pass", finding: `HOME write refused (exit ${r1.code}), working-folder write allowed` });
    },
  },
  {
    id: "boundary-sbx-signed-out",
    title: "case 118: sbx installed and signed out, derm falls back to srt and says why",
    harness: "pi",
    async run({ binPath, version }) {
      const why = needs();
      if (why) return { status: "skip", finding: why };
      const dirs = box("signedout");
      withPi(dirs, binPath);
      const log = fakeSbx(dirs.bin, { signedIn: false });
      const r = derm(dirs, ["pi", "--no-daemon", "--", "--version"]);
      const calls = existsSync(log) ? readFileSync(log, "utf8") : "";
      const v = (version ?? "").split(" ").pop();
      if (r.code !== 0 || !r.out.includes(v) || !/runs under srt \(sbx: sbx is installed and not signed in to Docker\)/.test(r.err)) {
        return done(dirs, { status: "fail", finding: `exit ${r.code}; stderr ${JSON.stringify(r.err.slice(0, 400))}` });
      }
      if (!/^version \| telemetry=1$/m.test(calls) || !/^ls -q --no-input \| telemetry=1$/m.test(calls) || /^(run|create)/m.test(calls)) {
        return done(dirs, { status: "fail", finding: `sbx calls: ${JSON.stringify(calls)}` });
      }
      return done(dirs, { status: "pass", finding: "probed version and ls with telemetry off, fell back to srt, Pi answered" });
    },
  },
  {
    id: "boundary-sbx-chosen",
    title: "sbx installed and signed in: derm picks it; with request T-2 it creates, attaches and removes the sandbox",
    harness: "pi",
    async run() {
      const why = needs({ srt: false });
      if (why) return { status: "skip", finding: why };
      const dirs = box("sbx");
      const log = fakeSbx(dirs.bin, { signedIn: true });
      const r = derm(dirs, ["pi", "--no-daemon", "--", "--version"]);
      const calls = existsSync(log) ? readFileSync(log, "utf8").trim().split("\n") : [];
      if (r.code !== 0 || !r.err.includes("pi runs under sbx (installed and signed in)")) {
        return done(dirs, { status: "fail", finding: `exit ${r.code}; stderr ${JSON.stringify(r.err.slice(0, 400))}` });
      }
      const steps = calls.filter((l) => !/^(version|ls|policy log) /.test(l)).map((l) => l.split(" | ")[0]);
      if (steps[0]?.startsWith("create ")) {
        const ok =
          /^create --name derm-[0-9a-f]{12} .*docker\.io\/sbx\/pi-kit:latest \S+$/.test(steps[0]) &&
          !steps[0].includes("--kit") &&
          /^run --name derm-[0-9a-f]{12}( -e \S+)* -- --version$/.test(steps[1] ?? "") &&
          /^rm --force derm-[0-9a-f]{12}$/.test(steps.at(-1) ?? "");
        return done(dirs, ok ? { status: "pass", finding: `sbx chosen; ${steps.length} steps: create (kit positional), attach, remove` } : { status: "fail", finding: `sbx steps: ${JSON.stringify(steps)}` });
      }
      // Before integration applies request T-2: plan.rs's one `sbx run`.
      const one = steps.length === 1 && /^run --name derm-derm-[0-9a-f]{12} .*--kit docker\.io\/sbx\/pi-kit:latest pi /.test(steps[0]);
      return done(dirs, one ? { status: "info", finding: "sbx chosen; request T-2 not applied, so one `sbx run` with --kit (SB1) and no removal (SB3)" } : { status: "fail", finding: `sbx steps: ${JSON.stringify(steps)}` });
    },
  },
  {
    id: "boundary-none-stops",
    title: "case 129: no boundary and no one at a terminal, derm warns, names each reason and its install line, and stops",
    harness: "pi",
    async run({ binPath }) {
      const why = needs({ srt: false });
      if (why) return { status: "skip", finding: why };
      const dirs = box("stop");
      withPi(dirs, binPath, { srt: false });
      const r = derm(dirs, ["pi", "--no-daemon", "--", "--version"]);
      const named = r.err.includes("sbx: sbx is not installed") && r.err.includes("To use it: ") && r.err.includes("srt: srt is not installed") && r.err.includes("npm install -g @anthropic-ai/sandbox-runtime");
      if (r.code !== 2 || r.out.trim() !== "" || !named || !r.err.includes("no one is at a terminal")) {
        return done(dirs, { status: "fail", finding: `exit ${r.code}; stdout ${JSON.stringify(r.out.slice(0, 100))}; stderr ${JSON.stringify(r.err.slice(0, 600))}` });
      }
      return done(dirs, { status: "pass", finding: "exit 2, Pi never started, both reasons and install lines named" });
    },
  },
  {
    id: "boundary-pre-answer",
    title: "case 129: a pre-answer of run-as-you in a private settings file runs; the same file writable by others stops",
    harness: "pi",
    async run({ binPath, version }) {
      const why = needs({ srt: false });
      if (why) return { status: "skip", finding: why };
      const dirs = box("pre");
      withPi(dirs, binPath, { srt: false });
      mkdirSync(path.join(dirs.home, ".derm"), { mode: 0o700 });
      const f = path.join(dirs.home, ".derm", "settings.json");
      writeFileSync(f, JSON.stringify({ version: 1, boundary: { preAnswer: "run-as-you" } }), { mode: 0o600 });
      const ok = derm(dirs, ["pi", "--no-daemon", "--", "--version"]);
      chmodSync(f, 0o666);
      const loose = derm(dirs, ["pi", "--no-daemon", "--", "--version"]);
      const v = (version ?? "").split(" ").pop();
      if (ok.code !== 0 || !ok.out.includes(v) || !ok.err.includes('pre-answers "run-as-you"')) {
        return done(dirs, { status: "fail", finding: `private file: exit ${ok.code}; ${JSON.stringify(ok.err.slice(-300))}` });
      }
      if (loose.code !== 2 || loose.out.trim() !== "" || !loose.err.includes("counts as unset")) {
        return done(dirs, { status: "fail", finding: `file others can write: exit ${loose.code}; ${JSON.stringify(loose.err.slice(-300))}` });
      }
      return done(dirs, { status: "pass", finding: "0600 pre-answer ran Pi as you; 0666 counted as unset and stopped" });
    },
  },
  {
    id: "boundary-terminal",
    title: "case 129: with a person at a terminal (a pty), yes runs as you and no stops",
    harness: "pi",
    async run({ binPath, version }) {
      const why = needs({ srt: false });
      if (why) return { status: "skip", finding: why };
      if (!existsSync("/usr/bin/python3")) return { status: "skip", finding: "no /usr/bin/python3 for the pty" };
      const dirs = box("tty");
      withPi(dirs, binPath, { srt: false });
      const driver = path.join(dirs.root, "pty.py");
      writeFileSync(
        driver,
        [
          "import os, pty, select, sys, time",
          "answer = sys.argv[1].encode()",
          "pid, fd = pty.fork()",
          "if pid == 0:",
          "    os.execvpe(sys.argv[2], sys.argv[2:], os.environ)",
          "out = b''; sent = False; end = time.time() + 60",
          "while time.time() < end:",
          "    r, _, _ = select.select([fd], [], [], 0.2)",
          "    if fd in r:",
          "        try: chunk = os.read(fd, 4096)",
          "        except OSError: break",
          "        if not chunk: break",
          "        out += chunk",
          "        if not sent and b'Type yes' in out:",
          "            os.write(fd, answer + b'\\n'); sent = True",
          "_, st = os.waitpid(pid, 0)",
          "sys.stdout.write(out.decode(errors='replace'))",
          "sys.stdout.write('\\nEXIT %d\\n' % os.waitstatus_to_exitcode(st))",
        ].join("\n"),
      );
      const PATH = [dirs.bin, path.dirname(process.execPath), "/usr/bin", "/bin"].join(":");
      const via = (answer) =>
        spawnSync("/usr/bin/python3", ["-I", driver, answer, dermBin(), "run", "pi", "--no-daemon", "--", "--version"], {
          cwd: dirs.work,
          env: { PATH, HOME: dirs.home, LANG: "C" },
          encoding: "utf8",
          timeout: 90000,
        }).stdout ?? "";
      const yes = via("yes");
      const no = via("no");
      const v = (version ?? "").split(" ").pop();
      if (!yes.includes("Type yes") || !yes.includes(v) || !/EXIT 0\s*$/.test(yes)) {
        return done(dirs, { status: "fail", finding: `yes: ${JSON.stringify(yes.slice(-400))}` });
      }
      if (no.includes(v) || !/EXIT 2\s*$/.test(no) || !no.includes("the answer was not yes")) {
        return done(dirs, { status: "fail", finding: `no: ${JSON.stringify(no.slice(-400))}` });
      }
      return done(dirs, { status: "pass", finding: "asked once on the terminal; yes ran Pi as you, no stopped with exit 2" });
    },
  },
];
