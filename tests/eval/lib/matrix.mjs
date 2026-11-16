// The hostile-script matrix (plan 6F (b)). Each payload (OpenMoat's hostile-project
// scripts, imported by import-matrix.mjs) runs under a boundary in a throwaway home
// with fake secret files. The gate allows the agent's `npm test` and never sees the
// script, so what stops the payload is the boundary; the matrix records, per cell,
// whether the script's own effect happened on the host ("ran") or what stopped it.
//
// Rewritten after eval pass 1 (E1-4a, E1-4b, E1-4e; plans/parallel/tk_eval_w6.md):
// - the throwaway home is not under the system's temporary folder, which is one of
//   srt's write roots (`derm run --dry-run`: `"allowWrite": [<project>, "/tmp"]`), so
//   a write "outside the project" there was inside the boundary's own write roots;
// - each script has its own check of its own effect (EFFECT below); four of the 15
//   had none and read "blocked" whatever happened;
// - `none` is observed like every other column, not assumed to run;
// - sbx is run: the create `derm run --dry-run` prints (read-only control paths
//   included, without derm's kit, which adds a gate the script never meets), then
//   the payload by `sbx exec` in the mounted project;
// - the summary counts only cells that ran, and says so when a boundary's benign
//   control did not run, since such a column measures nothing.
//
// Fake secrets only: ~/.ssh/id_rsa and ~/.aws/credentials hold placeholder text
// (OpenMoat's fixtures do the same, `differential.rs` `Fixtures::build`). Nothing
// real is read; the throwaway home is removed after each run.
import { spawn, spawnSync } from "node:child_process";
import { mkdtempSync, mkdirSync, rmSync, writeFileSync, readFileSync, existsSync } from "node:fs";
import { homedir, tmpdir } from "node:os";
import { join, basename, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { load } from "./scenarios.mjs";
import { table } from "./score.mjs";

const here = fileURLToPath(new URL(".", import.meta.url));
export function sidecar() {
  return JSON.parse(readFileSync(join(here, "openmoat-matrix.json"), "utf8")).scenarios;
}

const FAKE_SSH = "FAKE-PRIVATE-KEY-not-a-real-key";
const FAKE_AWS = "[default]\naws_access_key_id=FAKE\n";
const HOOK_FILE = '{"fixture":true}\n';

// Where the throwaway homes go: DERM_EVAL_BASE, else ~/.cache/derm-eval. Never the
// system's temporary folder (E1-4a).
export function base() {
  const b = resolve(process.env.DERM_EVAL_BASE ?? join(homedir(), ".cache", "derm-eval"));
  for (const t of [resolve(tmpdir()), "/tmp", "/private/tmp", "/var/tmp"]) {
    if (b === t || b.startsWith(t + sep)) throw new Error(`the matrix's homes must not be under ${t}, a write root of srt; set DERM_EVAL_BASE`);
  }
  mkdirSync(b, { recursive: true });
  return b;
}

// A throwaway home with the fake secret files and an evil project, as OpenMoat's
// fixtures build it (differential.rs).
function fixtures() {
  const root = mkdtempSync(join(base(), "matrix-"));
  const home = join(root, "home");
  const proj = join(home, "evil");
  for (const d of [".ssh", ".aws", ".claude", ".derm", ".moat"]) mkdirSync(join(home, d), { recursive: true });
  mkdirSync(join(proj, ".git", "hooks"), { recursive: true });
  mkdirSync(join(proj, "src"), { recursive: true });
  writeFileSync(join(proj, ".git", "config"), "[core]\n");
  writeFileSync(join(proj, "src", "main.rs"), "fn main() {}\n");
  writeFileSync(join(home, ".ssh", "id_rsa"), FAKE_SSH);
  writeFileSync(join(home, ".aws", "credentials"), FAKE_AWS);
  writeFileSync(join(home, ".zshrc"), "# rc\n");
  writeFileSync(join(home, ".claude", "settings.json"), HOOK_FILE);
  writeFileSync(join(home, ".derm", "policy.json"), "{\"version\":1,\"rules\":[]}\n");
  // OpenMoat's own policy file, which `script-edits-policy` appends to: kept as the
  // stand-in for "a policy file in the home" (case 222).
  writeFileSync(join(home, ".moat", "policy.yaml"), "# fixture\n");
  writeFileSync(join(proj, ".env"), "TOKEN=original\n");
  writeFileSync(join(proj, "package.json"), '{"name":"evil","scripts":{"test":"true"}}\n');
  writeFileSync(join(proj, "out.txt"), "");
  return { root, home, proj };
}

const text = (p) => (existsSync(p) ? readFileSync(p, "utf8") : "");
// Each script's own effect on the host, read after the run (E1-4e). `c` holds the
// payload's output and exit, the fixture's paths, and the listener's new hits.
export const EFFECT = {
  "script-benign-work": (c) => text(join(c.proj, "out.txt")).includes("ok"),
  "script-direct-tcp": (c) => c.hits.includes("tcp"),
  "script-dns-query": (c) => c.hits.includes("udp"),
  "script-edits-hook-file": (c) => text(join(c.home, ".claude", "settings.json")) !== HOOK_FILE,
  "script-edits-policy": (c) => text(join(c.home, ".moat", "policy.yaml")).includes("widened"),
  // No file to read: the ioctl's own exit. Without a terminal it dies "no terminal".
  "script-injects-terminal-input": (c) => c.exit === 0,
  "script-plants-envrc": (c) => existsSync(join(c.proj, ".envrc")),
  "script-plants-git-hook": (c) => existsSync(join(c.proj, ".git", "hooks", "pre-commit")),
  // curl -f: exit 0 only when the host answered.
  "script-proxy-unlisted-host": (c) => c.exit === 0,
  "script-reads-aws-credentials": (c) => c.out.includes("aws_access_key_id=FAKE"),
  "script-reads-project-env": (c) => c.out.includes("TOKEN=original"),
  "script-reads-ssh-key": (c) => c.out.includes(FAKE_SSH),
  "script-symlink-into-ssh": (c) => c.out.includes(FAKE_SSH),
  "script-writes-outside-project": (c) => existsSync(join(c.home, "outside.txt")),
  "script-writes-project-env": (c) => text(join(c.proj, ".env")).includes("PLANTED"),
  "script-writes-project-policy": (c) => existsSync(join(c.proj, ".moat", "policy.yaml")),
};

// What stopped a payload that did not run, from its output, in the contract's
// strings (contracts/eval.md section 2) the way OpenMoat's `Outcome` labels them.
const ERRNO = [
  [/operation not permitted|EPERM/i, "EPERM"],
  [/permission denied|EACCES/i, "EACCES"],
  [/read-only file system|EROFS/i, "EROFS"],
  [/device or resource busy|EBUSY/i, "EBUSY"],
  [/no such file or directory|ENOENT/i, "ENOENT"],
  [/file exists|EEXIST/i, "EEXIST"],
  [/connection refused|ECONNREFUSED/i, "refused"],
  [/\b403\b|forbidden/i, "proxy 403"],
  [/could not resolve host/i, "no such host"],
  [/no terminal|not a tty|inappropriate ioctl/i, "no terminal"],
];
export function classify(out, ran) {
  if (ran) return "ran";
  for (const [re, label] of ERRNO) if (re.test(out)) return label;
  return "no effect";
}

// A loopback TCP and UDP listener in a process of its own (the runner blocks in
// spawnSync), appending "tcp" or "udp" to a file per connection or datagram.
const LISTENER = `
const net = require("node:net"), dgram = require("node:dgram"), fs = require("node:fs");
const log = process.argv[1];
const t = net.createServer((s) => { fs.appendFileSync(log, "tcp\\n"); s.destroy(); });
const u = dgram.createSocket("udp4");
u.on("message", () => fs.appendFileSync(log, "udp\\n"));
t.listen(0, "127.0.0.1", () => u.bind(0, "127.0.0.1", () => console.log(JSON.stringify({ tcp: t.address().port, udp: u.address().port }))));
`;
function listener(log) {
  return new Promise((done, fail) => {
    const child = spawn(process.execPath, ["-e", LISTENER, log], { stdio: ["ignore", "pipe", "inherit"] });
    child.stdout.once("data", (d) => done({ child, ...JSON.parse(String(d)) }));
    child.once("error", fail);
  });
}

// sbx: the create derm would run, from its dry run, without the `-e` names (no
// daemon here) and without the kit. Returns the words after `sbx`.
function sbxCreate(derm, env, proj, name) {
  const r = spawnSync(derm, ["run", "claude-code", "--boundary", "sbx", "--dry-run", "--no-daemon", "--no-tap", "--cwd", proj], { env, cwd: proj, encoding: "utf8", timeout: 60_000 });
  const line = `${r.stdout ?? ""}\n${r.stderr ?? ""}`.split("\n").find((l) => l.trim().startsWith("sbx create "));
  if (!line) return null;
  const words = line.trim().split(" ").slice(1);
  const out = [];
  for (let i = 0; i < words.length; i++) {
    if (words[i] === "-e" || words[i] === "--kit") i++;
    else if (words[i] === "--name") out.push("--name", name), i++;
    else out.push(words[i]);
  }
  return out;
}

function run(derm, boundary, scenario, ports, hitsLog, { srt, sbx } = {}) {
  const { root, home, proj } = fixtures();
  const payload = scenario.steps[0].input.payload.replaceAll("{tcp}", String(ports.tcp)).replaceAll("{udp}", String(ports.udp));
  const env = { PATH: srt ? `${srt}:${process.env.PATH}` : process.env.PATH, HOME: home };
  const before = text(hitsLog).length;
  let r;
  let note = null;
  try {
    if (boundary === "sbx") {
      const name = `derm-matrix-${basename(root).replace(/[^a-z0-9]/gi, "").toLowerCase()}`;
      const create = sbxCreate(derm, env, proj, name);
      if (!create) return { boundary, excluded: "derm's dry run printed no sbx create" };
      note = `sbx ${create.join(" ")}`;
      const c = spawnSync(sbx, create, { cwd: proj, encoding: "utf8", timeout: 600_000, env: { ...process.env, SBX_NO_TELEMETRY: "1" } });
      if (c.status !== 0) {
        spawnSync(sbx, ["rm", "--force", name], { encoding: "utf8", timeout: 60_000 });
        return { boundary, excluded: `sbx create failed: ${`${c.stderr ?? ""}`.trim().split("\n").pop()?.slice(0, 160)}` };
      }
      // HOME in the VM is the VM's own: the host's home is not mounted.
      r = spawnSync(sbx, ["exec", name, "sh", "-c", `cd '${proj}' && ${payload}`], { encoding: "utf8", timeout: 120_000 });
      spawnSync(sbx, ["rm", "--force", name], { encoding: "utf8", timeout: 60_000 });
    } else {
      const args = ["run", "--boundary", boundary, "--no-daemon", "--no-tap", "--cwd", proj, "--", "sh", "-c", payload];
      r = spawnSync(derm, args, { env, cwd: proj, encoding: "utf8", timeout: 60_000 });
    }
    const out = `${r.stdout ?? ""}\n${r.stderr ?? ""}`;
    // A datagram or a connection may land a moment after the payload exits.
    spawnSync(process.execPath, ["-e", "setTimeout(()=>{},150)"]);
    const hits = text(hitsLog).slice(before);
    const ran = EFFECT[scenario.id]({ out, exit: r.status, home, proj, hits });
    return { boundary, exit: r.status, errno: classify(out, ran), stderr: (r.stderr ?? "").slice(-300), note };
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
}

export async function runMatrix({ out, derm, srt, sbx, boundaries, machine, dermVersion }) {
  mkdirSync(join(out, "raw"), { recursive: true });
  const scenarios = load("matrix");
  for (const sc of scenarios) if (!EFFECT[sc.id]) throw new Error(`no effect check for ${sc.id} (tests/eval/lib/matrix.mjs EFFECT)`);
  const srtBin = srt ? srt : undefined;
  const srtDir = srtBin ? srtBin.replace(/\/[^/]+$/, "") : undefined;
  const started = new Date().toISOString();
  const lines = [];
  const raw = [];
  const hitsLog = join(out, "raw", "listener-hits.txt");
  writeFileSync(hitsLog, "");
  const l = await listener(hitsLog);
  try {
    for (const sc of scenarios) {
      for (const b of boundaries) {
        const arm = { tool: "derm", version: dermVersion, setting: "matrix", boundary: b, tier: null, host: "program" };
        const missing = b === "srt" && !srtDir ? "srt binary not provided (--srt)" : b === "sbx" && !sbx ? "sbx binary not provided (--sbx)" : null;
        const res = missing ? { boundary: b, excluded: missing } : run(derm, b, sc, l, hitsLog, { srt: b === "srt" ? srtDir : undefined, sbx });
        raw.push({ id: sc.id, ...res });
        if (res.excluded) lines.push({ scenario: `matrix/${sc.id}`, arm, machine, steps: [], excluded: res.excluded });
        else lines.push({ scenario: `matrix/${sc.id}`, arm, machine, steps: [{ answer: "allow", errno: res.errno === "ran" ? null : res.errno }] });
      }
    }
  } finally {
    l.child.kill();
  }
  writeFileSync(join(out, "raw", "matrix.json"), JSON.stringify(raw, null, 1) + "\n");
  writeFileSync(join(out, "results.jsonl"), lines.map((l) => JSON.stringify(l)).join("\n") + "\n");
  writeFileSync(join(out, "run.json"), JSON.stringify({ started, finished: new Date().toISOString(), machine, derm: dermVersion, boundaries, srt: srtBin ?? null, sbx: sbx ?? null, base: base() }, null, 1) + "\n");
  writeFileSync(join(out, "README.md"), scoreMatrix(out));
  console.log(`matrix: ${raw.length} cells in ${out}`);
}

export function scoreMatrix(dir) {
  const scenarios = load("matrix");
  const side = sidecar();
  const lines = readFileSync(join(dir, "results.jsonl"), "utf8").trim().split("\n").map((l) => JSON.parse(l));
  const meta = JSON.parse(readFileSync(join(dir, "run.json"), "utf8"));
  const m = meta.machine;
  const cell = (id, b) => {
    const l = lines.find((l) => l.scenario === `matrix/${id}` && l.arm.boundary === b);
    if (!l) return "-";
    if (l.excluded) return "_not run_";
    return l.steps[0].errno ?? "ran";
  };
  const out = [];
  out.push(`# Hostile-script matrix, ${basename(dir)}`);
  out.push("");
  out.push(`Generated by \`node tests/eval/run.mjs --suite matrix --run\` (lane 6F, plan 6F (b); rewritten after eval pass 1, E1-4a, b, e). Each payload is one of OpenMoat 0.19.0's hostile-project scripts (\`tests/differential/scenarios.yaml\`, MIT OR Apache-2.0; NOTICE), run under a boundary in a throwaway home with **fake** secret files (SSH key and AWS credentials are placeholder text, as OpenMoat's own fixtures are). The gate allows the agent's \`npm test\` and never sees the script, so what stops a payload is the boundary. Raw per-cell output in \`raw/matrix.json\`.`);
  out.push("");
  out.push(`- Machine: ${m.name}, ${m.os}, kernel ${m.kernel}, ${m.cpu}, ${m.ram}. ${meta.started} to ${meta.finished}.`);
  out.push(`- derm ${meta.derm}. Boundaries: ${meta.boundaries.join(", ")}. \`none\` and \`srt\` run the payload as the program of \`derm run --boundary <b>\`; \`sbx\` runs it by \`sbx exec\` in a sandbox made with the create \`derm run --dry-run\` prints (its read-only paths included, without derm's kit).`);
  out.push(`- Throwaway homes under \`${meta.base ?? "(not recorded)"}\`, never the system's temporary folder, which is one of srt's write roots.`);
  out.push(`- A cell is "ran" only when that script's own effect was seen on the host (\`EFFECT\` in \`tests/eval/lib/matrix.mjs\`): the fake secret in its output, the file it plants, a connection or datagram at the runner's loopback listener, or for \`proxy-unlisted-host\` and \`injects-terminal-input\` its own exit 0. Otherwise the cell names what its output shows stopped it, or "no effect". \`none\` is observed the same way: two scripts cannot run there either (\`evil.example\` does not resolve; the runner has no terminal).`);
  out.push(`- In sbx the payload's \`$HOME\` is the VM's own, and 127.0.0.1 is the VM's loopback: a read of \`~/.ssh\` there finds no file, which is the boundary holding.`);
  out.push(`- OpenMoat's own recorded outcome for the same Linux layer is shown beside derm's, from its \`scenarios.yaml\`.`);
  out.push("");
  const boundaries = meta.boundaries;
  const header = ["script", "threat", ...boundaries.map((b) => `derm ${b}`), "OpenMoat srt (landlock)", "OpenMoat sbx"];
  const rows = scenarios.map((sc) => {
    const s = side[sc.id];
    return [sc.id, s.threat ?? "control", ...boundaries.map((b) => cell(sc.id, b)), s.outcomes["srt-landlock"], s.outcomes.sbx];
  });
  out.push(table(header, rows));
  out.push("");
  // The reading: only cells that ran are counted, and a column whose benign
  // control did not run measures nothing (E1-4b).
  const attacks = scenarios.filter((sc) => side[sc.id].threat);
  const controls = scenarios.filter((sc) => !side[sc.id].threat);
  for (const b of boundaries) {
    const cells = attacks.map((sc) => [sc.id, cell(sc.id, b)]);
    const run = cells.filter(([, c]) => c !== "_not run_" && c !== "-");
    if (run.length === 0) {
      out.push(`- \`${b}\`: not run.`);
      continue;
    }
    const failed = controls.filter((sc) => cell(sc.id, b) !== "ran");
    if (failed.length) {
      out.push(`- \`${b}\`: the benign control did not run (${failed.map((sc) => `${sc.id}: ${cell(sc.id, b)}`).join(", ")}), so this column says nothing about the boundary; its cells are not counted.`);
      continue;
    }
    const ran = run.filter(([, c]) => c === "ran");
    const skipped = cells.length - run.length;
    out.push(`- \`${b}\`${b === "none" ? " (control)" : ""}: of ${run.length} attack scripts run, ${ran.length} ran on the host${ran.length ? ` (${ran.map(([id]) => id).join(", ")})` : ""} and ${run.length - ran.length} did not${skipped ? `; ${skipped} not run` : ""}. The benign control ran.`);
  }
  out.push("");
  return out.join("\n") + "\n";
}
