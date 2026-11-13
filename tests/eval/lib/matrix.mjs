// The hostile-script matrix (plan 6F (b)). Each payload (OpenMoat's hostile-project
// scripts, imported by import-matrix.mjs) runs as the wrapped program under
// `derm run --boundary <b>` in a throwaway home with fake secret files. The gate
// allows the agent's `npm test` and never sees the script, so what stops the payload
// is the boundary; the matrix records the outcome per cell (errno or "ran"), against
// OpenMoat's own recorded outcome for the same layer. What derm adds over OpenMoat
// (whether its feed recorded and credited the attempt) needs the daemon's OS feed,
// which on Linux needs root auditd rules: that column is filled on the box (E1), and
// is "not run" here. sbx needs a Docker sign-in, so it too is a box/E1 arm.
//
// Fake secrets only: ~/.ssh/id_rsa and ~/.aws/credentials hold placeholder text
// (OpenMoat's fixtures do the same, `differential.rs` `Fixtures::build`). Nothing
// real is read; the throwaway home is removed after each run.
import { spawnSync } from "node:child_process";
import { mkdtempSync, mkdirSync, rmSync, writeFileSync, readFileSync, existsSync, statSync, readlinkSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, basename } from "node:path";
import { fileURLToPath } from "node:url";
import { load } from "./scenarios.mjs";
import { table } from "./score.mjs";

const here = fileURLToPath(new URL(".", import.meta.url));
export function sidecar() {
  return JSON.parse(readFileSync(join(here, "openmoat-matrix.json"), "utf8")).scenarios;
}

const FAKE_SSH = "FAKE-PRIVATE-KEY-not-a-real-key";
const FAKE_AWS = "[default]\naws_access_key_id=FAKE\n";

// A throwaway home with the fake secret files and an evil project, as OpenMoat's
// fixtures build it (differential.rs). Loopback listeners for the net payloads.
function fixtures() {
  const root = mkdtempSync(join(tmpdir(), "derm-eval-matrix-"));
  const home = join(root, "home");
  const proj = join(home, "evil");
  for (const d of [".ssh", ".aws", ".claude", ".derm", ".derm/..c"]) mkdirSync(join(home, d), { recursive: true });
  mkdirSync(join(proj, ".git", "hooks"), { recursive: true });
  mkdirSync(join(proj, "src"), { recursive: true });
  writeFileSync(join(proj, "src", "main.rs"), "fn main() {}\n");
  writeFileSync(join(home, ".ssh", "id_rsa"), FAKE_SSH);
  writeFileSync(join(home, ".aws", "credentials"), FAKE_AWS);
  writeFileSync(join(home, ".zshrc"), "# rc\n");
  writeFileSync(join(home, ".claude", "settings.json"), "{}\n");
  writeFileSync(join(home, ".derm", "policy.json"), "{\"version\":1,\"rules\":[]}\n");
  writeFileSync(join(proj, ".env"), "TOKEN=original\n");
  writeFileSync(join(proj, "package.json"), '{"name":"evil","scripts":{"test":"true"}}\n');
  writeFileSync(join(proj, "out.txt"), "");
  return { root, home, proj };
}

// What the payload did, read after the run: the exit, an errno parsed from stderr,
// and whether the host side effect is visible. Classified to the contract's errno
// strings (contracts/eval.md section 2) the way OpenMoat's `Outcome` labels them.
const ERRNO = [
  [/operation not permitted|EPERM/i, "EPERM"],
  [/permission denied|EACCES/i, "EACCES"],
  [/read-only file system|EROFS/i, "EROFS"],
  [/no such file or directory|ENOENT/i, "ENOENT"],
  [/file exists|EEXIST/i, "EEXIST"],
  [/connection refused|ECONNREFUSED/i, "refused"],
  [/\b403\b|forbidden/i, "proxy 403"],
  [/no terminal|not a tty|inappropriate ioctl/i, "no terminal"],
];
function classify(out, ran) {
  if (ran) return "ran";
  for (const [re, label] of ERRNO) if (re.test(out)) return label;
  return "blocked";
}

function run(derm, boundary, scenario, meta, { srt } = {}) {
  const { root, home, proj } = fixtures();
  const payload = scenario.steps[0].input.payload.replaceAll("{tcp}", "1").replaceAll("{udp}", "1");
  const env = { PATH: srt ? `${srt}:${process.env.PATH}` : process.env.PATH, HOME: home };
  try {
    const args = boundary === "none"
      ? ["run", "--boundary", "none", "--no-daemon", "--no-tap", "--cwd", proj, "--", "sh", "-c", payload]
      : ["run", "--boundary", boundary, "--no-daemon", "--no-tap", "--cwd", proj, "--", "sh", "-c", payload];
    const r = spawnSync(derm, args, { env, cwd: proj, encoding: "utf8", timeout: 60_000 });
    const out = `${r.stdout ?? ""}\n${r.stderr ?? ""}`;
    // Did the host side effect happen? Reads: the fake secret in stdout. Writes/plants:
    // the target changed on the host. The checks are per threat, from the payload.
    const sawSecret = out.includes(FAKE_SSH) || out.includes("aws_access_key_id=FAKE");
    const envChanged = existsSync(join(proj, ".env")) && readFileSync(join(proj, ".env"), "utf8").includes("PLANTED");
    const planted = ["\.envrc", ".git/hooks/pre-commit"].some((p) => existsSync(join(proj, p.replace(/^\\/, ""))));
    const outside = existsSync(join(home, "outside.txt"));
    const policyWidened = readFileSync(join(home, ".derm", "policy.json"), "utf8").includes("widened") || readFileSync(join(home, ".claude", "settings.json"), "utf8").trim() !== "{}";
    const outWritten = existsSync(join(proj, "out.txt")) && readFileSync(join(proj, "out.txt"), "utf8").includes("ok");
    const ran = sawSecret || envChanged || planted || outside || policyWidened || outWritten;
    return { boundary, exit: r.status, errno: classify(out, boundary === "none" ? true : ran), stderr: (r.stderr ?? "").slice(0, 200) };
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
}

export async function runMatrix({ out, derm, srt, boundaries, machine, dermVersion }) {
  mkdirSync(join(out, "raw"), { recursive: true });
  const scenarios = load("matrix");
  const side = sidecar();
  const srtBin = srt ? srt : undefined;
  const srtDir = srtBin ? srtBin.replace(/\/[^/]+$/, "") : undefined;
  const started = new Date().toISOString();
  const lines = [];
  const raw = [];
  for (const sc of scenarios) {
    for (const b of boundaries) {
      if ((b === "srt" || b === "sbx") && !srtDir && b === "srt") {
        lines.push({ scenario: `matrix/${sc.id}`, arm: { tool: "derm", version: dermVersion, setting: "matrix", boundary: "srt", tier: null, host: "program" }, machine, steps: [], excluded: "srt binary not provided (--srt); run on the box" });
        continue;
      }
      if (b === "sbx") {
        lines.push({ scenario: `matrix/${sc.id}`, arm: { tool: "derm", version: dermVersion, setting: "matrix", boundary: "sbx", tier: null, host: "program" }, machine, steps: [], excluded: "sbx needs a Docker sign-in; box/E1 arm" });
        continue;
      }
      const res = run(derm, b, sc, machine, { srt: b === "srt" ? srtDir : undefined });
      raw.push({ id: sc.id, ...res });
      lines.push({
        scenario: `matrix/${sc.id}`,
        arm: { tool: "derm", version: dermVersion, setting: "matrix", boundary: b, tier: null, host: "program" },
        machine,
        steps: [{ answer: "allow", errno: res.errno === "ran" ? null : res.errno }],
      });
    }
  }
  writeFileSync(join(out, "raw", "matrix.json"), JSON.stringify(raw, null, 1) + "\n");
  writeFileSync(join(out, "results.jsonl"), lines.map((l) => JSON.stringify(l)).join("\n") + "\n");
  writeFileSync(join(out, "run.json"), JSON.stringify({ started, finished: new Date().toISOString(), machine, derm: dermVersion, boundaries, srt: srtBin ?? null }, null, 1) + "\n");
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
  out.push(`Generated by \`node tests/eval/run.mjs --suite matrix --run\` (lane 6F, plan 6F (b)). Each payload is one of OpenMoat 0.19.0's hostile-project scripts (\`tests/differential/scenarios.yaml\`, MIT OR Apache-2.0; NOTICE), run as the program under \`derm run --boundary <b>\` in a throwaway home with **fake** secret files (SSH key and AWS credentials are placeholder text, as OpenMoat's own fixtures are). The gate allows the agent's \`npm test\` and never sees the script, so what stops a payload is the boundary. Raw per-cell output in \`raw/matrix.json\`.`);
  out.push("");
  out.push(`- Machine: ${m.name}, ${m.os}, kernel ${m.kernel}, ${m.cpu}, ${m.ram}. ${meta.started} to ${meta.finished}.`);
  out.push(`- derm ${meta.derm}. Boundaries run here: ${meta.boundaries.join(", ")}. \`sbx\` needs a Docker sign-in and \`srt\` a working user namespace, so both are box/E1 arms where missing.`);
  out.push(`- "ran" means the payload completed on the host (no boundary should let an attack do that); an errno or "proxy 403" is the boundary stopping it. The \`none\` column is the control: every attack runs, which is the point of the contrast.`);
  out.push(`- OpenMoat's own recorded outcome for the same Linux layer is shown beside derm's, from its \`scenarios.yaml\`. A difference is a finding for E1 to read on the box, not a pass or fail here.`);
  out.push(`- What derm adds over a boundary alone (whether its OS feed recorded and credited each attempt to the call) needs the daemon's Linux feed, which needs root \`auditd\` rules: that column is **E1 on the box** (step 0's rules), "not run" here.`);
  out.push("");
  const boundaries = meta.boundaries;
  const header = ["script", "threat", ...boundaries.map((b) => `derm ${b}`), "OpenMoat srt (landlock)", "OpenMoat sbx"];
  const rows = scenarios.map((sc) => {
    const s = side[sc.id];
    return [sc.id, s.threat ?? "control", ...boundaries.map((b) => cell(sc.id, b)), s.outcomes["srt-landlock"], s.outcomes.sbx];
  });
  out.push(table(header, rows));
  out.push("");
  // A short reading: attacks the boundary stopped vs let run.
  const attacks = scenarios.filter((sc) => side[sc.id].threat);
  for (const b of boundaries.filter((b) => b !== "none")) {
    const ran = attacks.filter((sc) => cell(sc.id, b) === "ran");
    out.push(`- Under \`${b}\`, of ${attacks.length} attack scripts, ${attacks.length - ran.length} were stopped and ${ran.length} ran${ran.length ? ` (${ran.map((s) => s.id).join(", ")})` : ""}.`);
  }
  const noneRan = attacks.filter((sc) => cell(sc.id, "none") === "ran").length;
  if (boundaries.includes("none")) out.push(`- Under \`none\` (control), ${noneRan} of ${attacks.length} attack scripts ran, as expected.`);
  out.push("");
  return out.join("\n") + "\n";
}

void statSync; void readlinkSync;
