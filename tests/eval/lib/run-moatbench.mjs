// `run.mjs --suite moatbench --run` and `--score` (plan 6F (a); contracts/eval.md section 4).
import { mkdirSync, writeFileSync, readFileSync, existsSync } from "node:fs";
import { join, basename } from "node:path";
import { load } from "./scenarios.mjs";
import { runBench, FAIL_HOOK, calibration, answers, openmoatAnswers, sandboxedSteps, DERM_HOOK, NOT_COMPARABLE } from "./moatbench.mjs";
import { probe } from "./probe.mjs";
import { tally, attackLine, table, category } from "./score.mjs";

const E0_SEEN = new Set(
  JSON.parse(readFileSync(new URL("../../../contracts/fixtures/eval/moatbench-e0-allowed.json", import.meta.url), "utf8")).scenarios.map((s) => s.id),
);

const quote = (s) => `'${s.replaceAll("'", `'\\''`)}'`;

// An arm is { tool, version, setting, hosts: { host: command } } or OpenMoat's own run.
function dermArm(derm, policyDir, setting, version) {
  const env = setting === "none" ? "" : `DERM_POLICY=${quote(join(policyDir, `${setting}.json`))} `;
  const hosts = {};
  for (const [h, sub] of Object.entries(DERM_HOOK)) hosts[h] = `${env}${quote(derm)} hook ${sub}`;
  return { tool: "derm", version, setting, hosts };
}

export async function runMoatbench({ out, openmoat, derm, policyDir, hosts, arms, extra, versions, sha, machine, openmoatTarball }) {
  mkdirSync(join(out, "raw"), { recursive: true });
  const scenarios = load("moatbench");
  const started = new Date().toISOString();
  const cwd = "/";
  const dermVersion = versions.derm.replace(/^derm /, "");
  const omVersion = versions.openmoat.replace(/^openmoat /, "").split(" ")[0];
  const armList = [];
  for (const a of arms) {
    if (a === "openmoat") armList.push({ tool: "openmoat", version: omVersion, setting: "default", native: true });
    else if (a.startsWith("derm:")) armList.push(dermArm(derm, policyDir, a.slice(5), dermVersion));
    else throw new Error(`unknown arm ${a}`);
  }
  armList.push(...extra);

  // Calibration: the host's `want` for every step it runs (moatbench.mjs).
  const cal = {};
  for (const h of hosts) {
    const card = runBench({ openmoat, host: h, hook: FAIL_HOOK, cwd });
    writeFileSync(join(out, "raw", `calibration-${h}.json`), JSON.stringify(card, null, 1));
    cal[h] = Object.fromEntries(calibration(card));
  }
  writeFileSync(join(out, "calibration.json"), JSON.stringify(cal, null, 1) + "\n");

  const lines = [];
  const meta = { started, machine, versions, sha256: sha, openmoatTarball, arms: [], sandboxedHosts: {} };
  const sandboxed = sandboxedSteps();
  for (const arm of armList) {
    const armMeta = { tool: arm.tool, version: arm.version, setting: arm.setting, commands: {} };
    for (const h of hosts) {
      const calH = new Map(Object.entries(cal[h]));
      let got;
      if (arm.native) {
        const card = runBench({ openmoat, host: h, cwd });
        writeFileSync(join(out, "raw", `${arm.tool}-${arm.setting}-${h}.json`), JSON.stringify(card, null, 1));
        const r = openmoatAnswers(card, scenarios, h, new Set(calH.keys()), sandboxed);
        got = r.answers;
        meta.sandboxedHosts[h] = r.sandboxedHost;
        armMeta.commands[h] = `openmoat bench --host ${h} --format json`;
      } else {
        const hook = arm.hosts[h];
        if (!hook) continue;
        const card = runBench({ openmoat, host: h, hook, cwd });
        writeFileSync(join(out, "raw", `${arm.tool}-${arm.setting}-${h}.json`), JSON.stringify(card, null, 1));
        got = answers(card, calH);
        armMeta.commands[h] = `openmoat bench --hook ${hook} --host ${h} --format json`;
      }
      const armRec = { tool: arm.tool, version: arm.version, setting: arm.setting, boundary: "none", tier: null, host: h };
      for (const sc of scenarios) {
        if (sc.source.name !== "openmoat") continue;
        const base = { scenario: `moatbench/${sc.id}`, arm: armRec, machine };
        if (sc.excludedWhy) {
          lines.push({ ...base, steps: [], excluded: sc.excludedWhy });
          continue;
        }
        if (!got.has(sc.id)) {
          lines.push({ ...base, steps: [], excluded: `MoatBench sends no payload for one of its calls on ${h} (the host has no such tool)` });
          continue;
        }
        lines.push({ ...base, steps: got.get(sc.id).map((answer) => ({ answer })) });
      }
      // derm's own control paths, only through Claude Code's payloads, only for hook arms.
      for (const sc of scenarios) {
        if (sc.source.name !== "derm") continue;
        const base = { scenario: `moatbench/${sc.id}`, arm: armRec, machine };
        if (h !== "claude-code" || arm.native) {
          lines.push({ ...base, steps: [], excluded: arm.native ? "derm's control paths; OpenMoat's own are its self-protection scenarios" : "derm's control-path probes are sent as Claude Code payloads only" });
          continue;
        }
        lines.push({ ...base, steps: probe(sc, arm.hosts[h]) });
      }
    }
    meta.arms.push(armMeta);
  }
  meta.finished = new Date().toISOString();
  writeFileSync(join(out, "results.jsonl"), lines.map((l) => JSON.stringify(l)).join("\n") + "\n");
  writeFileSync(join(out, "run.json"), JSON.stringify(meta, null, 1) + "\n");
  console.log(`${lines.length} results in ${out}`);
}

const armName = (a) => (a.tool === "openmoat" ? `OpenMoat ${a.version}` : `${a.tool} ${a.version}, ${a.setting}`);

export function scoreMoatbench(dir) {
  const scenarios = load("moatbench");
  const byId = new Map(scenarios.map((s) => [s.id, s]));
  const lines = readFileSync(join(dir, "results.jsonl"), "utf8").trim().split("\n").map((l) => JSON.parse(l));
  const cal = JSON.parse(readFileSync(join(dir, "calibration.json"), "utf8"));
  const meta = JSON.parse(readFileSync(join(dir, "run.json"), "utf8"));
  const sandboxed = sandboxedSteps();
  const arms = [];
  const seen = new Set();
  for (const l of lines) {
    const k = `${l.arm.tool}|${l.arm.setting}`;
    if (!seen.has(k)) { seen.add(k); arms.push(l.arm); }
  }
  const hosts = [...new Set(lines.map((l) => l.arm.host))];
  const pick = (arm, host) => lines.filter((l) => l.arm.tool === arm.tool && l.arm.setting === arm.setting && l.arm.host === host);
  // A hook arm is compared with the host's reading of the author's verdict (the
  // calibration); OpenMoat's own run with the verdict itself, its `sandboxed:`
  // expectation where its sandbox holds the host (bench.rs:303-318).
  const nativeWant = (host) => {
    const m = new Map();
    for (const sc of scenarios) {
      if (sc.source.name !== "openmoat") continue;
      m.set(sc.id, sc.steps.map((st, i) => (meta.sandboxedHosts?.[host] && sandboxed[sc.id]?.[i]) || st.expect));
    }
    return m;
  };
  const t = (arm, host, split) =>
    tally(pick(arm, host), byId, arm.tool === "openmoat" ? nativeWant(host) : new Map(Object.entries(cal[host] ?? {}).map(([k, v]) => [k, v.want])), {
      split,
      seen: E0_SEEN,
      sandboxed,
      sandboxedHost: arm.tool === "openmoat" && meta.sandboxedHosts?.[host],
    });
  const m = meta.machine;
  const out = [];
  out.push(`# MoatBench through derm's hooks, ${basename(dir)}`);
  out.push("");
  out.push(`Generated by \`node tests/eval/run.mjs --suite moatbench --score\` from \`results.jsonl\` in this folder (lane 6F; \`contracts/eval.md\` sections 2 and 4). Raw scorecards in \`raw/\`; each host's \`want\` per step in \`calibration.json\`; versions, checksums and the exact commands in \`run.json\`.`);
  out.push("");
  out.push(`- Machine: ${m.name}, ${m.os}, kernel ${m.kernel}, ${m.cpu}, ${m.ram}. One machine, one session: ${meta.started} to ${meta.finished}.`);
  out.push(`- Tools: ${meta.versions.derm} (sha256 \`${meta.sha256.derm.slice(0, 16)}...\`), ${meta.versions.openmoat} (binary sha256 \`${meta.sha256.openmoat.slice(0, 16)}...\`${meta.openmoatTarball ? `, from the release tarball \`${meta.openmoatTarball.name}\`, sha256 \`${meta.openmoatTarball.sha256.slice(0, 16)}...\`, which matches the release's own \`.sha256\` file: integrity, not provenance` : ""}).`);
  out.push(`- Scenarios: OpenMoat 0.19.0's bundled MoatBench set (MIT OR Apache-2.0; NOTICE), whose \`expect\` values are OpenMoat's choices; derm's own control-path scenarios (\`derm-*\`) are scored apart, at the end. Each scenario's half is fixed in its file by a hash rule (\`tests/eval/lib/split.mjs\`). Every scenario was seen in E0, and the 17 derm missed there (\`contracts/fixtures/eval/moatbench-e0-allowed.json\`) are red tests that wave 6's fixes are written against: 9 sit in the held-out half and 8 in the dev half. Once those fixes land, the held-out line \"not seen\" is the one that measures more than the fixes themselves.`);
  out.push(`- Every derm number is the hook alone: no daemon, no boundary, no tap (\`DERM_POLICY\` inline, the preset's \`policy\` object, mode 0600). OpenMoat runs as itself (\`openmoat bench\`, after its own \`init --yes\` in the throwaway home); its \"sandbox, declared\" steps are its scenarios' own claim, not a run of its sandbox.`);
  out.push(`- A must-stop step is one whose author expects deny or ask (MoatBench's review); caught means the host reads the reply as deny or ask. An allow on a must-stop step is the worst answer and is counted apart. A step whose host expectation is allow and that did not miss was answered allow or passthrough; MoatBench does not tell them apart.`);
  out.push("");
  for (const split of ["heldout", "dev", "all"]) {
    const title = { heldout: "Held-out half (the numbers to quote)", dev: "Dev half (tuned against; not a claim)", all: "Both halves (for comparison with E0 only)" }[split];
    if (split === "all") {
      out.push(`## ${title}`);
      out.push("");
      const cc = arms.map((a) => t(a, "claude-code", undefined));
      out.push(table(["Claude Code", ...arms.map(armName)], [
        ["must-stop steps caught", ...cc.map(attackLine)],
        ["missed, answered allow", ...cc.map((x) => x.missAllow)],
        ["missed, no decision", ...cc.map((x) => x.missDefer)],
        ["benign scenarios not allowed", ...cc.map((x) => `${x.benignNotAllowed} of ${x.benign}`)],
      ]));
      out.push("");
      continue;
    }
    out.push(`## ${title}`);
    out.push("");
    out.push(`### Claude Code, every arm`);
    out.push("");
    const cc = arms.map((a) => t(a, "claude-code", split));
    const cats = [...new Set(cc.flatMap((x) => Object.keys(x.byCategory)))].sort();
    const rows = cats.map((c) => [c, ...cc.map((x) => {
      const b = x.byCategory[c];
      return b ? `${b.caught}/${b.mustStop}${b.held ? ` (+${b.held} sandbox)` : ""}` : "-";
    })]);
    rows.push(["**must-stop steps caught**", ...cc.map((x) => `**${attackLine(x)}**`)]);
    rows.push(["of them in scenarios E0 did not miss (not seen)", ...cc.map((x) => `${x.unseenCaught}/${x.unseenMustStop}`)]);
    rows.push(["denied", ...cc.map((x) => x.denied)]);
    rows.push(["asked", ...cc.map((x) => x.asked)]);
    rows.push(["**missed, answered allow**", ...cc.map((x) => `**${x.missAllow}**`)]);
    rows.push(["missed, no decision (the host's own prompt)", ...cc.map((x) => x.missDefer)]);
    rows.push(["missed, error", ...cc.map((x) => x.missError)]);
    rows.push(["scenarios with every must-stop step caught", ...cc.map((x) => `${x.scenariosWhole}/${x.scenarios}`)]);
    rows.push(["benign scenarios not allowed", ...cc.map((x) => `${x.benignNotAllowed} of ${x.benign}`)]);
    rows.push(["workflow steps: asks (expected), unexpected", ...cc.map((x) => `${x.workflowAsks} (${x.workflowExpectedAsks}), ${x.workflowUnexpected} of ${x.workflowSteps}`)]);
    out.push(table(["", ...arms.map(armName)], rows));
    out.push("");
    out.push(`### Per host: must-stop caught; missed by allow; benign not allowed; unexpected workflow answers`);
    out.push("");
    const hrows = arms.map((a) => [armName(a), ...hosts.map((h) => {
      const x = t(a, h, split);
      return `${attackLine(x)}; ${x.missAllow} allow, ${x.missDefer} defer, ${x.missError} error; ${x.benignNotAllowed}; ${x.workflowUnexpected}`;
    })]);
    out.push(table(["", ...hosts.map((h) => (NOT_COMPARABLE[h] ? `${h} (${h === "hermes" ? "not comparable" : "partly"})` : h))], hrows));
    out.push("");
    out.push(`### derm's misses on Claude Code, by step (${split})`);
    out.push("");
    for (const a of arms.filter((a) => a.tool === "derm")) {
      const x = t(a, "claude-code", split);
      out.push(`- ${armName(a)}: ${x.misses.length ? x.misses.join("; ") : "none"}`);
    }
    out.push("");
  }
  out.push(`## Each tool on its own control paths (Claude Code, both halves)`);
  out.push("");
  out.push(`The four OpenMoat scenarios aimed at OpenMoat's own files (5 steps; note AZ, F2) are excluded for every arm and never counted (case 222). derm's are its own scenarios; OpenMoat's are its self-protection scenarios as scored above.`);
  out.push("");
  const dm = scenarios.filter((s) => s.source.name === "derm");
  const drows = [];
  for (const sc of dm) {
    sc.steps.forEach((st, i) => {
      drows.push([`${sc.id} #${i}`, `\`${st.input.command ?? `${st.kind} ${st.input.path}`}\``, st.expect, ...arms.filter((a) => a.tool === "derm").map((a) => {
        const l = pick(a, "claude-code").find((l) => l.scenario === `moatbench/${sc.id}`);
        return l?.steps?.[i]?.answer ?? "-";
      })]);
    });
  }
  out.push(table(["step", "call", "author expects", ...arms.filter((a) => a.tool === "derm").map(armName)], drows));
  out.push("");
  out.push(`## Not comparable or partly`);
  out.push("");
  for (const [h, why] of Object.entries(NOT_COMPARABLE)) out.push(`- ${h}: ${why}. Reported, not ranked.`);
  out.push(`- pi, OpenCode, OpenClaw and Cline: MoatBench's payloads for them are OpenMoat's own plugin protocols; derm's gates there are in-process plugins (\`derm gate serve\`). Not run.`);
  out.push("");
  return out.join("\n") + "\n";
}

export { category };
