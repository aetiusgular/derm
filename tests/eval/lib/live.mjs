// The live run of the join and effects suites (plan 6F (d), (f); eval pass 1's
// E1-4d: the run existed only as E1's own scripts, outside the repository).
//
// Each scenario's shell steps run as Bash calls of a real Claude Code, driven by a
// fake Messages server (tests/cli-contract/lib/fakeMessages.mjs), under
// `derm run claude-code --boundary <b>` against the person's live daemon and OS
// feed. After every chat has run and the feed has caught up, the daemon's own log
// is read (`derm audit export`, the whole log, not the report's cut) and each
// declared effect is matched to its OS event and to the join's record of it.
//
// What counts:
// - an effect that did not happen on the host (the file is not there, no connection
//   reached the listener) is `seenByTruth: false` and scores nothing;
// - a read is excluded, with the count printed: a plain read is not audited, and a
//   secret under the run's throwaway home is not under the feed's rules, which name
//   the real home (E1-3, E1-4d). A fork is excluded: the join records no candidates
//   for forks;
// - a write or a connect that happened is `not seen` (no OS event), `right` (the
//   join chose its own call), `wrong` (another call) or `uncredited` (candidates,
//   none chosen, or no join record).
//
// Linux only: the chat reaches the live daemon through XDG_RUNTIME_DIR, with HOME a
// throwaway. The Mac's collector arm is not built here.
import { spawn, spawnSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import net from "node:net";
import http from "node:http";
import { homedir } from "node:os";
import { basename, dirname, join } from "node:path";
import { load, ROOT } from "./scenarios.mjs";
import { table } from "./score.mjs";
import { base } from "./matrix.mjs";

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function run(bin, args, opts) {
  return new Promise((resolve) => {
    const ch = spawn(bin, args, { ...opts, stdio: ["ignore", "pipe", "pipe"], detached: true });
    let out = "", err = "";
    ch.stdout.on("data", (x) => (out += x));
    ch.stderr.on("data", (x) => (err += x));
    const t = setTimeout(() => { try { process.kill(-ch.pid, "SIGKILL"); } catch { /* gone */ } }, 240_000);
    ch.on("close", (code) => { clearTimeout(t); resolve({ code, out, err }); });
  });
}

// An effects scenario names the call the agent made and the hidden payload behind
// it. The project gets the files that make the call run the payload: an npm script
// or a Makefile target, as a project would hide it.
export function projectFiles(sc) {
  const step = sc.steps[0].input;
  if (step.command) return { commands: sc.steps.map((s) => s.input.command), files: sc.files ?? {} };
  const files = { "hidden.sh": `#!/bin/sh\n${step.payload}\n` };
  const call = step.call.trim();
  const m = /^npm (?:run )?([a-z-]+)$/.exec(call);
  const mk = /^make ([a-z-]+)$/.exec(call);
  if (m) {
    const script = m[1] === "install" ? "postinstall" : m[1];
    files["package.json"] = JSON.stringify({ name: "eval", version: "1.0.0", scripts: { [script]: "sh ./hidden.sh" } });
  } else if (mk) {
    files.Makefile = `${mk[1]}:\n\tsh ./hidden.sh\n`;
  } else {
    throw new Error(`${sc.id}: no project form for the call ${JSON.stringify(call)}`);
  }
  return { commands: [call], files };
}

export async function runLive({ suite, out, derm, claude, boundary = "none", delayMs = 0, reps = 1, settleMs = 20_000, machine, dermVersion, only }) {
  if (process.platform !== "linux") throw new Error("the live run is Linux only");
  const { startFakeMessages, textBlock, toolUse } = await import(join(ROOT, "tests", "cli-contract", "lib", "fakeMessages.mjs"));
  mkdirSync(join(out, "raw"), { recursive: true });
  const scenarios = load(suite).filter((s) => !only || only.includes(s.id));
  const started = new Date().toISOString();
  // E1-10: the daemon's folder is under the real home folder
  // (~/.derm/run/derm), and no variable moves it for `derm run`. Each chat
  // gets a throwaway HOME, so that home's `.derm/run/derm` is a link to the
  // live daemon's folder.
  const daemonDir = join(homedir(), ".derm", "run", "derm");
  if (!existsSync(join(daemonDir, "daemon.sock"))) throw new Error(`no live daemon at ${daemonDir}`);
  const claudeVersion = (spawnSync(claude, ["--version"], { encoding: "utf8" }).stdout ?? "").trim().split(" ")[0] || "unknown";
  const recs = [];
  const roots = [];
  for (let rep = 1; rep <= reps; rep++) {
    for (const sc of scenarios) {
      const root = mkdtempSync(join(base(), `live-${sc.id.slice(0, 24)}-`));
      roots.push(root);
      const home = join(root, "home"), work = join(home, "work"), bin = join(root, "bin");
      for (const d of [home, work, bin, join(home, ".derm"), join(home, ".ssh"), join(home, ".aws")]) mkdirSync(d, { recursive: true, mode: 0o700 });
      mkdirSync(join(home, ".derm", "run"), { recursive: true, mode: 0o700 });
      symlinkSync(daemonDir, join(home, ".derm", "run", "derm"));
      writeFileSync(join(home, ".derm", "policy.json"), JSON.stringify({ version: 1, rules: [{ tool: "bash", action: "allow" }] }), { mode: 0o600 });
      writeFileSync(join(home, ".ssh", "id_rsa"), "FAKE-PRIVATE-KEY-not-a-real-key");
      writeFileSync(join(home, ".aws", "credentials"), "[default]\naws_access_key_id=FAKE\n");
      writeFileSync(join(work, "shared.txt"), "x\n");
      let conns = 0;
      const listener = net.createServer((c) => { conns++; c.on("data", () => {}); c.on("error", () => {}); c.end(); });
      await new Promise((r) => listener.listen(0, "127.0.0.1", r));
      const port = listener.address().port;
      const { commands, files } = projectFiles(sc);
      for (const [f, body] of Object.entries(files)) {
        mkdirSync(dirname(join(work, f)), { recursive: true });
        writeFileSync(join(work, f), body.replaceAll("{PORT}", String(port)), { mode: 0o755 });
      }
      symlinkSync(claude, join(bin, "claude"));
      const tag = `${sc.id.replace(/[^a-z0-9]/gi, "").slice(0, 10)}${rep}x${Date.now() % 100000}`;
      const ids = commands.map((_, i) => `toolu_ev${tag}n${i}`);
      const fake = await startFakeMessages({
        script: (b) => {
          const s = JSON.stringify(b.messages ?? []);
          const k = ids.filter((id) => s.includes(`"tool_use_id":"${id}"`)).length;
          return k < ids.length ? [toolUse("Bash", { command: commands[k].replaceAll("{PORT}", String(port)), description: `step ${k}` }, ids[k])] : [textBlock("done")];
        },
      });
      // A model's own latency: each reply is held `delayMs` before it is asked for.
      let baseUrl = fake.baseUrl, proxy = null;
      if (delayMs > 0) {
        const u = new URL(fake.baseUrl);
        proxy = http.createServer((req, res) => {
          const chunks = [];
          req.on("data", (c) => chunks.push(c));
          req.on("end", () => setTimeout(() => {
            const up = http.request({ host: u.hostname, port: u.port, path: req.url, method: req.method, headers: req.headers }, (ur) => { res.writeHead(ur.statusCode, ur.headers); ur.pipe(res); });
            up.on("error", () => res.end());
            up.end(Buffer.concat(chunks));
          }, delayMs));
        });
        await new Promise((r) => proxy.listen(0, "127.0.0.1", r));
        baseUrl = `http://127.0.0.1:${proxy.address().port}`;
      }
      const chat = `evl-${suite}-${tag}`;
      const env = {
        PATH: [bin, dirname(process.execPath), dirname(derm), "/usr/local/libexec/derm-srt", "/usr/local/bin", "/usr/bin", "/bin", ...(process.env.DERM_EVAL_PATH ?? "").split(":").filter(Boolean)].join(":"),
        HOME: home, LANG: "C.UTF-8", NO_COLOR: "1",
        DISABLE_AUTOUPDATER: "1", DISABLE_TELEMETRY: "1", CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC: "1",
        // The contract tests' published dummy; the fake server never checks it.
        ANTHROPIC_API_KEY: "sk-ant-api03-contract-test-dummy-key-not-real",
        ANTHROPIC_BASE_URL: baseUrl,
      };
      // Untapped: the tap sends to the real provider, which a fake model is not.
      const args = ["run", "claude-code", "--boundary", boundary, "--chat", chat, "--cwd", work, "--no-tap"];
      if (boundary === "srt") args.push("--model-url", baseUrl);
      args.push("--", "-p", "go", "--model", "claude-sonnet-4-5", "--output-format", "json");
      const t0 = Date.now();
      const r = await run(derm, args, { env, cwd: work });
      // A late effect (a background child) lands after the chat's last call.
      const late = Math.max(0, ...sc.effects.map((e) => e.after ?? 0));
      await sleep(late + 500);
      await fake.close();
      listener.close();
      proxy?.close();
      const rec = { suite, scenario: sc.id, rep, chat, home, work, ids, port, conns, exit: r.code, ms: Date.now() - t0, stderr: r.err.slice(-2000), happened: sc.effects.map((e) => happened(e, { home, work, conns })) };
      recs.push(rec);
      console.log(`${suite}/${sc.id} rep ${rep}: exit ${r.code}, ${rec.ms} ms`);
    }
  }
  await sleep(settleMs);
  const log = join(out, "raw", "activity.jsonl");
  const ex = spawnSync(derm, ["audit", "export", "--out", log], { env: { ...process.env }, encoding: "utf8", maxBuffer: 1 << 28 });
  const chats = new Set(recs.map((r) => r.chat));
  const events = {};
  if (existsSync(log)) {
    for (const line of readFileSync(log, "utf8").split("\n")) {
      if (!line.includes('"evl-')) continue;
      let e;
      try { e = JSON.parse(line); } catch { continue; }
      e = e.event ?? e;
      if (chats.has(e.chatId)) (events[e.chatId] ??= []).push(e);
    }
    // Only these chats' records are kept beside the results.
    writeFileSync(log, Object.values(events).flat().map((e) => JSON.stringify(e)).join("\n") + "\n");
  }
  const lines = recs.map((rec) => {
    const sc = scenarios.find((s) => s.id === rec.scenario);
    const scored = score(sc, rec, events[rec.chat] ?? []);
    rec.scored = scored;
    return {
      scenario: `${suite}/${sc.id}`,
      arm: { tool: "derm", version: dermVersion, setting: `live${delayMs ? `, ${delayMs} ms model delay` : ""}`, boundary, tier: null, host: `claude-code ${claudeVersion}` },
      machine,
      steps: [],
      effects: scored.filter((s) => !s.excluded).map((s) => ({ seenByTruth: s.happened, seenByTool: s.result !== "not seen" && s.happened, credited: s.credited ?? null, correct: s.happened ? s.result === "right" : null })),
    };
  });
  writeFileSync(join(out, "raw", "runs.json"), JSON.stringify(recs, null, 1) + "\n");
  writeFileSync(join(out, "results.jsonl"), lines.map((l) => JSON.stringify(l)).join("\n") + "\n");
  writeFileSync(join(out, "run.json"), JSON.stringify({ suite, started, finished: new Date().toISOString(), machine, derm: dermVersion, claude: claudeVersion, boundary, delayMs, reps, exportExit: ex.status, exportErr: (ex.stderr ?? "").slice(-300) }, null, 1) + "\n");
  writeFileSync(join(out, "README.md"), scoreLive(out));
  for (const root of roots) rmSync(root, { recursive: true, force: true });
  console.log(`${suite} live: ${recs.length} chats in ${out}`);
}

function happened(e, { home, work, conns }) {
  if (e.what === "write") {
    if (e.path.startsWith("~/")) return existsSync(join(home, e.path.slice(2)));
    return existsSync(join(e.path === "outside.txt" ? home : work, e.path));
  }
  if (e.what === "connect") return conns > 0;
  return null; // a read or a fork leaves nothing to look at
}

// Each declared effect against the chat's records. In the join suite effect i is
// step i's; in the effects suite every effect is the one call's.
export function score(sc, rec, events) {
  const joins = new Map(events.filter((e) => e.kind === "join.candidates").map((e) => [e.detail?.effect, e.detail]));
  const stepOf = new Map();
  for (const e of events) {
    if (e.kind !== "approval" || e.source !== "adapter") continue;
    rec.ids.forEach((id, i) => { if (String(e.id).includes(id)) stepOf.set(e.id, i); });
  }
  const steps = (call) => (call == null ? null : (Array.isArray(call) ? call : [call]).map((c) => stepOf.get(c) ?? `?${String(c).slice(0, 24)}`));
  return sc.effects.map((eff, i) => {
    const own = rec.suite === "join" ? i : 0;
    const label = `${eff.what} ${eff.path ?? eff.host ?? ""}`.trim();
    if (eff.what === "read" || eff.what === "fork") return { effect: label, excluded: eff.what };
    const did = rec.happened[i];
    if (!did) return { effect: label, happened: false, result: "did not happen" };
    const detail = (e) => JSON.stringify(e.detail ?? {});
    const match = (e) => {
      if (e.source !== "auditd") return false;
      // A rename's final name is its `dest`; `path` is the name it had.
      if (eff.what === "write") return ["write", "create", "rename", "truncate"].includes(e.kind) && [e.detail?.path, e.detail?.dest].some((p) => String(p ?? "").endsWith(`/${basename(eff.path)}`));
      return e.kind === "net.connect" && detail(e).includes(eff.host) && detail(e).includes(String(rec.port));
    };
    const hits = events.filter(match);
    if (hits.length === 0) return { effect: label, happened: true, result: "not seen" };
    const seen = new Set();
    let credited = null;
    for (const e of hits) {
      const j = joins.get(e.id);
      if (!j) { seen.add("uncredited"); continue; }
      const chosen = steps(j.chosen);
      if (chosen == null) seen.add("uncredited");
      else if (chosen.length === 1 && chosen[0] === own) seen.add("right");
      else { seen.add("wrong"); credited = `step ${chosen.join(",")}`; }
    }
    const result = seen.has("right") ? "right" : seen.has("wrong") ? "wrong" : "uncredited";
    return { effect: label, happened: true, result, credited: result === "right" ? `step ${own}` : credited };
  });
}

export function scoreLive(dir) {
  const meta = JSON.parse(readFileSync(join(dir, "run.json"), "utf8"));
  const recs = JSON.parse(readFileSync(join(dir, "raw", "runs.json"), "utf8"));
  // Scored again from the kept records, so a fix to the scorer reads an old run.
  const log = join(dir, "raw", "activity.jsonl");
  if (existsSync(log)) {
    const events = {};
    for (const line of readFileSync(log, "utf8").split("\n")) {
      if (!line.trim()) continue;
      const e = JSON.parse(line);
      (events[e.chatId] ??= []).push(e);
    }
    const byId = new Map(load(meta.suite).map((s) => [s.id, s]));
    for (const rec of recs) if (byId.has(rec.scenario)) rec.scored = score(byId.get(rec.scenario), rec, events[rec.chat] ?? []);
  }
  const m = meta.machine ?? {};
  const out = [];
  out.push(`# ${meta.suite === "join" ? "Join accuracy" : "Effect visibility"}, live, ${basename(dir)}`);
  out.push("");
  out.push(`Generated by \`node tests/eval/run.mjs --suite ${meta.suite} --live\` (\`tests/eval/lib/live.mjs\`). Each scenario's shell steps ran as Bash calls of a real Claude Code ${meta.claude} with a fake model, under \`derm run claude-code --boundary ${meta.boundary} --no-tap\`, against the live daemon and its auditd feed; each declared effect was then matched to its OS event and to the join's record in the daemon's own log.`);
  out.push("");
  out.push(`- Machine: ${m.name}, ${m.os}, kernel ${m.kernel}, ${m.cpu}, ${m.ram}. ${meta.started} to ${meta.finished}.`);
  out.push(`- derm ${meta.derm}. ${meta.reps} rep(s). Model delay ${meta.delayMs} ms per reply${meta.delayMs ? "" : " (a fake model answers at once, which no real model does)"}.`);
  const failed = recs.filter((r) => r.exit !== 0);
  if (failed.length) out.push(`- ${failed.length} chat(s) did not exit 0 (${[...new Set(failed.map((r) => r.scenario))].join(", ")}); read their effects with that in mind.`);
  if (meta.exportExit !== 0) out.push(`- \`derm audit export\` exited ${meta.exportExit}: ${meta.exportErr}`);
  out.push("");
  const tally = (list) => {
    const t = { happened: 0, right: 0, wrong: 0, uncredited: 0, "not seen": 0, "did not happen": 0, read: 0, fork: 0 };
    for (const s of list) {
      if (s.excluded) t[s.excluded]++;
      else if (!s.happened) t["did not happen"]++;
      else { t.happened++; t[s.result]++; }
    }
    return t;
  };
  const ids = [...new Set(recs.map((r) => r.scenario))];
  const rows = ids.map((id) => {
    const t = tally(recs.filter((r) => r.scenario === id).flatMap((r) => r.scored));
    return [id, t.happened, t.right, t.wrong, t.uncredited, t["not seen"], t["did not happen"], t.read + t.fork];
  });
  out.push(table(["scenario", "effects that happened", "credited right", "credited wrong", "seen, none chosen", "not seen", "did not happen", "excluded"], rows));
  out.push("");
  const t = tally(recs.flatMap((r) => r.scored));
  const credited = t.right + t.wrong;
  out.push(`- Of ${t.happened} writes and connects that happened, ${t.right} were credited to their own call, ${t.wrong} to another, ${t.uncredited} were seen with no call chosen, and ${t["not seen"]} left no OS record.`);
  out.push(`- Crediting precision ${credited ? ((100 * t.right) / credited).toFixed(1) : "n/a"}% (${t.right} of ${credited} credited), recall ${t.happened ? ((100 * t.right) / t.happened).toFixed(1) : "n/a"}% (${t.right} of ${t.happened}).`);
  out.push(`- Excluded and not scored: ${t.read} reads (a plain read is not audited, and a secret under this run's throwaway home is not under the feed's rules, which name the real home) and ${t.fork} forks (the join records no candidates for a fork). ${t["did not happen"]} declared effects did not happen on the host and score nothing.`);
  out.push("");
  return out.join("\n") + "\n";
}
