// A client for the daemon's socket (contracts/daemon-protocol.md). Used for
// `approve` (a policy `ask` on a harness with no ask of its own, or before
// Claude Code's own prompt) and for `event` (the adapter record). Every call
// is bounded in time; a daemon that is down never blocks a turn longer than
// the connect timeout. Canonical copy: packages/derm-claude-plugin/src/core/.

import { randomUUID } from "node:crypto";
import { constants, lstatSync, readFileSync } from "node:fs";
import http from "node:http";
import net from "node:net";
import { homedir, platform } from "node:os";
import path from "node:path";
import { ownedByTrusted, trustedOwners } from "./owner.ts";
import { insideFolder } from "./policy.ts";

export const CONNECT_TIMEOUT_MS = 800;
const MAX_LINE_BYTES = 1024 * 1024;

/** contracts/daemon-protocol.md section 1, with `DERM_DAEMON_SOCKET` as an override for tests and `derm run`. */
export function socketPath(env: NodeJS.ProcessEnv = process.env): string {
  if (env.DERM_DAEMON_SOCKET && env.DERM_DAEMON_SOCKET.trim() !== "") return env.DERM_DAEMON_SOCKET;
  if (platform() === "darwin") return path.join(homedir(), "Library", "Application Support", "derm", "daemon.sock");
  const runtime = env.XDG_RUNTIME_DIR;
  if (runtime && runtime.trim() !== "") return path.join(runtime, "derm", "daemon.sock");
  return path.join(homedir(), ".derm", "run", "derm", "daemon.sock");
}

/**
 * The socket is trusted only when it is a socket owned by this user in a
 * folder owned by this user that no one else can write. Another user could
 * otherwise plant a socket that answers `yes` to every approval. Under an
 * agents' user (owner.ts), "this user" is the person it works for: the
 * socket is `derm run`'s bridge, and one the agent made is refused.
 */
export function socketLooksOwned(sock: string, system: NodeJS.Platform = platform()): string | undefined {
  // Windows (lane Z's request 2): the daemon's endpoint is a named pipe, and
  // Node's `net` gives no way to read the server's process or its token
  // (note AU sections 2.1 to 2.3), so a pipe another process squatted first
  // cannot be told from derm's. Until lane Z builds the server check, the
  // hook never sends a token there: it fails closed (proposed case AU-1).
  if (system === "win32") return "the daemon's endpoint cannot be checked on Windows yet (no server check is built)";
  // No uid to check against: refused, never trusted (it was trusted before).
  if (typeof process.getuid !== "function") return "this system gives no owner to check the daemon socket against";
  try {
    const s = lstatSync(sock);
    if (!s.isSocket()) return "not a socket";
    if (!ownedByTrusted(s.uid)) return "socket owned by another user";
    const d = lstatSync(path.dirname(sock));
    if (!d.isDirectory()) return "socket folder is not a folder";
    if (!ownedByTrusted(d.uid)) return "socket folder owned by another user";
    if ((d.mode & 0o022) !== 0) return "socket folder writable by others";
    return undefined;
  } catch {
    return "no daemon socket";
  }
}

const HEX64 = /^[0-9a-f]{64}$/;

export { insideFolder };

/**
 * The chat token this hook presents: `DERM_CHAT_TOKEN`, else the file
 * `DERM_CHAT_TOKEN_FILE` names (`derm run` writes it, for harnesses that strip
 * secret-named variables from a hook's environment, rules case 76). Never the
 * daemon's own `daemon.token`: a hook is not the daemon, and the daemon scope
 * can mint tokens, read every chat and become an approver (integration w1
 * decision). The file must be absolute, a regular file (not a link), yours,
 * readable by you alone, small, outside the session folder, and not named
 * `daemon.token` (security finding S3; `exchange` also closes when the daemon
 * says the token it got has daemon scope).
 */
export function chatToken(env: NodeJS.ProcessEnv = process.env, cwd: string = process.cwd()): string | undefined {
  const fromEnv = env.DERM_CHAT_TOKEN?.trim();
  if (fromEnv && HEX64.test(fromEnv)) return fromEnv;
  const file = env.DERM_CHAT_TOKEN_FILE?.trim();
  if (!file || !path.isAbsolute(file) || insideFolder(file, cwd)) return undefined;
  if (path.basename(file) === "daemon.token") return undefined;
  try {
    const st = lstatSync(file);
    if (!st.isFile() || st.size > 256) return undefined;
    if (!ownedByTrusted(st.uid)) return undefined;
    // Yours alone; under an agents' user, the person's copy in the chat's
    // bridge, which the agent may read but no one but the person may write.
    const loose = trustedOwners()?.agent ? (st.mode & 0o022) !== 0 : (st.mode & 0o077) !== 0;
    if (loose) return undefined;
    const t = readFileSync(file, { encoding: "utf8", flag: constants.O_RDONLY | constants.O_NOFOLLOW }).trim();
    return HEX64.test(t) ? t : undefined;
  } catch {
    return undefined;
  }
}

type Reply = Record<string, unknown> & { ok?: boolean; error?: string };

/** The host name sbx's VM reaches the host by (Docker's "Develop and test locally" page). */
export const SBX_HOST = "host.docker.internal";

/**
 * Inside an sbx VM the daemon's socket is not there (the sbx smoke test, step
 * 5: no host folder but the project is mounted), and the only way to the host
 * is the receiver's HTTP port at `host.docker.internal` (step 4). The hook
 * takes that route only when `derm run` said so: `DERM_BOUNDARY=sbx`,
 * `DERM_OTLP_ENDPOINT` a plain `http://host.docker.internal:<port>` with no
 * user, path, query or fragment, and no socket file where the socket would
 * be (lane T's P4-R2, integration w5 continue). On the host the socket is
 * always the route; a project that sets these variables reaches only a
 * daemon port on the host that sbx's own rule opened, and the daemon there
 * applies the token's chat scope (contracts/daemon-protocol.md section 4).
 */
export function vmEndpoint(env: NodeJS.ProcessEnv = process.env): URL | undefined {
  if (env.DERM_BOUNDARY?.trim() !== "sbx") return undefined;
  const raw = env.DERM_OTLP_ENDPOINT?.trim();
  if (!raw) return undefined;
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    return undefined;
  }
  if (url.protocol !== "http:" || url.hostname !== SBX_HOST || url.port === "") return undefined;
  if (url.username !== "" || url.password !== "" || url.search !== "" || url.hash !== "") return undefined;
  if (url.pathname !== "/" && url.pathname !== "") return undefined;
  try {
    lstatSync(socketPath(env));
    return undefined;
  } catch (e) {
    return (e as NodeJS.ErrnoException)?.code === "ENOENT" ? url : undefined;
  }
}

const VM_ROUTES: Record<string, { path: string; field: string }> = {
  event: { path: "/derm/v1/event", field: "event" },
  approve: { path: "/derm/v1/approve", field: "request" },
};

/** One HTTP request to the daemon's derm route; its reply line, or why not. */
export function postVm(url: URL, token: string, request: Record<string, unknown>, replyTimeoutMs: number): Promise<Reply | { failed: string }> {
  const route = VM_ROUTES[String(request.op)];
  if (!route) return Promise.resolve({ failed: `no route for ${String(request.op)} from a VM` });
  const body = JSON.stringify({ [route.field]: request[route.field] });
  return new Promise((resolve) => {
    let settled = false;
    let timer: NodeJS.Timeout | undefined;
    const done = (r: Reply | { failed: string }) => {
      if (settled) return;
      settled = true;
      if (timer) clearTimeout(timer);
      req.destroy();
      resolve(r);
    };
    const req = http.request(
      {
        host: url.hostname,
        port: Number(url.port),
        method: "POST",
        path: route.path,
        headers: { "content-type": "application/json", "content-length": Buffer.byteLength(body), "x-derm-token": token },
        agent: false,
      },
      (res) => {
        let text = "";
        res.setEncoding("utf8");
        res.on("data", (c: string) => {
          text += c;
          if (text.length > MAX_LINE_BYTES) done({ failed: "daemon reply too long" });
        });
        res.on("end", () => {
          if (res.statusCode !== 200) return done({ failed: `daemon answered HTTP ${String(res.statusCode)}` });
          try {
            const reply = JSON.parse(text) as unknown;
            done(typeof reply === "object" && reply !== null && !Array.isArray(reply) ? (reply as Reply) : { failed: "daemon sent a bad reply" });
          } catch {
            done({ failed: "daemon sent a reply that is not JSON" });
          }
        });
        res.on("error", () => done({ failed: "daemon reply failed" }));
      },
    );
    timer = setTimeout(() => done({ failed: "daemon connect timed out" }), CONNECT_TIMEOUT_MS);
    req.on("socket", (sock) => {
      sock.on("connect", () => {
        if (timer) clearTimeout(timer);
        timer = setTimeout(() => done({ failed: "daemon reply timed out" }), replyTimeoutMs);
      });
    });
    req.on("error", (e: NodeJS.ErrnoException) => done({ failed: `daemon unreachable (${e.code ?? "error"})` }));
    req.end(body);
  });
}

/** One connection: hello, then each request in order, one reply line each. */
export async function exchange(
  requests: readonly Record<string, unknown>[],
  opts: { env?: NodeJS.ProcessEnv; client: string; replyTimeoutMs: number; cwd?: string },
): Promise<{ replies: Reply[] } | { error: string }> {
  const env = opts.env ?? process.env;
  const cwd = opts.cwd ?? process.cwd();
  const sock = socketPath(env);
  if (env.DERM_DAEMON_SOCKET?.trim() && insideFolder(sock, cwd)) return { error: "DERM_DAEMON_SOCKET is inside the session folder, which a project can set; not used" };
  // Whatever named it (DERM_DAEMON_SOCKET, XDG_RUNTIME_DIR, HOME): a project's
  // settings can set the hook's environment, and a socket the agent made in
  // the project would answer its own approvals (security finding S14,
  // integration w2).
  if (!path.isAbsolute(sock)) return { error: "the daemon socket is not an absolute path; not used" };
  if (insideFolder(sock, cwd)) return { error: "the daemon socket is inside the session folder, which a project can set; not used" };
  const token = chatToken(env, cwd);
  if (!token) return { error: "no chat token (start the harness with derm run)" };
  const vm = vmEndpoint(env);
  if (vm) {
    const replies: Reply[] = [];
    for (const request of requests) {
      const r = await postVm(vm, token, request, opts.replyTimeoutMs);
      if ("failed" in r) return { error: r.failed as string };
      replies.push(r);
    }
    return { replies };
  }
  const notOwned = socketLooksOwned(sock);
  if (notOwned) return { error: notOwned };

  return await new Promise((resolve) => {
    const replies: Reply[] = [];
    const lines = [{ op: "hello", token, client: opts.client }, ...requests];
    let buf = "";
    let settled = false;
    let timer: NodeJS.Timeout | undefined;
    const socket = net.createConnection({ path: sock });
    const finish = (out: { replies: Reply[] } | { error: string }) => {
      if (settled) return;
      settled = true;
      if (timer) clearTimeout(timer);
      socket.destroy();
      resolve(out);
    };
    const arm = (ms: number, label: string) => {
      if (timer) clearTimeout(timer);
      timer = setTimeout(() => finish({ error: label }), ms);
    };
    arm(CONNECT_TIMEOUT_MS, "daemon connect timed out");
    socket.on("error", (e: NodeJS.ErrnoException) => finish({ error: `daemon unreachable (${e.code ?? "error"})` }));
    socket.on("close", () => finish({ error: "daemon closed the connection" }));
    socket.on("connect", () => {
      socket.write(`${JSON.stringify(lines[0])}\n`);
      arm(2000, "daemon hello timed out");
    });
    socket.on("data", (chunk) => {
      buf += chunk.toString("utf8");
      if (buf.length > MAX_LINE_BYTES) return finish({ error: "daemon line too long" });
      let nl: number;
      while ((nl = buf.indexOf("\n")) >= 0) {
        const line = buf.slice(0, nl).trim();
        buf = buf.slice(nl + 1);
        if (line === "") continue;
        let reply: Reply;
        try {
          reply = JSON.parse(line) as Reply;
        } catch {
          return finish({ error: "daemon sent a line that is not JSON" });
        }
        if (typeof reply !== "object" || reply === null) return finish({ error: "daemon sent a bad line" });
        if (replies.length === 0 && reply.ok !== true) return finish({ error: `daemon refused hello: ${String(reply.error ?? "no reason")}` });
        // A hook is never the daemon: a token that got daemon scope (a copy of
        // daemon.token under another name) is not used (security finding S3).
        if (replies.length === 0 && reply.scope !== "chat") return finish({ error: "the token has daemon scope; a hook presents only a chat token" });
        replies.push(reply);
        if (replies.length === lines.length) return finish({ replies: replies.slice(1) });
        socket.write(`${JSON.stringify(lines[replies.length])}\n`);
        arm(opts.replyTimeoutMs, "daemon reply timed out");
      }
    });
  });
}

export type ApproveRequest = {
  id: string;
  chat: string;
  harness: string;
  tool: string;
  summary: string;
  timeoutSeconds: number;
};

export type ApproveOutcome =
  | { answer: "yes" | "no"; by: "approver" | "timeout" | "none" }
  | { unreachable: string };

/** Sends `approve` and waits for the answer (contract section 2, rule 3). */
export async function approve(request: ApproveRequest, env?: NodeJS.ProcessEnv): Promise<ApproveOutcome> {
  const result = await exchange([{ op: "approve", request }], {
    client: `derm hook (${request.harness})`,
    replyTimeoutMs: (request.timeoutSeconds + 5) * 1000,
    ...(env ? { env } : {}),
  });
  if ("error" in result) return { unreachable: result.error };
  const reply = result.replies[0];
  if (!reply || reply.ok !== true) return { unreachable: `daemon refused approve: ${String(reply?.error ?? "no reply")}` };
  const answer = reply.answer === "yes" ? "yes" : "no";
  const by = reply.by === "approver" || reply.by === "timeout" || reply.by === "none" ? reply.by : "approver";
  // Only an explicit yes from an approver counts as yes.
  if (answer === "yes" && by !== "approver") return { answer: "no", by };
  return { answer, by };
}

/**
 * The id of a gate decision record: `<harness>-<call id>-decision-<128
 * random bits>`. The agent holds the hook's chat token (case 66) and call ids
 * count up, so an id it can work out beforehand let it post a forged
 * decision first (box test w2, BW2; integration w2 review W2-S3). The call id
 * keeps only the characters the daemon keeps (`clean_id`), cut so the whole
 * id fits its 128-character cap with the random part whole.
 */
export function decisionId(harness: string, callId: string | undefined): string {
  const nonce = randomUUID().replace(/-/g, "");
  const call = (callId ?? "unknown").replace(/[^A-Za-z0-9_.:-]/g, "_") || "unknown";
  const room = 128 - harness.length - "--decision-".length - nonce.length;
  return `${harness}-${call.slice(0, Math.max(1, room))}-decision-${nonce}`;
}

export type AdapterEvent = {
  id: string;
  chatId: string;
  harness: string;
  kind: "tool.call" | "approval" | "install.call";
  summary: string;
  detail: Record<string, unknown>;
};

/** Posts one adapter record (contracts/events.md section 4). Best effort; never throws. */
export async function postEvent(event: AdapterEvent, env?: NodeJS.ProcessEnv): Promise<boolean> {
  try {
    const result = await exchange(
      [
        {
          op: "event",
          event: { ...event, at: 0, source: "adapter", summary: event.summary.slice(0, 200), detail: { trust: "client", ...event.detail } },
        },
      ],
      { client: `derm hook (${event.harness})`, replyTimeoutMs: 1500, ...(env ? { env } : {}) },
    );
    return "replies" in result && result.replies[0]?.ok === true;
  } catch {
    return false;
  }
}
