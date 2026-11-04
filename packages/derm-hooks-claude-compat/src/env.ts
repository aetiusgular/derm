// How the hook finds its chat token when the agent strips it from the hook's
// environment (rules case 76).
//
// Command Code 1.88 drops every variable whose name matches /TOKEN/i (and 14
// more patterns) before it runs a hook, so neither DERM_CHAT_TOKEN nor
// DERM_CHAT_TOKEN_FILE reaches it (contracts/hook-dialects.md section 2a;
// npm:command-code dist/cli.mjs, the hook env filter). DERM_CHAT_ID and
// DERM_DAEMON_SOCKET match none of the patterns and do reach it.
//
// `derm run --boundary none` writes the token file at
// `<the daemon socket's folder>/chats/<chat id>.token`
// (crates/derm-cli/src/run/mod.rs: `state_root = dir`, the socket's parent,
// `token_path = state_root.join("chats").join(format!("{chat}.token"))`) and
// names that socket in DERM_DAEMON_SOCKET. So, with both token variables gone,
// the hook works the path out from those two. Nothing new is trusted: the
// core's chatToken() still refuses the file unless it is absolute, a regular
// file, yours, 0600, small, outside the session folder and not daemon.token,
// and the daemon still refuses a token that is not a chat token.
//
// The socket must be derm's own (L-S6). `derm run` never takes its socket from
// DERM_DAEMON_SOCKET; it uses derm-core's default
// (crates/derm-audit-linux/src/client.rs socket_path, derm-core
// src/runtime.rs socket_path_with: `~/Library/Application Support/derm` on
// macOS, else `$XDG_RUNTIME_DIR/derm`, a private `/run/user/<uid>/derm`, or
// `~/.derm/run/derm`). So the path is derived only when the socket's folder is
// one of those, worked out from this process's uid and its passwd home, never
// from HOME or XDG_RUNTIME_DIR, which whatever set DERM_DAEMON_SOCKET could
// set as well. An XDG_RUNTIME_DIR other than /run/user/<uid> gets no derived
// path: the ask then has no token and is a deny.

import { userInfo } from "node:os";
import path from "node:path";

/** The folders `derm run`'s socket can be in for this user, from the uid and the passwd home. */
export function defaultSocketDirs(): string[] {
  let home: string | undefined;
  try {
    home = userInfo().homedir;
  } catch {
    home = undefined;
  }
  const dirs: string[] = [];
  if (process.platform === "darwin") {
    if (home) dirs.push(path.join(home, "Library", "Application Support", "derm"));
    return dirs;
  }
  const uid = process.getuid?.();
  if (uid !== undefined) dirs.push(path.join("/run/user", String(uid), "derm"));
  if (home && path.isAbsolute(home)) dirs.push(path.join(home, ".derm", "run", "derm"));
  return dirs;
}

/** A chat id as `derm run` mints it (`derm-` and 12 hex) or as a test names it: no separators, no dots at the start. */
const CHAT_ID = /^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$/;

export function derivedTokenFile(env: NodeJS.ProcessEnv, socketDirs: readonly string[] = defaultSocketDirs()): string | undefined {
  const chat = env.DERM_CHAT_ID?.trim();
  const sock = env.DERM_DAEMON_SOCKET?.trim();
  if (!chat || !sock || !CHAT_ID.test(chat) || !path.isAbsolute(sock)) return undefined;
  if (path.normalize(sock) !== sock || path.basename(sock) !== "daemon.sock") return undefined;
  const dir = path.dirname(sock);
  if (!socketDirs.includes(dir)) return undefined;
  return path.join(dir, "chats", `${chat}.token`);
}

/** The hook's environment, with DERM_CHAT_TOKEN_FILE filled in from DERM_CHAT_ID and DERM_DAEMON_SOCKET when both token variables are absent. */
export function hookEnv(env: NodeJS.ProcessEnv, socketDirs?: readonly string[]): NodeJS.ProcessEnv {
  const out: NodeJS.ProcessEnv = { ...env };
  if (env.DERM_CHAT_TOKEN?.trim() || env.DERM_CHAT_TOKEN_FILE?.trim()) return out;
  const derived = derivedTokenFile(env, socketDirs);
  if (derived) out.DERM_CHAT_TOKEN_FILE = derived;
  return out;
}
