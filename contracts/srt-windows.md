# srt on Windows: the handoff and `derm enter`

Written by the wave 5b base on 10 Nov 2026 (`plans/toolkit_wave5b_plan.md` lane 5bD, case 230, proposed cases 230 and 231). Evidence: note BC sections 5 and 11 and `plans/parallel/tk_w5b_base.md` "Part 2 results", run on the box's Windows 11 (build 26200) with srt 0.0.82. Marks: **V** read at the pin or run, **I** inference, **NF** not found. Fixture: `fixtures/srt-windows/handoff.json`.

## 1. What srt 0.0.82 does on Windows (V unless marked)

- One sandbox account per machine (`srt-sandbox`), one install record (`HKLM\SOFTWARE\sandbox-runtime`); a second `srt-win install --sandbox-user` makes a second account and overwrites the record, and both share `sandbox-runtime-users` (part 2, run; `install.rs:66-72, 537-545`). **One account per chat is not available.**
- Two sandboxed processes open each other with `PROCESS_ALL_ACCESS`; neither opens the user's processes (part 2, run). The child token's default DACL grants the sandbox SID `GENERIC_ALL` (`token.rs:375-415`).
- srt's CLI cannot run two chats at once: the second's proxy fails `listen EACCES 127.0.0.1:60082` (part 2, run).
- The argv form POSIX-quotes each word for bash (`dist/cli.js:458`) and runs the string through `cmd.exe /d /s /c` (`windows-sandbox-utils.js:74-78`): derm hands srt **one command string with `-c`**.
- Inside: the command runs as `srt-sandbox`, with that account's profile, no `NO_PROXY`, and proxies on `localhost:60081`. srt deletes `NO_PROXY`, so loopback goes through its proxy; with `network.allowLocalBinding` on it sets `no_proxy` to the loopback hosts (BCR-4), so **derm pins `allowLocalBinding` off**. Direct TCP to `127.0.0.1:60089`, inside the WFP permit range 60080 to 60089, connects; `:60100` is refused (EACCES). Through the proxy, `:60100` is blocked with `allowedDomains: []` and reached with `["127.0.0.1","localhost"]` (part 2, run).
- Pipes are judged by their DACL, not WFP; a DACL'd pipe was reachable from inside (part 2, run).
- 0.0.82 reads only listed tool folders of the profile; `%USERPROFILE%\.derm` and `.codex` are not readable (README 825-870). Under the experimental MXC backend a sandboxed command reads the whole system drive but the deny list (README 1016; BCR-9): derm uses the srt-win backend only.
- srt's proxy credential is `srt.<base64 of the command>:<32 hex>@` in `http_proxy`, `all_proxy` and `CLOUDSDK_PROXY_PASSWORD`; a redactor keyed on `srt:` misses it (part 2: it leaked into one output file).

## 2. What derm builds on it (lane 5bD; built, not run with real srt until the Windows test w5b; as built per request 5bD-3)

1. **One srt chat at a time on the machine** (case 230), across Windows users: `derm run --boundary srt` takes a machine-wide lock before it starts srt and refuses a second chat with the reason ("srt on Windows runs every chat as one sandbox account; another srt chat is running"). The default boundary never picks srt on Windows while the lock is held.
2. **The handoff file**, per chat, written by `derm run` as the user before srt starts: in a folder of the user's whose inheritance is broken (`C:\derm-win-w5` was readable by Users, part 2), granted read to the sandbox account on the file alone, for the chat's life, revoked once `derm enter` has read it by `derm enter` deleting it (the sandbox account gets read and delete on that file alone, SDDL `FRSD`; where the delete fails, `derm run` removes it at stop) (case 231). Its shape is section 3. A read by anything else is detectable with a SACL (event 4663 names the reader, part 2, run; it needs an administrator's audit policy), which derm reports only where that policy is on (NF whether to turn it on: Tony's call).
3. **`derm.exe enter <handoff>` is srt's command** (one string, section 1). It reads the handoff by handle (a regular file, the sandbox account's read grant only, under 64 KiB), sets the chat's variables from it (`DERM_CHAT_TOKEN`, `DERM_CHAT_TOKEN_FILE` and `DERM_CHAT_FILE` among them), and starts the harness by its absolute path (never `.cmd`, case 138). The harness's state folder is per chat (`CLAUDE_CONFIG_DIR`, `CODEX_HOME`; BC section 5, I), writable; its control files are denied (the srt write and deny lists derm builds on Unix, as srt-win ACEs); `%USERPROFILE%\.derm` stays unreadable (case 143).
   As built, `derm run` (not `derm enter`) writes the token file `token` and the chat file `chat.json` (`{"version":1,"chat","policy","policyProblem","daemon":{"http"}}`) beside the handoff, read-only to the sandbox account for the chat's life, so the agent cannot replace them. The harness's state is a copy in `%USERPROFILE%\.derm-srt\state\<harness>`, emptied at start and stop: a sandbox chat keeps no history.
4. **The gate inside** reaches the daemon through srt's proxy on the daemon's HTTP port alone (`allowedDomains` with `127.0.0.1:<port>`; BC section 5: the Unix route carries over), never a pipe open to the sandbox account (any srt chat could use it). The policy is the copy `derm run` loaded and judged on the host (`gate::policy`); the gate inside reads it, and the route, from `chat.json` (`DERM_CHAT_FILE`), not from the handoff, which is gone once read. **Not built** (request 5bD-2, for the close): until it is, a gate inside srt on Windows finds no policy and no daemon, every call asks, and an ask with no daemon is a deny.
5. **Sign-in**: Claude Code keeps a plaintext `.credentials.json` unless a credman flag is set; Codex's store is `file` by default; refresh tokens are single use (BC section 5, V). As built, the sign-in host stays shut under srt on Windows (no renewal inside), as for a keychain store on macOS (cases 186, 190): the chat stops once its copied access token expires, and says so at the start.
6. **`derm enter --check <handoff>`** reads and validates a handoff and prints what it would do, as one JSON line (as built: `{"ok","chat","harness","program","args","cwd","variables","tokenFile","chatFile","daemon","policyProblem","expires","skipped"}`, and on Windows `writableHere` in place of a refusal, since the user who runs `--check` owns the file), and starts nothing; on a non-Windows host it does the same (the file's rules that need Windows are reported as `"skipped"`). `derm doctor` and the contract test use it.

## 3. The handoff file

```json
{
  "version": 1,
  "chat": "derm-0123456789ab",
  "harness": "claude-code",
  "argv": ["C:\\Users\\u\\AppData\\Roaming\\npm\\node_modules\\@anthropic-ai\\claude-code\\bin\\claude.exe", "-p", "hi"],
  "cwd": "C:\\work\\proj",
  "variables": {"DERM_CHAT_ID": "derm-0123456789ab", "DERM_BOUNDARY": "srt", "CLAUDE_CONFIG_DIR": "C:\\Users\\u\\.derm-srt\\chats\\derm-0123456789ab\\claude"},
  "token": "<64 hex: the chat token>",
  "daemon": {"http": "http://127.0.0.1:60088"},
  "policy": {"version": 1, "rules": []},
  "policyProblem": null,
  "expires": 1762790400000
}
```

- `argv[0]` absolute, a `.exe`; `cwd` absolute; `variables` names match `^[A-Z][A-Z0-9_]{0,63}$`, and none of srt's whole overlay and its account's profile (as built: `enter/handoff.rs` `RESERVED`, wider than `PATH`, `PATHEXT`, `ComSpec`, `SystemRoot` and the proxy variables); `token` is 64 lower-case hex; `daemon.http` a loopback URL inside 60080 to 60089 (section 1's permit range) or the proxy route; `policy` a parsed policy (`contracts/policy.schema.json`) with `policyProblem` the host's load problem or `null`; `expires` milliseconds, after which `enter` refuses.
- Anything else, any extra key, or a file that is not exactly this shape: `derm enter` refuses and starts nothing.

## 4. Security

`derm enter` runs as the sandbox account, so everything it reads is judged by handle. It never runs a shell (case 138). The token and the policy reach the sandbox only through the handoff. What still holds across chats is section 2's single lock: two srt chats on one machine are never kept apart (case 230).
