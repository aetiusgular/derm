# `derm gate serve`: the co-process the in-process plugins ask

Written by the wave 5b base on 10 Nov 2026 (`plans/toolkit_wave5b_plan.md` section 2.0, part 3; lane 5bC fills it). Evidence: note BC section 4 (`research-notes/BC_wave5b_base_research.md`). Marks: **V** read at the pin or run, **I** inference, **NF** not found. Fixture: `fixtures/gate-serve/exchange.jsonl`.

## 1. Who starts it, and when

Pi and oh-my-pi (through derm-pi), OpenCode, Kilo, OpenClaw, Amp and Cline load JavaScript plugins only. Each plugin starts `derm gate serve --agent <id>` once per session, with the session's environment (`DERM_POLICY`, `DERM_DAEMON_SOCKET`, `DERM_CHAT_TOKEN` or `DERM_CHAT_TOKEN_FILE`, `DERM_CHAT_ID`, `DERM_FULL_ACCESS`), and keeps it for the session's life.

- Spawning a child works from a plugin in Pi, OpenCode, Kilo and Hermes (V); oh-my-pi and OpenClaw likely (I); Amp and Cline already run each plugin in a separate process, and a spawn from there is not run (BC 4).
- **derm is found by its absolute path, never on PATH** (case 227): the plugin runs the launcher its package ships, which runs derm from its fixed per-user install folder after case 109's file check (a regular file of the user's, writable by no one else). How the launcher learns that folder is lane 5bC's and 5bF's (I).
- **It fails closed** (case 228): a plugin whose co-process cannot start, exits, or does not answer a request in time answers deny for every call until it has started it again, says why, and never decides in process. A throw blocks in Pi (`docs/extensions.md:3252`), oh-my-pi (30 s) and OpenClaw (15 s) (BC 4, V); **Cline drops a plugin after five failures and then runs calls (fails open), with 3 s per hook and 4 s at setup** (BC 4, V), so Cline's co-process starts and answers within that and `derm status` names Cline's failure mode. Amp's failure mode is NF; Amp keeps its TypeScript gate until a real Amp run passes with the co-process (wave 5b plan, lane 5bC; BBR-13).

## 2. The wire

JSON lines on stdin (requests) and stdout (replies), UTF-8, one object per line, at most 1 MiB a line; stderr is for people. Each request carries an `id` (a string or a number the plugin chooses); each reply echoes it and has `ok`. Requests may be pipelined; replies come in request order. A line that is not JSON, or over the cap, gets `{"id": null, "ok": false, "error": ...}` and the co-process exits 2 (the plugin then denies, section 1).

The first line is `hello`:

```
{"id":0,"op":"hello","agent":"pi","protocol":1}
{"id":0,"ok":true,"protocol":1,"policy":{"loaded":true,"problem":null}}
```

`agent` must equal `--agent`; a mismatch is `ok: false` and exit 2. `policy.problem` is the checked load's reason when the policy is empty (`gate::policy::load_for_hook`: every call then asks).

### 2.1 `decide`

```
{"id":1,"op":"decide","call":{"tool":"bash","input":{"command":"ls"},"chat":"c-1","toolUseId":"t1","fullAccess":false,"description":null}}
{"id":1,"ok":true,"action":"allow","normalizedTool":"bash","reason":"rule bash allow","updatedInput":null,"redacted":0,"askTimeoutSeconds":60}
```

`call` is `gate::core::GateCall` (`tool` as the agent gave it, `input` the tool's input, `chat`, `toolUseId`, `fullAccess` where the plugin knows it, else `DERM_FULL_ACCESS`); `description` is the tool's description where the host shows one (Pi), for the description pin (case 96). The reply is `gate::core::decide_call`'s `GateAnswer`, one decide path with `derm hook` and `derm acp` (case 229). The co-process posts the decision's `approval` record itself (contracts/events.md section 4, `gate::daemon::post_event`, the id from `decision_id`), and the `install.call` records for an install (`gate::core::install_events`); the plugin posts neither.

### 2.2 `approve`

```
{"id":2,"op":"approve","call":{...},"answer":{...the decide reply...},"canAsk":true}
{"id":2,"ok":true,"kind":"harness","reason":"rule github/* ask (no derm approver connected)"}
```

`gate::core::resolve_ask` through the daemon's approver: `kind` is `allow`, `deny`, or `harness` (show the host's own prompt; only when `canAsk`). The reply comes within the answer's `askTimeoutSeconds` plus 5 s. derm-pi keeps its own `ctx.ui.confirm` and its input freeze (case 88): it asks `approve` with `canAsk: true`, and on `harness` shows its prompt over the frozen input.

### 2.3 `event`

```
{"id":3,"op":"event","event":{"id":"pi-t1-decision-<32 hex>","chatId":"c-1","harness":"pi","kind":"approval","summary":"bash allow","detail":{"decision":"allow","tool":"bash","by":"user"}}}
{"id":3,"ok":true}
```

For a record only the plugin knows (an ask the host's own prompt answered, a tool result's redaction count). `kind` is `approval` or `tool.call`; `detail.trust` is set to `client` by the co-process, whatever the plugin sent.

### 2.4 `memory.check` and `memory.approve` (derm-pi's index record, case 48)

The record is derm-pi's `~/.derm/memory-index.json` (`DERM_MEMORY_STATE` when absolute): `{"version":1,"projects":{<real path>:{<folder>/INDEX.md:{"sha256","lines"}}}}` (`packages/derm-pi/extensions/memory.ts:360-470` at `e29ce27`). The co-process judges it **by handle on every OS** (Windows by its access list, the rule `gate::policy` applies; wave 5b plan call 3), so Windows keeps approvals.

```
{"id":4,"op":"memory.check","project":"/home/u/p","rel":"memory/INDEX.md","sha256":"<64 hex>"}
{"id":4,"ok":true,"state":"changed","trusted":true,"lines":["- a"]}
{"id":5,"op":"memory.approve","project":"/home/u/p","rel":"memory/INDEX.md","sha256":"<64 hex>","lines":["- a","- b"]}
{"id":5,"ok":true,"written":true}
```

`state`: `approved` (the hash matches), `changed` (another hash is approved: `lines` are the approved ones, for the card), `unknown` (none). `trusted: false` when the record cannot be used (a link, others can write it, not the user's, unreadable): then nothing is approved and `memory.approve` answers `written: false`. A missing record is trusted and empty. `memory.approve` writes a new 0600 file beside the record and renames it over, as `memory.ts` does. Only the person's click sends `memory.approve` (case 48); the co-process cannot tell a click from a call, so the plugin's own guard stays.

## 3. Errors

`{"id":<id>,"ok":false,"error":"<text>"}` for a request it refuses (an unknown op, a bad field); the co-process keeps running. A plugin reads any reply without `ok: true` to a `decide` or `approve` as a deny.

## 4. Security

The co-process runs as the user, with the session's environment: a chat token is the agent's too (case 66). It reads no file a request names except the memory record's own path, which comes from its environment, never from a request. It writes nothing but the memory record. It answers only on its own stdio.
