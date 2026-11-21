# Contract: derm's project tools and the screen a chat serves

Written by step P's base ("P base, go"), 20 Nov 2026, from `research-notes/CD_project_layer_base.md` sections 6 and 7 (with the check's C3). Builds plan step P5's reader, P6 and P7 (`plans/toolkit_agent_accounts_plan.md` revision 5, section 3.4; Tony's calls 18 to 20). Lanes PD and PE build against this file, `project-tools.schema.json` and `fixtures/project/`; no lane edits them during the build. The op lines are `daemon-protocol.md` section 6; the records `events.md` section 7.

## 1. The server

- `derm-daemon project-mcp`: a stdio MCP server the harness starts, registered as `derm_project` in each project home's harness configs by the helper at the project's first chat (plan P2's gateway entry, lane PA writes the entry, lane PE the server), and listed in the library as computer use is (`library/catalog/derm-computer-use/`; the entry is integration's). A subcommand of the daemon's binary beside `cu-mcp`.
- It adds no secret of its own. It finds the chat token and the socket by `computer_use/relay.rs`'s `chat_token` and `socket_path` (V, `relay.rs:85-125`): `DERM_CHAT_TOKEN`, else the file `DERM_CHAT_TOKEN_FILE` names; `DERM_DAEMON_SOCKET`, absolute and outside the session folder, else the default. It does **not** use `relay.rs`'s `endpoint`, which reads `cu.endpoint` in a folder the caller must own and refuses an account chat's bridge folder (V, `relay.rs:128-150`; C3).
- It dials the socket (an account chat's bridge `daemon.sock`, which passes a `hello` with this chat's token and then copies bytes, V `bridge.rs:12-17`; the daemon's own socket elsewhere), sends `hello` with the chat token, and speaks `msg.send`, `msg.take`, `screen.read` and `screen.list` (`daemon-protocol.md` 6.2). The daemon answers each from the token's chat and project, never from a field in the line.
- Like `cu-mcp` it stays alive for the harness's life and answers a tool call with an error while it has no target or the daemon is gone, never by exiting (case 39).
- Its tools reach the gate as `derm_project/derm_message` and `derm_project/derm_terminal_read` (policy step 1). The presets' rules for them are integration's (request).

## 2. The tools

Schemas: `project-tools.schema.json` (`$defs`: `messageInput`, `messageOutput`, `messageList`, `readInput`, `readOutput`, `readList`), each with its `x-derm-tool` name and model-facing description.

### 2.1 `derm_message`

- Send: `{to: <chat id> | "*", text: <1 byte to 16 KiB of UTF-8>, reply_to?: <message id>}` returns `{id, delivered: [chat ids], asked: [chat ids]}`. `"*"` is every other running chat of the caller's project.
- Read: `{action: "read"}` returns `{messages: [{id, from: {chat, harness, account, agent: true}, at, text, reply_to?}]}` and removes them. `account` is the agent account's slug, or `""` for a chat that runs as the person.
- Every message is marked as from an agent (`from.agent: true`) in every rendering; the server's text for the model starts with `Message from agent chat <chat> (<harness>)`. It never claims to be the person.
- A message waits in the daemon's memory for its chat, at most 64 messages and 256 KiB per chat (oldest dropped, counted), and ends with the chat's `run.stop` (I).

### 2.2 `derm_terminal_read`

- `{chat: <chat id>, lines?: <1 to 2000; default the screen>}` returns `{chat, rows, cols, text, truncated, at}`, `text` by section 3.
- `{action: "list"}` returns `{chats: [{chat, harness, account, rows, cols, at}]}`: the chats of the caller's project that serve a screen, the caller excluded.
- Read only: nothing a tool call sends reaches the other chat's input (P-C5).

### 2.3 Same project, other projects, the session grant

- **Same project:** the daemon compares the project it holds for the caller's token (`token.mint`'s `project`) with the one it holds for the target chat. `""` is no project: a chat with `""` reaches no chat and is reached by none. Nothing in the call's text decides it.
- **Across projects** (P7, Tony's call 20): the daemon asks the person through the approver, as the gate's `ask` does (cases 71, 97): an `approve` request with `tool` `derm_project/derm_message` or `derm_project/derm_terminal_read`, the caller's chat as `chat`, and a summary naming both projects by folder. The card offers "this once" and "for this session". A session grant is kept in the daemon's memory only, for the ordered pair (caller's project, target's project), and ends when the caller's chat stops (its `run.stop`); it is recorded as `project.grant` and never written to a file a chat can reach (P-C7). With no approver, or a timeout, the answer is no (case 63). Default ask (call 20).
- **Claude Code's own inbox** (P6, P-C6): a Claude Code chat under derm starts with `"crossSessionInbound": "refuse"` at the top level of derm's last `--settings` block (`run/claude_gate.rs`'s `block`; case 246), since on Linux its inbox takes lines with no auth token by default (V by read, 2.1.322: `authRequired = s.requireAuth ?? ZNr()`, `ZNr()` true on Windows only; the setting's own description: "'refuse' opts this session out. An explicit value always wins"). The key sits beside `teammateMode` and the other top-level settings in its schema (V by read). Whether a project's `.claude/settings.json` can override derm's `--settings` value: I, lane PE's test settles it with the real 2.1.322 where the cloud allows.
- **Push:** delivery is pull, by `{action: "read"}`, for every harness. Claude Code's channels (`notifications/claude/channel`, behind `--channels`) exist in the binary (V by read, not run); if derm ever pushes through one, its server never declares the `.../permission` notification, which answers a permission prompt (note CD section 0, item 9).

## 3. The screen (lane PD's engine, lane PE's tool)

### 3.1 The reader

`derm run` (`crates/derm-cli/src/run/pty/`, lane PD) holds the harness on its own pty, passes signals, resize and raw mode, copies the harness's output to the person's terminal unchanged, and feeds the same bytes to a terminal parser sized to the person's terminal, with a scrollback of at most 10,000 lines (`derm_core::project::screen::MAX_SCROLLBACK_LINES`). The parser has no writer: queries in the output are not answered by derm (the person's own terminal still answers them, as today). vt100 0.18.1 is the candidate (MSRV 1.85, derm's toolchain 1.97.0): it executes C0 and never stores it, and sends C1 and U+FFFD to a callback (V, `perform.rs:8-30`); it stores format characters as text (V), so section 3.3's filter runs after it. Lane PD vets it as a dependency (rules section 5, item 9).

### 3.2 `screen.put`

`derm run` runs as the person and holds daemon scope, so it pushes the rendered screen with `screen.put {chat, rows, cols, text, scrollbackLines, at}` (`daemon-protocol.md` 6.3), at most once every 250 ms while the output changes and once at the chat's end. The daemon keeps the last screen per chat in memory only and drops it at the chat's `run.stop` plus the keep of case 205. Screen text is content: never in a record, and on disk only under the content switch.

### 3.3 Text

- At most 512 KiB of UTF-8 per `screen.put` and per reply (`screen::MAX_TEXT_BYTES`), under the socket's 1 MiB line cap (V, `socket.rs:18`; case 185), cut from the top on a character boundary with `truncated: true`.
- Rows joined by `\n`, trailing spaces trimmed.
- Removed, and counted: every character of Unicode category Cc other than `\n` and `\t`; every Cf character (U+00AD, U+0600 to U+0605, U+061C, U+06DD, U+070F, U+180E, U+200B to U+200F, U+202A to U+202E, U+2060 to U+2064, U+2066 to U+206F, U+FEFF, U+FFF9 to U+FFFB, U+110BD, U+110CD, U+13430 to U+1343F, U+1BCA0 to U+1BCA3, U+1D173 to U+1D17A, U+E0001, U+E0020 to U+E007F: the whole Cf category of the Unicode version lane PD names, from the UCD, not this list); U+FFFD.
- `derm_core::project::screen::clean` is the one filter, run by `derm run` before `screen.put` and by the daemon again before a reply leaves (3.4).

### 3.4 The daemon's second pass

`screen.read`'s reply text goes through `clean` again in the daemon, whatever `screen.put` sent, so a `derm run` that skipped it (an older build, a bug) never hands control bytes to an agent.

### 3.5 The corpus

`fixtures/project/screen-corpus.json`: CSI, OSC 0, OSC 52, DCS, DECRQSS, C1 in UTF-8, U+202E, U+200B, U+FEFF and the isolates, tag characters, BEL, BS and FF, U+FFFD, each with what a terminal shows. Written by hand from note CC section 4 and vt100's source (rules 9.12: not recorded from a harness); P-B4 runs the reader against Claude Code's and Codex's TUIs on the box.
