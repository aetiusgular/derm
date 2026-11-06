# Contract: the events lane A emits, and the adapter record

Written by tk session 0, 27 Oct 2026, from the fork's receiver at `159ef3e` (`src-tauri/src/otel_receiver/decode.rs`, `normalize.rs`) and its recorded fixture `tests/fixtures/otlp/claude-2.1.302-logs.json` (copied into this repository). Lane A emits; lane B decodes.

## 1. How the receiver reads a record (read in code)

- The event name is the `event.name` attribute if present, else the record's `eventName`, else the body when it is a string (`decode.rs:25-57`).
- Claude Code 2.1.302 sends the **short** name in `event.name` (`tool_result`) and the prefixed name in the body (`claude_code.tool_result`): every record in the fixture does.
- `normalize.rs:42-46` strips `claude_code.` and `codex.` only. A name `pi.tool_result` with no short `event.name` would land as kind `otel.pi.tool_result`.
- `describe` (`normalize.rs:106-170`) maps short names to kinds: `tool_result` to `tool.call`, `tool_decision` to `approval`, `api_request` to `model.request`, `api_error` to `model.error`, `user_prompt` to `prompt`, `conversation_starts` to `session.start`, `assistant_response` to `message`.
- Attributes starting `user.` or `organization.` and `account_id` are dropped; `prompt`, `prompt_text`, `user_prompt`, `response` and `*.prompt` are dropped unless content logging is on (`normalize.rs:28-40`).
- The receive time is the event's time; the record's own time goes to `detail.harnessAt` (`normalize.rs:206-211`, review S4).

## 2. What lane A emits

OTLP JSON logs (`POST $DERM_OTLP_ENDPOINT/v1/logs`, header `x-derm-token: $DERM_CHAT_TOKEN`), one `resourceLogs` entry per batch, batched at 1 second.

Resource attributes: `service.name` = `pi`, or `oh-my-pi` when the package runs under oh-my-pi (Bun; lane I's request 6, integration w2), `host.arch`, `os.type`. No `service.version`: Pi gives an extension no version without a runtime import of Pi, and the receiver keeps only `service.name` (`decode.rs:333-342`; lane A).

Per record: `timeUnixNano`, body `{"stringValue": "pi.<name>"}`, and these attributes, mirrored from Claude Code's:

| `event.name` (short) | From Pi event | Attributes |
|---|---|---|
| `user_prompt` | `before_agent_start` | `session.id`, `prompt.id`, `event.sequence`, `event.timestamp`, `prompt_length`; `prompt` only with the content switch on |
| `tool_decision` | `tool_call` (after the gate decided) | the above, `tool_name` (as Pi gave it), `tool_name_normalized`, `tool_use_id`, `decision` (`accept`, `reject`, `ask_accept`, `ask_reject`, `ask_timeout`), `source` (`derm-policy`), `reason` |
| `tool_result` | `tool_execution_end` | the above, `tool_name`, `tool_use_id`, `success`, `duration_ms`, `tool_result_size_bytes`, `tool_result_sha256`, `parent_tool_use_id`; `tool_input` only with the content switch on |
| `api_request` | `message_end` | the above, `model`, `input_tokens`, `output_tokens`, `duration_ms` when Pi gives them, `provider`, `stop_reason` |
| `assistant_response` | `message_end` | the above, `model`, `response_length`; `response` only with the content switch on |

Lane A confirmed the events in Pi 1.4.0's `docs/extensions.md` and `types.d.ts` and ran them in a real Pi (`plans/parallel/tk_lane_A.md`). `provider`, `stop_reason` and `parent_tool_use_id` are lane A's additions; the receiver keeps them under `detail.attributes`. Int64 attributes go as decimal strings (the OTLP JSON mapping); the decoder reads both. The `event.name` values above are fixed: they are what `describe` already understands. Integration w1 ran the emitter into lane B's real receiver: a Pi bash call landed as one `tool.call` record in the `derm run` chat (`tests/integration/w1.mjs`).

Rules:

- The emitter never blocks a turn. A failed POST is counted and dropped; the count is shown in Pi's status line if lane A adds one.
- No token, no POST. No endpoint, no POST. Nothing is sent anywhere but `DERM_OTLP_ENDPOINT`, which must be a loopback URL (`127.0.0.1`, `::1`, `localhost`); any other host is refused and counted.
- Under sbx, `derm run` rewrites the endpoint to `host.docker.internal:<port>` (lane D), which is not loopback, so the emitter refuses it and a Pi chat under sbx has no OTLP feed in wave 1. Integration w1 kept the loopback rule (lane D's request 1): widening it would let any `DERM_OTLP_ENDPOINT` an agent sets name a host on the network, and whether sbx's proxy keeps the `Host` header the receiver checks is not known. The sbx policy log is that chat's feed. The box test records what sbx does with the header; a later wave can allow the one name only when `DERM_BOUNDARY=sbx`. Since integration w5's continue, the hook core does that for its own records and asks (`daemon-protocol.md` section 4, the derm routes); Pi's emitter does not yet.
- Content off by default; hashes and sizes on.

## 3. What lane B changed in the receiver

- `short_name` strips `pi.` beside `claude_code.` and `codex.`.
- The header is `x-derm-token`.
- A chat token can be minted for any of the 14 preset harness ids (`harness_env::harness_id`).
- `apply_export` (replacing the fork's `apply_to_child`) sets Claude Code's and Codex's own OTel export for a process derm starts; `derm run` does not call it yet (integration w1: a wave 4 item for lane R, which owns `derm run` then), so a `derm run claude-code` chat has the hook's adapter records and no Claude Code OTel feed.

## 4. The adapter record

Clients that are not OTel exporters (lane F's hook scripts, `derm run`) post `event` lines on the socket (`daemon-protocol.md`, section 2) with `source: "adapter"` (or `run`), their own `id`, and `detail.trust: "client"`. The id for a tool call is `<harness>-<tool_use_id>` when the harness gives a tool-use id, so the OTel record and the adapter record for one call can be joined (case 35: the last copy per id wins, within one chat; one call, two records, joined by `tool_use_id` in `detail`). Lane F's hooks post the decision as `kind: "approval"`, id `<harness>-<tool_use_id>-decision-<32 hex>` (`<harness>-unknown-decision-<32 hex>` when the harness gives no call id): the last part is 128 random bits from the core's `decisionId`, so the agent, which holds the same chat token, cannot post under that id first (integration w2's fix pass, box test w2 BW2; before it the id was `<harness>-<tool_use_id>-decision`, and call ids count up). Join a decision to its call by `detail.toolUseId`, never by the id; a second adapter decision for one call in one chat is kept as a conflict copy and flagged (`daemon-protocol.md`, section 2; FP1-S4). Written once per chat and id (S9: a later copy never replaces it), and the result as `kind: "tool.call"`, id `<harness>-<tool_use_id>`, with `resultSha256`, the size and the redaction count, never content. A hook posts only with a chat token (`contracts/policy.md` section 5).

## 5. Wave 5's records (the wave 5 base, 4 Nov 2026)

Written by the wave 5 base from `plans/toolkit_universal_plan.md` (revision 7) sections 2 to 6 and notes AR, AS and AT; nothing here is built yet. Each record is an ordinary event (`daemon-protocol.md`, section 3). The detail shapes are `wave5-records.schema.json`, with one example of each in `fixtures/tap/records.json` and `fixtures/installs/records.json`; `contracts.test.ts` validates them. A lane that needs a field not here asks integration (rules section 10); it does not add one.

Two sources are new, and only the daemon writes them: no socket client, chat or daemon scope, may post one (`daemon.rs`'s `op_event`; `tests/socket.rs`, `no_socket_client_posts_a_tap_or_derm_record`). A lane whose process is not the daemon (a `derm-tap` binary, say) asks integration to open daemon scope for its source, with the reason.

- `tap`: the model tap (lane S).
- `derm`: what the daemon derives itself (lanes S, W, X).

| `kind` | `source` | Who | What it says |
|---|---|---|---|
| `tap.request` | `tap` | lane S | One model round trip: API, upstream host, model, tokens, timing, how many tools were offered and called, `incomplete` when the stream was cut (case 115), the HTTP status |
| `tap.call` | `tap` | lane S | One tool call the model asked for: its call id (`tool_use.id` for Anthropic, `call_id` for the Responses API), the tool as named and normalized, the arguments' sha256 and size, the file paths the arguments name, and, once the harness sends the result back, the result's sha256 and size. Id `tap-<chat>-<call id>`, so the result replaces the call's first copy (case 35) |
| `join.candidates` | `derm` | lane S | An effect event and the calls it may belong to, each with how it fits (`tool-use-id`, `tree`, `path`, `window`, `mcp-server`) and why. `chosen` names a call only when the tree or a path separates it; otherwise null (miss 10, case 123). Id `join-<effect id>` |
| `install.call` | `adapter` | lane X, through every gate | A shell call the gate read as an install: the manager, `add` or `run` (`npx`, `uvx`, `bunx`, `dlx`; case 131), each package with its version and whether the lockfile already has it, the decision, and the pre-install check's results when it ran |
| `install.lockdiff` | `derm` | lane X | Per install call: the lockfile, packages added, removed and changed, with versions. Names and versions are metadata, kept with the content switch off (case 85 as changed) |
| `install.control` | `derm` | lane X | A write to a control path by a process under an install call (case 133): the path, the process, the call it is credited to. Only a call the join chose, or, for a shell the join placed among several running shell calls (each `by: tree`, none chosen), the install among them, with "(one of N calls running)" in the summary; never a call merely running at the time (box test w5, BW5-13; integration w5 fix pass 1's review, F1) |
| `content.purge` | `derm` | lane S | Content files of a chat deleted at the end of their retention (case 126): how many, how many bytes, the retention. The hashed records stay |
| `agent.unregistered` | `derm` | lane W, through integration | A known agent executable the OS layer saw outside every registered tree (case 122): the executable, the preset id, its pid and its parent |
| `cu.action` | `cua` | lane U | One `computer_use` action: the action, the target app, the delivery (`background`, `foreground`), the verdict (`ok`, `denied`, `blocked`, `timeout_outcome_unknown`, `error`), the screenshot's sha256 (the image itself follows the content switch), the grant it ran under. A mutation after a timeout is never retried (case 120) |

Every record keeps hashes, sizes, paths, package names and versions, and never content, headers or a token. Content (prompts, arguments, results, the model's text, argv words, screenshots) is kept only when the content switch is on, in files under the daemon's data folder, `content/<chat id>/` (folder 0700, files 0600), for the retention the user chose, 1 to 7 days; a record says `contentKept: true` when its content is in such a file. No header is ever kept, content on or off (case 114). This replaces `DERM_LOG_CONTENT` as the content switch, for `run.start`'s argv words too (case 85 as changed 4 Nov); done by integration w5's continue (5 Nov): `DERM_LOG_CONTENT` is read nowhere. The daemon's receiver never keeps `prompt`, `prompt_text`, `user_prompt`, `response`, `tool_input`, Claude Code's `tool_parameters` (the Bash command line with `OTEL_LOG_TOOL_DETAILS`) or Codex's `arguments` and `output` (its tool events carry the command and the result, `tests/fixtures/otlp/codex-0.161.0-logs.json`) in a record (security finding W5C-S5); with the switch on it writes them to `<ms>-r<days>-otel_<id>.request` and `.response` files, one pair at most per OTLP request whatever its record count, a line `{"record": <record id>, "fields": {...}}` per record (`response` and `output` to `.response`), and at most 256 MiB of them, from at most 20,000 OTLP requests, per chat a day, counted in the daemon's memory (re-review W5R-9); past that a record says `contentCapped: true` and nothing is written (security finding W5C-S6) and the record carries `contentKept: true` and `contentFiles` (names only); `derm run` writes the argv words to `<ms>-r<days>-run_<id>.argv` and `run.start` says the same. Pi's emitter sends the text only with the switch on, read from the same file. The OS feeds' `exec` records (`auditd`, `eslogger`) keep the argv's shape only, content on or off: the program, flag names, and `[N chars]` for every other word, with `argvShaped: true` and a summary built from it (`derm_core::argv::shape`, applied in the daemon's `ingest`; box test w5, BW5-12).

`run.start`'s detail gains six fields, each set only by the seam that makes it (the base's stubs set none, so a chat reads as before wave 5):

| Field | Set by | Shape |
|---|---|---|
| `boundaryChoice` | lane T, `crates/derm-cli/src/run/boundary/` | `chosen` (`sbx`, `srt`, `none`), `named` (the user gave `--boundary`), `reasons` (each unavailable boundary, why, and its install line), `answeredBy` (`flag`; `default`, derm picked sbx or srt with no question, lane T's request T-1; `terminal`, `pre-answer`, `no-one`; with `no-one` there is no start, case 129, except in a dry run, which starts nothing anyway), `preAnswer` (the setting used, or null) |
| `tap` | lane S, `run/tap/` | `on`, and when off the `reason` (`--no-tap`, the setting, or the agent takes no base URL), `via`, `api`, `upstream`. A chat with `on: false` is "untapped" in `derm status` (case 127) |
| `agentUser` | lane V, `run/user/` | `user`, `uid`, `how` (the route lane V reads first: a fixed `sudo` rule, a systemd unit, or another) |
| `content` | lane S | `on`, `retentionDays` |
| `ioUring` | lane T | `not-audited` for no boundary on Linux, and for srt where its seccomp helper does not run (case 128); `blocked` for srt where it does (x86_64 and aarch64 Linux: srt 0.0.81 refuses `io_uring_setup`, `io_uring_enter` and `io_uring_register`, its README line 1214, lane T by run; request T-1); `own-kernel` under sbx; absent elsewhere |
| `sbxKit` | lane T's request P4-R3, integration w5's close, `run/boundary/sbx.rs` | Under sbx only: `added` (derm's kit, its gate in the VM, went on the create) and, when not, `why` (no kit for this agent, `DERM_SBX_KIT=off`, no usable policy, a Windows host). `derm status` reads it to say whether derm's gate is in the VM |

The user's switches for all of this are one file, `~/.derm/settings.json` (`settings.schema.json`): lane W's `derm setup` writes it, behind a question per switch; lanes S, T, U and X read their own key. `~/.derm/` is a control path (`policy.md`, section 4, step 7a), so a gated agent's write to it asks and srt denies it.
