# derm-hermes-plugin

The derm policy gate for Hermes Agent (T2.4, wave 2 lane I; moved to `derm hook hermes` by wave 5b lane 5bB). Written against Hermes's source at v0.22.5 (`bf0203a7`) and read again at `main` `78abaaf` (10 Nov 2026). **Not run against a real Hermes yet**: installing Hermes was refused in the lanes' workspaces. The plugin's own code is tested (Python `unittest`, with the real `derm hook hermes` and a real policy file); `tests/cli-contract/checks/I/hermesGate.mjs` is written for the box test and has not run.

## How it works

Hermes runs Python plugins. This one (`__init__.py`, `derm_gate.py`) registers two hooks and hands each call to `derm hook hermes <pre|post>`, derm's one gate in Rust, run by its absolute path. So the rules are the same as in every other harness, at the cost of one derm start per tool call. (`bin/derm-decide.mjs` and `src/` are the Node decider it used until wave 5b; integration removes them at the switch-over.)

derm is never looked up on `PATH` (rules case 227): the plugin runs the absolute path in `derm-path` beside `derm_gate.py`, which `derm connect hermes --gate` writes, else `~/.local/bin/derm`, else `/usr/bin/derm`. Each is used only when it is a regular file of yours or root's that no one else may write, in a folder no one else may write, and `derm-path` is held to the same rule. On Windows the check cannot be made from Python's standard library yet, so the plugin blocks every call there.

- **pre_tool_call**:
  - **deny** returns `{"action": "block", "message": "derm: <reason>"}`; Hermes gives the message to the model as the tool's result.
  - **ask** goes to the derm daemon's approver first (`derm watch --approve`). With no approver it goes to Hermes's own approval gate (`{"action": "approve"}`), which asks you in a foreground chat or through the gateway and blocks when no one can answer. **Under `--yolo`, `/yolo`, an unattended turn or `approvals.mode: off`, Hermes's gate approves everything, so there derm blocks the ask instead.** An approver's no, or a timeout, is a block.
  - **allow** returns nothing; with secret-like values redacted from an MCP tool's input it returns `{"action": "modify", "args"}`. In a shell command or a write they make the call an ask.
  - A call whose input names Hermes's own files or switches (`~/.hermes/`, `HERMES_HOME`, `HERMES_SAFE_MODE`, `HERMES_YOLO_MODE`, `HERMES_ENABLE_PROJECT_PLUGINS`, `HERMES_ACCEPT_HOOKS`) asks.
- **transform_tool_result** replaces a result that holds a secret-like value with the redacted text, and records the call in the derm daemon (a hash, no content).
- **Everything that goes wrong blocks**: no derm it can trust, a decision that takes over 25 seconds, an answer the plugin cannot read. Hermes also blocks a `pre_tool_call` callback that raises or runs past `plugins.hook_callback_timeout` (30 s by default). An ask waits at most 20 seconds. If you lower `plugins.hook_callback_timeout` under 25 seconds, every slow decision blocks.

MCP tools reach the gate as `mcp__<server>__<tool>`; the shell tool is `terminal`.

## Install

Hermes installs plugins per profile, into `$HERMES_HOME/plugins/` (default `~/.hermes`). From a clone of derm:

```bash
cp -r /abs/path/derm/packages/derm-hermes-plugin ~/.hermes/plugins/derm
hermes plugins enable derm
```

Then write derm's absolute path beside it (`derm connect hermes --gate` does this; by hand: `command -v derm > ~/.hermes/plugins/derm/derm-path && chmod 600 ~/.hermes/plugins/derm/derm-path`, after checking that the path printed is derm's) and restart the gateway. `plugins.enabled` is opt-in: a plugin that is not listed does not load, and `plugins.disabled` always wins. `HERMES_SAFE_MODE=1` loads no plugin at all. For another profile, copy it into `~/.hermes/profiles/<name>/plugins/derm` and enable it there. derm never installs into a project's `.hermes/plugins/`.

Needs derm (with `derm hook`, wave 5b). No Node, no Python dependencies.

## Known limits

- **A later plugin's `modify` changes the call after derm decided.** Hermes gives every `pre_tool_call` callback the original args and merges all `modify` returns afterwards (`hermes_cli/plugins.py:1967-1976`). A `block` from derm still wins over everything. Orca's Hermes plugin only observes.
- One derm process per tool call adds its start time to every call (not measured for the Rust gate yet; Node's was about 0.09 s).

## Environment

As the Claude Code plugin: `DERM_POLICY`, `DERM_DAEMON_SOCKET`, `DERM_CHAT_TOKEN`, `DERM_CHAT_TOKEN_FILE`, `DERM_CHAT_ID` (else Hermes's `session_id`), read from Hermes's own environment.
