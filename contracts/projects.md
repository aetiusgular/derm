# Contract: projects, the layout under each account, and each harness's files

Written by step P's base ("P base, go"), 20 Nov 2026, from `research-notes/CD_project_layer_base.md` (the base's research and its separate check, findings C1 to C6 settled with Tony's calls of 20 Nov, 23:06). Builds `plans/toolkit_agent_accounts_plan.md` revision 5, section 3.4 (P1 to P3), Linux only. Lanes PA, PB and PF build against this file and its fixtures; no lane edits it during the build (a change is a request for P integration). Marks: **V** read at the version named or run, **I** design or inference, as note CD marks them. The tool and screen contracts are `project-tools.md`; the records are `events.md` section 7; the op lines are `daemon-protocol.md` section 6.

Pins (note CD section 1): Claude Code **2.1.322**, Codex **0.167.2** (`rust-v0.167.2` = `ce21072`), Pi **1.4.0** for today and **1.6.0** for P3's Pi half (nothing below 1.5.1, C1), bubblewrap 0.11.1, the box's kernel 7.0.0-43-generic. A lane re-checks that no pin moved before it builds (rules 9.20).

## 1. The registry (lane PA; plan P1, Tony's call 16)

### 1.1 Where, and the checks

- `~/.derm/projects.json`, the person's own, mode 0600 inside `~/.derm` (0700). No agent account reaches the person's home, and every account chat's probe checks that `~/.derm` is hidden before it starts (V, `run/user/chat.rs:149-161`); srt and the Standard tier deny `~/.derm` (V, `docs/verbs/run.md`, `contracts/sandbox.md`). So no chat can name or move a project (I, from those reads).
- One reader, `crates/derm-cli/src/project/` (`project::load`). It refuses the file unless the file and every folder from `/` to it are the person's or root's, none a link, none group or world writable, the file a regular file of at most 1 MiB, parsed whole: unknown fields refused at every level, `version` 1, ids unique, folders unique, each `id` equal to the id of its `folder` (1.3). A missing file is an empty registry. A file that is there and refused stops a start that needs a project and names the fix (the shape of case 277); it never runs the chat without a project. These are case 226's checks, applied to a second file. Folders above `~/.derm` may be root's sticky folders (a home under `/tmp`'s 1777, as the base's own red test has it): in a sticky folder only an entry's owner, the folder's owner or root may rename or remove the entry (chmod(1), "restricted deletion flag"; inode(7), `S_ISVTX`), so no other user can swap the person's folder under it (lane PA's reading, request PA-5; P integration, 22 Nov 2026, kept it). `~/.derm` itself and the file are never group or world writable.
- A file of its own, not a key in `settings.json`, so no settings reader changes (case 285).

### 1.2 Format

`projects.schema.json`; fixture `fixtures/project/projects.json`.

```json
{"version": 1, "projects": [
  {"id": "6853732bf2a99f2b", "folder": "/home/u/work", "name": "work", "added": 1763700000000}
]}
```

- `folder`: the real path (every link resolved) when `add` took it, absolute, no trailing `/`, no `.` or `..` part, no NUL or control character.
- `name`: the person's label, 1 to 120 characters with no control or format character, shown back, never parsed. Defaults to the folder's last part.
- `added`: milliseconds since the epoch.

### 1.3 The id

The first 16 lowercase hex characters of the SHA-256 of the folder's real path, as its bytes (`derm_core::project::ProjectId::of_real_path`, the reference). 16 keeps Claude Code's inbox socket inside a project's runtime folder under its 103-byte limit (2.4). A moved or renamed folder is a new project; a later `derm project add` names it again (I). 64 bits: a collision among one person's projects is not a practical risk (I).

### 1.4 `derm project add|list|remove` and the nearest-folder rule

- `derm project add <folder> [--name <label>]`: takes the real path. Refuses `/`, the person's home itself, a folder inside `~/.derm`, a folder already named, and a folder that is not a folder. A folder inside or above a named one is refused unless `--nested` is given (I). Writes a new 0600 file beside the registry and renames it over, as `memory.ts` does.
- `derm project list`: id, folder, name, one per line; `--json` the file's `projects` array.
- `derm project remove <id|folder>`: deletes the entry and says that the project's folders under each account stay until `derm agents` cleans them (I).
- The chat's project: its working folder by real path; the deepest named folder that holds it by whole path parts (`/a/b` holds `/a/b/c`, not `/a/bc`). Tony's call 16, this session's reading accepted at 21:41.
- **No project** (P-C2): a chat on an agent account outside every named folder, and not placed by 1.5, is refused before anything starts: `derm: <folder> is in no project; name one with: derm project add <folder>`. A chat that runs as the person (`--boundary` srt, sbx, the Standard tier, or `none` with no account) gets `project: ""` and is not refused.

### 1.5 The worktree rule (git read, no git run; C5)

Runs only when no named folder holds the working folder.

1. Walk up from the working folder to the first folder that holds `.git`. If `.git` is a folder, stop: no worktree.
2. Read `.git` as a regular file of at most 4 KiB, not a link: one line `gitdir: <path>`. A relative `<path>` is joined to the folder that holds the `.git` file, as git does (V, git `v2.48.0` `setup.c:976-982`, `read_gitfile_gently`). Take its real path: `<gd>`. It must end in `/worktrees/<name>`.
3. Read `<gd>/gitdir` (the back-link): one line naming a `.git`. A relative value is joined to `<gd>/`, as git does (V, `worktree.c:114-118`). Its real path must be the `.git` file of step 2. Otherwise: no project (a planted `.git` cannot claim another project's worktree; a chat of one project cannot write another project's `.git/worktrees`, I).
4. Read `<gd>/commondir` (relative to `<gd>`, gitrepository-layout's "relative to $GIT_DIR"), take its real path, and apply 1.4's rule to it. A worktree joins the project its common folder sits in.

No git process runs, so no repository config runs (cases 27, 31). git 2.48 writes both links relative when `worktree.useRelativePaths` is on (V, `Documentation/config/worktree.txt:11-19`); 2.43 writes them absolute (V, run). The box's git version: NF (P-B3 step).

## 2. The layout under each account (lanes PA and PF; plan P2)

### 2.1 Today (V)

`/var/lib/derm/agents` is root's, 0755; each account home `/var/lib/derm/agents/<slug>` is the account's, 0700 (`packaging/linux/agent-user/install-account.sh:157-165`). A chat's domain writes the whole account home (`landlock/mod.rs`, `chat_spec`), and the harness is found on `<home>/.local/bin:/usr/local/bin:/usr/bin:/bin` (`accounts.rs`). Both change here.

### 2.2 Folders

| Path | Owner, mode | Made by | When | Domain right of a chat of project `<id>` |
|---|---|---|---|---|
| `/var/lib/derm/agents/<slug>/` | account, 0700 | installer (today) | `derm agents add` | none (no longer written) |
| `.../<slug>/signin/` | account, 0700 | installer (lane PF) | `derm agents add` | none |
| `.../<slug>/signin/<harness>/` (`claude-code`, `codex`, `pi`) | account, 0700 | installer (lane PF) | `derm agents add` | read and write, only the chat's own harness's folder |
| `.../<slug>/projects/` | account, 0700 | installer (lane PF) | `derm agents add` | none |
| `.../projects/<id>/` | account, 0700 | the helper, as the account, before the domain (lane PA) | the project's first chat on that account | none |
| `.../projects/<id>/home` | account, 0700 | the helper (PA) | same | read, write; `HOME` |
| `.../projects/<id>/tmp` | account, 0700 | the helper (PA) | same | read, write; `TMPDIR` |
| `.../projects/<id>/run` | account, 0700 | the helper (PA) | same | read, write; `XDG_RUNTIME_DIR` |

- The helper makes a missing folder with `mkdirat` under an already-open parent, never following a link, and refuses one that is there and is not a folder of the account's with mode 0700 (the shape of case 273). The installer's undo removes `signin/` and `projects/` with the account (lane PF).
- Nothing a chat runs comes from a folder a chat writes (AI-1): the domain's `exec` list holds no folder of its `write` list.
- `/tmp`, `/var/tmp`, `/dev/shm` stay in every domain until the mount layer (lane PG): programs that hard-code `/tmp` still meet across projects. `derm status` names it (open, I).
- The account home's own dot-files are no longer read by a chat, since `HOME` is the project home; `sudo -n -u` runs no login shell (case 282).

### 2.3 What each harness gets (V for each harness's reads at its pin; I for derm's design)

How the variables reach the harness: `keep()` never passes `HOME`, `PATH`, `USER`, `LOGNAME`, `SHELL` or any `XDG_*` name through `sudo` (V, `run/user/mod.rs:366-385`), so `HOME`, `TMPDIR`, `XDG_RUNTIME_DIR` and `PATH` go on `/usr/bin/env`'s argv after the helper, as `PATH` does today (`chat.rs`, `rewrite`). They are paths, not secrets, so argv is allowed (case 85). (`TMPDIR` is not on `keep()`'s list; it goes on argv too, so all four take one route.) A secret, such as the per-chat proxy credential of P10's I-3 and I-4, stays in the environment through `--preserve-env`, in both spellings, `HTTPS_PROXY` and `https_proxy`, one value (undici reads the lower first, Codex the upper; note CD section 0, item 5; Pi 1.6.0's `httpProxy` setting only fills an unset `HTTPS_PROXY`, `dist/core/http-dispatcher.js` `applyHttpProxySettings`, read by the base).

| Variable or link | Value | Why |
|---|---|---|
| `HOME` | `<id dir>/home` | moves Claude Code's `~/.claude`, `~/.claude.json`, transcripts and sessions (V, run 2.1.330), Codex's `~/.codex` (V, `home-dir/src/lib.rs:13-62`; dirs-sys 0.5.0 reads `HOME` first), Pi's `~/.pi/agent` (V, `config.js:491-497`; 1.6.0 `510-516`) |
| `TMPDIR` | `<id dir>/tmp` | Claude Code's scratch and, with no `XDG_RUNTIME_DIR`, its inbox socket (V, binary) |
| `XDG_RUNTIME_DIR` | `<id dir>/run` | Claude Code's inbox `cc-socks/<pid>.sock` (V, binary, both versions) |
| `PATH` | `/usr/local/bin:/usr/bin:/bin` | no home entry; the harness found there is root's and writable by no one else (`trusted_tool`'s check) |
| `DISABLE_AUTOUPDATER`, `DISABLE_UPDATES`, `ENABLE_CLAUDEAI_MCP_SERVERS` | `1`, `1`, `false`, Claude Code chats; the same three in derm's `--settings` block's `env`, with `disableClaudeAiConnectors: true` | box research BR-4: the account's Claude Code updated itself into the shared home and the next chat ran that copy. 2.1.322 turns its background updater off for either of the first two (V by read: its bundle's `vb`), and Anthropic's own sandbox runner sets the first and the third for the Claude Code it starts (V, same bundle). Each settings source's `env` goes into `process.env` in the order user, project, local, flag, policy (V by read: `Uo()` is `ci.filter`), so a project home's `~/.claude/settings.json` could undo the argv value; the flag source's cannot be undone. `disableClaudeAiConnectors` true in any source closes claude.ai's connectors (`ePe()`, V by read), whose calls go to `mcp-proxy.anthropic.com` (Tony, 22 Nov: closed for account chats). That the updater writes nothing under these is V by read, not run with an update pending |
| Codex: `-c check_for_update_on_startup=false` | on its command line, beside derm's hooks | BR-4's Codex half: 0.167.2 checks for a release at start and writes `$CODEX_HOME/version.json`, then offers to run the update (V by read: `tui/src/updates.rs:27-48`, `updates_cache.rs:20-22`, `update_prompt.rs`); the key is `config_toml.rs:533`, default true (`core/src/config/mod.rs:4316`). An update runs only on the person's choice in the TUI (V, `update_prompt.rs`), and as the account `npm install -g` cannot write a root-owned prefix (I) |
| Pi: `PI_OFFLINE` | `1` | BR-4's Pi half: 1.6.0 checks `pi.dev/api/latest-version` at start and only shows a notice (V, `utils/version-check.js`); it installs a settings package that is missing, and refreshes an unpinned `-e` npm source, into the home at start (V, `core/package-manager.js:1129-1170`), which `PI_OFFLINE` stops, with the version check and the model catalog refresh (V, `main.js:488-491`, `package-manager.js:53-58`). Pi updates itself only by `pi update` (V, `package-manager-cli.js:248`). derm's own `-e` is a local folder, never refreshed |
| `HTTPS_PROXY`, `https_proxy`, `NO_PROXY`, `no_proxy` | the chat's own sign-in tunnel (credential in the URL), and `localhost,127.0.0.1,::1`; a chat with no other proxy whose harness has a sign-in host | case 283, below |
| `CODEX_HOME` | unset | it must exist when set (V); the home's `.codex` is used |
| Codex: `<home>/.codex/auth.json` | link to `<slug>/signin/codex/auth.json` | Codex resolves links and renames a temp file onto the target in the target's folder; the link survives and the store folder must be writable (V, `storage.rs:274-295`, `storage_file.rs:10-62`, same at 0.171.0) |
| Codex: `<home>/.codex/auth.lock` | link to `<slug>/signin/codex/auth.lock` | Codex's cross-process commit lock is `<home>/auth.lock` (V, `storage.rs:189-212`); linked homes share it (C6, V by run: `flock` through two links) |
| Pi: `<home>/.pi/agent/auth.json` | link to `<slug>/signin/pi/auth.json` | Pi 1.6.0 locks the resolved file (V, `auth-storage.js:50-51`, #11655); 1.4.0 and 1.5.0 lock the link's path and lose writes (C1). The Pi half needs Pi 1.5.1 or later on the box, checked at start by `pi --version` (I), and derm's Pi preset re-verified at 1.6.0 (case 81) |
| Claude Code: `CLAUDE_SECURESTORAGE_CONFIG_DIR` | `<slug>/signin/claude-code` | no link: a renewal renames a temp file over the path, so a link becomes a file (V by read, 2.1.322 and 2.1.330; not run). The variable names the store folder (V by read; reads run at 2.1.330); undocumented. **On since P-B1 passed on the box** (22 Nov 2026, Claude Code 2.1.322, `plans/parallel/acctP_box_research.md`: with the variable a forced renewal in one project home wrote the store's file by temp file and rename and a second project home read it with no write; with a link the renewal replaced the link). The switch is a constant (`agents::signin::CLAUDE_CODE_STORE`); turned off, a Claude Code chat on an agent account is refused, naming P-B1. `derm agents login claude-code` signs in to the store (`CLAUDE_SECURESTORAGE_CONFIG_DIR` on `env`'s argv) and `derm agents status` looks for `signin/claude-code/.credentials.json`; a file left in the account home's `~/.claude` from before is not counted. The variable is undocumented: re-read per version (case 81); verified at 2.1.322 only |

Added by P integration (22 Nov 2026):

- **Pi's floor** (request PB-4): an agent account's Pi is refused below 1.5.1. The version is read from the root-owned install's own `package.json` (`@earendil-works/pi-coding-agent`, at most four folders above the program's real path), nothing is run (`run/user/chat.rs` `pi_floor`); a program in no Pi install derm can read is refused too. The box runs Pi 1.4.0 today: it needs 1.6.0 installed as root before a Pi account chat starts.
- **derm's gate** (request PA-2): the project home is the chat's to write, so derm puts its gate on the harness's own command line, not in the home: Codex gets `-c hooks={PreToolUse, PostToolUse, state}` and `-c features.hooks=true` (its session flags, which it reads for hooks and hook state above the user layer, V by read at 0.167.2: `hooks/src/engine/discovery.rs:156-215, 433-451, 472, 972-990`, `config_rules.rs:15-68`, `config/src/overrides.rs:22`, `config/src/fingerprint.rs:54-66`; not run, the Codex binary did not run here); Pi gets `-e /usr/local/lib/derm/derm-pi` (Pi 1.6.0 loads a folder named by `-e` as a package for that run, `dist/main.js:636`, `core/resource-loader.js:386`, `core/package-manager.js:790-802`) when that folder is a root-owned copy of derm's Pi package only root can change, and `DERM_BIN` names the helper's derm; with no such copy the chat starts with no derm gate and its start line says so in capitals. `run.start`'s `gate` is `{expected, route}` for an account chat, `expected` true only for a route whose gate blocks when it fails (Pi's; Codex's fails open, case 70).
- **The sign-in tunnel and derm-egress take a credential** (lane PB's I-3, I-4; request PB-3): each `derm agents login` tunnel mints a one-time credential and each brokered chat's derm-egress one per chat (`derm-egress/src/auth.rs`); a client without it gets 407 with `Proxy-Authenticate: Basic realm="derm"`, nothing goes upstream, and no record is made. The URL that carries it is a secret: shown only through `shown_url()`. `derm agents login codex` signs in to the store through `CODEX_HOME=<slug>/signin/codex` on `env`'s argv.
- **Secrets bound to a project** (lane PB's I-4; `secret-projects.schema.json`, fixture `fixtures/project/secret-projects.json`): a chat gets only the secrets bound to its project, a chat in no project only the unbound ones, and the start names what was left out (`run/broker.rs`).
- **Both proxy spellings** reach an account chat's harness (request PB-2): `keep()` passes `https_proxy`, `http_proxy` and `no_proxy` when derm sets them.

Added by P integration's fix pass (22 Nov 2026, `plans/parallel/acctP_fix.md`):

- **The harness by its root-owned path, the sign-in's too** (box research BR-4): `derm agents login` runs the harness from the root install on `/usr/local/bin:/usr/bin:/bin` (`chat::root_install`), by its absolute path, with no folder of the account's home on its `PATH`, and Claude Code's updater off (`DISABLE_AUTOUPDATER=1`, `DISABLE_UPDATES=1`). A chat already did (lane PA).
- **A renewal inside an account chat** (case 283). A chat whose harness has a sign-in host (`run/harness.rs` `sign_in_hosts`: `platform.claude.com:443` for Claude Code, `auth.openai.com:443` for Codex) and no other proxy gets its own sign-in tunnel, the login's (`agents::tunnel`), opened by `derm run` for the chat's life: CONNECT to those hosts on 443 only, TLS passed through unread, direct or through the person's own `http://` proxy, and only for a client with this chat's own proxy credential (minted per chat, in the environment only; 407 otherwise). The harness gets it as `HTTPS_PROXY` and `https_proxy`, with `NO_PROXY` and `no_proxy` naming loopback so the tap and derm's own ports stay direct; `HTTP_PROXY` is not set. `run.start`'s `agentUser.signInTunnel` lists its hosts, or is null. A brokered account chat already has derm-egress as its proxy; derm-egress passes the same hosts through unread there (`Config::pass_through`, never a secret's own host) and records the connection as `egress.connect` with `passThrough: true` and no request read. Neither carries `api.anthropic.com` (the model host goes through the tap) or `mcp-proxy.anthropic.com`.
- **`mcp-proxy.anthropic.com` closed for account chats** (Tony, 22 Nov 2026): Claude Code's claude.ai connectors off (above), the chat's tunnel does not admit it, and derm-egress refuses it in a brokered account chat (`Policy::deny`, reason "the host is closed to this chat").

The helper makes the links with `symlinkat` under the open project home, as the account, before the domain, and refuses a path there that is something else (a file the harness left, a link to anywhere else): it never follows, reads or copies a sign-in file (note CB 4.1). `crate::agents::signin::link_project_home` (lane PB) makes them; lane PA's helper calls it (section 4).

### 2.4 Socket path length (V for the limit, I for the sum)

Claude Code falls back to the shared `/tmp/cc-socks-<uid>/` when its socket path passes 103 bytes (`var Q=103`, binary). `/var/lib/derm/agents/` (21) + slug (at most 15) + `/projects/` (10) + id (16) + `/run` (4) + `/cc-socks/` (10) + pid (at most 7) + `.sock` (5) = 88. Held by `derm_core::project`'s test.

## 3. Each harness's files at the pin (8.3 item 6)

The machine-readable table is `fixtures/project/harness-files.json`; each row names its source. What runs later in a project home is `events.md` 7.2's `project.control` list. Not run: Codex and Pi themselves, Claude Code 2.1.322 (strings only), the TUIs, a renewal (note CD section 10).

## 4. The functions across lanes (declared by the base)

A lane calls another lane's code only through these. Each is a stub on the base that keeps today's behaviour or answers "not built", and the red tests in `crates/derm-cli/src/contracts_acctp.rs`, `crates/derm-cli/tests/contracts_acctp.rs`, `crates/derm-daemon/tests/contracts_acctp.rs` and `crates/derm-audit-linux/tests/contracts_acctp.rs` call them.

| Function | Owner | Called by |
|---|---|---|
| `derm_core::project::{ProjectId, valid_id, valid_field, kinds, layout}` | the base (reference; no lane's) | everyone |
| `derm_core::project::screen::clean` | PD | PD (`derm run`), PE (the daemon's second pass) |
| `derm_cli::project::{load, find, main}` | PA | integration's `run/mod.rs` (before `token.mint`), PA's `run/user/` |
| `derm_cli::run::user::project::{project_env, project_chat_spec}` | PA | PA's chat route |
| `derm_cli::agents::signin::link_project_home` | PB | PA's helper, when it makes a project home |
| `derm_cli::run::pty::Reader` | PD | PD's `derm run` loop |
| `derm_daemon::project::State` (`note_mint`, `project_of`, `stamp`, `overwritten`, the five ops, `forget_chat`) | PE | `daemon.rs` (wired by the base) |
| `derm_daemon::installs::project::project_control` | PC | PC's flagger |
| `derm_audit_linux::action::unix_sockaddr` | PC | PC's feed |

`derm run` sends `token.mint`'s `project` from `project::find` once PA builds it; until then it sends none (the daemon then holds `""`). That line in `run/mod.rs` is integration's (request).
