# derm setup

`derm setup` is the first command after an install. It finds the agents on your `PATH`, then asks one question per switch, writes what you answered and prints every change. Return takes the choice in brackets, which is always the one that changes nothing or the safe one.

```sh
derm setup --dry-run                    # what it finds and would ask; writes nothing
derm setup --packages ~/src/derm        # ask, then write (the folder of a release's source or a clone)
derm setup sandbox                      # sbx and srt per agent; sbx login and policy init on a yes
derm setup presets                      # the policy presets
derm setup preset workspace-write       # one preset's policy, as it would be written
```

It needs a terminal: a script, a scheduled run or an agent's tool gets "needs a terminal" and exit 2. It refuses to run inside a `derm run` chat, since an agent must not set its own policy (the gate and the boundary are what stand against an agent; the question guards against a mistake).

## The questions

| Switch | Default | Written to |
|---|---|---|
| The policy: a preset, or keep yours | workspace-write when you have none; keep when you have one | `~/.derm/policy.json` |
| What `derm run` does when no boundary is available and no one can answer | leave it (it stops) | `boundary.preAnswer` |
| The model tap | on | `tap.on` |
| Content capture: prompts, arguments, results and the model's text, kept on this machine | off; or 1 to 7 days | `content` |
| A model server of your own for the tap (your box's llama-swap) | no | `tap.upstreams` |
| Computer use | off; a daemon restart applies a change | `computerUse.on` |
| The pre-install check: package names to the registry and api.osv.dev | off | `installs.check` |
| derm's gate in each agent whose gate is built and not registered | no | through `derm connect <agent> --gate --write`, which shows the change and asks again |
| A shim per agent in `~/.derm/bin` that runs it through `derm run` | no | `~/.derm/bin/<program>` |

The settings keys are `contracts/settings.schema.json`. derm setup checks the whole file against it before it writes: a file that fails the schema is ignored by every reader, and its `boundary.preAnswer` counts as unset.

## The policy presets

| Preset | What it does |
|---|---|
| workspace-write (default) | Quiet inside, strict at the edges. Reads, edits and shell commands in the project run. Pushes, GitHub writes, deploys (vercel, netlify, fly), cloud CLIs (aws, gcloud, az), containers, kubectl, terraform, remote shells, package installs and control files ask. Docker's host access (`--privileged`, `-v`, `--mount` and the like) and derm's own controls (`derm setup`, `derm watch approve`, `derm connect --write`) are denied |
| read-only | Reads run; writes, edits and shell commands ask, except the read commands it lists (`git status`, `git log`, `gh pr view` and others) |
| strict | workspace-write, with a deny where the plan says strict: force pushes and history rewrites, production deploys, IAM changes, destructive GitHub commands, `kubectl apply` and `delete`, `terraform apply` and `destroy` |

Each preset file (`crates/derm-cli/src/setup/presets/`) names the version of every CLI its rules were read at, and its gaps. The command rules (`"command": ["git", "push"]`) are `contracts/policy.md` section 7.

**Under sbx.** derm's sbx kit copies your policy into the VM and starts Claude Code in full access there, so every ask is a deny. workspace-write is built for that: ordinary work runs, and the edges stop. With no policy file, the kit is not added and the chat runs under sbx with no gate in the VM; writing a policy is what turns the in-VM gate on. sbx mounts your project read-write, so `derm run` adds read-only mounts over what git and the agent read and run later, where it exists: `.git/hooks`, `.git/config`, submodule and worktree configs, and the agent's own project settings (the list srt holds read-only). In the VM a commit works; `git config`, a new hook, or renaming `.git` is refused. sbx cannot hold a path that does not exist, so a control file the chat makes (a first `.claude/settings.local.json`, say) is named when the chat ends, and in `run.stop` as `sbxControlChanged`: read it before you run git or an agent there (`.git/commondir` is one of those paths: it names another folder whose config and hooks git then uses). A control path that is a link is not held; its target is compared before and after. If sbx holds no Anthropic credential (`sbx secret ls --service anthropic`) and `ANTHROPIC_API_KEY` is not set, `derm run` says so before Claude Code starts; store one with `sbx secret set anthropic` or log in inside the sandbox.

**Asks with no one to answer.** In full access (the harness's own approvals off) no one can answer an ask, so derm's gate denies what the policy would ask. Inside a boundary that is the containment, that stops ordinary work: on Terminal-Bench an unattended Codex had 112 of 294 shell calls denied, most for a glob, a variable or an escape the matcher cannot read. Under `--boundary sbx` the gate of Claude Code and Codex therefore allows what it would ask and records each one; a deny rule still denies. For a boundary of your own (a benchmark's container, a CI job's VM) say so with `derm run --asks allow`. On a bare machine without the flag nothing changes. The decision is the daemon's, from `run.start`: a `DERM_ASKS` variable set by an agent or a project allows nothing.

**What an sbx chat's record holds.** The gate's decisions from inside the VM (Claude Code only: derm's kit), Claude Code's or Codex's own telemetry (tool calls, model requests and costs, sent from the VM to the daemon's port), and sbx's policy log of the VM's network calls. The host's OS feed does not see inside the VM: no file the agent writes and no program it runs there is in it. What the feed does record is sbx's own client on your machine. `derm run` finds it once, refuses one that comes from a relative `PATH` entry or from the chat's folders, and starts it by its real path. That program's lock files, analytics queue and connections to Docker's services (ports 443 and 65535) under your home are counted as expected (`sbxClient`) and not flagged. Anything else it does is flagged, and so is any other program named `sbx`. The telemetry export does not depend on your own `OTEL_*` variables: they do not reach the VM. The agent has sudo in the VM and could cut the route to the daemon's port. derm notices: an sbx chat whose export was on, whose agent was seen to work (a gate record, or a call in sbx's policy log to a host that is not this machine) and from which no telemetry arrived is flagged `telemetry silent`, when it stops or after two minutes. The model tap is off under sbx. sbx up to 0.51.0 does not pass the agent's output on when its standard input is closed or `/dev/null` (run on Linux, 16 Nov 2026: `sbx run ... -- -p ... </dev/null` printed nothing of the reply, with or without derm; with a terminal or an open pipe it printed). Docker's 0.53.0 notes say it is fixed ("`sbx run` preserves agent output when stdin is `/dev/null` or a closed pipe"); not rerun there. On an older sbx, give `derm run --boundary sbx` an open standard input in a script, or read the reply from the chat's record.

**Shell text.** Under every preset a shell command holding `$`, a backtick, `!`, braces, `~`, a backslash or a glob asks, since the gate cannot read what the shell will run (step 7b). In the VM that is a deny: the agent has to spell such commands out.

## The launch route

An agent started from a plain terminal is outside derm's boundary and records. A shim in `~/.derm/bin/<program>` runs the agent through `derm run <agent> --`, after taking its own folder off `PATH` so `derm run` finds the real program. derm never edits your shell's startup file; it prints the line to add:

```sh
export PATH="$HOME/.derm/bin:$PATH"
```

Remove a shim, or the folder from `PATH`, to run the agent without derm. A file in `~/.derm/bin` that derm did not write is left alone.

In Orca, set each agent's command override to `derm run <agent> --` in Orca's settings (derm prints the line per agent; it does not write Orca's settings).

## What it never does

It writes no project file, managed file or shell startup file, runs no installer (it prints the line; an install needs your own sudo or brew), and writes no policy this derm's matcher refuses, because then every call would ask. Every file it writes is 0600 (shims 0700) in a 0700 `~/.derm`, written through a new file and a rename, never through a link; an old file is kept in `~/.derm/backups/` first. It refuses a `~/.derm` that is a link, another user's, or writable by others.
