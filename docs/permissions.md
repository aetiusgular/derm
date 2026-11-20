# Permissions

derm groups what it checks into eight permissions, the way macOS groups app access into Files and Folders, Full Disk Access, Screen Recording and the rest. This page says what each one does today, with and without a sandbox, and where the code is.

Two setups decide how strong each permission is:

- **Gate only** (`derm init`, the light tier). derm checks each tool call before it runs. It does not stop a program the agent starts from doing something the call did not show: a script the agent wrote can still read a file the gate would ask about.
- **Gate and sandbox** (`derm setup`, then `derm run <agent> --boundary srt`). The operating system also refuses what the sandbox does not allow, whatever program asks. This is the setup that works like macOS.

"Ask" means the agent's own prompt shows derm's question. Where an agent has no prompt (Codex, OpenCode, Cursor and others), or no one is there to answer, an ask is a deny ([quick start](install/quick.md#what-an-ask-becomes)).

## The eight permissions today

| Permission | Gate only | Gate and srt |
|---|---|---|
| **Project folder** | Reads, edits and shell commands run. Pushes, deploys, cloud commands, installs and `git reset --hard` ask | Writes are held to the project, srt's temp folder and the agent's own folders |
| **Other folders** (your home, Desktop, Documents) | File reads run; a shell command that names `~` asks | Reads run except the hidden folders below; writes outside the project are refused |
| **Secrets** (`~/.ssh`, `~/.aws`, `.env`, sign-in files) | Any call that names one asks | Unreadable |
| **Files that run later** (git hooks, CI workflows, shell start-up files, agent skills) | Any call that names one asks | `.git/hooks`, `.git/config` and shell start-up files are read-only, and the call still asks |
| **Network** | Not checked, except a cloud metadata address, which asks | Only the model's host (through derm's tap), derm's own ports and hosts you add with `--allow-host`; everything else is refused |
| **Running downloaded code** (`curl ... \| sh`, new packages) | A shell that reads its program from a pipe asks; a new package asks | The same, and the download needs a host the sandbox allows |
| **Computer use** (screen and input) | Off | Off. Not shipped on macOS yet (open item S2) |
| **derm itself** (its policy, its folder, `derm setup`) | A call that names derm's files asks; `derm setup`, `derm init`, `derm secret add`, `derm watch --approve` and `derm connect --write` are denied | Also: `~/.derm` is unreadable and the policy is read-only |

Destructive commands (`rm -rf ~`, `dd` to a disk, `kill -9 -1`) ask in every setup.

## Where the code is

| Permission | Gate | Sandbox (srt) |
|---|---|---|
| Project folder | the default preset, `crates/derm-cli/src/setup/presets/workspace-write.json` | write roots, `crates/derm-cli/src/run/plan.rs` |
| Other folders | the preset's `read` rule; shell text step 7b in `crates/derm-core/src/policy.rs` (`allow_steps`) | `denyRead` and `allowWrite`, `run/plan.rs` |
| Secrets | `SECRET_PATHS`, step 7d, `crates/derm-core/src/policy.rs` | `denyRead`, `run/plan.rs` |
| Files that run later | `RUNS_LATER_PATHS` and `CONTROL_PATHS`, steps 7a and 7d | srt's own read-only list |
| Network | `METADATA_ADDRESSES`, step 7d | `network.allowedDomains`, `run/plan.rs` |
| Running downloaded code | `command::stdin_program` (step 7d); package installs, `crates/derm-core/src/installs/` | the same allow list |
| Computer use | `computerUse.on` in `~/.derm/settings.json`, off by default (`crates/derm-cli/src/setup/mod.rs`) | `derm cu` ([docs](verbs/cu.md)) |
| derm itself | `CONTROL_PATHS`, step 7a; the preset's `derm` command rules | `~/.derm` in `denyRead` |

The matcher's steps are in [`contracts/policy.md`](../contracts/policy.md), section 4.

## Planned

Not built yet:

- **Named permissions in every answer.** Each ask and deny will say which of the eight it is, so a prompt reads "derm: secrets, `~/.aws/credentials`" instead of a rule's text.
- **`derm permissions`**: one list of what each agent and project may do, with when each grant was last used, like the Privacy page in System Settings. `derm permissions revoke` takes one back.
- **`derm allow <permission>`**: grants for this chat, this project or always. Secrets, computer use and derm itself can be granted only from your own terminal, with your login password, never from a prompt inside a chat. That is what stops an agent from approving itself.
- **Grants that expire** when they go unused.
- **One question for each new folder and each new host**, in place of today's flat allow or refuse.
- **`derm init` turning on the sandbox** where the machine supports it, and saying in one line where it does not.
