# The agents' user (Linux)

A second local account that runs one person's coding agents, so an agent
cannot read the person's daemon token, answer its own asks, use `sudo`,
start Docker containers or open the person's files (S2 part c; rules cases
53 and 125). `derm run <harness> --boundary none` then starts the harness as
that account; srt and sbx chats are unchanged (their boundary already keeps
the agent away from the token).

Run on your yes only: these scripts change the system as root. Read
`--dry-run` first.

```
sudo packaging/linux/agent-user/install.sh --owner <you> --dry-run
sudo packaging/linux/agent-user/install.sh --owner <you>
```

## What install.sh changes, and the undo

| Change | Where | Undo |
|---|---|---|
| A system user and group, default `derm-agent`, home `/var/lib/derm-agent` (0700), shell `/bin/bash`, password locked, in no other group | `/etc/passwd`, `/etc/group`, `/etc/shadow` | `userdel --remove derm-agent` |
| You may start any program as `derm-agent` without a password: `<you> ALL=(derm-agent) NOPASSWD:SETENV: ALL`. Nothing lets `derm-agent` run anything as you or root. Checked with `visudo -c` first | `/etc/sudoers.d/derm-agent-<you>` (0440 root; no `.` in the name, which both sudo and sudo-rs skip) | `rm` the file |
| The folder for each chat's bridge: `/run/derm-agent` (root, 0755) and `/run/derm-agent/<your uid>` (yours, 0711), remade at boot | `/etc/tmpfiles.d/derm-agent-<you>.conf` | `rm` the file and `/run/derm-agent/<uid>` |
| Who runs whose agents, read by `derm run` and by the gate inside the harness | `/etc/derm/agent-users.json` (root, 0644) | your entry removed; the file goes when empty |

`uninstall.sh --owner <you>` does every undo above, after stopping the
agents' processes (a user with processes cannot be removed). `--keep-home`
keeps `/var/lib/derm-agent` and the logins in it.

The rule's `ALL`: sudo and sudo-rs treat a rule whose command is `ALL` as
`SETENV`, which is what lets `derm run` keep its own variables
(`--preserve-env`). It runs your process as a lesser user and gives that user
nothing back. A narrower rule (one root-owned wrapper with a fixed variable
list in `env_keep`) is possible and not built.

## After install: each harness as the agents' user

A harness run as `derm-agent` looks for its login and settings in
`/var/lib/derm-agent`, not in your home: Claude Code in `~/.claude/` and
`~/.claude.json`, Codex in `~/.codex/auth.json`, Pi in `~/.pi/agent/auth.json`
(each 0600). Your logins are not copied: a copy would give the agent your
subscription token, and a separate login can be revoked on its own.

```
sudo -u derm-agent -H bash -l
# as derm-agent: Node, then each harness, under ~/.local
#   (fnm, or a Node tarball unpacked into ~/.local; then npm install -g --prefix ~/.local <harness>)
claude          # then /login
codex login
pi              # then /login
```

`derm run` looks the harness up on the agents' user's `PATH`
(`/var/lib/derm-agent/.local/bin:/usr/local/bin:/usr/bin:/bin`) and refuses
to start, naming the fix, when it is missing there.

## The chat's folder

The agents' user writes only the folders it is given. Your home is 0750 on
Ubuntu, so it cannot enter it, and `derm run` refuses a chat whose folder it
cannot write. Keep the projects agents work on in a folder you share with
it, outside your home, for example:

```
sudo install -d -o <you> -g derm-agent -m 2770 /srv/agents/<project>
```

(setgid, so new files keep the `derm-agent` group). Files the agent writes
there that you later run (git hooks, `package.json` scripts, CI files) are
still the agent's work: review them (cases 25, 133).

## What derm run checks every time

Before the harness starts, as the agents' user and through the same `sudo`
route: it cannot read the daemon's folder, `daemon.token`, `~/.derm`, your
policy or your harness logins; it can write the chat's folders; it has the
harness. Any miss stops the start. The account itself must not be root or
you, and must be in no group that leads to root or to your files (`sudo`,
`docker`, `lxd`, `incus`, `libvirt`, `disk`, `shadow`, `adm`,
`systemd-journal`, your own group).

## Not covered

- The audit feed (`derm-audit-feed`) has rules for your uid only. Generate
  them for the agents' uid too, as root, on your yes.
- macOS: no second user; srt keeps the token out of reach there.
- Processes the agent leaves running outlive the chat; you cannot signal
  another user's processes (`sudo -u derm-agent pkill -u derm-agent` can).
- `DERM_RUN_AS=you derm run ...` runs one chat as you anyway. A `yes` for it
  then needs your login password (S2 part b).
- Two chats as the agents' user at once share one uid. One chat's agent can
  read the other's `/proc/<pid>/environ` (proc(5): same uid), which holds its
  chat token and socket path, and then post records and raise asks in the
  other chat's name (integration w5's security review, W5-S5, medium; case 66
  does not hold between such chats). Run one agents'-user chat at a time until
  derm gives each chat its own uid.
