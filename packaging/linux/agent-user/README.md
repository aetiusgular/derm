# Agent accounts and the agents' user (Linux)

Two forms live here. `install.sh --account` (below, the accounts build) makes
one agent account per subscription, as many chats on each as you want, with a
firewall table that lets the accounts reach loopback only. `install.sh
--owner` (further down) is wave 5's single agents' user, which `derm run
--boundary none` reads until lane L1 moves it to the accounts.

## Agent accounts, one per subscription

```
sudo packaging/linux/agent-user/install.sh --account max1 --subscription "Claude Max, personal" --dry-run
sudo packaging/linux/agent-user/install.sh --account max1 --subscription "Claude Max, personal"
```

`<slug>` is 1 to 21 of `a-z`, `0-9` and `-`: the account is
`derm-agent-<slug>`, and useradd takes 32 characters. The subscription label is
what you call it, shown back and never parsed; control and format characters
(newlines, bidi overrides) are refused. `--owner` defaults to the person who
ran `sudo`.

| Step | What changes | Undo |
|---|---|---|
| 1 | `/usr/local/lib/derm/agents.py` (root's, 0644): the helper the unit and the check run, copied from `accounts.py` and checked by hash | removed with the last account |
| 2 | The group `derm-agents` (system group, no members listed). An existing group with members is refused | `groupdel`, with the last account |
| 3 | The user `derm-agent-<slug>`: system user, primary group `derm-agents` and no other group, home `/var/lib/derm/agents/<slug>` (0700), password locked | `userdel --remove` (`--keep-home` keeps it) |
| 4 | `/etc/derm/agents.json` (root's, 0644): `{"version": 1, "group": "derm-agents", "accounts": [{"name", "uid", "subscription", "home"}]}`, exactly the contract in `plans/parallel_build_accounts.md` section 2. A file there that is not a regular file of root's, is group or world writable, or does not parse is refused, and nothing is written over it | the entry removed; the file goes with the last account |
| 5 | `/etc/derm/agents.nft` and the table `inet derm_agents`, loaded (below) | written again without the account; `nft delete table inet derm_agents` with the last |
| 6 | `/etc/systemd/system/derm-agents-nft.service`, enabled: loads the table at boot and again after `nftables.service` restarts or reloads, whose `/etc/nftables.conf` starts with `flush ruleset` on Ubuntu and Debian | `systemctl disable`, removed with the last account |
| 7 | `/etc/sudoers.d/derm-agent-<slug>`: `<you> ALL=(derm-agent-<slug>) NOPASSWD:SETENV: ALL`, checked with `visudo -c`. Last, so nothing runs as the account before its table is in place | `rm` |

`uninstall.sh --account <slug>` does every undo, in the reverse order: the
sudoers rule first, then the account's processes, its entry, the table, the
user, and the group with the last account. It removes only a user install.sh
made (its comment is `derm agent <slug>`), and runs on a half-installed
account too.

### The table

```
table inet derm_agents {
	set uids { type uid; elements = { <each account's uid> } }
	chain output {
		type filter hook output priority filter; policy accept;
		meta skgid <derm-agents> jump agents
		meta skuid @uids jump agents
	}
	chain agents {
		meta l4proto { tcp, udp } th dport 53 counter reject with icmpx admin-prohibited
		oif "lo" ip daddr 127.0.0.0/8 accept
		oif "lo" ip6 daddr ::1 accept
		counter reject with icmpx admin-prohibited
	}
}
```

- By group and by uid: `meta skgid` is the socket file's fsgid (Linux 6.18
  `net/netfilter/nft_meta.c:152-154`), which a set-group-id program changes. A
  set-group-id program took a group-only rule's account out (run); the uid set
  holds it, and the group holds a set-user-id one.
- Loopback addresses only. Your machine's own LAN address goes through `lo`
  too and is refused.
- DNS is refused on loopback as well (the resolver stub on 127.0.0.53):
  derm-egress resolves names.
- Reject, not drop: a dropped TCP SYN is resent until `connect()` times out;
  the reject fails it at once with `EHOSTUNREACH`, and a datagram gets `EPERM`
  (both run). Your other tables do not change this: an `accept` in another
  table's output chain still meets this one (run).

### The check

```
python3 -I /usr/local/lib/derm/agents.py check [--json]          # as anyone
sudo -n -u derm-agent-<slug> python3 -I /usr/local/lib/derm/agents.py check --probe
```

`nft list` needs `CAP_NET_ADMIN` (nfnetlink refuses every message without
it, Linux 6.18 `net/netfilter/nfnetlink.c:661`; nft 1.0.9 as a plain user:
"Operation not permitted"), so the check reads what root wrote instead:
`agents.json` (trusted as above), the group and each account (primary group,
no other group, home), `agents.nft` against the table rendered again from
`agents.json` byte for byte, the unit, and `/run/derm/agents-nft.loaded`, a
marker root writes on each load with the boot id and the table's hash. The
marker says the table was loaded this boot; it does not see a flush by hand.
`--probe`, run as an agent account, asks the kernel: a datagram to 192.0.2.1
must get `EPERM`, a TCP connect there `EHOSTUNREACH` at once, a datagram to
127.0.0.53:53 `EPERM`, and a datagram to its own socket on 127.0.0.1 must
arrive. Exit 0 when all pass, 1 otherwise; each failure names its fix.

### Not covered

- Other services on loopback stay reachable: whatever listens on 127.0.0.1
  (a local proxy, a database, Docker's API if bound there) is the agents' to
  reach, as derm's own ports are.
- Name lookups that do not use port 53: glibc's `nss-resolve` asks
  systemd-resolved over its Unix socket (`/run/systemd/resolve/io.systemd.Resolve`),
  which no firewall sees, and resolved then queries upstream (nss-resolve(8);
  not run here, the workspace has no resolved). Unix sockets and
  D-Bus to local services are lane L1's (Landlock) to narrow.
- A program both set-user-id and set-group-id to another user and group leaves
  both matches (none on Ubuntu 24.04's base image: `find / -perm -6000` found
  none here).
- A flush by hand (`nft flush ruleset`) is not seen by the unit or the
  marker; only `--probe` shows it.
- Without systemd as PID 1 the unit is installed but nothing loads the table
  at boot; install.sh says so.
- IPv6 was not run here (the cloud workspace's kernel has no `AF_INET6`).

### Tests

`accounts.test.ts` (vitest, Linux, no root): names, labels, the contract's
reader, the rendered table, the unit, the dry runs. `tests/root-e2e.sh` (root,
throwaway machines only: `sudo DERM_L2_ROOT_TEST=1 tests/root-e2e.sh`): real
users, the loaded table, real sockets for an agent account, its owner,
another user and root, set-id programs, another table's accept, every file
tampered with, two accounts, and every undo, ending with nothing left.

## The single agents' user (wave 5, `--owner`)

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
