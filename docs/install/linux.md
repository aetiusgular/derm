# Install on Linux

x86_64 only for now. The release has two forms of the same three static binaries (`derm`, `derm-daemon`, `derm-audit-feed`), built for `x86_64-unknown-linux-musl`: they link no shared library, so they run on any x86_64 distribution. aarch64 waits for a machine to test it on.

## Check what you downloaded

Each release lists every file's SHA-256 in `SHA256SUMS`, and GitHub keeps a build provenance attestation for each Linux file.

```sh
sha256sum -c --ignore-missing SHA256SUMS
gh attestation verify derm_<version>_amd64.deb --repo aetiusgular/derm
```

## The .deb (Debian, Ubuntu)

```sh
sudo apt install ./derm_<version>_amd64.deb
derm --version    # derm <version>
```

From your home folder apt installs it and warns that the download is "performed unsandboxed as root", because its `_apt` user cannot read the file there. To avoid the warning, check and install it from a folder of your own that `_apt` can read, not from `/tmp` itself, where another user could put a file of the same name first: `d=$(mktemp -d) && chmod 755 "$d"`, then download into `$d`, run `sha256sum -c` there and `sudo apt install "$d"/derm_<version>_amd64.deb`. It installs the binaries in `/usr/bin` and the systemd user unit in `/usr/lib/systemd/user/derm-daemon.service`. It runs no script on install, enables nothing and starts nothing. To run the daemon as your user:

```sh
systemctl --user enable --now derm-daemon
derm status
```

To keep it running after you log out: `loginctl enable-linger $USER`. To remove: `systemctl --user disable --now derm-daemon && sudo apt remove derm`.

## The tarball

```sh
tar -xzf derm-<version>-x86_64-unknown-linux-musl.tar.gz
cd derm-<version>-x86_64-unknown-linux-musl
install -D -m 0755 derm derm-daemon derm-audit-feed -t ~/.local/bin
install -D -m 0644 derm-daemon.service ~/.config/systemd/user/derm-daemon.service
systemctl --user daemon-reload
systemctl --user enable --now derm-daemon
```

The unit in the tarball starts `~/.local/bin/derm-daemon`; the one in the .deb starts `/usr/bin/derm-daemon`.

## Then

`derm setup` finds your agents and asks, one question each, for a policy, the tap, content capture, computer use, the pre-install check, each agent's gate and a shim that runs it through `derm run` ([derm setup](setup.md)). `derm setup sandbox` says whether sbx and srt can run each agent here.

## srt on Ubuntu 24.04 and later

`derm run --boundary srt` uses Anthropic's sandbox runtime (srt 0.0.81) on bubblewrap. srt also runs a seccomp step inside bubblewrap that makes a user namespace of its own, and that step needs `CAP_SYS_ADMIN` there.

- **Ubuntu 26.04** loads Ubuntu's AppArmor profile `/etc/apparmor.d/bwrap-userns-restrict`. It runs everything bubblewrap starts under its child profile `unpriv_bwrap`, which denies every capability, so srt fails with `apply-seccomp: write /proc/self/setgroups ... Permission denied`. The sysctl `kernel.apparmor_restrict_unprivileged_userns` does not change that profile, and an AppArmor profile for srt's own programs cannot lift it, because bubblewrap sets `no_new_privs`. `derm setup sandbox` and `derm run` say so and name the profile.
- **Ubuntu 24.04** ships that profile unloaded (in the `apparmor-profiles` package's extra profiles). There the sysctl at 1 stops bubblewrap itself, and srt's own note applies: the sysctl at 0, or a profile that allows user namespaces for srt's bubblewrap. Loading Ubuntu's `bwrap-userns-restrict` there makes srt fail as on 26.04.

derm changes none of this. Without a root change, use `--boundary sbx` (Claude Code, Codex, Copilot CLI, Droid, Cursor and Kiro keep derm's gate in the VM through derm's kit) or `--boundary none`. Every root change that lets srt start lets any local program make a user namespace with capabilities, the kernel surface Ubuntu's restriction exists to narrow (Ubuntu: "Understanding AppArmor User Namespace Restriction"). Two, narrowest first; neither is tested on 26.04 yet:

1. A copy of bubblewrap for srt, under a profile shaped like Ubuntu's own `chrome` and `linux-sandbox` profiles (`flags=(unconfined)` and `userns`). The system bubblewrap keeps Ubuntu's profile; the copy does not, and any local user can run it. It does not follow bubblewrap's security updates: copy it again after each one (`cmp /usr/bin/bwrap /usr/local/libexec/derm-srt/bwrap` says whether it differs).

   ```sh
   sudo install -d -m 0755 /usr/local/libexec/derm-srt
   sudo install -m 0755 /usr/bin/bwrap /usr/local/libexec/derm-srt/bwrap
   printf '%s\n' 'abi <abi/5.0>,' 'include <tunables/global>' \
     'profile derm-srt-bwrap /usr/local/libexec/derm-srt/bwrap flags=(unconfined) {' \
     '  userns,' '  include if exists <local/derm-srt-bwrap>' '}' \
     | sudo tee /etc/apparmor.d/derm-srt-bwrap >/dev/null
   sudo apparmor_parser -r /etc/apparmor.d/derm-srt-bwrap
   ```

   derm takes the first `bwrap` on `PATH`, so start srt chats with that folder first: `PATH=/usr/local/libexec/derm-srt:$PATH derm run <agent> --boundary srt`. Undo: `sudo apparmor_parser -R /etc/apparmor.d/derm-srt-bwrap && sudo rm /etc/apparmor.d/derm-srt-bwrap && sudo rm -r /usr/local/libexec/derm-srt`.

2. Ubuntu's profile off and the sysctl at 0, for every program on the machine: `sudo ln -s /etc/apparmor.d/bwrap-userns-restrict /etc/apparmor.d/disable/ && sudo apparmor_parser -R /etc/apparmor.d/bwrap-userns-restrict && sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0`. Undo: `sudo rm /etc/apparmor.d/disable/bwrap-userns-restrict && sudo apparmor_parser -r /etc/apparmor.d/bwrap-userns-restrict && sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=1`. The sysctl does not survive a reboot unless a file in `/etc/sysctl.d/` sets it.

## Where derm keeps things

| What | Where |
|---|---|
| Your policy | `~/.derm/policy.json` (`DERM_POLICY` moves it) |
| The daemon's socket, token and OTLP port | `~/.derm/run/derm/` (0700; the files 0600). Until eval pass 1 (E1-10) it was `$XDG_RUNTIME_DIR/derm/`; restart the daemon and the feed after an upgrade, and install the audit rules again |
| The activity log | `$XDG_DATA_HOME/derm` or `~/.local/share/derm` |
| Backups of configs `derm connect` changed | `~/.derm/backups/` |

### Over SSH

The daemon keeps its socket and token under your home folder, not in `/run/user/<uid>`. That folder is made at login, after auditd has loaded its rules at boot, and a rule for a folder that does not exist yet does not load, so reads of the token were not recorded after a reboot (`derm watch report` said `OS FEED NOT WATCHING`). `~/.derm/run` is there at boot. A home that is not there at boot (encrypted at login, or on the network) still has that gap until the rules are loaded again after login, and `derm watch report` still says so. The folder is on disk, so the daemon writes a new token and a new socket at every start.

Two things you will see under srt that are not derm's doing (eval pass 1, E1-6 and E1-7):

- **"Failed to create stream fd: Operation not permitted" at the top of a command's output, on Ubuntu 26.04.** Ubuntu's im-config 0.62 runs `systemd-cat` from a login shell's start-up (`/etc/profile.d/im-config_wayland.sh` sources `/usr/share/im-config/initializer`, whose `logger_debug` runs it whenever `IM_CONFIG_VERBOSE` is non-empty, and it is set to `"false"`). srt refuses the Unix socket `systemd-cat` opens to the journal, so it prints the line. The command itself runs. Codex's sandbox shows the same trace (github.com/openai/codex/issues/22367). derm does not hide a shell's stderr; the line goes away with an im-config that does not do this (Debian's 1.1), or by clearing `IM_CONFIG_VERBOSE` in your own profile.
- **A command's background child ends with the command.** srt starts each command under bubblewrap with a process namespace of its own (`--unshare-pid --die-with-parent`; srt 0.0.82, seen in `ps` inside it), and when that namespace's first process exits the kernel ends every process left in it. So `( sleep 1; echo late > late.txt ) &` writes nothing under srt (run in the cloud workspace, 16 Nov 2026: `late.txt` never appeared), and a dev server started with `&` is gone when its command returns. Start a long-running program as its own command, or use `--boundary sbx` or `none`.

## The audit feed (optional, root)

`derm-audit-feed` turns auditd records of a `derm run` chat's processes into daemon events. Its rules are installed by root, and derm only prints them: run `derm-audit-feed rules` as the user your agents run as, read what it prints, and install it yourself as `/etc/audit/rules.d/50-derm-<uid>.rules` (one file per user, so rules for a second user, such as the agents' user, never replace yours), then `augenrules --load`. Then run the feed as that user (it refuses root; it needs read access to `/var/log/audit/audit.log`, the `adm` group on Ubuntu): `systemctl --user enable --now derm-audit-feed.service` (the `.deb` installs the unit in `/usr/lib/systemd/user/`; the tarball carries it, to copy into `~/.config/systemd/user/`), or `derm-audit-feed run` by hand. The unit is wanted by `derm-daemon.service`, so every start of the daemon starts it, and `PartOf=` stops and restarts it with the daemon; a feed started by hand exits when the daemon restarts and does not come back. `derm watch report` says when no feed is attached. Make the rules after derm has run once and after the tools whose secrets you care about are set up: a rule can only be loaded for a folder that exists (`~/.aws`, `~/.kube`, `~/.derm/run`), and for a file whose folder exists. The feed checks this while it runs: it opens each sensitive path that exists and looks for its own record, and `derm watch report` prints `OS FEED NOT WATCHING` with the paths the loaded rules do not cover, such as a folder made, or deleted and made again, after the install. Reads there are not recorded until you run `derm-audit-feed rules` again and install what it prints; the line goes away within ten minutes of that, or at once when the feed restarts. Without it, `derm status` says the OS layer is off and the feed holds the agents' own telemetry and the gate's records.

## From a clone

```sh
cargo build --release -p derm-cli -p derm-daemon -p derm-audit-linux
```

Rust 1.97.0 (`rust-toolchain.toml`). The binaries land in `target/release/`.
