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
```

It installs the binaries in `/usr/bin` and the systemd user unit in `/usr/lib/systemd/user/derm-daemon.service`. It runs no script on install, enables nothing and starts nothing. To run the daemon as your user:

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

## Where derm keeps things

| What | Where |
|---|---|
| Your policy | `~/.derm/policy.json` (`DERM_POLICY` moves it) |
| The daemon's socket, token and OTLP port | `$XDG_RUNTIME_DIR/derm/` (0700; the files 0600) |
| The activity log | `$XDG_DATA_HOME/derm` or `~/.local/share/derm` |
| Backups of configs `derm connect` changed | `~/.derm/backups/` |

## The audit feed (optional, root)

`derm-audit-feed` turns auditd records of a `derm run` chat's processes into daemon events. Its rules are installed by root, and derm only prints them: run `derm-audit-feed rules` as the user your agents run as, read what it prints, and install it yourself as `/etc/audit/rules.d/50-derm.rules`, then `augenrules --load`. Then `derm-audit-feed run`, as that user (it refuses root; it needs read access to `/var/log/audit/audit.log`, the `adm` group on Ubuntu). Without it, `derm status` says the OS layer is off and the feed holds the agents' own telemetry and the gate's records.

## From a clone

```sh
cargo build --release -p derm-cli -p derm-daemon -p derm-audit-linux
```

Rust 1.97.0 (`rust-toolchain.toml`). The binaries land in `target/release/`.
