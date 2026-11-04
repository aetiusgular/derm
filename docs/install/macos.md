# Install on macOS

The release has `derm-<version>-macos.zip`, which unpacks to one folder, `derm-<version>-macos/` (since 0.1.2; 0.1.0's zip had no top folder): `derm` and `derm-daemon` as universal binaries (Apple silicon and Intel), each signed with a Developer ID and the hardened runtime, and the zip notarized by Apple; beside them the launchd agent `io.github.aetiusgular.derm.daemon.plist`, `LICENSE`, `NOTICE` and `README.md`.

With Homebrew, from the tap `aetiusgular/homebrew-tap`: `brew install aetiusgular/tap/derm`. Homebrew marks only casks as downloaded from the internet, not formulae, so Gatekeeper does not check these binaries when they come through brew; `brew services start derm` runs the daemon (not started by the install). Homebrew needs the Command Line Tools for it (`xcode-select --install`), even with Xcode installed: a formula without a prebuilt bottle runs Homebrew's build checks, and on macOS 26 those require them.

## Download and check

```sh
shasum -a 256 -c --ignore-missing SHA256SUMS
unzip derm-<version>-macos.zip
cd derm-<version>-macos
install -m 0755 derm derm-daemon ~/.local/bin/
derm --version    # derm <version>
```

A notarization ticket cannot be stapled to a bare binary ("it's not currently possible to staple tickets to them", Apple, Customizing the notarization workflow), so the first time a binary from the zip runs, Gatekeeper looks its ticket up online. That first run needs a network connection; later runs do not.

`derm-audit-feed`, the Linux auditd feed, is not in the macOS zip.

## The daemon as a launchd agent

```sh
sed -e "s|__DERM_DAEMON__|$HOME/.local/bin/derm-daemon|" -e "s|__HOME__|$HOME|" \
  io.github.aetiusgular.derm.daemon.plist > ~/Library/LaunchAgents/io.github.aetiusgular.derm.daemon.plist
launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/io.github.aetiusgular.derm.daemon.plist
derm status
```

Run the lines from the unpacked folder, where the plist is. The first start of a binary from the zip can take several seconds (16 s once in the release check, while launchd already said running): poll `derm status` rather than sleeping a fixed time.

The plist is `crates/derm-daemon/units/io.github.aetiusgular.derm.daemon.plist` in the repository. To stop it: `launchctl bootout gui/$(id -u)/io.github.aetiusgular.derm.daemon`.

## Where derm keeps things

| What | Where |
|---|---|
| Your policy | `~/.derm/policy.json` (`DERM_POLICY` moves it) |
| The daemon's socket, token, OTLP port and activity log | `~/Library/Application Support/derm/` (0700; the files 0600) |
| The daemon's own log, under launchd | `~/Library/Logs/derm-daemon.log` |

## Not in this release

The activity collector (an Endpoint Security daemon that runs as root) and the computer-use helper app are built from `macos/` but not shipped: the helper waits for the open approver finding S2, the collector for a test of its signed bundle. `derm cu status` prints `helper: missing` until a helper is installed.

## From a clone

```sh
cargo build --release -p derm-cli -p derm-daemon
```

Rust 1.97.0 (`rust-toolchain.toml`) and the Xcode command line tools.
