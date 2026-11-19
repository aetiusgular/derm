#!/bin/sh
# derm's gate for Codex inside the sbx VM, root's half: the first install
# command of derm's v3 kit (packaging/sbx-kit/codex/derm-gate-codex.yaml).
#
# Runs once, as root, when sbx creates the sandbox, after the codex
# workload's own install step and before Codex first starts. The kit's
# overlay put its files in /opt/derm-kit-src. A failure here fails
# `sbx create`, so derm run says the chat did not start: the gate is never
# left half there.
#
# What it can and cannot hold. The agent has passwordless sudo in the VM,
# so nothing here stands against an agent that sets out to remove it. Root
# owns derm and the marketplace. Codex copies the plugin into the agent's
# own folder and keeps its trust in the agent's own config.toml, the only
# places Codex reads them from, so the agent's user can change both. The
# policy is the agent user's own, because derm trusts a policy only from
# its own uid.
set -eu

src=/opt/derm-kit-src
dest=/opt/derm-kit
home=/home/agent
bin=/usr/local/bin/derm

fail() {
  echo "derm kit: $*" >&2
  exit 1
}

# The staging folder, with the policy in it, goes however the script ends.
# dash runs no EXIT trap on a signal, so a signal exits, which runs it.
trap 'rm -rf "$src"' EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

[ -f "$src/derm" ] || fail "$src/derm is missing; the kit was not built by derm run"
[ -f "$src/policy.json" ] || fail "$src/policy.json is missing; derm run adds the kit only with a policy"
[ -f "$src/trust.toml" ] || fail "$src/trust.toml is missing; the kit was not built by derm run"
[ -f "$src/mkt/derm/hooks/derm-gate.sh" ] || fail "$src/mkt is missing; the kit was not built by derm run"
[ -d "$home" ] || fail "$home is missing; this image is not one derm's kit knows"

# The derm the kit carries is the host's own on Linux, or one the person
# put there for the VM. Whether it runs in this image (its architecture,
# its C library) is found out here, before anything is installed.
chmod 0755 "$src/derm"
ver=$("$src/derm" --version 2>&1) || fail "the derm this kit carries does not run in this VM ($(printf '%s' "$ver" | head -n 1)); it was built for another system or C library. Run the chat without the kit (DERM_SBX_KIT=off), or use a static Linux build of derm"

# derm, where the plugin's launcher looks for it: /usr/local/bin is one of
# its folders and ~/.local/bin, which comes first, is not there in this
# image (hooks/derm-gate.sh; the launcher refuses a derm others can write).
if [ -e "$bin" ]; then fail "$bin is already there; derm's kit will not replace a derm it did not install"; fi
install -o root -g root -m 0755 "$src/derm" "$bin"

# The plugin's marketplace, the trust entries and the agent's half, owned
# by root and read-only to the agent's user.
rm -rf "$dest"
mkdir -p "$dest"
cp -R "$src/mkt" "$dest/mkt"
cp "$src/trust.toml" "$src/setup.sh" "$dest/"
chown -R root:root "$dest"
chmod -R u=rwX,go=rX "$dest"

# The VM marker: root's alone, at a path no variable moves. derm takes its
# VM route to the daemon's HTTP port only when this file holds
# (crates/derm-cli/src/gate/daemon.rs, security finding W5C-S2).
printf 'derm sbx kit\n' > "$dest/sbx-vm"
chown root:root "$dest/sbx-vm"
chmod 0644 "$dest/sbx-vm"

# The policy, where the hook looks for it ($HOME/.derm/policy.json), owned
# by the agent user and writable by no one else.
mkdir -p "$home/.derm"
cp "$src/policy.json" "$home/.derm/policy.json"
chown agent:agent "$home/.derm" "$home/.derm/policy.json"
chmod 0755 "$home/.derm"
chmod 0644 "$home/.derm/policy.json"

rm -rf "$src"
echo "derm kit: derm is installed for Codex's gate ($ver)"
