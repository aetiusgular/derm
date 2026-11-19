#!/bin/sh
# derm's gate inside the sbx VM for an agent that takes a command hook
# (Copilot CLI, Droid, Cursor, Kiro), with derm itself as the gate: root's
# half, the first install command of derm's v3 kit
# (packaging/sbx-kit/hooks/derm-gate-hooks.yaml).
#
#   sh /opt/derm-kit-src/install.sh <agent>
#
# Runs once, as root, when sbx creates the sandbox, after the agent
# workload's own install step and before the agent first starts. The kit's
# overlay put its files in /opt/derm-kit-src. A failure here fails
# `sbx create`, so derm run says the chat did not start: the gate is never
# left half there. The second command, as the agent's user, registers the
# hook: `derm kit register <agent> --home /home/agent`.
#
# What it can and cannot hold. The agent has passwordless sudo in the VM,
# so nothing here stands against an agent that sets out to remove it. Root
# owns derm. The registration sits in the agent's own config, which its
# user can rewrite; derm's gate denies a write to those files only where
# the policy's control paths name them. The policy is the agent user's own,
# because derm trusts a policy only from its own uid.
set -eu

agent="${1:-}"
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

case "$agent" in
  copilot-cli | droid | cursor | kiro) ;;
  *) fail "install.sh takes copilot-cli, droid, cursor or kiro" ;;
esac

[ -f "$src/derm" ] || fail "$src/derm is missing; the kit was not built by derm run"
[ -f "$src/policy.json" ] || fail "$src/policy.json is missing; derm run adds the kit only with a policy"
[ -d "$home" ] || fail "$home is missing; this image is not one derm's kit knows"

# The derm the kit carries is the host's own on Linux, or one the person
# put there for the VM. Whether it runs in this image (its architecture,
# its C library) is found out here, before anything is installed.
chmod 0755 "$src/derm"
ver=$("$src/derm" --version 2>&1) || fail "the derm this kit carries does not run in this VM ($(printf '%s' "$ver" | head -n 1)); it was built for another system or C library. Run the chat without the kit (DERM_SBX_KIT=off), or use a static Linux build of derm"

# derm, at the path the hook names. A derm already there is not replaced.
if [ -e "$bin" ]; then fail "$bin is already there; derm's kit will not replace a derm it did not install"; fi
install -o root -g root -m 0755 "$src/derm" "$bin"

# The VM marker: root's alone, at a path no variable moves. derm takes its
# VM route to the daemon's HTTP port only when this file holds
# (crates/derm-cli/src/gate/daemon.rs, security finding W5C-S2), and
# `derm kit register` writes only where it holds.
rm -rf "$dest"
mkdir -p "$dest"
printf 'derm sbx kit\n' > "$dest/sbx-vm"
chown -R root:root "$dest"
chmod 0755 "$dest"
chmod 0644 "$dest/sbx-vm"

# The policy, where the gate looks for it ($HOME/.derm/policy.json), owned
# by the agent user and writable by no one else.
mkdir -p "$home/.derm"
cp "$src/policy.json" "$home/.derm/policy.json"
chown agent:agent "$home/.derm" "$home/.derm/policy.json"
chmod 0755 "$home/.derm"
chmod 0644 "$home/.derm/policy.json"

rm -rf "$src"
echo "derm kit: derm is installed for $agent's gate ($ver)"
