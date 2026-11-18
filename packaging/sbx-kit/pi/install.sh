#!/bin/sh
# derm's Pi package inside the sbx VM, root's half: the first install
# command of derm's v2 mixin (packaging/sbx-kit/pi/spec.yaml).
#
# Runs once, as root, when sbx creates the sandbox, after sbx copied the
# kit's files/home/ into /home/agent and after the Pi kit's own install
# step, before Pi first starts. A failure here fails `sbx create`, so derm
# run says the chat did not start.
#
# What it can and cannot hold. Root owns the package in /opt/derm-kit, so
# the agent's user cannot edit the gate's code. Pi reads its package list
# from the agent's own ~/.pi/agent/settings.json, the only place it reads
# one from, so the agent's user can take the package out; derm's gate asks
# before a write to Pi's settings only where the policy or a control path
# says so. The policy is the agent user's own, because the gate trusts a
# policy only from its own uid.
set -eu

src=/home/agent/.derm-kit-src
dest=/opt/derm-kit
home=/home/agent

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

[ -f "$src/derm-pi/package.json" ] || fail "$src/derm-pi is missing; the kit was not built by derm run"
[ -f "$src/derm-pi/extensions/gate.ts" ] || fail "$src/derm-pi has no gate; the kit was not built by derm run"
[ -f "$src/policy.json" ] || fail "$src/policy.json is missing; derm run adds the kit only with a policy"
[ -f "$src/setup.sh" ] || fail "$src/setup.sh is missing; the kit was not built by derm run"

# The package and the agent's half, owned by root and read-only to the
# agent's user. Copied, not moved: what lands in /opt/derm-kit is root's
# own from the first byte.
rm -rf "$dest"
mkdir -p "$dest"
cp -R "$src/derm-pi" "$dest/derm-pi"
cp "$src/setup.sh" "$dest/setup.sh"
chown -R root:root "$dest"
chmod -R u=rwX,go=rX "$dest"

# The VM marker: root's alone, at a path no variable moves. derm's Pi
# emitter posts to the daemon's port on the host only when this file holds
# (packages/derm-pi/src/vm.ts).
printf 'derm sbx kit\n' > "$dest/sbx-vm"
chown root:root "$dest/sbx-vm"
chmod 0644 "$dest/sbx-vm"

# The policy, where the gate looks for it ($HOME/.derm/policy.json), owned
# by the agent user and writable by no one else.
mkdir -p "$home/.derm"
cp "$src/policy.json" "$home/.derm/policy.json"
chown agent:agent "$home/.derm" "$home/.derm/policy.json"
chmod 0755 "$home/.derm"
chmod 0644 "$home/.derm/policy.json"

rm -rf "$src"
echo "derm kit: derm's Pi package is in $dest"
