#!/bin/sh
# derm's gate inside the sbx VM, for Claude Code, with derm itself as the
# gate: the install hook of the v3 kit derm builds under DERM_SBX_KIT=rust
# (packaging/sbx-kit/claude-rs/derm-gate-claude.yaml). Runs once, as root,
# when sbx creates the sandbox, after the claude workload's own install
# hooks and before Claude Code first starts (lifecycle@1 at
# sandbox-kit-spec 6838e3e). The kit's overlay put its files in
# /opt/derm-kit-src. A failure here fails `sbx create`, so derm run says the
# chat did not start: the gate is never left half there.
#
# What it can and cannot hold. The agent has passwordless sudo in the VM
# (the claude image's agent is in group sudo, seen in the VM; Docker's
# security page), so nothing here stands against an agent that sets out to
# remove it. Root owns derm and the hook registration, so an ordinary write
# by the agent does not change them; the policy is the agent user's own,
# because derm trusts a policy only from its own uid, and the gate itself
# denies writes to ~/.derm (a control path) under full access.
set -eu

src=/opt/derm-kit-src
dest=/opt/derm-kit
home=/home/agent
bin=/usr/local/bin/derm
settings=/etc/claude-code/managed-settings.json

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
[ -d "$home" ] || fail "$home is missing; this image is not one derm's kit knows"

# The derm the kit carries is the host's own on Linux, or one the person
# put there for the VM. Whether it runs in this image (its architecture,
# its C library) is found out here, before anything is installed.
chmod 0755 "$src/derm"
ver=$("$src/derm" --version 2>&1) || fail "the derm this kit carries does not run in this VM ($(printf '%s' "$ver" | head -n 1)); it was built for another system or C library. Run the chat with derm's other kit (unset DERM_SBX_KIT), or use a static Linux build of derm"

# derm, at the path the hooks name. A derm already there is not replaced.
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

# The hooks, in Claude Code's managed settings (Claude Code reads
# /etc/claude-code on Linux), merged with whatever another kit put there.
# Managed, so a kit or the agent rewriting ~/.claude/settings.json does not
# drop them. derm writes them itself: exec form, derm by its absolute path,
# and PreToolUse blocks when the hook fails.
mkdir -p /etc/claude-code
"$bin" kit register claude-code >/dev/null || fail "the hooks were not registered in $settings"
[ -f "$settings" ] || fail "$settings is not there after the registration"
chown root:root /etc/claude-code "$settings"
chmod 0755 /etc/claude-code
chmod 0644 "$settings"

rm -rf "$src"
echo "derm kit: derm's gate is registered for Claude Code ($ver)"
