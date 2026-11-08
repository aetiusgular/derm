#!/bin/sh
# derm's gate inside the sbx VM, for Claude Code: the v3 kit's install hook
# (packaging/sbx-kit/claude/derm-gate-claude.yaml). Runs once, as root, when
# sbx creates the sandbox, after the claude workload's own install hooks and
# before Claude Code first starts (lifecycle@1 at sandbox-kit-spec 6838e3e:
# install hooks run once, in dependency order, before the entrypoint). The
# kit's overlay put its files in /opt/derm-kit-src. A failure here fails
# `sbx create`, so derm run says the chat did not start: the gate is never
# left half there.
#
# What it can and cannot hold. The agent has passwordless sudo in the VM
# (the claude image's agent is in group sudo, seen in the VM; Docker's
# security page), so nothing here stands against an agent that sets out to
# remove it. Root owns the gate's code and its hook
# registration, so an ordinary write by the agent does not change them; the
# policy is the agent user's own, because derm's hook trusts a policy only
# from its own uid (src/core/policy.ts), and the gate itself denies writes
# to ~/.derm (a control path) under full access.
set -eu

src=/opt/derm-kit-src
dest=/opt/derm-kit
settings=/etc/claude-code/managed-settings.json

fail() {
  echo "derm kit: $*" >&2
  exit 1
}

[ -d "$src/plugin" ] || fail "$src/plugin is missing; the kit was not built by derm run"
[ -f "$src/policy.json" ] || fail "$src/policy.json is missing; derm run adds the kit only with a policy"

# derm's hook is TypeScript run by Node's own type stripping: Node 22.18 or
# later, with process.features.typescript (bin/derm-hook.mjs). sbx's v3
# claude image has no Node, so the kit carries its own (the Dockerfile);
# whether it runs here and strips types is checked before anything else.
[ -x "$src/node" ] || fail "$src/node is missing; the kit was not built by derm run"
node_bin="$src/node"
"$node_bin" -e '
const [major, minor] = process.versions.node.split(".").map(Number);
const ok = (major > 22 || (major === 22 && minor >= 18)) && Boolean(process.features && process.features.typescript);
process.exit(ok ? 0 : 1);
' || fail "$("$node_bin" --version) cannot run derm's gate: it needs Node 22.18 or later with type stripping (process.features.typescript)"

# The gate's code and its Node, owned by root and read-only to the agent
# user.
rm -rf "$dest"
mkdir -p "$dest"
cp -R "$src/plugin/." "$dest/"
cp "$node_bin" "$dest/node"
chown -R root:root "$dest"
chmod -R u=rwX,go=rX "$dest"
chmod 0755 "$dest/node"
node_bin="$dest/node"

# The VM marker: root's alone, at a path no variable moves. The hook takes
# its VM route to the daemon's HTTP port only when this file holds, so a
# project on the host that sets DERM_BOUNDARY and DERM_OTLP_ENDPOINT cannot
# send the hook's approvals to a listener of its own (src/core/daemon.ts,
# security finding W5C-S2).
printf 'derm sbx kit\n' > "$dest/sbx-vm"
chown root:root "$dest/sbx-vm"
chmod 0644 "$dest/sbx-vm"

# The policy, where the hook looks for it ($HOME/.derm/policy.json), owned
# by the agent user and writable by no one else.
mkdir -p /home/agent/.derm
cp "$src/policy.json" /home/agent/.derm/policy.json
chown agent:agent /home/agent/.derm /home/agent/.derm/policy.json
chmod 0755 /home/agent/.derm
chmod 0644 /home/agent/.derm/policy.json

# The hooks, in Claude Code's managed settings (Claude Code reads
# /etc/claude-code on Linux, read in its 2.1.311 binary), merged with
# whatever another kit put there. Managed, so a kit or the agent rewriting
# ~/.claude/settings.json does not drop them.
mkdir -p /etc/claude-code
"$node_bin" "$src/register-hooks.mjs" "$settings" "$node_bin" "$dest/bin/derm-hook.mjs"
chown root:root /etc/claude-code "$settings"
chmod 0755 /etc/claude-code
chmod 0644 "$settings"

rm -rf "$src"
echo "derm kit: derm's gate is registered for Claude Code ($("$node_bin" --version))"
