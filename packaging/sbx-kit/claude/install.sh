#!/bin/sh
# derm's gate inside the sbx VM, for Claude Code: the kit's setup.install
# (packaging/sbx-kit/claude/spec.yaml). Runs once, as root, when sbx creates
# the sandbox, after the kit's files/ are in /home/agent (SPEC-v2 5.6, 5.8,
# 9.6 at sbx-kits-contrib 1de3c1e). A failure here fails `sbx create`, so
# derm run says the chat did not start: the gate is never left half there.
#
# What it can and cannot hold. The agent has passwordless sudo in the VM
# (SPEC-v2 9.1; Docker's security page), so nothing here stands against an
# agent that sets out to remove it. Root owns the gate's code and its hook
# registration, so an ordinary write by the agent does not change them; the
# policy is the agent user's own, because derm's hook trusts a policy only
# from its own uid (src/core/policy.ts), and the gate itself denies writes
# to ~/.derm (a control path) under full access.
set -eu

src=/home/agent/.derm-kit
dest=/opt/derm-kit
settings=/etc/claude-code/managed-settings.json

fail() {
  echo "derm kit: $*" >&2
  exit 1
}

[ -d "$src/plugin" ] || fail "$src/plugin is missing; the kit was not built by derm run"
[ -f "$src/policy.json" ] || fail "$src/policy.json is missing; derm run adds the kit only with a policy"

# derm's hook is TypeScript run by Node's own type stripping: Node 22.18 or
# later, with process.features.typescript (bin/derm-hook.mjs). The claude
# image gets Node from Ubuntu's nodejs package (sbx-kits-contrib
# shell/Dockerfile:247); whether that build strips types is checked here.
node_bin=$(command -v node || true)
[ -n "$node_bin" ] || fail "no node in this image; derm's gate needs Node 22.18 or later"
"$node_bin" -e '
const [major, minor] = process.versions.node.split(".").map(Number);
const ok = (major > 22 || (major === 22 && minor >= 18)) && Boolean(process.features && process.features.typescript);
process.exit(ok ? 0 : 1);
' || fail "$("$node_bin" --version) cannot run derm's gate: it needs Node 22.18 or later with type stripping (process.features.typescript)"

# The gate's code, owned by root and read-only to the agent user.
rm -rf "$dest"
mkdir -p "$dest"
cp -R "$src/plugin/." "$dest/"
chown -R root:root "$dest"
chmod -R u=rwX,go=rX "$dest"

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
