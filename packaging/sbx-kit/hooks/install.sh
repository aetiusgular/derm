#!/bin/sh
# derm's gate inside the sbx VM for an agent that takes a command hook
# (Copilot CLI, Droid, Cursor, Kiro): the v3 kit's install hook
# (packaging/sbx-kit/hooks/derm-gate-hooks.yaml).
#
#   sh /opt/derm-kit-src/install.sh <agent>
#
# Runs once, as root, when sbx creates the sandbox, after the agent's own
# kit's install hooks and before the agent first starts (lifecycle@1 at
# sandbox-kit-spec 6838e3e; the order was seen on the box for all four,
# sbx 0.51.0, 17 Nov 2026). The kit's overlay put its files in
# /opt/derm-kit-src. A failure here fails `sbx create`, so derm run says
# the chat did not start: the gate is never left half there.
#
# What it can and cannot hold. The agent has passwordless sudo in the VM
# (uid 1000 agent, group sudo, seen in each of the four VMs), so nothing
# here stands against an agent that sets out to remove it. Root owns the
# gate's code. The registration is in the agent's own config under its
# home, the only place these agents read a hook from, so the agent's user
# can rewrite it; derm's gate denies a write to those files only where the
# policy or a control path says so. The policy is the agent user's own,
# because derm's hook trusts a policy only from its own uid
# (src/core/policy.ts).
set -eu

agent=${1-}
src=/opt/derm-kit-src
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

case "$agent" in
  copilot-cli | droid | cursor | kiro) ;;
  *) fail "install.sh takes copilot-cli, droid, cursor or kiro" ;;
esac

[ -d "$src/plugin" ] || fail "$src/plugin is missing; the kit was not built by derm run"
[ -f "$src/policy.json" ] || fail "$src/policy.json is missing; derm run adds the kit only with a policy"
[ -d "$home" ] || fail "$home is missing; this image is not one derm's kit knows"

# derm's hook is TypeScript run by Node's own type stripping: Node 22.18 or
# later, with process.features.typescript (bin/derm-hook.mjs). The kit
# carries its own Node (the Dockerfile); whether it runs here and strips
# types is checked before anything else.
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
# its VM route to the daemon's HTTP port only when this file holds
# (src/core/daemon.ts, security finding W5C-S2).
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

# The hook, in the agent's own config. Each file written, and each folder
# made for it, goes to the agent's user: these agents write their own
# settings there.
wrote=$("$node_bin" "$src/register-agent.mjs" "$agent" "$home" "$node_bin" "$dest/bin/derm-hook.mjs") || fail "the hook was not registered for $agent"
printf '%s\n' "$wrote" | while IFS= read -r f; do
  [ -n "$f" ] || continue
  d=$(dirname "$f")
  while [ "$d" != "$home" ] && [ "$d" != / ]; do
    chown agent:agent "$d"
    d=$(dirname "$d")
  done
  chown agent:agent "$f"
  chmod 0644 "$f"
done

rm -rf "$src"
echo "derm kit: derm's gate is registered for $agent ($("$node_bin" --version))"
