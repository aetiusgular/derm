#!/bin/bash
# Sets up a second local user that runs one person's coding agents (derm,
# wave 5 lane V; S2 part c, rules cases 53 and 125). Run as root, once per
# person, on that person's yes. It changes the system: read what it prints
# first, or run it with --dry-run. uninstall.sh undoes every step.
#
#   sudo packaging/linux/agent-user/install.sh --owner <you> [--agent derm-agent] [--dry-run] [--yes]
#
# What it does, each step printed before it runs:
#   1. A system user and group <agent> (default derm-agent), home
#      /var/lib/<agent> (0700), shell /bin/bash, password locked, in no other
#      group. An existing user is used only if this script made it (its
#      comment says so) and it is in no group that leads to root.
#   2. /etc/sudoers.d/derm-agent-<owner>: <owner> may start any program as
#      <agent>, without a password, keeping the variables derm names. Nothing
#      lets <agent> run anything as <owner> or root. Checked with visudo -c
#      before it is put in place.
#   3. /etc/tmpfiles.d/derm-agent-<owner>.conf and the folders it names:
#      /run/derm-agent (root's, 0755) and /run/derm-agent/<owner uid> (the
#      owner's, 0711), where derm run keeps each chat's bridge.
#   4. /etc/derm/agent-users.json (root's, 0644): which user runs whose
#      agents, read by derm run and by the gate inside the harness.
# It installs no harness: each one is installed and logged in as <agent>
# (README.md).

set -euo pipefail
umask 022

AGENT="derm-agent"
OWNER="${SUDO_USER:-}"
DRY=0
YES=0
ANCHOR=/etc/derm/agent-users.json
MARK="derm agents for"
NAME_RE='^[a-z_][a-z0-9_-]{0,31}$'
FORBIDDEN="root sudo admin wheel docker lxd incus incus-admin libvirt disk shadow adm systemd-journal"

die() { echo "install.sh: $*" >&2; exit 1; }
say() { echo "== $*"; }
run() {
	printf '   $'; printf ' %q' "$@"; printf '\n'
	if [ "$DRY" = 0 ]; then "$@"; fi
}

while [ $# -gt 0 ]; do
	case "$1" in
		--owner) OWNER="${2:-}"; shift 2 ;;
		--agent) AGENT="${2:-}"; shift 2 ;;
		--dry-run) DRY=1; shift ;;
		--yes) YES=1; shift ;;
		-h|--help) sed -n '2,25p' "$0"; exit 0 ;;
		*) die "unknown argument: $1" ;;
	esac
done

[[ "$OWNER" =~ $NAME_RE ]] || die "--owner must be a plain login name (got '$OWNER')"
[[ "$AGENT" =~ $NAME_RE ]] || die "--agent must be a plain login name (got '$AGENT')"
[ "$OWNER" != "$AGENT" ] || die "the agents' user cannot be the owner"
if [ "$DRY" = 0 ] && [ "$(id -u)" != 0 ]; then die "run as root (or with --dry-run)"; fi
for tool in useradd usermod passwd visudo systemd-tmpfiles python3 getent install; do
	command -v "$tool" >/dev/null || die "$tool is not installed"
done

OWNER_UID="$(getent passwd "$OWNER" | cut -d: -f3)" || true
[ -n "$OWNER_UID" ] || die "no user $OWNER"
[ "$OWNER_UID" -ge 1000 ] || die "$OWNER has uid $OWNER_UID: the owner must be a person's account"
OWNER_GROUP="$(id -gn "$OWNER")"
HOME_DIR="/var/lib/$AGENT"
AGENT_PATH="$HOME_DIR/.local/bin:/usr/local/bin:/usr/bin:/bin"
SUDOERS="/etc/sudoers.d/derm-agent-$OWNER"
TMPFILES="/etc/tmpfiles.d/derm-agent-$OWNER.conf"

# An existing user is ours only if our comment is on it.
if getent passwd "$AGENT" >/dev/null; then
	comment="$(getent passwd "$AGENT" | cut -d: -f5)"
	case "$comment" in
		"$MARK $OWNER") EXISTS=1 ;;
		*) die "a user $AGENT exists and was not made by this script (comment '$comment'); pick another --agent" ;;
	esac
else
	EXISTS=0
fi

echo "This sets up '$AGENT' to run $OWNER's coding agents (derm, S2 part c)."
echo "Owner: $OWNER (uid $OWNER_UID). Agents' user: $AGENT, home $HOME_DIR."
[ "$DRY" = 1 ] && echo "(dry run: nothing changes)"
if [ "$DRY" = 0 ] && [ "$YES" = 0 ]; then
	read -r -p "Go ahead? [y/N] " answer
	[ "$answer" = y ] || [ "$answer" = Y ] || die "stopped; nothing changed"
fi

say "1. the user $AGENT"
if [ "$EXISTS" = 0 ]; then
	run useradd --system --user-group --create-home --home-dir "$HOME_DIR" \
		--shell /bin/bash --comment "$MARK $OWNER" "$AGENT"
	run passwd --lock "$AGENT"
fi
run chmod 0700 "$HOME_DIR"
if [ "$DRY" = 0 ]; then
	for g in $(id -nG "$AGENT"); do
		for f in $FORBIDDEN "$OWNER_GROUP"; do
			[ "$g" != "$f" ] || die "$AGENT is in the group $g, which gives a way to root or to $OWNER's files; remove it (gpasswd -d $AGENT $g) and run again"
		done
	done
fi

say "2. $SUDOERS"
rule="$OWNER ALL=($AGENT) NOPASSWD:SETENV: ALL"
echo "   $rule"
if [ "$DRY" = 0 ]; then
	tmp="$(mktemp)"
	trap 'rm -f "$tmp"' EXIT
	printf '# derm: %s may start programs as %s (S2 part c). Undo: uninstall.sh\n%s\n' "$OWNER" "$AGENT" "$rule" >"$tmp"
	visudo -c -q -f "$tmp" || die "visudo refused the rule; nothing installed"
	install -o root -g root -m 0440 "$tmp" "$SUDOERS"
fi

say "3. $TMPFILES"
tmpfiles="d /run/derm-agent 0755 root root -
d /run/derm-agent/$OWNER_UID 0711 $OWNER $OWNER_GROUP -"
echo "$tmpfiles" | sed 's/^/   /'
if [ "$DRY" = 0 ]; then
	printf '# derm: per-chat bridges for %s (S2 part c). Undo: uninstall.sh\n%s\n' "$OWNER" "$tmpfiles" >"$TMPFILES"
	chmod 0644 "$TMPFILES"
	systemd-tmpfiles --create "$TMPFILES"
fi

say "4. $ANCHOR"
AGENT_UID="$( [ "$DRY" = 1 ] && [ "$EXISTS" = 0 ] && echo 0 || id -u "$AGENT")"
echo "   $AGENT (uid $AGENT_UID) runs $OWNER's agents, PATH $AGENT_PATH"
if [ "$DRY" = 0 ]; then
	install -d -o root -g root -m 0755 /etc/derm
	python3 -I - "$ANCHOR" "$AGENT" "$AGENT_UID" "$OWNER" "$OWNER_UID" "$AGENT_PATH" <<'PY'
import json, os, sys
path, agent, uid, owner, owner_uid, agent_path = sys.argv[1:]
data = {"version": 1, "agents": []}
if os.path.lexists(path):
    st = os.lstat(path)
    if not os.path.isfile(path) or os.path.islink(path) or st.st_uid != 0:
        sys.exit(f"{path} exists and is not a regular file of root's; fix it by hand")
    with open(path) as f:
        data = json.load(f)
    if data.get("version") != 1:
        sys.exit(f"{path} is not version 1")
data["agents"] = [a for a in data["agents"] if a.get("ownerUid") != int(owner_uid)]
data["agents"].append({"user": agent, "uid": int(uid), "owner": owner,
                       "ownerUid": int(owner_uid), "path": agent_path, "how": "sudo"})
tmp = path + ".new"
fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o644)
with os.fdopen(fd, "w") as f:
    json.dump(data, f, indent=2)
    f.write("\n")
os.chmod(tmp, 0o644)
os.replace(tmp, path)
PY
fi

say "done"
cat <<EOF
Next, as $AGENT (each harness keeps its own login under $HOME_DIR):
  sudo -u $AGENT -H bash -l     # a shell as $AGENT, to install and log in
  # install Node and each harness for $AGENT under $HOME_DIR/.local, then log in:
  #   claude  (then /login),  codex login,  pi  (then /login)
Then: derm run <harness> --boundary none  starts the harness as $AGENT.
On the box, regenerate the audit rules for $AGENT's uid (derm-audit-feed rules) on your yes.
Undo: sudo packaging/linux/agent-user/uninstall.sh --owner $OWNER --agent $AGENT
EOF
