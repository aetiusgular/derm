#!/bin/bash
# Undoes install.sh for one owner (derm, wave 5 lane V). Run as root.
#
#   sudo packaging/linux/agent-user/uninstall.sh --owner <you> [--agent derm-agent] [--keep-home] [--dry-run]
#
# Removes, each printed first: the owner's entry in /etc/derm/agent-users.json
# (the file too when it is left empty), /etc/sudoers.d/derm-agent-<owner>,
# /etc/tmpfiles.d/derm-agent-<owner>.conf, /run/derm-agent/<owner uid>, and the
# user <agent> with its home (/var/lib/<agent>: the harnesses' logins there go
# with it) unless --keep-home. It removes a user only if install.sh made it.
# It stops the agents' processes first: a user with processes cannot be
# removed.

set -euo pipefail

AGENT="derm-agent"
OWNER="${SUDO_USER:-}"
DRY=0
KEEP=0
ANCHOR=/etc/derm/agent-users.json
MARK="derm agents for"
NAME_RE='^[a-z_][a-z0-9_-]{0,31}$'

die() { echo "uninstall.sh: $*" >&2; exit 1; }
say() { echo "== $*"; }
run() {
	printf '   $'; printf ' %q' "$@"; printf '\n'
	if [ "$DRY" = 0 ]; then "$@"; fi
}

while [ $# -gt 0 ]; do
	case "$1" in
		--owner) OWNER="${2:-}"; shift 2 ;;
		--agent) AGENT="${2:-}"; shift 2 ;;
		--keep-home) KEEP=1; shift ;;
		--dry-run) DRY=1; shift ;;
		-h|--help) sed -n '2,13p' "$0"; exit 0 ;;
		*) die "unknown argument: $1" ;;
	esac
done
[[ "$OWNER" =~ $NAME_RE ]] || die "--owner must be a plain login name"
[[ "$AGENT" =~ $NAME_RE ]] || die "--agent must be a plain login name"
if [ "$DRY" = 0 ] && [ "$(id -u)" != 0 ]; then die "run as root (or with --dry-run)"; fi
OWNER_UID="$(getent passwd "$OWNER" | cut -d: -f3)" || true
[ -n "$OWNER_UID" ] || die "no user $OWNER"

say "the entry for $OWNER in $ANCHOR"
if [ -f "$ANCHOR" ] && [ "$DRY" = 0 ]; then
	python3 -I - "$ANCHOR" "$OWNER_UID" <<'PY'
import json, os, sys
path, owner_uid = sys.argv[1], int(sys.argv[2])
if os.path.islink(path) or os.lstat(path).st_uid != 0:
    sys.exit(f"{path} is not a regular file of root's; fix it by hand")
with open(path) as f:
    data = json.load(f)
data["agents"] = [a for a in data.get("agents", []) if a.get("ownerUid") != owner_uid]
if not data["agents"]:
    os.remove(path)
else:
    tmp = path + ".new"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o644)
    with os.fdopen(fd, "w") as f:
        json.dump(data, f, indent=2)
        f.write("\n")
    os.replace(tmp, path)
PY
	rmdir /etc/derm 2>/dev/null || true
fi

say "sudoers, tmpfiles and the bridge folder"
run rm -f "/etc/sudoers.d/derm-agent-$OWNER" "/etc/tmpfiles.d/derm-agent-$OWNER.conf"
run rm -rf "/run/derm-agent/$OWNER_UID"
if [ "$DRY" = 0 ]; then rmdir /run/derm-agent 2>/dev/null || true; fi

say "the user $AGENT"
if getent passwd "$AGENT" >/dev/null; then
	comment="$(getent passwd "$AGENT" | cut -d: -f5)"
	[ "$comment" = "$MARK $OWNER" ] || die "$AGENT was not made by install.sh for $OWNER (comment '$comment'); not removed"
	run pkill -KILL -u "$AGENT" || true
	if [ "$KEEP" = 1 ]; then run userdel "$AGENT"; else run userdel --remove "$AGENT"; fi
else
	echo "   no user $AGENT"
fi
say "done"
