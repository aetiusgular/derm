#!/bin/bash
# One agent account for one subscription (derm, plans/parallel_build_accounts.md
# lane L2; note CB sections 2.1 and 5). Run as root, on the person's yes; read
# --dry-run first. uninstall.sh --account <slug> undoes every step.
#
#   sudo packaging/linux/agent-user/install.sh --account <slug> --subscription <label> \
#        [--owner <you>] [--dry-run] [--yes]
#
# <slug>: 1 to 21 of a-z, 0-9 and - (the account is derm-agent-<slug>, and
# useradd takes 32 characters). <label>: what you call the subscription, shown
# back and never parsed ("Claude Max, personal").
#
# Each step is printed before it runs, with its undo:
#   1. /usr/local/lib/derm/agents.py (root's, 0644): the helper the unit and
#      derm's check run, copied from here and checked by hash.
#   2. the group derm-agents (system group, no members listed).
#   3. the user derm-agent-<slug>: system user, primary group derm-agents and
#      no other group, home /var/lib/derm/agents/<slug> (0700), password
#      locked, shell /bin/bash.
#   4. /etc/derm/agents.json (root's, 0644): the account, exactly as the
#      contract in plans/parallel_build_accounts.md section 2 says.
#   5. /etc/derm/agents.nft and the table inet derm_agents: every outbound
#      packet from the group or from an account's uid is refused unless it
#      goes to 127.0.0.0/8 or ::1, and DNS (port 53) is refused on loopback
#      too: derm-egress resolves names.
#   6. derm-agents-nft.service, enabled, so the table comes back at boot and
#      after nftables.service flushes the ruleset.
#   7. /etc/sudoers.d/derm-agent-<slug>: <you> may start programs as the
#      account without a password (derm run, derm agents login). Last, so
#      nothing runs as the account before its table is in place.

set -euo pipefail
umask 022
export LC_ALL=C

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
PY=/usr/bin/python3
NFT=/usr/sbin/nft
HELPER=/usr/local/lib/derm/agents.py
ANCHOR=/etc/derm/agents.json
RULES=/etc/derm/agents.nft
UNIT=/etc/systemd/system/derm-agents-nft.service
GROUP=derm-agents
HOMES=/var/lib/derm/agents
NAME_RE='^[a-z_][a-z0-9_-]{0,31}$'

SLUG=""
LABEL=""
LABEL_SET=0
OWNER="${SUDO_USER:-}"
DRY=0
YES=0

die() { echo "install.sh: $*" >&2; exit 1; }
say() { echo "== $*"; }
run() {
	printf '   $'; printf ' %q' "$@"; printf '\n'
	if [ "$DRY" = 0 ]; then "$@"; fi
}

while [ $# -gt 0 ]; do
	case "$1" in
		--account) SLUG="${2-}"; shift 2 || die "--account needs a slug" ;;
		--subscription) LABEL="${2-}"; LABEL_SET=1; shift 2 || die "--subscription needs a label" ;;
		--owner) OWNER="${2-}"; shift 2 || die "--owner needs a login" ;;
		--dry-run) DRY=1; shift ;;
		--yes) YES=1; shift ;;
		-h|--help) sed -n '2,33p' "$0"; exit 0 ;;
		*) die "unknown argument: $1" ;;
	esac
done

for tool in "$PY" "$NFT"; do [ -x "$tool" ] || die "$tool is not installed"; done
for tool in useradd groupadd groupdel passwd visudo getent install id sha256sum; do
	command -v "$tool" >/dev/null || die "$tool is not installed"
done
"$PY" -I "$HERE/accounts.py" valid-slug "$SLUG" || die "--account '$SLUG' refused"
[ "$LABEL_SET" = 1 ] || die "--subscription <label> is required: what you call this subscription"
"$PY" -I "$HERE/accounts.py" valid-label "$LABEL" || die "--subscription refused"
[[ "$OWNER" =~ $NAME_RE ]] || die "--owner must be a plain login name (got '$OWNER'); run with sudo or pass --owner"
if [ "$DRY" = 0 ] && [ "$(id -u)" != 0 ]; then die "run as root (or with --dry-run)"; fi

ACCOUNT="derm-agent-$SLUG"
HOME_DIR="$HOMES/$SLUG"
COMMENT="derm agent $SLUG"
SUDOERS="/etc/sudoers.d/derm-agent-$SLUG"
OWNER_UID="$(getent passwd "$OWNER" | cut -d: -f3)" || true
[ -n "$OWNER_UID" ] || die "no user $OWNER"
[ "$OWNER_UID" -ge 1000 ] || die "$OWNER has uid $OWNER_UID: the owner must be a person's account"
case "$OWNER" in derm-agent*) die "the owner cannot be an agent account" ;; esac

# What exists already. An existing group is used only with no members listed;
# an existing user only if this script made it, in this group.
GROUP_EXISTS=0
if getent group "$GROUP" >/dev/null; then
	GROUP_EXISTS=1
	members="$(getent group "$GROUP" | cut -d: -f4)"
	[ -z "$members" ] || die "the group $GROUP exists with members ($members): it is not derm's to use; remove them or the group"
fi
USER_EXISTS=0
if getent passwd "$ACCOUNT" >/dev/null; then
	IFS=: read -r _ _ uid gid comment home _ < <(getent passwd "$ACCOUNT")
	[ "$comment" = "$COMMENT" ] || die "a user $ACCOUNT exists and was not made by this script (comment '$comment')"
	[ "$home" = "$HOME_DIR" ] || die "$ACCOUNT has home $home, not $HOME_DIR"
	[ "$GROUP_EXISTS" = 1 ] && [ "$gid" = "$(getent group "$GROUP" | cut -d: -f3)" ] \
		|| die "$ACCOUNT's primary group is not $GROUP"
	USER_EXISTS=1
fi
# The accounts file must be one root wrote; a reader refuses anything else,
# and so does this script, rather than write over it.
if [ -e "$ANCHOR" ] || [ -L "$ANCHOR" ]; then
	"$PY" -I "$HERE/accounts.py" anchor-names >/dev/null || die "fix $ANCHOR by hand first; nothing changed"
fi

echo "This makes the agent account $ACCOUNT for the subscription \"$LABEL\" (derm)."
echo "Its traffic reaches loopback only. $OWNER (uid $OWNER_UID) may start programs as it."
[ "$DRY" = 1 ] && echo "(dry run: nothing changes)"
if [ "$DRY" = 0 ] && [ "$YES" = 0 ]; then
	read -r -p "Go ahead? [y/N] " answer
	[ "$answer" = y ] || [ "$answer" = Y ] || die "stopped; nothing changed"
fi
DONE=0
if [ "$DRY" = 0 ]; then
	trap '[ "$DONE" = 1 ] || echo "install.sh: stopped before the end; undo what it did: sudo $HERE/uninstall.sh --account $SLUG" >&2' EXIT
fi

say "1. $HELPER (undo: rm, with the last account)"
run install -d -o root -g root -m 0755 /usr/local/lib/derm
run install -o root -g root -m 0644 "$HERE/accounts.py" "$HELPER"
if [ "$DRY" = 0 ]; then
	[ "$(sha256sum <"$HERE/accounts.py")" = "$(sha256sum <"$HELPER")" ] || die "$HELPER does not match what was copied"
	A=("$PY" -I "$HELPER")
else
	A=("$PY" -I "$HERE/accounts.py")
fi

say "2. the group $GROUP (undo: groupdel, with the last account)"
if [ "$GROUP_EXISTS" = 0 ]; then
	run groupadd --system "$GROUP"
else
	echo "   exists"
fi

say "3. the user $ACCOUNT (undo: userdel --remove $ACCOUNT)"
run install -d -o root -g root -m 0755 /var/lib/derm "$HOMES"
if [ "$USER_EXISTS" = 0 ]; then
	run useradd --system --gid "$GROUP" --no-user-group --create-home --home-dir "$HOME_DIR" \
		--shell /bin/bash --comment "$COMMENT" "$ACCOUNT"
	run passwd --lock "$ACCOUNT"
else
	echo "   exists"
fi
run chmod 0700 "$HOME_DIR"
if [ "$DRY" = 0 ]; then
	ACCOUNT_UID="$(id -u "$ACCOUNT")"
	GID="$(getent group "$GROUP" | cut -d: -f3)"
	[ "$(id -G "$ACCOUNT")" = "$GID" ] || die "$ACCOUNT is in groups $(id -Gn "$ACCOUNT"), not only $GROUP; remove the others (gpasswd -d $ACCOUNT <group>) and run again"
else
	ACCOUNT_UID="<uid>"
	GID="<gid>"
fi

say "4. $ANCHOR (undo: the entry removed; the file goes with the last account)"
echo "   {\"name\": \"$ACCOUNT\", \"uid\": $ACCOUNT_UID, \"subscription\": <the label>, \"home\": \"$HOME_DIR\"}"
if [ "$DRY" = 0 ]; then
	install -d -o root -g root -m 0755 /etc/derm
	"${A[@]}" upsert "$SLUG" "$ACCOUNT_UID" "$LABEL"
fi

say "5. $RULES and the table inet derm_agents (undo: nft delete table inet derm_agents, with the last account)"
if [ "$DRY" = 0 ]; then
	tmp="$(mktemp /etc/derm/.agents.nft.XXXXXX)"
	"${A[@]}" render >"$tmp"
	"$NFT" -c -f "$tmp" || { rm -f "$tmp"; die "nft refused the table; nothing loaded"; }
	chmod 0644 "$tmp"
	mv -f "$tmp" "$RULES"
	run "$NFT" -f "$RULES"
	"${A[@]}" marker
	sed 's/^/   | /' "$RULES"
else
	echo "   (the group's gid and the account's uid are known only after steps 2 and 3)"
	"${A[@]}" render --gid 0 --uid 0 | sed 's/^/   | /'
fi

say "6. $UNIT (undo: systemctl disable, rm, with the last account)"
run install -o root -g root -m 0644 "$HERE/derm-agents-nft.service" "$UNIT"
if [ -d /run/systemd/system ]; then
	run systemctl daemon-reload
	run systemctl enable derm-agents-nft.service
	# Started already by hand above; this records it as active.
	run systemctl start derm-agents-nft.service
else
	echo "   systemd is not running here: the unit is in place but nothing loads the table at"
	echo "   boot. After a reboot run: sudo $NFT -f $RULES"
fi

say "7. $SUDOERS (undo: rm)"
rule="$OWNER ALL=($ACCOUNT) NOPASSWD:SETENV: ALL"
echo "   $rule"
if [ "$DRY" = 0 ]; then
	tmp="$(mktemp)"
	printf '# derm: %s may start programs as %s. Undo: uninstall.sh --account %s\n%s\n' "$OWNER" "$ACCOUNT" "$SLUG" "$rule" >"$tmp"
	visudo -c -q -f "$tmp" || { rm -f "$tmp"; die "visudo refused the rule; the account has no sudo rule"; }
	install -o root -g root -m 0440 "$tmp" "$SUDOERS"
	rm -f "$tmp"
fi

DONE=1
say "done"
cat <<EOF
Check, as anyone:          $PY -I $HELPER check
Check the kernel, as it:   sudo -n -u $ACCOUNT $PY -I $HELPER check --probe
Sign it in to a harness:   derm agents login (lane L4); until then: sudo -u $ACCOUNT -i, then the harness's own login
Undo:                      sudo $HERE/uninstall.sh --account $SLUG
EOF
