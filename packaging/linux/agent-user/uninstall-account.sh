#!/bin/bash
# Undoes install.sh --account for one account (derm, lane L2). Run as root.
#
#   sudo packaging/linux/agent-user/uninstall.sh --account <slug> [--keep-home] [--dry-run] [--yes]
#
# Each step is printed first. In order: the sudoers rule (so nothing new
# starts as the account), the account's processes, its entry in
# /etc/derm/agents.json, the table (written again without the account's uid,
# or deleted with the unit and the marker when it was the last), the user
# and its home (the harnesses' logins in signin/ and every project's folders
# go with it unless --keep-home), the group derm-agents with the last
# account, and, with the last account, TIOCSTI as it was before the install,
# the helper, and this undo's own copy. The user is removed only if
# install.sh made it. Runs on a half-installed account too.
#
# Run the copy the install keeps where only root writes, as the install's
# undo line says: sudo /usr/local/libexec/derm/agent-user/uninstall.sh
# --account <slug>. That copy checks itself against the sha256 the install
# recorded before it changes anything (review AI-8).

set -euo pipefail
umask 022
export LC_ALL=C

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
PY=/usr/bin/python3
NFT=/usr/sbin/nft
HELPER=/usr/local/lib/derm/agents.py
UNINSTALLER=/usr/local/libexec/derm/agent-user
ANCHOR=/etc/derm/agents.json
RULES=/etc/derm/agents.nft
UNIT=/etc/systemd/system/derm-agents-nft.service
MARKER=/run/derm/agents-nft.loaded
GROUP=derm-agents
HOMES=/var/lib/derm/agents

SLUG=""
KEEP=0
DRY=0
YES=0

die() { echo "uninstall.sh: $*" >&2; exit 1; }
say() { echo "== $*"; }
run() {
	printf '   $'; printf ' %q' "$@"; printf '\n'
	if [ "$DRY" = 0 ]; then "$@"; fi
}

while [ $# -gt 0 ]; do
	case "$1" in
		--account) SLUG="${2-}"; shift 2 || die "--account needs a slug" ;;
		--keep-home) KEEP=1; shift ;;
		--dry-run) DRY=1; shift ;;
		--yes) YES=1; shift ;;
		-h|--help) sed -n '2,19p' "$0"; exit 0 ;;
		*) die "unknown argument: $1" ;;
	esac
done
[ -x "$PY" ] || die "$PY is not installed"
if [ -f "$HELPER" ]; then A=("$PY" -I "$HELPER"); else A=("$PY" -I "$HERE/accounts.py"); fi
# Root's copy runs only as the install recorded it: every folder to it
# root's alone, each file the sha256 in /etc/derm/uninstall.sha256.
if [ "$HERE" = "$UNINSTALLER" ]; then
	"${A[@]}" verify-uninstaller || die "this copy is not what the install recorded; nothing changed. Write the package out again (derm agents installer <folder>) and run its uninstall.sh"
fi
# The same rule as install.sh: 1 to 15 of a-z, 0-9 and -, and never a slug
# that would name wave 5's derm-agent user or the group (accounts.py).
"${A[@]}" valid-slug "$SLUG" || die "--account '$SLUG' refused"
if [ "$DRY" = 0 ] && [ "$(id -u)" != 0 ]; then die "run as root (or with --dry-run)"; fi

ACCOUNT="derm-$SLUG"
COMMENT="derm agent $SLUG"
SUDOERS="/etc/sudoers.d/derm-$SLUG"

echo "This removes the agent account $ACCOUNT$([ "$KEEP" = 1 ] && echo ", keeping its home") (derm)."
[ "$DRY" = 1 ] && echo "(dry run: nothing changes)"
if [ "$DRY" = 0 ] && [ "$YES" = 0 ]; then
	read -r -p "Go ahead? [y/N] " answer
	[ "$answer" = y ] || [ "$answer" = Y ] || die "stopped; nothing changed"
fi

OURS=0
if getent passwd "$ACCOUNT" >/dev/null; then
	comment="$(getent passwd "$ACCOUNT" | cut -d: -f5)"
	[ "$comment" = "$COMMENT" ] || die "$ACCOUNT was not made by install.sh (comment '$comment'); nothing removed"
	OURS=1
fi

say "1. $SUDOERS"
run rm -f "$SUDOERS"

say "2. the processes of $ACCOUNT"
if [ "$OURS" = 1 ]; then
	run pkill -KILL -u "$ACCOUNT" || true
	if [ "$DRY" = 0 ]; then
		for _ in 1 2 3 4 5 6 7 8 9 10; do pgrep -u "$ACCOUNT" >/dev/null || break; sleep 0.2; done
		! pgrep -u "$ACCOUNT" >/dev/null || die "$ACCOUNT still has processes; nothing else removed"
	fi
else
	echo "   no user $ACCOUNT"
fi

say "3. the entry for $ACCOUNT in $ANCHOR"
LEFT=0
if [ -e "$ANCHOR" ] || [ -L "$ANCHOR" ]; then
	if [ "$DRY" = 0 ]; then
		LEFT="$("${A[@]}" remove "$SLUG")" || die "fix $ANCHOR by hand first; the sudoers rule is gone, the rest stays"
	else
		LEFT="$("${A[@]}" anchor-names | grep -vxc -- "$ACCOUNT" || true)"
	fi
fi
echo "   accounts left: $LEFT"

say "4. the table inet derm_agents"
if [ "$LEFT" -gt 0 ]; then
	if [ "$DRY" = 0 ]; then
		tmp="$(mktemp /etc/derm/.agents.nft.XXXXXX)"
		"${A[@]}" render >"$tmp"
		"$NFT" -c -f "$tmp" || { rm -f "$tmp"; die "nft refused the table; the old one stays loaded"; }
		chmod 0644 "$tmp"
		mv -f "$tmp" "$RULES"
		run "$NFT" -f "$RULES"
		"${A[@]}" marker
	else
		echo "   written again without $ACCOUNT's uid, and loaded"
	fi
else
	if [ -d /run/systemd/system ] && [ -f "$UNIT" ]; then
		run systemctl disable --now derm-agents-nft.service || true
	fi
	if [ -x "$NFT" ]; then
		if [ "$DRY" = 1 ] || "$NFT" list table inet derm_agents >/dev/null 2>&1; then
			run "$NFT" delete table inet derm_agents
		fi
	fi
	run rm -f "$RULES" "$UNIT" "$MARKER"
	# The bridges' base (install-account.sh step 9). /run/derm-agent/<uid>
	# is left: it is empty between chats, gone at the next boot, and wave 5's
	# --owner form may use the same folder.
	for f in /etc/tmpfiles.d/derm-accounts-*.conf; do
		[ -e "$f" ] && run rm -f "$f"
	done
	if [ -d /run/systemd/system ]; then run systemctl daemon-reload; fi
fi

# Step P (lane PC's request R4): the account's own audit rules. Found by
# the account the file's header names ("## The agent account derm-<slug>
# (uid N)", derm-audit-feed rules --account), not by the uid the user has
# now: a user already gone, or a uid given again, would leave the file to
# audit a later user under derm's rules (security review PI-S7).
audit_files=()
for f in /etc/audit/rules.d/50-derm-*.rules; do
	[ -f "$f" ] && [ ! -L "$f" ] || continue
	grep -qF -- "## The agent account $ACCOUNT (uid " "$f" && audit_files+=("$f")
done
if [ "${#audit_files[@]}" -gt 0 ]; then
	say "4b. ${audit_files[*]}"
	run rm -f "${audit_files[@]}"
	if [ -x /usr/sbin/augenrules ]; then run /usr/sbin/augenrules --load || true; fi
fi

say "5. the user $ACCOUNT$([ "$KEEP" = 0 ] && echo ", with its home, signin/ and projects/")"
if [ "$OURS" = 1 ]; then
	if [ "$KEEP" = 1 ]; then run userdel "$ACCOUNT"; else run userdel --remove "$ACCOUNT"; fi
else
	echo "   no user $ACCOUNT"
fi

say "6. the group $GROUP"
if [ "$LEFT" -gt 0 ]; then
	echo "   kept: $LEFT account(s) use it"
elif getent group "$GROUP" >/dev/null; then
	gid="$(getent group "$GROUP" | cut -d: -f3)"
	users="$(getent passwd | awk -F: -v g="$gid" '$4 == g { print $1 }' | grep -vx -- "$ACCOUNT" || true)"
	members="$(getent group "$GROUP" | cut -d: -f4)"
	if [ -n "$users$members" ]; then
		echo "   kept: $users $members still use it"
	else
		run groupdel "$GROUP"
	fi
fi
if [ "$DRY" = 0 ] && [ "$KEEP" = 0 ]; then rmdir "$HOMES" /var/lib/derm 2>/dev/null || true; fi

# Last, so a step above that stops leaves the undo in place to run again.
say "7. with the last account: TIOCSTI as before, the helper, and this undo's copy"
if [ "$LEFT" -gt 0 ]; then
	echo "   kept: $LEFT account(s) left"
elif [ "$DRY" = 1 ]; then
	echo "   dev.tty.legacy_tiocsti back to $(cat /etc/derm/tiocsti.before 2>/dev/null || echo 'what it is (nothing recorded)'); rm $HELPER; rm -r $UNINSTALLER"
else
	before="$("${A[@]}" tiocsti-restore)" || die "TIOCSTI was not put back; set dev.tty.legacy_tiocsti by hand"
	case "$before" in
		kept) echo "   dev.tty.legacy_tiocsti: nothing recorded, left as it is" ;;
		*) echo "   dev.tty.legacy_tiocsti = $before, as before the install; /etc/sysctl.d/90-derm-agents.conf removed" ;;
	esac
	# This script may be the copy being removed: bash reads it from a file
	# it holds open, so the unlink does not cut it short.
	"${A[@]}" remove-uninstaller
	echo "   removed $UNINSTALLER and /etc/derm/uninstall.sha256"
	run rm -f "$HELPER"
	rmdir /usr/local/lib/derm /run/derm /etc/derm 2>/dev/null || true
fi
say "done"
