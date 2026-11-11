#!/bin/sh
# derm's gate launcher for a plugin's hooks file (wave 5b lane 5bF).
#
#   /bin/sh <plugin>/hooks/derm-gate.sh <agent> <event>
#
# A plugin's own hooks file cannot know where derm is when it is installed,
# so it runs this file with /bin/sh by its absolute path, and this file runs
# `derm hook <agent> <event>` from derm's own install folders
# (contracts/hook-dialects.md 9.1; rules case 227). Until wave 5b the hooks
# file ran `node` found on PATH, and a project's settings `env.PATH` chose
# which node ran derm's gate (note BC, BC-3, run). Nothing here looks a
# program up on PATH, and nothing here reads a variable a project can set,
# except HOME, which no project setting reaches in Claude Code (note BC
# section 3, run) and which is used only when it is absolute.
#
# The folders are the ones derm's installs use, in the order the in-process
# plugins try them (packages/*/src/serve/client.ts, installCandidates; a
# Rust test holds the two lists equal, case 112). A derm is run only when its
# real path is a regular, executable file owned by you or root that no one
# else may write, in a folder of the same kind, the folder it is named in
# too, none of it inside the session's folder, as case 109's rule says.
# Anything else blocks the call in the agent's own form and says why.
#
# The same file sits in derm's Claude Code plugin, Codex plugin and Gemini
# extension (a test holds the three equal). POSIX sh only: dash, bash and
# macOS's sh run it. Windows does not (lane 5bF's Windows half).

agent=${1-}
event=${2-}

# The agent's own block when derm cannot run: Claude Code and Codex read
# exit 2 with the reason on stderr; Gemini reads its JSON on stdout as well.
block() {
  reason="derm: $*"
  if [ "$agent" = gemini ]; then
    printf '{"decision":"deny","reason":"%s"}\n' "$(printf '%s' "$reason" | /usr/bin/tr -d '"\\')"
  fi
  printf '%s\n' "$reason" >&2
  exit 2
}

case "$agent:$event" in
  claude-code:pre | claude-code:post | codex:pre | codex:post | gemini:before | gemini:after) ;;
  *) agent=; block "derm-gate.sh takes claude-code pre|post, codex pre|post or gemini before|after" ;;
esac

[ -x /usr/bin/id ] || block "no /usr/bin/id to read your user id"
me=$(/usr/bin/id -u) || block "cannot read your user id"

# The mode string and owner of a path, links not followed: "<mode> <uid>".
mode_owner() {
  out=$(/bin/ls -ldn -- "$1" 2>/dev/null) || return 1
  # shellcheck disable=SC2086
  set -- $out
  printf '%s %s' "$1" "$3"
}

# Owned by you or root, no group or other write bit, no access list that
# could grant one ("+"; macOS's "@" marks extended attributes only).
closed() {
  mo=$(mode_owner "$1") || return 1
  mode=${mo%% *}
  uid=${mo#* }
  case "$uid" in "$me" | 0) ;; *) return 1 ;; esac
  case "$mode" in
    ?????w* | ????????w*) return 1 ;;
    *+) return 1 ;;
  esac
  return 0
}

# The real folder of a path's parent, links followed.
real_dir() {
  (cd -P -- "${1%/*}" 2>/dev/null && pwd -P)
}

here=$(pwd -P 2>/dev/null) || here=

# Why a candidate may not run, or nothing when it may.
refuse() {
  c=$1
  [ -e "$c" ] || [ -L "$c" ] || { echo "not there"; return; }
  dir=$(real_dir "$c") || { echo "its folder cannot be read"; return; }
  closed "$dir" || { echo "others may write $dir"; return; }
  f=$dir/${c##*/}
  hops=0
  while [ -L "$f" ]; do
    hops=$((hops + 1))
    [ "$hops" -le 8 ] || { echo "too many links"; return; }
    line=$(/bin/ls -ld -- "$f" 2>/dev/null) || { echo "cannot be read"; return; }
    to=${line#*" -> "}
    case "$to" in
      /*) ;;
      *) to=${f%/*}/$to ;;
    esac
    dir=$(real_dir "$to") || { echo "a link leads nowhere"; return; }
    closed "$dir" || { echo "others may write $dir"; return; }
    f=$dir/${to##*/}
  done
  [ -f "$f" ] || { echo "not a regular file"; return; }
  [ -x "$f" ] || { echo "not executable"; return; }
  closed "$f" || { echo "owned by someone else, or others may write it"; return; }
  if [ -n "$here" ] && [ "$here" != / ]; then
    case "$f" in "$here"/*) echo "inside the session's folder, which a project can write"; return ;; esac
  fi
  echo "ok $f"
}

sys=
for u in /usr/bin/uname /bin/uname; do
  [ -x "$u" ] && sys=$("$u" -s 2>/dev/null) && break
done
case "$sys" in
  Darwin) brew="/opt/homebrew/bin/derm /usr/local/bin/derm" ;;
  *) brew="/home/linuxbrew/.linuxbrew/bin/derm /usr/local/bin/derm" ;;
esac
local_bin=
case "${HOME-}" in /?*) local_bin=${HOME%/}/.local/bin/derm ;; esac

tried=
for c in $local_bin $brew /usr/bin/derm; do
  res=$(refuse "$c")
  case "$res" in
    "ok "/*) exec "${res#ok }" hook "$agent" "$event" ;;
    "not there") ;;
    *) tried="$tried; $c: $res" ;;
  esac
done
block "no derm this hook can trust${tried:+ (${tried#; })}: install derm in ~/.local/bin, Homebrew or /usr/bin (derm is never looked up on PATH, rules case 227)"
