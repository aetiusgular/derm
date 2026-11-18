#!/bin/sh
# derm's gate for Codex inside the sbx VM, the agent's half: the second
# install command of derm's v3 kit, run as the agent's user after
# install.sh. Codex's own commands add the marketplace and the plugin, so
# the plugin lands where this Codex keeps plugins and config.toml gets the
# entries this Codex writes. Then the trust entries: Codex skips a plugin's
# hook it does not trust, and says nothing (the Terminal-Bench agent does
# the same three steps, tests/eval/harbor/derm_codex.py).
set -eu

fail() {
  echo "derm kit: $*" >&2
  exit 1
}

kit=/opt/derm-kit
cfg="${CODEX_HOME:-$HOME/.codex}/config.toml"

[ -f "$kit/trust.toml" ] || fail "$kit/trust.toml is missing; install.sh did not run"
command -v codex >/dev/null 2>&1 || fail "no codex on PATH in this image"

codex plugin marketplace add "$kit/mkt" --json >/dev/null || fail "codex plugin marketplace add failed ($(codex --version 2>&1 | head -n 1))"
codex plugin add derm@derm --json >/dev/null || fail "codex plugin add derm@derm failed ($(codex --version 2>&1 | head -n 1))"

grep -q '^\[plugins\."derm@derm"\]' "$cfg" 2>/dev/null || fail "Codex did not record the plugin in $cfg"
grep -q 'derm@derm:hooks/hooks.json' "$cfg" || cat "$kit/trust.toml" >> "$cfg"

echo "derm kit: derm's gate is registered for codex ($(codex --version 2>&1 | head -n 1))"
