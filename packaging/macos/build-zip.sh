#!/bin/bash
# Builds, signs and notarizes the macOS release zip. Runs on a Mac with Xcode's
# command line tools, both Apple Rust targets, one "Developer ID Application"
# identity in the login keychain, and a notarytool keychain profile.
#
#   packaging/macos/build-zip.sh <version> [keychain-profile]   (default tk-notary)
#
# Writes target/dist-macos/derm-<version>-macos.zip, its sha256 line in
# SHA256SUMS.macos beside it, and the notary log in notary-log.json.
# The identity is read from the keychain and passed to codesign; this script
# never prints it. No stapling: a ticket cannot be stapled to a bare binary.
set -euo pipefail

version=${1:?usage: build-zip.sh <version> [keychain-profile]}
profile=${2:-tk-notary}
[[ $version =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?$ ]] || { echo "bad version: $version" >&2; exit 2; }
[[ $(uname -s) == Darwin ]] || { echo "macOS only" >&2; exit 2; }

root=$(cd "$(dirname "$0")/../.." && pwd)
cd "$root"
out=target/dist-macos
stage=$out/stage
zip=$out/derm-$version-macos.zip
rm -rf "$out"
mkdir -p "$stage"

for t in aarch64-apple-darwin x86_64-apple-darwin; do
  cargo build --release --locked --target "$t" -p derm-cli -p derm-daemon
done

# Signing identifiers: derm-daemon is the peer the collector and the helper
# accept (macos/activity-collector/src/caller.rs PEER_ID); the CLI gets its own.
ids=(derm:io.github.aetiusgular.derm.cli derm-daemon:io.github.aetiusgular.derm)

n=$(security find-identity -v -p codesigning | grep -c '"Developer ID Application: ' || true)
[[ $n == 1 ]] || { echo "want exactly one Developer ID Application identity, found $n" >&2; exit 1; }
identity=$(security find-identity -v -p codesigning | awk '/"Developer ID Application: / { print $2; exit }')

for pair in "${ids[@]}"; do
  bin=${pair%%:*}
  id=${pair#*:}
  lipo -create -output "$stage/$bin" \
    "target/aarch64-apple-darwin/release/$bin" "target/x86_64-apple-darwin/release/$bin"
  lipo "$stage/$bin" -verify_arch arm64 x86_64
  codesign --force --options runtime --timestamp --identifier "$id" --sign "$identity" "$stage/$bin"
  codesign --verify --strict --verbose=2 "$stage/$bin"
done
unset identity

install -m 0644 crates/derm-daemon/units/io.github.aetiusgular.derm.daemon.plist LICENSE NOTICE README.md "$stage/"
chmod 0755 "$stage/derm" "$stage/derm-daemon"

# ditto keeps the signatures intact (Apple's notarization docs use it).
(cd "$stage" && ditto -c -k --norsrc --noextattr . "../$(basename "$zip")")

xcrun notarytool submit "$zip" --keychain-profile "$profile" --wait --output-format json > "$out/notary-submit.json"
sub=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["id"])' "$out/notary-submit.json")
status=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["status"])' "$out/notary-submit.json")
xcrun notarytool log "$sub" --keychain-profile "$profile" "$out/notary-log.json"
echo "notarization $sub: $status"
[[ $status == Accepted ]] || exit 1

(cd "$out" && shasum -a 256 "$(basename "$zip")" > SHA256SUMS.macos)
cat "$out/SHA256SUMS.macos"
