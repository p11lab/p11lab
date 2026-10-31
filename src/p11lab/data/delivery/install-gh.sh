#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Install the pinned gh CLI for Linux amd64 with hash verification.
# No Docker required. Pins must match p11lab.publish.GH_PIN (parity-tested).
# The gate enforces GH_EXECUTABLE_SHA256 before execution; installer
# compromise still fails closed. Windows packaging is a B-G2c follow-up.
# Usage: install-gh.sh --output-dir DIR
set -eu

GH_VERSION=2.103.2
GH_URL=https://github.com/cli/cli/releases/download/v2.103.2/gh_2.103.2_linux_amd64.tar.gz
GH_SHA256=62ccf747115ddc61237efffdde66a3c8f70ba249433dc64f70801089b59c59c8
GH_SIZE=15031001
GH_EXECUTABLE_SHA256=cbfdc94f3a5c0713c0d6df3e0a1d88a59a76b0c52332aad7d21d112f9da2cc0e
GH_MEMBER=gh_2.103.2_linux_amd64/bin/gh

output_dir=""
while [ "$#" -gt 0 ]; do
  case "$1" in
    --output-dir) output_dir="$2"; shift 2 ;;
    --output-dir=*) output_dir="${1#--output-dir=}"; shift ;;
    *) echo "install-gh.sh: unexpected argument: $1" >&2; exit 2 ;;
  esac
done
if [ -z "$output_dir" ]; then
  echo "install-gh.sh: --output-dir is required" >&2; exit 2
fi
if [ "$(uname -s)" != "Linux" ] || [ "$(uname -m)" != "x86_64" ]; then
  echo "install-gh.sh: this installer covers Linux amd64 only" >&2; exit 2
fi
for tool in curl tar sha256sum; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "install-gh.sh: required tool missing: $tool" >&2; exit 2
  fi
done

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT INT TERM
archive="$work/gh.tar.gz"
curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' --retry 3 --max-time 120 --max-filesize "$GH_SIZE" --output "$archive" "$GH_URL"
size="$(wc -c < "$archive")"
if [ "$size" != "$GH_SIZE" ]; then
  echo "install-gh.sh: size mismatch: got $size want $GH_SIZE" >&2; exit 1
fi
digest="$(sha256sum "$archive")"
digest="${digest%% *}"
if [ "$digest" != "$GH_SHA256" ]; then
  echo "install-gh.sh: checksum mismatch: got $digest" >&2; exit 1
fi
if ! tar -tzf "$archive" | grep -qx "$GH_MEMBER"; then
  echo "install-gh.sh: archive lacks $GH_MEMBER" >&2; exit 1
fi
tar -xzf "$archive" -C "$work" "$GH_MEMBER"
chmod 755 "$work/$GH_MEMBER"
exe_digest="$(sha256sum "$work/$GH_MEMBER")"
exe_digest="${exe_digest%% *}"
if [ "$exe_digest" != "$GH_EXECUTABLE_SHA256" ]; then
  echo "install-gh.sh: executable checksum mismatch: got $exe_digest" >&2; exit 1
fi
report="$("$work/$GH_MEMBER" --version)"
case "$report" in
  *"gh version $GH_VERSION"*) ;;
  *) echo "install-gh.sh: version self-report mismatch" >&2; exit 1 ;;
esac
mkdir -p "$output_dir"
cp "$work/$GH_MEMBER" "$output_dir/gh"
chmod 755 "$output_dir/gh"
echo "$output_dir/gh"
