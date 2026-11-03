#!/usr/bin/env bash
# The artifacts release's build recipe: .github/workflows/release.yml runs this on a fresh runner of each
# architecture to build that architecture's assets into OUT (named as scripts/versions.sh asset names them, with
# SHA256SUMS-ARCH), using STATE as a scratch state directory. release.yml, this file and the scripts it runs are
# hashed into the release's inputs.txt (scripts/pin-artifacts.sh --inputs), so a change to how a release is built
# needs a new ARTIFACTS_TAG, as a change to what it is built from does.
# usage: release-assets.sh STATE OUT
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
state=$(realpath -m "$1")
out=$(realpath -m "$2")
# Built natively, never cross: the runner's architecture, whatever the environment says.
ARCH=$(uname -m)
export ARCH
# shellcheck source=versions.sh
source "$root/scripts/versions.sh"
# Made first, as this user: the builds make STATE with sudo, and with it any missing parent OUT shares.
mkdir -p "$out"

# Firecracker builds with the toolchain its own rust-toolchain.toml (at FC_COMMIT) pins; rustup installs it.
sudo apt-get update -q
sudo apt-get install -y -q --no-install-recommends musl-tools libseccomp-dev
"$root/scripts/build-firecracker.sh" --state "$state"
# The kernel is re-hosted, not built: the pinned upstream one.
"$root/scripts/fetch.sh" --state "$state" --kernel

firecracker=$(asset firecracker) vmlinux=$(asset vmlinux) inputs=$(asset inputs.txt) sums=SHA256SUMS-$ARCH
install -m 755 "$state/artifacts/firecracker" "$out/$firecracker"
install -m 644 "$state/artifacts/vmlinux" "$out/$vmlinux"
"$root/scripts/pin-artifacts.sh" --inputs > "$out/$inputs"
(cd "$out" && sha256sum "$firecracker" "$vmlinux" "$inputs" > "$sums")
"$out/$firecracker" --version
cat "$out/$inputs" "$out/$sums"
