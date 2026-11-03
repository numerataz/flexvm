#!/usr/bin/env bash
# Shared versions; callers may override them in the environment.
FC_VERSION=${FC_VERSION:-v1.17.0}
# The commit FC_VERSION's tag names (`git ls-remote` its refs/tags/FC_VERSION^{}): build-firecracker.sh refuses a
# checkout of any other, so a moved tag never changes what is built. Overriding FC_VERSION needs this too.
FC_COMMIT=${FC_COMMIT:-95f868c8e345b1cc8faccd1a3c910b4989dc3f58}
# The guest kernel, from Firecracker's CI bucket.
CI_VERSION=${CI_VERSION:-v1.15}
KERNEL=${KERNEL:-vmlinux-6.1.155}
# The architecture artifacts are fetched or built for: this host's, unless overridden. A release carries each of
# ARCHES.
ARCHES=(x86_64 aarch64)
ARCH=${ARCH:-$(uname -m)}
case $ARCH in
  x86_64 | aarch64) ;;
  *)
    echo "ARCH must be one of ${ARCHES[*]}, not $ARCH" >&2
    return 1
    ;;
esac
# Firecracker's CI bucket for an architecture (default ARCH).
ci_url() { echo "https://s3.amazonaws.com/spec.ccfc.min/firecracker-ci/$CI_VERSION/${1:-$ARCH}"; }
CI=$(ci_url)
# The numerataz/flexvm release holding the prebuilt patched Firecracker and that guest kernel, which flexvm
# downloads on first use (build.rs reads this line). .github/workflows/release.yml builds it when its tag is
# pushed; flexvm and fetch.sh download from it only once scripts/checksums.sha256 pins its assets
# (scripts/pin-artifacts.sh writes those lines). A change to what a release is built from (scripts/pin-artifacts.sh
# --inputs: Firecracker's version, commit and patches, the build recipe, the kernel) bumps this in the same change;
# see RELEASING in README.md. Tags use vMAJOR.MINOR.PATCH (artifacts-5 was the last artifacts-N; v0.1.0 was the first source release).
# A release's assets never change.
ARTIFACTS_TAG=${ARTIFACTS_TAG:-v0.3.0}
ARTIFACTS_URL=https://github.com/numerataz/flexvm/releases/download/$ARTIFACTS_TAG

# A release asset's name for an architecture (default ARCH): firecracker, vmlinux or inputs.txt. x86_64's
# keep the names of the releases before any other architecture had assets (v0.2.2 and older are x86_64 only, and
# their pins stay valid); the others' end in -ARCH (firecracker-aarch64, inputs-aarch64.txt). flexvm/build.rs names
# them the same way.
asset() {
  local arch=${2:-$ARCH}
  if [ "$arch" = x86_64 ]; then
    echo "$1"
  elif [[ $1 == *.txt ]]; then
    echo "${1%.txt}-$arch.txt"
  else
    echo "$1-$arch"
  fi
}

# The pinned SHA256 of a URL; 2 means absent, 1 means malformed or unreadable. Callers set root (the checkout).
# shellcheck disable=SC2154
pinned() {
  local lines checksum
  lines=$(awk -v url="$1" '$0 !~ /^[[:space:]]*#/ {for (i = 1; i <= NF; i++) if ($i == url) {print; break}}' "$root/scripts/checksums.sha256") || return 1
  if [ -z "$lines" ]; then return 2; fi
  checksum=$(awk 'NF == 2 {print $1}' <<< "$lines")
  if [[ $lines == *$'\n'* || ! $checksum =~ ^[[:xdigit:]]{64}$ ]]; then
    echo "Malformed SHA256 for $1 in scripts/checksums.sha256" >&2
    return 1
  fi
  echo "$checksum"
}
