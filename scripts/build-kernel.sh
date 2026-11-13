#!/usr/bin/env bash
# Build the reviewed guest kernel for this machine, with required facilities built in.
# Usage: build-kernel.sh [--state DIR] [--key]
# Requires cc, make, flex, bison, bc, libelf-dev, libssl-dev, pahole and xz-utils.
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
state=$(realpath -m "${FLEXVM_STATE_DIR:-/var/lib/flexvm}")
mode=
while (( $# )); do
  case "$1" in
    --state)
      if (( $# < 2 )) || [[ $2 == --* ]]; then echo '--state needs a directory' >&2; exit 2; fi
      state=$(realpath -m "$2"); shift 2 ;;
    --key) mode=key; shift ;;
    *) echo 'usage: build-kernel.sh [--state DIR] [--key]' >&2; exit 2 ;;
  esac
done
# shellcheck source=versions.sh
source "$root/scripts/versions.sh"
# shellcheck source=../kernel/source.env
source "$root/kernel/source.env"
LINUX_SOURCE_SHA256=$(pinned "$LINUX_SOURCE_URL")
inputs=(scripts/build-kernel.sh kernel/source.env "kernel/config/$ARCH.config" kernel/features.config "kernel/features-$ARCH.config")
key=$({ (cd "$root" && sha256sum "${inputs[@]}"); printf '%s\n' "$LINUX_SOURCE_SHA256"; } | sha256sum | cut -d' ' -f1)
identity="build:linux-$LINUX_VERSION-$ARCH-$key"
if [ "$mode" = key ]; then echo "$identity"; exit 0; fi
if [ "$ARCH" != "$(uname -m)" ]; then echo "kernel builds must be native, not $ARCH on $(uname -m)" >&2; exit 1; fi
out=$state/artifacts
sudo mkdir -p "$out"
sudo touch "$out/.kernel.lock"
sudo chmod 644 "$out/.kernel.lock"
exec {lock}< "$out/.kernel.lock"
flock -x "$lock"
# A cached output is kept only when both its recipe and full content hash still match.
record=$(sudo cat "$out/vmlinux.sha256" 2>/dev/null || true)
checksum=${record%% *}
if [[ $checksum =~ ^[[:xdigit:]]{64}$ ]] && [[ $record == *" $identity" ]] &&
   printf '%s  %s\n' "$checksum" "$out/vmlinux" | sudo sha256sum --check --status; then
  echo "guest kernel $identity already built and verified"; exit 0
fi
build=${KERNEL_BUILD_DIR:-$root/build/kernel-$ARCH-${key:0:16}}
mkdir -p "$build"
# Same recipe can be requested concurrently by different state directories.
exec {build_lock}> "$build/.lock"
flock -x "$build_lock"
archive=$build/linux-$LINUX_VERSION.tar.xz
if ! printf '%s  %s\n' "$LINUX_SOURCE_SHA256" "$archive" | sha256sum --check --status 2>/dev/null; then
  download=$(mktemp "$build/.linux.XXXXXX")
  trap 'rm -f -- "$download"' EXIT
  curl -fL --retry 2 -o "$download" "$LINUX_SOURCE_URL"
  printf '%s  %s\n' "$LINUX_SOURCE_SHA256" "$download" | sha256sum --check --status
  mv "$download" "$archive"
  trap - EXIT
fi
src=$build/linux-$LINUX_VERSION
if [ ! -f "$src/Makefile" ]; then tar -xJf "$archive" -C "$build"; fi
cp "$root/kernel/config/$ARCH.config" "$src/.config"
# Apply explicit values with the kernel's own config editor, then verify olddefconfig
# retained every requested feature; an unavailable symbol is a build failure.
for fragment in "$root/kernel/features.config" "$root/kernel/features-$ARCH.config"; do
  while IFS= read -r line; do
    [[ $line == CONFIG_*=* ]] || continue
    name=${line%%=*}; value=${line#*=}; name=${name#CONFIG_}
    case "$value" in
      y) "$src/scripts/config" --file "$src/.config" --enable "$name" ;;
      n) "$src/scripts/config" --file "$src/.config" --disable "$name" ;;
      \"*\") "$src/scripts/config" --file "$src/.config" --set-str "$name" "${value:1:${#value}-2}" ;;
      *) echo "unsupported config value: $line" >&2; exit 1 ;;
    esac
  done < "$fragment"
done
export KBUILD_BUILD_USER=flexvm KBUILD_BUILD_HOST=builder KBUILD_BUILD_VERSION=1
export SOURCE_DATE_EPOCH
export KBUILD_BUILD_TIMESTAMP
KBUILD_BUILD_TIMESTAMP=$(date -u -d "@$SOURCE_DATE_EPOCH" '+%a %b %d %T UTC %Y')
# CI uses KVM=true/false to select tests; Linux uses KVM as a source directory.
# Linux also calls the aarch64 architecture arm64. Do not leak runner variables
# into kbuild's architecture/source-path decisions.
unset KVM
kernel_arch=x86
if [ "$ARCH" = aarch64 ]; then kernel_arch=arm64; fi
make -C "$src" ARCH="$kernel_arch" olddefconfig
for fragment in "$root/kernel/features.config" "$root/kernel/features-$ARCH.config"; do
  while IFS= read -r line; do
    [[ $line == CONFIG_*=* ]] || continue
    expected=$line
    if [[ $line == *=n ]]; then expected="# ${line%=n} is not set"; fi
    if ! grep -F -x -- "$expected" "$src/.config" >/dev/null; then
      echo "kernel configuration did not retain required setting: $line" >&2; exit 1
    fi
  done < "$fragment"
done
image=$build/vmlinux
if [ "$ARCH" = x86_64 ]; then
  make -C "$src" ARCH="$kernel_arch" -j"${JOBS:-$(nproc)}" vmlinux
  # DWARF generates kernel BTF; keep BTF but strip DWARF from the shipped ELF.
  objcopy --strip-debug "$src/vmlinux" "$image"
  machine=$(od -An -tx1 -j18 -N2 "$image" | tr -d ' \n')
  if [ "$machine" != 3e00 ]; then echo "kernel ELF architecture mismatch: $machine" >&2; exit 1; fi
else
  # Firecracker's arm64 loader accepts the Linux Image boot format, not vmlinux ELF.
  # The release asset keeps the historical name vmlinux-aarch64.
  make -C "$src" ARCH="$kernel_arch" -j"${JOBS:-$(nproc)}" Image
  cp "$src/arch/arm64/boot/Image" "$image"
  magic=$(od -An -tx1 -j56 -N4 "$image" | tr -d ' \n')
  if [ "$magic" != 41524d64 ]; then echo "invalid arm64 kernel Image magic: $magic" >&2; exit 1; fi
fi
placing=recording=
trap 'sudo rm -f -- "$placing" "$recording"' EXIT
placing=$(sudo mktemp -p "$out" .vmlinux.XXXXXX)
recording=$(sudo mktemp -p "$out" .vmlinux.sha256.XXXXXX)
sudo install -m 644 "$image" "$placing"
printf '%s  built by scripts/build-kernel.sh %s\n' "$(sudo sha256sum "$placing" | cut -d' ' -f1)" "$identity" | sudo tee "$recording" >/dev/null
sudo chmod 644 "$recording"
sudo mv -T "$placing" "$out/vmlinux"
sudo mv -T "$recording" "$out/vmlinux.sha256"
placing=recording=
trap - EXIT
file "$out/vmlinux"
