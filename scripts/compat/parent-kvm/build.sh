#!/usr/bin/env bash
# Build the x86 guest frontend and optional native worker with a prepared guest kernel tree.
set -euo pipefail
umask 022

if (( $# < 2 || $# > 3 )) || [[ ${3:-} != "" && ${3:-} != --native ]]; then
  echo "usage: $0 KERNEL_BUILD_DIR OUTPUT_DIR [--native]" >&2
  exit 2
fi

source_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
kernel_build=$(realpath -e -- "$1")
output=$(realpath -m -- "$2")
if [[ $(uname -m) != x86_64 ]] ||
   ! grep -Fxq 'CONFIG_X86_64=y' "$kernel_build/.config" ||
   ! grep -Fxq 'CONFIG_MODULES=y' "$kernel_build/.config"; then
  echo 'the parent KVM provider needs a prepared x86_64 guest kernel tree with modules enabled' >&2
  exit 2
fi

release=$(<"$kernel_build/include/config/kernel.release")
if [[ ! $release =~ ^[a-zA-Z0-9_.+-]+$ ]]; then
  echo 'invalid prepared guest kernel release' >&2
  exit 2
fi

if [[ -e $output || -L $output ]]; then
  echo "provider output already exists: $output" >&2
  exit 2
fi

parent=$(dirname -- "$output")
mkdir -p -- "$parent"
work=$(mktemp -d)
publish=
trap 'rm -rf -- "$work" "${publish:-}"' EXIT
publish=$(mktemp -d -- "$parent/.parent-kvm-build.XXXXXXXX")
mkdir -- "$work/module" "$publish/bundle"
cp -- "$source_dir"/{Makefile,mailbox.h,flexvm-pvkvm.c} "$work/module/"
env -u KVM -u LOCALVERSION make -j2 -C "$kernel_build" "M=$work/module" modules
install -m 0644 -- "$work/module/flexvm-pvkvm.ko" "$publish/bundle/"
printf '%s\n' "$release" > "$publish/bundle/kernel.release"
if [[ ${3:-} == --native ]]; then
  cc -std=c11 -O2 -Wall -Wextra -Werror -static -pthread "$source_dir/native-worker.c" -o "$publish/bundle/native-worker"
fi

mv -T --no-clobber -- "$publish/bundle" "$output"
if [[ -d $publish/bundle ]]; then
  echo "provider output already exists: $output" >&2
  exit 2
fi
