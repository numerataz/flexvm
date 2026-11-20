#!/usr/bin/env bash
# Build the guest frontend and optional native worker with a prepared guest kernel tree.
set -euo pipefail
umask 022

if (( $# < 2 || $# > 3 )) || [[ ${3:-} != "" && ${3:-} != --native ]]; then
  echo "usage: $0 KERNEL_BUILD_DIR OUTPUT_DIR [--native]" >&2
  exit 2
fi

source_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
kernel_build=$(realpath -e -- "$1")
output=$(realpath -m -- "$2")
if ! grep -Fxq 'CONFIG_MODULES=y' "$kernel_build/.config"; then
  echo 'the parent KVM provider needs a prepared guest kernel tree with modules enabled' >&2
  exit 2
fi
if grep -Fxq 'CONFIG_X86_64=y' "$kernel_build/.config"; then
  kernel_arch=x86
  target=x86_64
  worker=native-worker.c
elif grep -Fxq 'CONFIG_ARM64=y' "$kernel_build/.config"; then
  kernel_arch=arm64
  target=aarch64
  worker=arm-native-worker.c
else
  echo 'the parent KVM provider supports x86_64 and aarch64 kernel trees' >&2
  exit 2
fi
cross=${CROSS_COMPILE:-}
if [[ $(uname -m) != "$target" && -z $cross ]]; then
  echo "set CROSS_COMPILE for the $target guest kernel" >&2
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
cp -- "$source_dir"/{Makefile,mailbox.h,flexvm-pvkvm.c,arm-frontend.h,arm-vgic.h} "$work/module/"
env -u KVM -u LOCALVERSION make -j2 -C "$kernel_build" "ARCH=$kernel_arch" "CROSS_COMPILE=$cross" "M=$work/module" modules
install -m 0644 -- "$work/module/flexvm-pvkvm.ko" "$publish/bundle/"
printf '%s\n' "$release" > "$publish/bundle/kernel.release"
printf '1\n' > "$publish/bundle/checkpoint.version"
python3 - "$publish/bundle" <<'PYMODULE'
from pathlib import Path
import struct
import sys

bundle = Path(sys.argv[1])
module = (bundle / "flexvm-pvkvm.ko").read_bytes()
if not 0 < len(module) <= 4 << 20:
    raise SystemExit("parent KVM module exceeds its block attachment limit")
image = struct.pack("<8sI", b"FLEXKVM1", len(module)) + module
(bundle / "flexvm-pvkvm.img").write_bytes(image + bytes(-len(image) % 512))
PYMODULE
if [[ ${3:-} == --native ]]; then
  compiler=cc
  if [[ -n $cross ]]; then compiler=${cross}gcc; fi
  "$compiler" -std=c11 -O2 -Wall -Wextra -Werror -static -pthread "$source_dir/$worker" -o "$publish/bundle/native-worker"
fi

mv -T --no-clobber -- "$publish/bundle" "$output"
if [[ -d $publish/bundle ]]; then
  echo "provider output already exists: $output" >&2
  exit 2
fi
