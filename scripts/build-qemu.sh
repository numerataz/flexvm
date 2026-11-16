#!/usr/bin/env bash
# Fixed software CPU engine for x86 nested paging; Ubuntu 24.04's 8.2 lacks
# upstream b56617bbcb47 (NPT walks in real mode). Apply the TCG SVM restore fix
# without replacing apt files. FLEXVM_BUILD_JOBS bounds local build concurrency.
set -euo pipefail
umask 022
prefix=${1:?usage: build-qemu.sh INSTALL_PREFIX}
scripts_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
jobs=${FLEXVM_BUILD_JOBS:-$(nproc)}
if [[ ! "$jobs" =~ ^[1-9][0-9]*$ ]]; then
  echo 'FLEXVM_BUILD_JOBS must be a positive integer' >&2
  exit 2
fi
mkdir -p "$prefix"
prefix=$(realpath "$prefix")
build=$(mktemp -d)
trap 'python3 -c "import shutil,sys; shutil.rmtree(sys.argv[1])" "$build"' EXIT
curl --fail --location --retry 3 https://download.qemu.org/qemu-10.2.1.tar.xz -o "$build/qemu.tar.xz"
echo 'a3717477d8e2c84d630bfffbc20f6cd3293eb45aa1e6dac6d0cc27689991c9e1  '"$build/qemu.tar.xz" | sha256sum --check --strict
tar -xJf "$build/qemu.tar.xz" -C "$build"
cd "$build/qemu-10.2.1"
patch --batch -p1 < "$scripts_dir/patches/qemu-tcg-svm-restore.patch"
./configure --prefix="$prefix" --target-list=x86_64-softmmu --with-pkgversion=flexvm-tcg-nested-1 \
  --disable-docs --disable-tools --disable-guest-agent --disable-werror \
  --disable-download --disable-gtk --disable-sdl --disable-vnc \
  --disable-opengl --disable-curses --enable-slirp --enable-seccomp
make -j"$jobs"
make install
"$prefix/bin/qemu-system-x86_64" --version
