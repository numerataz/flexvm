#!/usr/bin/env bash
# Fixed software CPU engine for x86 nested paging; Ubuntu 24.04's 8.2 lacks
# upstream b56617bbcb47 (NPT walks in real mode). Install without replacing apt files.
set -euo pipefail
umask 022
prefix=${1:?usage: build-qemu.sh INSTALL_PREFIX}
mkdir -p "$prefix"
prefix=$(realpath "$prefix")
build=$(mktemp -d)
trap 'python3 -c "import shutil,sys; shutil.rmtree(sys.argv[1])" "$build"' EXIT
curl --fail --location --retry 3 https://download.qemu.org/qemu-10.2.1.tar.xz -o "$build/qemu.tar.xz"
echo 'a3717477d8e2c84d630bfffbc20f6cd3293eb45aa1e6dac6d0cc27689991c9e1  '"$build/qemu.tar.xz" | sha256sum --check --strict
tar -xJf "$build/qemu.tar.xz" -C "$build"
cd "$build/qemu-10.2.1"
./configure --prefix="$prefix" --target-list=x86_64-softmmu \
  --disable-docs --disable-tools --disable-guest-agent --disable-werror \
  --disable-download --disable-gtk --disable-sdl --disable-vnc \
  --disable-opengl --disable-curses --enable-slirp --enable-seccomp
make -j"$(nproc)"
make install
"$prefix/bin/qemu-system-x86_64" --version
