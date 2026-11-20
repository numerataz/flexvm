#!/usr/bin/env bash
# Build the pinned software CPU engine without replacing system QEMU.
# FLEXVM_BUILD_JOBS bounds build concurrency.
set -euo pipefail
umask 022
prefix=${1:?usage: build-qemu.sh INSTALL_PREFIX [x86_64|aarch64]}
arch=${2:-x86_64}
case "$arch" in
  x86_64) pkgversion=flexvm-tcg-nested-41 ;;
  aarch64) pkgversion=flexvm-tcg-arm-11 ;;
  *) echo "unsupported QEMU target: $arch" >&2; exit 2 ;;
esac
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
patch --batch -p1 < "$scripts_dir/patches/qemu-tcg-svm-feature-control.patch"
patch --batch -p1 < "$scripts_dir/patches/qemu-tcg-port-output-stop.patch"
patch --batch -p1 < "$scripts_dir/patches/qemu-tcg-shared-ram.patch"
patch --batch -p1 < "$scripts_dir/patches/qemu-tcg-run-control.patch"
patch --batch -p1 < "$scripts_dir/patches/qemu-tcg-run-cancel.patch"
patch --batch -p1 < "$scripts_dir/patches/qemu-tcg-scattered-slot.patch"
patch --batch -p1 < "$scripts_dir/patches/qemu-tcg-special-registers.patch"
patch --batch -p1 < "$scripts_dir/patches/qemu-tcg-protected-entry.patch"
patch --batch -p1 < "$scripts_dir/patches/qemu-tcg-per-vcpu-run.patch"
patch --batch -p1 < "$scripts_dir/patches/qemu-tcg-long-mode-entry.patch"
patch --batch -p1 < "$scripts_dir/patches/qemu-tcg-fpu-state.patch"
patch --batch -p1 < "$scripts_dir/patches/qemu-tcg-boot-msrs.patch"
patch --batch -p1 < "$scripts_dir/patches/qemu-tcg-cpuid-profile.patch"
patch --batch -p1 < "$scripts_dir/patches/qemu-tcg-mmio-exit.patch"
patch --batch -p1 < "$scripts_dir/patches/qemu-tcg-mmio-read.patch"
patch --batch -p1 < "$scripts_dir/patches/qemu-tcg-irq-line.patch"
patch --batch -p1 < "$scripts_dir/patches/qemu-tcg-irqfd-pulse.patch"
patch --batch -p1 < "$scripts_dir/patches/qemu-tcg-zero-slot.patch"
patch --batch -p1 < "$scripts_dir/patches/qemu-tcg-lapic-state.patch"
patch --batch -p1 < "$scripts_dir/patches/qemu-tcg-pio-exit.patch"
patch --batch -p1 < "$scripts_dir/patches/qemu-tcg-io-completion.patch"
patch --batch -p1 < "$scripts_dir/patches/qemu-tcg-pio-boundaries.patch"
patch --batch -p1 < "$scripts_dir/patches/qemu-tcg-pvh-sregs.patch"
patch --batch -p1 < "$scripts_dir/patches/qemu-tcg-irqchip-state.patch"
patch --batch -p1 < "$scripts_dir/patches/qemu-tcg-pit-state.patch"
patch --batch -p1 < "$scripts_dir/patches/qemu-tcg-debugregs.patch"
patch --batch -p1 < "$scripts_dir/patches/qemu-tcg-mp-state.patch"
patch --batch -p1 < "$scripts_dir/patches/qemu-tcg-xcrs.patch"
patch --batch -p1 < "$scripts_dir/patches/qemu-tcg-xsave.patch"
patch --batch -p1 < "$scripts_dir/patches/qemu-tcg-vcpu-events.patch"
patch --batch -p1 < "$scripts_dir/patches/qemu-tcg-parent-clock.patch"
patch --batch -p1 < "$scripts_dir/patches/qemu-tcg-parent-tsc-deadline.patch"
patch --batch -p1 < "$scripts_dir/patches/qemu-tcg-parallel-run.patch"
patch --batch -p1 < "$scripts_dir/patches/qemu-tcg-arm-shared-ram.patch"
patch --batch -p1 < "$scripts_dir/patches/qemu-tcg-arm-mmio-run.patch"
patch --batch -p1 < "$scripts_dir/patches/qemu-tcg-arm-vgic.patch"
patch --batch -p1 < "$scripts_dir/patches/qemu-tcg-arm-boot-registers.patch"
patch --batch -p1 < "$scripts_dir/patches/qemu-tcg-mmio-parallel-guard.patch"
patch --batch -p1 < "$scripts_dir/patches/qemu-tcg-arm-mp-state.patch"
patch --batch -p1 < "$scripts_dir/patches/qemu-tcg-worker-external-ram-checkpoint.patch"
patch --batch -p1 < "$scripts_dir/patches/qemu-tcg-worker-checkpoint-run-fence.patch"
patch --batch -p1 < "$scripts_dir/patches/qemu-tcg-arm-incoming-gic.patch"
patch --batch -p1 < "$scripts_dir/patches/qemu-tcg-resume-captured-worker.patch"
patch --batch -p1 < "$scripts_dir/patches/qemu-tcg-x86-checkpoint-clock.patch"
cp "$scripts_dir/compat/parent-kvm/slot-map.h" include/hw/misc/flexvm-slot-map.h
./configure --prefix="$prefix" --target-list="$arch-softmmu" --with-pkgversion="$pkgversion" \
  --disable-docs --disable-tools --disable-guest-agent --disable-werror \
  --disable-download --disable-gtk --disable-sdl --disable-vnc \
  --disable-opengl --disable-curses --enable-slirp --enable-seccomp
make -j"$jobs"
make install
"$prefix/bin/qemu-system-$arch" --version
