#!/usr/bin/env bash
# Package matching guest modules and development inputs from a completed native
# scripts/build-kernel.sh build. No module is ever loaded on the build host.
# Usage: package-kernel-modules.sh --source DIR --kernel IMAGE --output SDK.tar.gz [--runtime-output MODULES.tar.gz]
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
src= kernel= output= runtime_output=
while (( $# )); do
  case "$1" in
    --source|--kernel|--output|--runtime-output)
      if (( $# < 2 )) || [[ $2 == --* ]]; then echo "$1 needs a path" >&2; exit 2; fi
      case "$1" in
        --source) src=$(realpath -e "$2") ;;
        --kernel) kernel=$(realpath -e "$2") ;;
        --output) output=$(realpath -m "$2") ;;
        --runtime-output) runtime_output=$(realpath -m "$2") ;;
      esac
      shift 2 ;;
    *) echo 'usage: package-kernel-modules.sh --source DIR --kernel IMAGE --output FILE' >&2; exit 2 ;;
  esac
done
if [[ -z $src || -z $kernel || -z $output ]]; then
  echo 'usage: package-kernel-modules.sh --source DIR --kernel IMAGE --output FILE' >&2
  exit 2
fi
if [[ -n $runtime_output && $runtime_output == "$output" ]]; then
  echo 'runtime and development outputs must be different paths' >&2; exit 2
fi
# shellcheck source=versions.sh
source "$root/scripts/versions.sh"
# shellcheck source=../kernel/source.env
source "$root/kernel/source.env"
if [[ $ARCH != "$(uname -m)" ]]; then echo 'module bundles must be built natively' >&2; exit 1; fi
command -v pkg-config >/dev/null || { echo 'module packaging needs pkg-config and static libelf/zlib/zstd development libraries' >&2; exit 1; }
pkg-config --static --libs libelf >/dev/null
archive=$(dirname "$src")/linux-$LINUX_VERSION.tar.xz
# Serialize against the build script and other packaging of this source tree.
exec {build_lock}> "$(dirname "$src")/.lock"
flock -x "$build_lock"
printf '%s  %s\n' "$(pinned "$LINUX_SOURCE_URL")" "$archive" | sha256sum --check --status
grep -Fx 'CONFIG_MODULES=y' "$src/.config" >/dev/null
release=$(cat "$src/include/config/kernel.release")
if [[ ! $release =~ ^[a-zA-Z0-9_.+-]+$ ]]; then echo 'invalid built kernel release' >&2; exit 1; fi
work=$(mktemp -d)
placing=
trap 'rm -rf -- "$work"; rm -f -- "$placing"' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
mkdir -p "$work/source"
tar -xJf "$archive" -C "$work/source"
pristine=$work/source/linux-$LINUX_VERSION
"$root/scripts/apply-kernel-patches.sh" "$pristine"
# Generated inputs alone cannot account for edits to a source header. Reject a
# modified build tree instead of shipping clean source for a different kernel.
check_sources() {
  python3 - "$pristine" "$src" <<'PYSOURCE'
import filecmp
from pathlib import Path
import sys
clean, built = map(Path, sys.argv[1:])
for path in clean.rglob('*'):
    actual = built / path.relative_to(clean)
    if path.is_symlink():
        matches = actual.is_symlink() and path.readlink() == actual.readlink()
    elif path.is_file():
        matches = not actual.is_symlink() and actual.is_file() and filecmp.cmp(path, actual, shallow=False)
    else:
        matches = actual.is_dir() and not actual.is_symlink()
    if not matches:
        raise SystemExit(f'kernel build source differs from the verified archive: {actual}')
PYSOURCE
}
check_sources
# Tie the generated build inputs to the actual image, rather than its filename.
check_kernel() {
  if [[ $ARCH == x86_64 ]]; then
    objcopy --strip-debug "$src/vmlinux" "$work/kernel"
  else
    # Use the same ELF-to-Image recipe as arch/arm64/boot/Makefile, so a
    # stale boot/Image cannot authenticate a different development ELF.
    objcopy -O binary -R .note -R .note.gnu.build-id -R .comment -S "$src/vmlinux" "$work/kernel"
  fi
  cmp "$kernel" "$work/kernel"
  test "$(cat "$src/include/config/kernel.release")" = "$release"
  grep -Fx "#define UTS_RELEASE \"$release\"" "$src/include/generated/utsrelease.h" >/dev/null
}
check_kernel
bash "$pristine/scripts/extract-ikconfig" "$kernel" > "$work/config"
cmp "$src/.config" "$work/config"
# Linux uses KVM and ARCH as build variables; CI uses them for other purposes.
unset KVM LOCALVERSION
kernel_arch=x86
if [[ $ARCH == aarch64 ]]; then kernel_arch=arm64; fi
export KBUILD_BUILD_USER=flexvm KBUILD_BUILD_HOST=builder KBUILD_BUILD_VERSION=1
export SOURCE_DATE_EPOCH KBUILD_BUILD_TIMESTAMP
KBUILD_BUILD_TIMESTAMP=$(date -u -d "@$SOURCE_DATE_EPOCH" '+%a %b %d %T UTC %Y')
make -C "$src" ARCH="$kernel_arch" -j"${JOBS:-2}" modules
check_kernel
stage=$work/root
make -C "$src" ARCH="$kernel_arch" INSTALL_MOD_PATH="$stage" INSTALL_MOD_STRIP=1 DEPMOD=true modules_install
modules=$stage/lib/modules/$release
# modules_install makes absolute links into the builder. Replace them with a
# self-contained source/build tree with portable native build helpers.
rm -f -- "$modules/build" "$modules/source"
check_sources
mv "$pristine" "$modules/build"
build=$modules/build
cp -p "$src/.config" "$src/Module.symvers" "$src/System.map" "$build/"
cp -a "$src/include/generated" "$src/include/config" "$build/include/"
mkdir -p "$build/arch/$kernel_arch/include"
cp -a "$src/arch/$kernel_arch/include/generated" "$build/arch/$kernel_arch/include/"
# Keep the matching ELF's BTF for out-of-tree module BTF, including on ARM,
# where the boot image itself is not ELF. Strip DWARF to keep the bundle small.
objcopy --strip-debug "$src/vmlinux" "$build/vmlinux"
# External-module make treats the kernel tree as read-only and will not build
# missing fixdep/modpost/objtool/BTF helpers. Build those here, statically, so
# an Alpine/musl guest need not provide the builder's glibc loader or version.
make -C "$build" ARCH="$kernel_arch" -j"${JOBS:-2}" HOSTLDFLAGS=-static \
  HOSTPKG_CONFIG='pkg-config --static' modules_prepare tools/bpf/resolve_btfids
cmp "$build/.config" "$work/config"
test "$(cat "$build/include/config/kernel.release")" = "$release"
python3 - "$build" <<'PYTOOLS'
from pathlib import Path
import subprocess
import sys
for path in Path(sys.argv[1]).rglob('*'):
    if path.is_file() and not path.is_symlink() and path.stat().st_mode & 0o111:
        with path.open('rb') as stream:
            elf = stream.read(4) == b'\x7fELF'
        if elf and 'INTERP' in subprocess.check_output(['readelf', '-l', str(path)], text=True):
            raise SystemExit(f'kernel development helper requires a dynamic loader: {path}')
PYTOOLS
# External modules use the prepared headers/scripts/tools, not every in-tree
# driver and selftest. Preserve the full verified source as one compressed file
# for developers who need it, instead of adding 85,000 files to every SDK image.
python3 - "$build" "$kernel_arch" <<'PYPRUNE'
from pathlib import Path
import shutil
import sys
build, arch = Path(sys.argv[1]), sys.argv[2]
def keep(directory, names):
    for path in directory.iterdir():
        if path.name in names or path.name.startswith('localversion'):
            continue
        if path.is_dir() and not path.is_symlink():
            shutil.rmtree(path)
        else:
            path.unlink()
keep(build, {'.config', 'Module.symvers', 'System.map', 'vmlinux', 'Makefile',
             'Kbuild', 'Kconfig', 'COPYING', 'LICENSES', 'README',
             'include', 'scripts', 'arch', 'tools', '.flexvm-patches'})
keep(build / 'arch', {arch})
keep(build / 'tools', {'Makefile', 'build', 'include', 'scripts', 'arch',
                       'objtool', 'bpf', 'lib'})
keep(build / 'tools/bpf', {'resolve_btfids'})
PYPRUNE
# Intermediate tool objects are not used by external module builds.
find "$build" -type f \( -name '*.o' -o -name '*.a' \) -delete
mkdir -p "$stage/usr/src/flexvm"
cp "$archive" "$stage/usr/src/flexvm/"
ln -s build "$modules/source"
# These are dependency indexes only; depmod never inserts a host module.
depmod=$(command -v depmod || true)
if [[ -z $depmod && -x /sbin/depmod ]]; then depmod=/sbin/depmod; fi
if [[ -z $depmod ]]; then echo 'module packaging needs depmod (kmod)' >&2; exit 1; fi
"$depmod" -ae -F "$src/System.map" -b "$stage" "$release" 2> "$work/depmod.log"
if [[ -s $work/depmod.log ]]; then cat "$work/depmod.log" >&2; exit 1; fi
mkdir -p "$stage/usr/lib/flexvm"
python3 - "$stage" "$kernel" "$ARCH" "$release" "$(pinned "$LINUX_SOURCE_URL")" "$(basename "$archive")" <<'PY'
import hashlib
import json
from pathlib import Path
import sys
stage, kernel, arch, release, source_sha, source_name = sys.argv[1:]
stage = Path(stage)
build = stage / 'lib/modules' / release / 'build'
def digest(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()
manifest = {'version': 1, 'architecture': arch, 'release': release, 'development': True,
            'kernel_sha256': digest(kernel), 'source_sha256': source_sha,
            'config_sha256': digest(build / '.config'),
            'symbols_sha256': digest(build / 'Module.symvers'),
            'source_archive': 'usr/src/flexvm/' + source_name,
            'modules': {str(path.relative_to(stage)): digest(path)
                        for path in sorted((stage / 'lib/modules' / release).rglob('*.ko'))}}
(stage / 'usr/lib/flexvm/kernel-modules.json').write_text(json.dumps(manifest, sort_keys=True) + '\n')
PY
# Re-derive the image: modules may have relinked vmlinux, so comparing the
# pre-build temporary image again would authenticate stale build inputs.
check_kernel
cmp "$src/.config" "$work/config"
mkdir -p "$(dirname "$output")"
placing=$(mktemp "${output}.XXXXXX")
# Stable ownership/order/timestamps; gzip -n omits the temporary filename/time.
tar --mode='u+rwX,go+rX,go-w' --sort=name --mtime="@$SOURCE_DATE_EPOCH" --owner=0 --group=0 --numeric-owner -C "$stage" -cf - . | gzip -n > "$placing"
chmod 644 "$placing"
mv -T "$placing" "$output"
placing=
sha256sum "$output"
# Ordinary app images need runtime modules/indexes, not the complete SDK.
# Both archives retain the same kernel/source/configuration identity manifest.
if [[ -n $runtime_output ]]; then
  python3 - "$stage/usr/lib/flexvm/kernel-modules.json" <<'PYRUNTIME'
import json
from pathlib import Path
import sys
path = Path(sys.argv[1])
manifest = json.loads(path.read_text())
manifest['development'] = False
manifest['source_archive'] = None
path.write_text(json.dumps(manifest, sort_keys=True) + '\n')
PYRUNTIME
  mkdir -p "$(dirname "$runtime_output")"
  placing=$(mktemp "${runtime_output}.XXXXXX")
  tar --mode='u+rwX,go+rX,go-w' --sort=name --mtime="@$SOURCE_DATE_EPOCH" --owner=0 --group=0 --numeric-owner \
    --exclude="./lib/modules/$release/build" --exclude="./lib/modules/$release/source" --exclude='./usr/src' \
    -C "$stage" -cf - . | gzip -n > "$placing"
  chmod 644 "$placing"
  mv -T "$placing" "$runtime_output"
  placing=
  sha256sum "$runtime_output"
fi
