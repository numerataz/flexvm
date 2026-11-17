#!/usr/bin/env bash
# Apply the reviewed series to a verified source tree. Refuse a different series
# in a reused KERNEL_BUILD_DIR; use a fresh build directory after changing it.
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
if [[ $# != 1 || ! -f $1/Makefile ]]; then
  echo 'usage: apply-kernel-patches.sh LINUX_SOURCE' >&2; exit 2
fi
src=$(realpath -e "$1")
patches=$root/kernel/patches
record=$src/.flexvm-patches
mapfile -t series < "$patches/series"
(( ${#series[@]} > 0 )) || { echo 'empty kernel patch series' >&2; exit 1; }
declare -A listed
for name in "${series[@]}"; do
  if [[ ! $name =~ ^[0-9]+-[a-z0-9-]+\.patch$ || ! -f $patches/$name ]]; then
    echo "invalid kernel patch in series: $name" >&2; exit 1
  fi
  if [[ ${listed[$name]+present} ]]; then
    echo "duplicate kernel patch: $name" >&2; exit 1
  fi
  listed[$name]=1
done
shopt -s nullglob dotglob
entries=("$patches"/*)
shopt -u nullglob dotglob
if (( ${#entries[@]} != ${#series[@]} + 1 )); then
  echo 'kernel patch directory does not match its series' >&2; exit 1
fi
for entry in "${entries[@]}"; do
  name=${entry##*/}
  if [[ ! -f $entry || -L $entry || ( $name != series && ! ${listed[$name]+present} ) ]]; then
    echo "unlisted or invalid kernel patch input: $entry" >&2; exit 1
  fi
done
if [[ -e $record ]]; then
  diff -r "$patches" "$record"
  # Validate the actual source as well as its record. The current series has
  # one independent patch, so its inverse can be checked without modifying it.
  for name in "${series[@]}"; do
    patch -d "$src" -p1 --batch --fuzz=0 --reverse --dry-run < "$patches/$name"
  done
else
  for name in "${series[@]}"; do
    patch -d "$src" -p1 --batch --fuzz=0 --forward --dry-run < "$patches/$name"
    patch -d "$src" -p1 --batch --fuzz=0 --forward < "$patches/$name"
  done
  cp -a "$patches" "$record"
fi
