#!/bin/sh
# Only run in an isolated owned guest: drop_caches affects that guest globally.
set -eu
step=$1 nonce=$2
base=/var/lib/flexvm-root-inodes-$nonce
identity() { stat -Lc '%n %d %i' /usr/local/bin /usr/local/sbin; }
check() {
    actual=$(identity)
    expected=$(cat "$base/expected")
    test "$actual" = "$expected" || {
        printf 'root directory identities changed:\nexpected:\n%s\nactual:\n%s\n' "$expected" "$actual" >&2
        return 1
    }
}
if [ "$step" = prepare ]; then
    mkdir "$base"
    identity > "$base/expected"
fi
case $step in prepare|verify) ;; *) exit 2 ;; esac
# Close stat's inode references, evict dentries/inodes, then look them up again.
# Copy-up alone is insufficient to catch the nonpersistent overlay inode case.
for cycle in 1 2 3 4 5; do
    sync
    echo 2 > /proc/sys/vm/drop_caches
    check
done
if [ "$step" = prepare ]; then
    for directory in /usr/local/bin /usr/local/sbin; do
        printf '%s' "$nonce" > "$directory/.flexvm-inode-$nonce"
    done
    check
fi
printf 'root overlay identity stable after cache eviction and copy-up:\n'
cat "$base/expected"
