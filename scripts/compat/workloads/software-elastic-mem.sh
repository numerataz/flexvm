#!/bin/sh
# Verify software VM elastic memory (virtio-mem) grows dynamically under guest
# memory pressure beyond --mem and preserves the expanded RAM across pause and
# fresh-emulator stop/start.
set -eux
step=$1 nonce=$2 phase=$3
base=/run/flexvm-elastic-$nonce

mem_total_mib() {
    awk '/^MemTotal:/ {printf "%d\n", $2 / 1024}' /proc/meminfo
}

case $step in
prepare)
    mkdir -p "$base"
    initial=$(mem_total_mib)
    printf '%s\n' "$initial" > "$base/initial-mib"
    # Boot with small base RAM (e.g. 384 MiB); verify we start below 480 MiB.
    test "$initial" -lt 480
    # 1. Burst 420 MiB and release it to prove elastic grow AND shrink.
    python3 - <<'PY'
import time
chunks = []
for i in range(420):
    b = bytearray(1 << 20)
    for off in range(0, 1 << 20, 4096):
        b[off] = (i & 0xff) or 1
    chunks.append(b)
    if i % 32 == 31:
        time.sleep(0.15)
PY
    burst=$(mem_total_mib)
    test "$burst" -gt $((initial + 200))
    shrunk=$burst
    for _ in $(seq 1 40); do
        now=$(mem_total_mib)
        if [ "$now" -lt $((burst - 64)) ]; then
            shrunk=$now
            break
        fi
        sleep .5
    done
    test "$shrunk" -lt $((burst - 64))
    printf 'ELASTIC_BURST_AND_SHRINK %s -> %s -> %s MiB\n' "$initial" "$burst" "$shrunk"

    # 2. Allocate 420 MiB of anonymous RAM in a persistent background process,
    # exceeding the initial base RAM so virtio-mem grows again and stays intact.
    cat > "$base/holder.py" <<'PY'
import hashlib, os, pathlib, sys, time
base = pathlib.Path(sys.argv[1])
target_mib = int(sys.argv[2])
chunks = []
for i in range(target_mib):
    # Touch every page with deterministic non-zero bytes so the kernel commits RAM.
    b = bytearray(1 << 20)
    tag = f"{i:08x}".encode()
    for off in range(0, 1 << 20, 4096):
        b[off:off+8] = tag
    chunks.append(b)
    if i % 32 == 31:
        time.sleep(0.15)

def chunks_digest():
    h = hashlib.sha256()
    for b in chunks:
        h.update(bytes(b[:64]))
    return h.hexdigest()

digest = chunks_digest()
(base / "ready").write_text(f"{os.getpid()} {digest}\n")
while True:
    # Re-verify all chunks' digest every second to ensure RAM stays intact.
    assert chunks_digest() == digest
    time.sleep(1)
PY
    python3 "$base/holder.py" "$base" 420 >/dev/null 2>"$base/holder.err" &
    holder_pid=$!
    printf '%s\n' "$holder_pid" > "$base/holder-pid"
    for _ in $(seq 1 120); do
        if [ -s "$base/ready" ]; then break; fi
        kill -0 "$holder_pid" || { cat "$base/holder.err" >&2; exit 1; }
        sleep .5
    done
    test -s "$base/ready"
    after=$(mem_total_mib)
    printf '%s\n' "$after" > "$base/grown-mib"
    # Elastic virtio-mem must have grown MemTotal significantly above initial boot RAM.
    test "$after" -gt $((initial + 200))
    printf 'ELASTIC_GREW %s -> %s MiB\n' "$initial" "$after"
    ;;
verify)
    holder_pid=$(cat "$base/holder-pid")
    kill -0 "$holder_pid"
    test -s "$base/ready"
    test ! -s "$base/holder.err"
    set -- $(cat "$base/ready")
    test "$1" = "$holder_pid"
    test -n "${2:-}"
    grown=$(cat "$base/grown-mib")
    now=$(mem_total_mib)
    # Restored VM must retain the plugged virtio-mem capacity.
    test "$now" -ge $((grown - 16))
    printf 'ELASTIC_PHASE_OK %s initial=%s now=%s pid=%s digest=%s\n' "$phase" "$(cat "$base/initial-mib")" "$now" "$holder_pid" "$2"
    ;;
*) exit 2 ;;
esac
