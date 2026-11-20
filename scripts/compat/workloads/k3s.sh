#!/bin/sh
# Stock single-node K3s, with live application state through the outer VM lifecycle.
set -eux
step=$1 nonce=$2 phase=$3
base=/var/lib/flexvm-k3s-$nonce
image=public.ecr.aws/docker/library/busybox@sha256:73aaf090f3d85aa34ee199857f03fa3a95c8ede2ffd4cc2cdb5b94e566b11662
policy=IfNotPresent
k() { k3s kubectl -n flexvm-compat "$@"; }
trap 'result=$?; if [ "$result" -ne 0 ]; then
    systemctl --no-pager -l status k3s.service || true
    journalctl --no-pager -u k3s.service -n 50 || true
    k3s kubectl --request-timeout=5s get pods -A -o wide || true
    k3s kubectl --request-timeout=5s get events -A --sort-by=.lastTimestamp | tail -15 || true
fi; exit "$result"' 0
case $step in
prepare)
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq
    apt-get install -y -qq --no-install-recommends ca-certificates curl iptables kmod zstd python3
    mkdir -p "$base" /var/lib/rancher/k3s
    # The root is a RAM-backed union. A native upper filesystem lets the stock
    # containerd overlayfs snapshotter run without selecting a fallback driver.
    mount -t tmpfs -o size=2G,mode=0755 flexvm-k3s /var/lib/rancher/k3s
    mkdir -p /var/lib/rancher/k3s/agent/images
    version=v1.37.2+k3s1
    release=https://github.com/k3s-io/k3s/releases/download/v1.37.2%2Bk3s1
    case $(uname -m) in
        x86_64)
            arch=amd64 binary=k3s
            binary_sha=265b3ee6a3198ef14033c63ef46cbb32370d83795199fb6d1b01f21575eddbda
            images_sha=35a5af1e69b57b8b627a4f6b1c29ea104209b661067b8c97fd40dc3f860bfcd2 ;;
        aarch64)
            arch=arm64 binary=k3s-arm64
            binary_sha=a779ccf1e5e2e33a62f5a29c2f1c0bbf99431e100579d4c10f0aa0742a6aa84b
            images_sha=ca384f1a77aa83024bd82ad26fa4774971adb038e656a3b5b9af926be445a442 ;;
        *) exit 2 ;;
    esac
    curl --fail --location --retry 3 --connect-timeout 15 --max-time 300 "$release/$binary" -o /usr/local/bin/k3s
    printf '%s  %s\n' "$binary_sha" /usr/local/bin/k3s | sha256sum -c -
    chmod 755 /usr/local/bin/k3s
    archive=/var/lib/rancher/k3s/agent/images/k3s-airgap-images-$arch.tar.zst
    curl --fail --location --retry 3 --connect-timeout 15 --max-time 600 "$release/k3s-airgap-images-$arch.tar.zst" -o "$archive"
    printf '%s  %s\n' "$images_sha" "$archive" | sha256sum -c -
    curl --fail --location --retry 3 --connect-timeout 15 --max-time 120 \
        https://raw.githubusercontent.com/k3s-io/k3s/v1.37.2%2Bk3s1/install.sh -o "$base/install.sh"
    printf '%s  %s\n' ed01f89fd977bf20ac1516bbebf8370bf3ddbaa55dac8aba610956a4c78cc00b "$base/install.sh" | sha256sum -c -
    INSTALL_K3S_SKIP_DOWNLOAD=true INSTALL_K3S_VERSION="$version" \
        INSTALL_K3S_EXEC='server --node-name flexvm-test' sh "$base/install.sh"
    for attempt in $(seq 1 120); do
        if k3s kubectl get node flexvm-test --request-timeout=5s >/dev/null 2>&1; then break; fi
        sleep 1
    done
    k3s kubectl wait --for=condition=Ready node/flexvm-test --timeout=300s
    for deployment in coredns local-path-provisioner traefik metrics-server; do
        k3s kubectl -n kube-system wait --for=create "deployment/$deployment" --timeout=300s
        k3s kubectl -n kube-system rollout status "deployment/$deployment" --timeout=300s
    done
    # Imported images are now in containerd; do not retain a redundant RAM-backed archive.
    # Traefik readiness can precede its Gateway API CRD installer completing.
    # Wait for stock bootstrap jobs before requesting the full OpenAPI schema.
    for job in helm-install-traefik-crd helm-install-traefik helm-install-gateway-api-crd; do
        k3s kubectl -n kube-system wait --for=create "job/$job" --timeout=300s
        k3s kubectl -n kube-system wait --for=condition=complete "job/$job" --timeout=300s
    done
    rm "$archive"
    if [ -e /nested-input/busybox.tar ] || [ -e /nested-input/busybox.json ]; then
        python3 - "$image" <<'PYFIXTURE'
from pathlib import Path
import hashlib, json, platform, re, sys
root = Path('/nested-input')
metadata = json.loads((root / 'busybox.json').read_text())
assert metadata['source'] == sys.argv[1], metadata
assert metadata['architecture'] == {'x86_64': 'amd64', 'aarch64': 'arm64'}[platform.machine()], metadata
assert metadata['tag'] == 'docker.io/flexvm/busybox:compat', metadata
assert hashlib.sha256((root / 'busybox.tar').read_bytes()).hexdigest() == metadata['archive_sha256']
assert re.fullmatch(r'sha256:[0-9a-f]{64}', metadata['config_digest'])
print(metadata['config_digest'])
PYFIXTURE

        k3s ctr --namespace k8s.io images import /nested-input/busybox.tar
        image=docker.io/flexvm/busybox:compat
        policy=Never
        k3s crictl inspecti "$image" > "$base/fixture-image.json"
        k3s ctr --namespace k8s.io images export "$base/imported-image.tar" "$image"
        python3 /nested-input/verify-fixture-import.py --archive "$base/imported-image.tar" --metadata /nested-input/busybox.json
        rm "$base/imported-image.tar"
    fi
    python3 - "$nonce" "$image" "$policy" > "$base/workload.json" <<'PY'
import json, sys
nonce, image, policy = sys.argv[1:]
script = '''
test -f /data/index.html || printf %s "$NONCE" > /data/index.html
cookie=$(cat /proc/sys/kernel/random/uuid)
httpd -f -p 8080 -h /data &
counter=0
while :; do
    counter=$((counter + 1))
    printf '%s %s\n' "$cookie" "$counter" > /tmp/probe.new
    mv /tmp/probe.new /tmp/probe
    sleep .1
done
'''
container = dict(name='web', image=image, imagePullPolicy=policy, command=['sh', '-ec', script],
    env=[dict(name='NONCE', value=nonce)], ports=[dict(containerPort=8080)],
    securityContext=dict(allowPrivilegeEscalation=False, capabilities=dict(drop=['ALL'])),
    resources=dict(requests=dict(cpu='10m', memory='16Mi'), limits=dict(cpu='100m', memory='64Mi')),
    readinessProbe=dict(httpGet=dict(path='/', port=8080), periodSeconds=1),
    volumeMounts=[dict(name='data', mountPath='/data')])
pod = dict(securityContext=dict(runAsUser=1000, runAsGroup=1000, fsGroup=1000, runAsNonRoot=True),
    containers=[container], volumes=[dict(name='data', persistentVolumeClaim=dict(claimName='data'))])
backend = dict(service=dict(name='web', port=dict(number=8080)))
items = [
    dict(apiVersion='v1', kind='Namespace', metadata=dict(name='flexvm-compat')),
    dict(apiVersion='v1', kind='PersistentVolumeClaim', metadata=dict(name='data', namespace='flexvm-compat'),
        spec=dict(accessModes=['ReadWriteOnce'], storageClassName='local-path', resources=dict(requests=dict(storage='64Mi')))),
    dict(apiVersion='apps/v1', kind='Deployment', metadata=dict(name='web', namespace='flexvm-compat'),
        spec=dict(replicas=2, selector=dict(matchLabels=dict(app='web')),
            template=dict(metadata=dict(labels=dict(app='web')), spec=pod))),
    dict(apiVersion='v1', kind='Service', metadata=dict(name='web', namespace='flexvm-compat'),
        spec=dict(type='NodePort', selector=dict(app='web'), ports=[dict(port=8080, targetPort=8080)])),
    dict(apiVersion='networking.k8s.io/v1', kind='Ingress', metadata=dict(name='web', namespace='flexvm-compat'),
        spec=dict(ingressClassName='traefik', rules=[dict(host='flexvm.test', http=dict(paths=[
            dict(path='/', pathType='Prefix', backend=backend)]))])),
]
print(json.dumps(dict(apiVersion='v1', kind='List', items=items)))
PY
    k3s kubectl --request-timeout=120s apply -f "$base/workload.json"
    k rollout status deployment/web --timeout=300s
    k get service web -o jsonpath='{.spec.ports[0].nodePort}' > "$base/node-port"
    k3s kubectl get node flexvm-test -o json > "$base/node.json"
    k get pods -l app=web -o json > "$base/pods.json"
    for pod in $(k get pods -l app=web -o jsonpath='{.items[*].metadata.name}'); do
        k exec "$pod" -- cat /tmp/probe > "$base/$pod.probe"
    done
    systemctl show --property=MainPID --value k3s.service > "$base/server"
    k3s --version
    k3s crictl images
    ;;
verify)
    systemctl is-active --quiet k3s.service
    test "$(systemctl show --property=MainPID --value k3s.service)" = "$(cat "$base/server")"
    k3s kubectl wait --for=condition=Ready node/flexvm-test --timeout=180s
    k rollout status deployment/web --timeout=180s
    k3s kubectl get node flexvm-test -o json > "$base/node-now.json"
    python3 - "$base/node.json" "$base/node-now.json" <<'PYNODE'
import json, pathlib, sys
before, now = (json.loads(pathlib.Path(p).read_text())['metadata']['uid'] for p in sys.argv[1:])
assert before == now, (before, now)
PYNODE
    k get pods -l app=web -o json > "$base/now.json"
    python3 - "$base/pods.json" "$base/now.json" <<'PY'
import json, pathlib, sys
def identity(path):
    return {p['metadata']['name']: (p['metadata']['uid'], [(c['containerID'], c['restartCount']) for c in p['status']['containerStatuses']])
            for p in json.loads(pathlib.Path(path).read_text())['items']}
before, now = map(identity, sys.argv[1:])
assert len(now) == 2 and before == now, (before, now)
print(now)
PY
    set -- $(k get pods -l app=web -o jsonpath='{.items[*].metadata.name}')
    first=$1 second=$2
    for pod in "$first" "$second"; do
        k exec "$pod" -- sh -ec '
            test "$(cat /sys/fs/cgroup/memory.max)" = 67108864
            test "$(cat /sys/fs/cgroup/cpu.max)" = "10000 100000"'
        initial=$(awk '{print $1}' "$base/$pod.probe")
        k exec "$pod" -- sh -ec '
            expected=$1
            set -- $(cat /tmp/probe)
            test "$1" = "$expected"
            before=$2
            for attempt in $(seq 1 50); do
                set -- $(cat /tmp/probe)
                test "$1" = "$expected"
                if [ "$2" -gt "$before" ]; then printf "%s %s\n" "$1" "$2"; exit 0; fi
                sleep .2
            done
            echo "pod counter did not advance" >&2
            exit 1' sh "$initial"
        test "$(k exec "$pod" -- cat /data/index.html)" = "$nonce"
    done
    test "$(k exec "$first" -- wget -qO- http://web.flexvm-compat.svc.cluster.local:8080)" = "$nonce"
    peer=$(k get pod "$second" -o jsonpath='{.status.podIP}')
    test "$(k exec "$first" -- wget -qO- "http://$peer:8080")" = "$nonce"
    k exec "$first" -- wget -qO /dev/null https://github.com/robots.txt
    node_port=$(cat "$base/node-port")
    case $node_port in ''|*[!0-9]*) exit 1 ;; esac
    test "$node_port" -ge 30000 && test "$node_port" -le 32767
    test "$(k get service web -o jsonpath='{.spec.ports[0].nodePort}')" = "$node_port"
    node_ip=$(ip -4 -o addr show dev eth0 | awk '{split($4, a, "/"); print a[1]; exit}')
    test "$(curl --fail --silent --show-error --retry 10 --retry-connrefused --retry-delay 1 "http://$node_ip:$node_port")" = "$nonce"
    test "$(curl --fail --silent --show-error --retry 10 --retry-connrefused --retry-delay 1 -H 'Host: flexvm.test' "http://$node_ip/")" = "$nonce"
    printf 'K3S_PHASE_OK %s\n' "$phase"
    ;;
*) exit 2 ;;
esac
