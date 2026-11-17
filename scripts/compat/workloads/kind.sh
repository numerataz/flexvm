#!/bin/sh
# Stock kind in Docker, retaining live Kubernetes application state.
set -eux
step=$1 nonce=$2 phase=$3
base=/var/lib/flexvm-kind-$nonce
source_image=public.ecr.aws/docker/library/busybox@sha256:73aaf090f3d85aa34ee199857f03fa3a95c8ede2ffd4cc2cdb5b94e566b11662
image=flexvm/busybox:compat
node_image=kindest/node:v1.37.0@sha256:a1ed56cfb0e7b93589bdf97c8cd566405a265939e3620fc4f5de89adff580ae5
kubectl() { docker exec fvkind-control-plane kubectl --kubeconfig=/etc/kubernetes/admin.conf "$@"; }
k() { kubectl -n flexvm-compat "$@"; }
trap 'result=$?; if [ "$result" -ne 0 ]; then
    systemctl --no-pager -l status docker.service || true
    docker ps -a || true
    kubectl --request-timeout=5s get pods -A -o wide || true
    kubectl --request-timeout=5s get events -A --sort-by=.lastTimestamp | tail -15 || true
fi; exit "$result"' 0
case $step in
prepare)
    export DEBIAN_FRONTEND=noninteractive
    mkdir -p "$base" /var/lib/docker /var/lib/containerd
    mount -t tmpfs -o size=3G,mode=0711 flexvm-kind /var/lib/docker
    mount -t tmpfs -o size=3G,mode=0711 flexvm-kind-containerd /var/lib/containerd
    apt-get update -qq
    apt-get install -y -qq --no-install-recommends docker.io conntrack iptables nftables curl ca-certificates python3
    case $(uname -m) in
        x86_64) arch=amd64; sha=aee6151561422756b764a4ae28e7f44cda5af5a9eead3cc9985112b1de8d8e0d ;;
        aarch64) arch=arm64; sha=20022bee6cfcd5086cb7234d218e3454e6090022f2a8f55d1fa7fcf42c3867a2 ;;
        *) exit 2 ;;
    esac
    curl --fail --location --retry 3 --connect-timeout 15 --max-time 300 \
        "https://github.com/kubernetes-sigs/kind/releases/download/v0.33.0/kind-linux-$arch" -o /usr/local/bin/kind
    printf '%s  %s\n' "$sha" /usr/local/bin/kind | sha256sum -c -
    chmod 755 /usr/local/bin/kind
    systemctl start docker.service
    # Docker 29 uses the native containerd overlayfs image store by default;
    # earlier packaged engines call their native overlay driver overlay2.
    case $(docker info --format '{{.Driver}}') in overlay2|overlayfs) ;; *) exit 1 ;; esac
    docker pull "$node_image"
    docker pull "$source_image"
    docker tag "$source_image" "$image"
    test "$(docker image inspect --format '{{.Id}}' "$source_image")" = "$(docker image inspect --format '{{.Id}}' "$image")"
    docker image inspect "$node_image" "$source_image" > "$base/images.json"
    cat > "$base/kind.yaml" <<'EOF'
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
- role: control-plane
  extraPortMappings:
  - containerPort: 30089
    hostPort: 18089
    listenAddress: "127.0.0.1"
    protocol: TCP
EOF
    kind create cluster --name fvkind --image "$node_image" --config "$base/kind.yaml" --wait 600s
    # Export only the pulled platform; Docker 29 can otherwise export an
    # index referencing other platforms whose content was never downloaded.
    docker image save --platform "linux/$arch" -o "$base/busybox.tar" "$image"
    kind load image-archive "$base/busybox.tar" --name fvkind
    rm "$base/busybox.tar"
    kubectl wait --for=condition=Ready node/fvkind-control-plane --timeout=300s
    kubectl -n kube-system rollout status deployment/coredns --timeout=300s
    kubectl -n local-path-storage rollout status deployment/local-path-provisioner --timeout=300s
    python3 - "$nonce" "$image" > "$base/workload.json" <<'PY'
import json, sys
nonce, image = sys.argv[1:]
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
container = dict(name='web', image=image, imagePullPolicy='Never', command=['sh', '-ec', script],
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
        spec=dict(accessModes=['ReadWriteOnce'], storageClassName='standard', resources=dict(requests=dict(storage='64Mi')))),
    dict(apiVersion='apps/v1', kind='Deployment', metadata=dict(name='web', namespace='flexvm-compat'),
        spec=dict(replicas=2, selector=dict(matchLabels=dict(app='web')),
            template=dict(metadata=dict(labels=dict(app='web')), spec=pod))),
    dict(apiVersion='v1', kind='Service', metadata=dict(name='web', namespace='flexvm-compat'),
        spec=dict(type='NodePort', selector=dict(app='web'), ports=[dict(port=8080, targetPort=8080, nodePort=30089)])),

]
print(json.dumps(dict(apiVersion='v1', kind='List', items=items)))
PY

    docker exec -i fvkind-control-plane kubectl --kubeconfig=/etc/kubernetes/admin.conf apply -f - < "$base/workload.json"
    k rollout status deployment/web --timeout=300s
    kubectl get node fvkind-control-plane -o json > "$base/node.json"
    k get pods -l app=web -o json > "$base/pods.json"
    for pod in $(k get pods -l app=web -o jsonpath='{.items[*].metadata.name}'); do
        k exec "$pod" -- cat /tmp/probe > "$base/$pod.probe"
    done
    systemctl show --property=MainPID --value docker.service > "$base/server"
    docker inspect --format '{{.State.Pid}}' fvkind-control-plane > "$base/leader"
    kind version
    docker version
    kubectl version
    ;;
verify)
    systemctl is-active --quiet docker.service
    test "$(systemctl show --property=MainPID --value docker.service)" = "$(cat "$base/server")"
    test "$(docker inspect --format '{{.State.Pid}}' fvkind-control-plane)" = "$(cat "$base/leader")"
    kubectl wait --for=condition=Ready node/fvkind-control-plane --timeout=180s
    k rollout status deployment/web --timeout=180s
    kubectl get node fvkind-control-plane -o json > "$base/node-now.json"
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
    k exec "$first" -- wget -qO /dev/null http://example.com
    test "$(curl --fail --silent --show-error --retry 10 --retry-connrefused --retry-delay 1 http://127.0.0.1:18089)" = "$nonce"
    printf 'KIND_PHASE_OK %s\n' "$phase"
    ;;
*) exit 2 ;;
esac
