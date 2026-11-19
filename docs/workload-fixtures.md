# Verified workload image fixtures

The Kubernetes compatibility tests repeatedly imported the same pinned BusyBox
image into fresh guests. A public ECR `Data limit exceeded` response could stop a
run before it created its cluster. `scripts/compat/workload-fixture.py` prepares a
reusable input for the normal Docker and containerd import commands.

The source remains the reviewed immutable image in the helper. Skopeo fetches it
on a cold cache. Every cache hit verifies the upstream index against its pinned
SHA-256, selects the native Linux manifest, and verifies its configuration and
compressed layer descriptors by size and digest. Links and special files are
refused, and file counts and bytes are bounded. A corrupt cache fails validation.
A valid warm cache does not launch a registry client or converter.

The Docker import archive contains only its v2 manifest, configuration and regular
layer payloads. Legacy alias symlinks emitted by the converter are omitted.
Configuration bytes must hash to the authenticated source configuration; each
uncompressed layer must hash to the corresponding source `rootfs.diff_ids` entry.
The report records the source, architecture, manifest/configuration identities,
layer diff IDs and import archive checksum.

```sh
# Requires the native Skopeo package. OUTPUT must be a new directory.
python3 scripts/compat/workload-fixture.py \
  --cache /var/tmp/flexvm-busybox-cache \
  --output /var/tmp/flexvm-busybox-input
```

GitHub Actions saves the verified cache before running the workload. Native and
software harnesses seed the archive, metadata and import verifier into the guest,
checking each file's SHA-256 after transfer. Native `e2e.py` uses
`FLEXVM_WORKLOAD_FIXTURE` to pass these inputs to its kind and K3s cases. The
software matrix passes the corresponding `--seed` arguments explicitly.

The stock Docker/containerd daemon loads the image, then exports it again. The
guest verifier authenticates the daemon's actual configuration bytes and
filesystem layer diff IDs against the fixture report. Docker 29 exposes a
manifest digest as its image ID; that identifier is not assumed to be the image
configuration digest. The verifier handles Docker-compatible and OCI exports,
including bounded gzip decompression, without extracting archive paths.

Kind imports the local image into its node. Seeded K3s applications use the
imported local tag with `imagePullPolicy: Never`. Existing pod identities,
process/RAM canaries, counters, volume data, DNS, services and egress checks remain
enabled through every lifecycle phase. Standalone runs without fixture inputs
retain their pinned registry path. Supplying incomplete or invalid inputs fails.

This caches the BusyBox application fixture. Package installation, Kubernetes
binaries, the kind node image and other stock bootstrap assets still use their
normal sources. It does not fix the separate intermittent kind readiness failure
tracked in #1434.
