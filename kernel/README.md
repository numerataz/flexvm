# Guest kernel inputs

`scripts/build-kernel.sh` builds the archive named in `source.env`, verified
against `scripts/checksums.sha256` before extraction. The release pipeline runs
this recipe natively on each architecture and attests its outputs.

The vendored base configurations are from Firecracker v1.15.0:

- [x86_64](https://github.com/firecracker-microvm/firecracker/blob/v1.15.0/resources/guest_configs/microvm-kernel-ci-x86_64-6.1.config)
- [aarch64](https://github.com/firecracker-microvm/firecracker/blob/v1.15.0/resources/guest_configs/microvm-kernel-ci-aarch64-6.1.config)

These are configuration inputs, not Amazon Linux source or patches. The recipe
applies `features.config` and `features-ARCH.config` to the pinned Linux tree,
runs `olddefconfig`, and rejects any required setting that is not retained.
The common fragment includes FlexVM's pmem/DAX root, memory hotplug, namespaces,
cgroups and container facilities. Required drivers are built in, so stock OCI
images do not need a matching modules package. `CONFIG_MODULES` allows additional
user-supplied modules built for this exact kernel.

The native build outputs `vmlinux`, `kernel-modules.tar.gz` and
`kernel-sdk.tar.gz` with matching checksum records. The runtime archive contains
the release's module tree and dependency indexes. The SDK adds prepared headers,
generated configuration, symbol versions, the matching BTF ELF, static native
build helpers and the verified Linux source archive. It is injected only with
`--kernel-sdk` or an explicit `--kernel-modules FILE` selection. Guest builds
still need their own compiler, make, kmod, dwarves (`pahole` for BTF) and workload dependencies.

`scripts/package-kernel-modules.sh` verifies the source tree against that archive
and the actual boot image against the completed native build before packaging.
Bundle manifests bind architecture, kernel, source, configuration, symbol
versions and module payloads. Image preparation rejects mismatches before boot;
cache identities include the chosen bundle. Do not use a distro's unrelated
kernel headers for FlexVM modules. All loading and unloading occurs in the guest;
the build and acceptance harnesses never load these modules on the host.

The kernel build identity includes the exact source archive hash, script and
configuration contents. Published release provenance also binds the release
workflow and scripts. Changing these inputs requires a new immutable artifacts
tag; see [Releasing the artifacts](../README.md#releasing-the-artifacts).

The numbered patches in this directory target the **host** kernel for performance
experiments. The guest build does not apply them.
