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

The kernel build identity includes the exact source archive hash, script and
configuration contents. Published release provenance also binds the release
workflow and scripts. Changing these inputs requires a new immutable artifacts
tag; see [Releasing the artifacts](../README.md#releasing-the-artifacts).

The numbered patches in this directory target the **host** kernel for performance
experiments. The guest build does not apply them.
