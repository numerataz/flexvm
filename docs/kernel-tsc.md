# Nested x86 TSC initialization

The reviewed Linux 6.1 kernel initializes each new KVM vCPU to a unity TSC
multiplier before attempting its requested initial frequency. On software SVM,
hardware TSC scaling is unavailable. Frequency calibration can change between
KVM initialization and vCPU creation; an unsupported lower rate, or the software
catchup path for a higher rate, previously left the zero-allocated multiplier
unchanged. Reading the nested TSC then returned zero, and LAPIC deadline timers
scheduled increasingly long waits. The invalid state can predate a checkpoint.

The patch preserves frequency selection, valid hardware scaling and subsequent
`KVM_SET_TSC_KHZ` error handling. It prevents a stopped clock; it does not emulate
hardware frequency scaling. Existing outer checkpoints retain their saved
kernel and vCPU state; this initialization fix applies to newly created vCPUs
under the patched kernel.

`scripts/compat/software-boot.py --guest-kvm --guest-tsc --kernel IMAGE --output DIR`
runs a deterministic x86 regression with host KVM and vhost-vsock masked. It
requires emulated SVM without TSC scaling, requests half and twice the VM's
native frequency **before creating each vCPU**, and verifies nonzero, advancing
`MSR_IA32_TSC` reads. A lower vCPU frequency request must still fail with
`EINVAL`; a higher request must still select software catchup successfully. CI runs this alongside the existing nested Firecracker checkpoint
acceptance; neither acceptance deadline changes.

Kernel patches are listed in `kernel/patches/series`. The build recipe, patch
application script, ordered series and patch contents participate in the build
identity, release inputs and CI cache keys. Reusing a build directory with a
different recorded series fails; use a fresh `KERNEL_BUILD_DIR` in that case.
The SDK prepares and verifies the same patched source as the built kernel. Its
`lib/modules/RELEASE/build/.flexvm-patches` directory retains the ordered patches;
apply those to the digest-verified upstream source archive included under
`usr/src/flexvm` to recover the full matching source. Existing manifest fields
continue to identify that unchanged upstream archive and the actual kernel.
