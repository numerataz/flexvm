//! aarch64: MIDR_EL1 and the other identification registers of a vCPU as Firecracker sets it up
//! (PSCI 0.2, no CPU template), the counter frequency, the registers KVM_GET_REG_LIST names,
//! which Firecracker saves and restores one by one, the largest SVE vector length, the vGIC
//! version and stolen-time support. ioctl numbers and register encodings follow the arm64 KVM
//! uapi (linux/kvm.h, asm/kvm.h).
use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::{bail, util::Result};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Arm64 {
    /// MIDR_EL1, decoded.
    pub cpu: String,
    /// CNTFRQ_EL0. The guest reads the host's, and arm64 KVM cannot scale its counter.
    pub cntfrq_hz: u64,
    /// KVM_GET_REG_LIST: what Firecracker saves, and sets one by one on a load.
    pub regs: BTreeSet<u64>,
    /// `firecracker --version` and the binary's content hash.
    pub firecracker: String,
    /// Identification registers (MIDR, REVIDR, ID_*, CLIDR, AIDR, CTR) by name.
    pub id_regs: BTreeMap<String, u64>,
    /// Largest SVE vector length KVM offers, in bytes; 0 without SVE.
    pub sve_max_vl: u32,
    /// The vGIC Firecracker creates: 3 (with an ITS) or 2.
    pub gic: u32,
    /// KVM offers stolen-time reporting, which Firecracker sets up at boot when it can.
    pub pvtime: bool,
}

const KVM_REG_ARM64: u64 = 0x6000_0000_0000_0000;
const KVM_REG_ARCH_MASK: u64 = 0xff00_0000_0000_0000;
const KVM_REG_SIZE_MASK: u64 = 0x00f0_0000_0000_0000;
const KVM_REG_SIZE_U64: u64 = 0x0030_0000_0000_0000;
const KVM_REG_ARM_COPROC_MASK: u64 = 0x0fff_0000;
const KVM_REG_ARM64_SYSREG: u64 = 0x0013 << 16;

#[cfg(any(target_arch = "aarch64", test))]
/// ARM64_SYS_REG(op0, op1, crn, crm, op2).
const fn sys_reg(op0: u64, op1: u64, crn: u64, crm: u64, op2: u64) -> u64 {
    KVM_REG_ARM64 | KVM_REG_SIZE_U64 | KVM_REG_ARM64_SYSREG | op0 << 14 | op1 << 11 | crn << 7 | crm << 3 | op2
}

#[cfg(any(target_arch = "aarch64", test))]
const MIDR_EL1: u64 = sys_reg(3, 0, 0, 0, 0);

/// (op0, op1, crn, crm, op2) of a 64-bit system register.
fn sys_reg_fields(id: u64) -> Option<[u64; 5]> {
    let sysreg = id & KVM_REG_ARCH_MASK == KVM_REG_ARM64 && id & KVM_REG_SIZE_MASK == KVM_REG_SIZE_U64 && id & KVM_REG_ARM_COPROC_MASK == KVM_REG_ARM64_SYSREG;
    sysreg.then_some([(id >> 14) & 3, (id >> 11) & 7, (id >> 7) & 0xf, (id >> 3) & 0xf, id & 7])
}

#[cfg(any(target_arch = "aarch64", test))]
/// The identification space (op0 3, CRn 0): MIDR, REVIDR and the ID registers, CLIDR, AIDR,
/// CTR and DCZID. Not MPIDR, which KVM derives from the vCPU's index.
fn is_id_reg(id: u64) -> bool {
    match sys_reg_fields(id) {
        Some([3, 0, 0, crm, op2]) => !(crm == 0 && op2 == 5),
        Some([3, 1, 0, 0, _]) => true,
        Some([3, 3, 0, 0, op2]) => op2 == 1 || op2 == 7,
        _ => false,
    }
}

/// A system register by its architectural name where known, else as `S3_0_C0_C4_3`.
fn reg_name(id: u64) -> String {
    const NAMES: &[([u64; 5], &str)] = &[
        ([3, 0, 0, 0, 0], "MIDR_EL1"),
        ([3, 0, 0, 0, 5], "MPIDR_EL1"),
        ([3, 0, 0, 0, 6], "REVIDR_EL1"),
        ([3, 0, 0, 4, 0], "ID_AA64PFR0_EL1"),
        ([3, 0, 0, 4, 1], "ID_AA64PFR1_EL1"),
        ([3, 0, 0, 4, 2], "ID_AA64PFR2_EL1"),
        ([3, 0, 0, 4, 4], "ID_AA64ZFR0_EL1"),
        ([3, 0, 0, 4, 5], "ID_AA64SMFR0_EL1"),
        ([3, 0, 0, 4, 7], "ID_AA64FPFR0_EL1"),
        ([3, 0, 0, 5, 0], "ID_AA64DFR0_EL1"),
        ([3, 0, 0, 5, 1], "ID_AA64DFR1_EL1"),
        ([3, 0, 0, 5, 4], "ID_AA64AFR0_EL1"),
        ([3, 0, 0, 5, 5], "ID_AA64AFR1_EL1"),
        ([3, 0, 0, 6, 0], "ID_AA64ISAR0_EL1"),
        ([3, 0, 0, 6, 1], "ID_AA64ISAR1_EL1"),
        ([3, 0, 0, 6, 2], "ID_AA64ISAR2_EL1"),
        ([3, 0, 0, 6, 3], "ID_AA64ISAR3_EL1"),
        ([3, 0, 0, 7, 0], "ID_AA64MMFR0_EL1"),
        ([3, 0, 0, 7, 1], "ID_AA64MMFR1_EL1"),
        ([3, 0, 0, 7, 2], "ID_AA64MMFR2_EL1"),
        ([3, 0, 0, 7, 3], "ID_AA64MMFR3_EL1"),
        ([3, 0, 0, 7, 4], "ID_AA64MMFR4_EL1"),
        ([3, 1, 0, 0, 1], "CLIDR_EL1"),
        ([3, 1, 0, 0, 7], "AIDR_EL1"),
        ([3, 3, 0, 0, 1], "CTR_EL0"),
        ([3, 3, 0, 0, 7], "DCZID_EL0"),
    ];
    match sys_reg_fields(id) {
        Some(f) => NAMES.iter().find(|(e, _)| *e == f).map_or_else(|| format!("S{}_{}_C{}_C{}_{}", f[0], f[1], f[2], f[3], f[4]), |(_, n)| n.to_string()),
        None => format!("{id:#x}"),
    }
}

#[cfg(any(target_arch = "aarch64", test))]
/// "ARM part 0xd0c r3p1": implementer, part number, variant and revision.
fn describe_midr(midr: u64) -> String {
    const IMPLEMENTERS: &[(u64, &str)] = &[
        (0x41, "ARM"),
        (0x42, "Broadcom"),
        (0x43, "Cavium"),
        (0x46, "Fujitsu"),
        (0x48, "HiSilicon"),
        (0x4e, "NVIDIA"),
        (0x50, "APM"),
        (0x51, "Qualcomm"),
        (0x61, "Apple"),
        (0x6d, "Microsoft"),
        (0xc0, "Ampere"),
    ];
    let implementer = (midr >> 24) & 0xff;
    let name = IMPLEMENTERS.iter().find(|(i, _)| *i == implementer).map_or_else(|| format!("implementer {implementer:#x}"), |(_, n)| n.to_string());
    format!("{name} part {:#x} r{}p{}", (midr >> 4) & 0xfff, (midr >> 20) & 0xf, midr & 0xf)
}

#[cfg(any(target_arch = "aarch64", test))]
/// From KVM_REG_ARM64_SVE_VLS: bit `vq - 1` for each vector length of `vq` 128-bit quadwords.
fn sve_max_vl(vls: &[u64]) -> u32 {
    let top = vls.iter().enumerate().rev().find(|&(_, w)| *w != 0).map(|(i, w)| i as u32 * 64 + 64 - w.leading_zeros());
    top.unwrap_or(0) * 16
}

#[cfg(any(target_arch = "aarch64", test))]
/// As Firecracker's create_gic: a GICv3 with its ITS, else a GICv2.
fn gic_version(v3: bool, its: bool, v2: bool) -> Result<u32> {
    Ok(match (v3 && its, v2) {
        (true, _) => 3,
        (false, true) => 2,
        (false, false) => bail!("KVM offers no vGIC that Firecracker can create"),
    })
}

impl Arm64 {
    #[cfg(any(target_arch = "aarch64", test))]
    /// `ids` holds every identification register `regs` names, and MIDR_EL1.
    fn of_probe(
        regs: BTreeSet<u64>,
        ids: &BTreeMap<u64, u64>,
        cntfrq_hz: u64,
        sve_vls: Option<&[u64]>,
        gic: u32,
        pvtime: bool,
        firecracker: String,
    ) -> Result<Self> {
        let midr = *ids.get(&MIDR_EL1).ok_or("KVM has no MIDR_EL1")?;
        if cntfrq_hz == 0 {
            bail!("CNTFRQ_EL0 reads zero");
        }
        Ok(Arm64 {
            cpu: describe_midr(midr),
            cntfrq_hz,
            regs,
            firecracker,
            id_regs: ids.iter().map(|(&id, &value)| (reg_name(id), value)).collect(),
            sve_max_vl: sve_vls.map_or(0, sve_max_vl),
            gic,
            pvtime,
        })
    }

    /// Firecracker saves every register KVM lists and sets each on a load, which fails for one
    /// the target lacks. Kernels before writable ID registers (6.7) refuse an ID register that
    /// differs at all, so these must match exactly, as must what the guest reads unvirtualised.
    pub fn check_saved(&self, host: &Self, regs: &BTreeSet<u64>) -> Result<()> {
        super::check_identity([&self.cpu, &self.firecracker], [&host.cpu, &host.firecracker])?;
        if self.cntfrq_hz != host.cntfrq_hz {
            bail!(
                "snapshot incompatible with this host: counter frequency differs (snapshot: {} Hz; host: {} Hz), which arm64 cannot scale",
                self.cntfrq_hz,
                host.cntfrq_hz
            );
        }
        let missing: Vec<_> = regs.difference(&host.regs).map(|&id| reg_name(id)).collect();
        if !missing.is_empty() {
            bail!("snapshot incompatible with this host: KVM lacks saved registers {}", missing.join(", "));
        }
        for (name, want) in &self.id_regs {
            if host.id_regs.get(name) != Some(want) {
                let here = host.id_regs.get(name).map_or("none".into(), |v| format!("{v:#x}"));
                bail!("snapshot incompatible with this host: {name} differs (snapshot: {want:#x}; host: {here})");
            }
        }
        if self.sve_max_vl != host.sve_max_vl {
            bail!("snapshot incompatible with this host: SVE vector length differs (snapshot: {} bytes; host: {} bytes)", self.sve_max_vl, host.sve_max_vl);
        }
        if self.gic != host.gic {
            bail!("snapshot incompatible with this host: vGIC differs (snapshot: GICv{}; host: GICv{})", self.gic, host.gic);
        }
        if self.pvtime && !host.pvtime {
            bail!("snapshot incompatible with this host: KVM lacks stolen-time reporting (pvtime) that the guest was booted with");
        }
        Ok(())
    }
}

#[cfg(target_arch = "aarch64")]
mod kvm {
    use std::collections::{BTreeMap, BTreeSet};
    use std::fs::File;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

    use super::super::ioctl;
    use super::*;

    // _IO/_IOR/_IOW/_IOWR(KVMIO = 0xae, nr, size), checked in tests.
    pub(super) const KVM_CREATE_VM: libc::c_ulong = 0xae01;
    pub(super) const KVM_CHECK_EXTENSION: libc::c_ulong = 0xae03;
    pub(super) const KVM_CREATE_VCPU: libc::c_ulong = 0xae41;
    pub(super) const KVM_GET_ONE_REG: libc::c_ulong = 0x4010_aeab;
    pub(super) const KVM_ARM_VCPU_INIT: libc::c_ulong = 0x4020_aeae;
    pub(super) const KVM_ARM_PREFERRED_TARGET: libc::c_ulong = 0x8020_aeaf;
    pub(super) const KVM_GET_REG_LIST: libc::c_ulong = 0xc008_aeb0;
    pub(super) const KVM_CREATE_DEVICE: libc::c_ulong = 0xc00c_aee0;
    pub(super) const KVM_HAS_DEVICE_ATTR: libc::c_ulong = 0x4018_aee3;
    const KVM_CAP_ARM_SVE: libc::c_ulong = 170;
    const KVM_ARM_VCPU_PSCI_0_2: u32 = 2;
    const KVM_ARM_VCPU_SVE: u32 = 4;
    const KVM_CREATE_DEVICE_TEST: u32 = 1;
    const KVM_DEV_TYPE_ARM_VGIC_V2: u32 = 5;
    const KVM_DEV_TYPE_ARM_VGIC_V3: u32 = 7;
    const KVM_DEV_TYPE_ARM_VGIC_ITS: u32 = 8;
    const KVM_ARM_VCPU_PVTIME_CTRL: u32 = 2;
    const KVM_ARM_VCPU_PVTIME_IPA: u64 = 0;
    /// KVM_REG_ARM64 | KVM_REG_ARM64_SVE | KVM_REG_SIZE_U512 | 0xffff.
    pub(super) const KVM_REG_ARM64_SVE_VLS: u64 = 0x6060_0000_0015_ffff;

    /// struct kvm_vcpu_init { __u32 target; __u32 features[7]; }
    pub(super) type VcpuInit = [u32; 8];

    /// struct kvm_device_attr.
    #[repr(C)]
    pub(super) struct DeviceAttr {
        flags: u32,
        group: u32,
        attr: u64,
        addr: u64,
    }

    /// A vCPU as Firecracker's default_kvi initialises one, plus `features`. No memory, guest
    /// code or KVM_RUN; the caller drops these off-thread, as destroying a VM waits out RCU.
    fn probe_vcpu(kvm: &File, features: u32) -> Result<(OwnedFd, OwnedFd)> {
        let vm = unsafe { OwnedFd::from_raw_fd(ioctl(kvm, KVM_CREATE_VM, 0, "KVM_CREATE_VM")?) };
        let mut init: VcpuInit = [0; 8];
        ioctl(&vm, KVM_ARM_PREFERRED_TARGET, init.as_mut_ptr() as libc::c_ulong, "KVM_ARM_PREFERRED_TARGET")?;
        init[1] |= 1 << KVM_ARM_VCPU_PSCI_0_2 | features;
        let vcpu = unsafe { OwnedFd::from_raw_fd(ioctl(&vm, KVM_CREATE_VCPU, 0, "KVM_CREATE_VCPU")?) };
        ioctl(&vcpu, KVM_ARM_VCPU_INIT, init.as_ptr() as libc::c_ulong, "KVM_ARM_VCPU_INIT")?;
        Ok((vm, vcpu))
    }

    /// struct kvm_one_reg { __u64 id; __u64 addr; } into `value`, whose size `id` encodes.
    fn get_reg<T>(vcpu: &OwnedFd, id: u64, value: &mut T) -> Result<()> {
        let reg = [id, value as *mut T as u64];
        ioctl(vcpu, KVM_GET_ONE_REG, reg.as_ptr() as libc::c_ulong, &format!("KVM_GET_ONE_REG({})", reg_name(id)))?;
        Ok(())
    }

    fn reg_list(vcpu: &OwnedFd) -> Result<BTreeSet<u64>> {
        // struct kvm_reg_list { __u64 n; __u64 reg[]; }: KVM reports the size it needs with E2BIG.
        let mut buf = vec![0u64; 1];
        let result = unsafe { libc::ioctl(vcpu.as_raw_fd(), KVM_GET_REG_LIST, buf.as_mut_ptr()) };
        crate::syscall_check!(result < 0 && std::io::Error::last_os_error().raw_os_error() != Some(libc::E2BIG), "KVM_GET_REG_LIST");
        buf.resize(1 + buf[0] as usize, 0);
        crate::syscall_check!(unsafe { libc::ioctl(vcpu.as_raw_fd(), KVM_GET_REG_LIST, buf.as_mut_ptr()) } < 0, "KVM_GET_REG_LIST");
        let n = (buf[0] as usize).min(buf.len() - 1);
        Ok(buf[1..1 + n].iter().copied().collect())
    }

    /// KVM_CREATE_DEVICE_TEST: whether KVM could create one, without creating it.
    fn can_create(vm: &OwnedFd, kind: u32) -> bool {
        // struct kvm_create_device { __u32 type; __u32 fd; __u32 flags; }
        let mut device = [kind, 0, KVM_CREATE_DEVICE_TEST];
        unsafe { libc::ioctl(vm.as_raw_fd(), KVM_CREATE_DEVICE, device.as_mut_ptr()) == 0 }
    }

    fn cntfrq() -> u64 {
        let hz: u64;
        unsafe { std::arch::asm!("mrs {}, cntfrq_el0", out(reg) hz, options(nomem, nostack, preserves_flags)) };
        hz
    }

    pub fn probe(kvm: &File, firecracker: String) -> Result<Arm64> {
        let (vm, vcpu) = probe_vcpu(kvm, 0)?;
        let regs = reg_list(&vcpu)?;
        let mut ids = BTreeMap::new();
        for &id in regs.iter().filter(|&&id| is_id_reg(id)).chain([&MIDR_EL1]) {
            let mut value = 0u64;
            get_reg(&vcpu, id, &mut value)?;
            ids.insert(id, value);
        }
        let attr = DeviceAttr { flags: 0, group: KVM_ARM_VCPU_PVTIME_CTRL, attr: KVM_ARM_VCPU_PVTIME_IPA, addr: 0 };
        let pvtime = unsafe { libc::ioctl(vcpu.as_raw_fd(), KVM_HAS_DEVICE_ATTR, &attr) } == 0;
        let gic = gic_version(can_create(&vm, KVM_DEV_TYPE_ARM_VGIC_V3), can_create(&vm, KVM_DEV_TYPE_ARM_VGIC_ITS), can_create(&vm, KVM_DEV_TYPE_ARM_VGIC_V2));
        std::thread::spawn(move || drop((vcpu, vm)));
        // Vector lengths are readable only on a vCPU with SVE, which a VM's others must share.
        let mut vls = [0u64; 8];
        let sve = ioctl(kvm, KVM_CHECK_EXTENSION, KVM_CAP_ARM_SVE, "KVM_CHECK_EXTENSION(ARM_SVE)")? > 0;
        if sve {
            let (vm, vcpu) = probe_vcpu(kvm, 1 << KVM_ARM_VCPU_SVE)?;
            let read = get_reg(&vcpu, KVM_REG_ARM64_SVE_VLS, &mut vls);
            std::thread::spawn(move || drop((vcpu, vm)));
            read?;
        }
        Arm64::of_probe(regs, &ids, cntfrq(), sve.then_some(&vls[..]), gic?, pvtime, firecracker)
    }
}

#[cfg(target_arch = "aarch64")]
pub(super) use kvm::probe;

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    const ID_AA64PFR0_EL1: u64 = sys_reg(3, 0, 0, 4, 0);
    const ID_AA64ISAR0_EL1: u64 = sys_reg(3, 0, 0, 6, 0);
    /// KVM_REG_ARM_CORE regs.regs[0].
    const X0: u64 = 0x6030_0000_0010_0000;

    /// A Neoverse N1 host with a GICv3 and no SVE.
    pub(crate) fn host() -> Arm64 {
        let ids = [(MIDR_EL1, 0x413f_d0c1), (ID_AA64PFR0_EL1, 0x1100_0000_1011_1112), (ID_AA64ISAR0_EL1, 0x1000_1000_1021_0000)].into();
        let regs = [X0, MIDR_EL1, ID_AA64PFR0_EL1, ID_AA64ISAR0_EL1].into();
        Arm64::of_probe(regs, &ids, 25_000_000, None, 3, true, "Firecracker v1.17.0 (content a)".into()).unwrap()
    }

    /// Probes this host's KVM, which CI's arm runners lack (and `--ignored` is for root-only
    /// tests): `FLEXVM_TEST_KVM=1 cargo test -p flexvm probes_this_host -- --nocapture`.
    #[cfg(target_arch = "aarch64")]
    #[test]
    fn probes_this_host() {
        if std::env::var_os("FLEXVM_TEST_KVM").is_none() {
            return;
        }
        let kvm = std::fs::File::open("/dev/kvm").unwrap();
        let probed = kvm::probe(&kvm, "f".into()).unwrap();
        println!("{}", serde_json::to_string_pretty(&super::super::Compat::Aarch64(probed.clone())).unwrap());
        assert!(probed.id_regs.contains_key("MIDR_EL1") && probed.id_regs.contains_key("ID_AA64PFR0_EL1"), "{:?}", probed.id_regs);
        assert!(probed.regs.contains(&X0) && probed.regs.contains(&ID_AA64PFR0_EL1));
        assert!(probed.cntfrq_hz > 0 && (probed.gic == 2 || probed.gic == 3));
        // A second probe finds the same, and the record survives a round trip and checks against itself.
        assert_eq!(kvm::probe(&kvm, "f".into()).unwrap(), probed);
        let compat = super::super::Compat::Aarch64(probed);
        let back: super::super::Compat = serde_json::from_slice(&serde_json::to_vec(&compat).unwrap()).unwrap();
        assert_eq!(back, compat);
        compat.check(&back).unwrap();
    }

    #[test]
    fn sys_reg_encodings_match_the_uapi() {
        // ARM64_SYS_REG() values from asm/kvm.h.
        assert_eq!(MIDR_EL1, 0x6030_0000_0013_c000);
        assert_eq!(sys_reg(3, 0, 0, 0, 5), 0x6030_0000_0013_c005);
        assert_eq!(ID_AA64PFR0_EL1, 0x6030_0000_0013_c020);
        assert_eq!(sys_reg(3, 0, 0, 7, 4), 0x6030_0000_0013_c03c);
        assert_eq!(sys_reg(3, 3, 0, 0, 1), 0x6030_0000_0013_d801);
        assert_eq!(sys_reg(3, 1, 0, 0, 1), 0x6030_0000_0013_c801);
        assert_eq!(sys_reg_fields(sys_reg(3, 0, 0, 7, 4)), Some([3, 0, 0, 7, 4]));
        // Core, SVE and 32-bit registers are not system registers.
        assert_eq!(sys_reg_fields(X0), None);
        assert_eq!(sys_reg_fields(0x6060_0000_0015_ffff), None);
        assert_eq!(sys_reg_fields(MIDR_EL1 & !KVM_REG_SIZE_MASK | 0x0020_0000_0000_0000), None);
    }

    #[cfg(target_arch = "aarch64")]
    #[test]
    fn ioctl_numbers_match_the_uapi() {
        // _IOC(dir, KVMIO, nr, size) for the structs each takes.
        const fn ioc(dir: u64, nr: u64, size: usize) -> libc::c_ulong {
            (dir << 30 | (size as u64) << 16 | 0xae << 8 | nr) as libc::c_ulong
        }
        let (w, r) = (1, 2);
        assert_eq!(kvm::KVM_GET_ONE_REG, ioc(w, 0xab, size_of::<[u64; 2]>()));
        assert_eq!(kvm::KVM_ARM_VCPU_INIT, ioc(w, 0xae, size_of::<kvm::VcpuInit>()));
        assert_eq!(kvm::KVM_ARM_PREFERRED_TARGET, ioc(r, 0xaf, size_of::<kvm::VcpuInit>()));
        assert_eq!(kvm::KVM_GET_REG_LIST, ioc(r | w, 0xb0, size_of::<u64>()));
        assert_eq!(kvm::KVM_CREATE_DEVICE, ioc(r | w, 0xe0, size_of::<[u32; 3]>()));
        assert_eq!(kvm::KVM_HAS_DEVICE_ATTR, ioc(w, 0xe3, size_of::<kvm::DeviceAttr>()));
        assert_eq!([kvm::KVM_CREATE_VM, kvm::KVM_CHECK_EXTENSION, kvm::KVM_CREATE_VCPU], [ioc(0, 1, 0), ioc(0, 3, 0), ioc(0, 0x41, 0)]);
        // KVM_REG_ARM64 | KVM_REG_ARM64_SVE (0x15 << 16) | KVM_REG_SIZE_U512 (6 << 52) | 0xffff.
        assert_eq!(kvm::KVM_REG_ARM64_SVE_VLS, KVM_REG_ARM64 | 6 << 52 | 0x15 << 16 | 0xffff);
    }

    #[test]
    fn picks_the_identification_registers() {
        for id in
            [MIDR_EL1, sys_reg(3, 0, 0, 0, 6), ID_AA64PFR0_EL1, sys_reg(3, 0, 0, 1, 0), sys_reg(3, 1, 0, 0, 1), sys_reg(3, 1, 0, 0, 7), sys_reg(3, 3, 0, 0, 1)]
        {
            assert!(is_id_reg(id), "{}", reg_name(id));
        }
        // MPIDR, SCTLR_EL1, CSSELR_EL1, TPIDR_EL0, a core register and the SVE VLS.
        for id in [sys_reg(3, 0, 0, 0, 5), sys_reg(3, 0, 1, 0, 0), sys_reg(3, 2, 0, 0, 0), sys_reg(3, 3, 13, 0, 2), X0, 0x6060_0000_0015_ffff] {
            assert!(!is_id_reg(id), "{}", reg_name(id));
        }
        assert_eq!(reg_name(ID_AA64PFR0_EL1), "ID_AA64PFR0_EL1");
        assert_eq!(reg_name(sys_reg(3, 3, 0, 0, 1)), "CTR_EL0");
        assert_eq!(reg_name(sys_reg(3, 0, 0, 2, 3)), "S3_0_C0_C2_3");
        assert_eq!(reg_name(X0), "0x6030000000100000");
    }

    #[test]
    fn decodes_midr_and_sve_lengths() {
        assert_eq!(describe_midr(0x413f_d0c1), "ARM part 0xd0c r3p1");
        assert_eq!(describe_midr(0x431f_0af1), "Cavium part 0xaf r1p1");
        assert_eq!(describe_midr(0x7f00_1000), "implementer 0x7f part 0x100 r0p0");
        assert_eq!(host().cpu, "ARM part 0xd0c r3p1");
        // 128 to 512 bits; 2048 bits; none.
        assert_eq!(sve_max_vl(&[0b1011, 0, 0, 0, 0, 0, 0, 0]), 64);
        assert_eq!(sve_max_vl(&[0xffff, 0, 0, 0, 0, 0, 0, 0]), 256);
        assert_eq!(sve_max_vl(&[0; 8]), 0);
        assert_eq!(sve_max_vl(&[0, 1, 0, 0, 0, 0, 0, 0]), 65 * 16);
    }

    #[test]
    fn gic_follows_firecracker_fallback() {
        assert_eq!(gic_version(true, true, true).unwrap(), 3);
        assert_eq!(gic_version(true, true, false).unwrap(), 3);
        // A GICv3 Firecracker cannot give an ITS fails over to a GICv2.
        assert_eq!(gic_version(true, false, true).unwrap(), 2);
        assert_eq!(gic_version(false, false, true).unwrap(), 2);
        assert!(gic_version(true, false, false).is_err());
        assert!(gic_version(false, false, false).is_err());
    }

    #[test]
    fn records_what_the_probe_found() {
        let h = host();
        assert_eq!(h.id_regs["MIDR_EL1"], 0x413f_d0c1);
        assert_eq!(h.id_regs["ID_AA64PFR0_EL1"], 0x1100_0000_1011_1112);
        assert_eq!(h.regs.len(), 4);
        let sve = Arm64::of_probe(h.regs.clone(), &[(MIDR_EL1, 0x410f_d4f0)].into(), 1_000_000_000, Some(&[0b1111, 0, 0, 0, 0, 0, 0, 0]), 3, true, "f".into())
            .unwrap();
        assert_eq!(sve.sve_max_vl, 64);
        assert!(Arm64::of_probe(h.regs.clone(), &BTreeMap::new(), 1, None, 3, true, "f".into()).is_err());
        assert!(Arm64::of_probe(h.regs.clone(), &[(MIDR_EL1, 1)].into(), 0, None, 3, true, "f".into()).is_err());
        assert_eq!(serde_json::from_value::<Arm64>(serde_json::to_value(&h).unwrap()).unwrap(), h);
    }

    #[test]
    fn accepts_the_same_host_and_extra_registers() {
        let snapshot = host();
        snapshot.check_saved(&snapshot, &snapshot.regs).unwrap();
        let mut more = snapshot.clone();
        more.regs.insert(sys_reg(3, 0, 1, 0, 0));
        more.id_regs.insert("ID_AA64PFR2_EL1".into(), 0);
        more.pvtime = true;
        snapshot.check_saved(&more, &snapshot.regs).unwrap();
        // A VM state saved where there were more registers needs them all.
        let error = snapshot.check_saved(&snapshot, &more.regs).unwrap_err().to_string();
        assert!(error.contains("KVM lacks saved registers S3_0_C1_C0_0"), "{error}");
        snapshot.check_saved(&more, &more.regs).unwrap();
        // A guest booted without stolen time loads where there is.
        let mut without = snapshot.clone();
        without.pvtime = false;
        without.check_saved(&snapshot, &snapshot.regs).unwrap();
    }

    #[test]
    fn rejects_each_mismatch_with_its_name() {
        let snapshot = host();
        type Change = fn(&mut Arm64);
        let cases: [(Change, &str); 10] = [
            (|h| h.cpu = "ARM part 0xd40 r1p1".into(), "CPU differs"),
            (|h| h.firecracker = "Firecracker v1.18.0 (content a)".into(), "Firecracker differs"),
            (|h| h.cntfrq_hz = 25_000_001, "counter frequency differs (snapshot: 25000000 Hz; host: 25000001 Hz)"),
            (
                |h| {
                    h.regs.remove(&X0);
                },
                "KVM lacks saved registers 0x6030000000100000",
            ),
            (
                |h| {
                    h.regs.remove(&ID_AA64ISAR0_EL1);
                },
                "saved registers ID_AA64ISAR0_EL1",
            ),
            // Fewer features, and more: an older kernel refuses any ID register that differs.
            (|h| *h.id_regs.get_mut("ID_AA64PFR0_EL1").unwrap() &= !0xf, "ID_AA64PFR0_EL1 differs (snapshot: 0x1100000010111112; host: 0x1100000010111110)"),
            (|h| *h.id_regs.get_mut("ID_AA64ISAR0_EL1").unwrap() |= 0xf << 60, "ID_AA64ISAR0_EL1 differs"),
            (
                |h| {
                    h.id_regs.remove("ID_AA64ISAR0_EL1");
                },
                "ID_AA64ISAR0_EL1 differs (snapshot: 0x1000100010210000; host: none)",
            ),
            (|h| h.gic = 2, "vGIC differs (snapshot: GICv3; host: GICv2)"),
            (|h| h.pvtime = false, "stolen-time"),
        ];
        for (change, expected) in cases {
            let mut h = snapshot.clone();
            change(&mut h);
            let e = snapshot.check_saved(&h, &snapshot.regs).unwrap_err().to_string();
            assert!(e.contains(expected), "{e}");
        }
        let mut sve = snapshot.clone();
        sve.sve_max_vl = 32;
        let e = sve.check_saved(&snapshot, &snapshot.regs).unwrap_err().to_string();
        assert!(e.contains("SVE vector length differs (snapshot: 32 bytes; host: 0 bytes)"), "{e}");
    }
}
