//! Snapshot compatibility preflight. A template records its build host's architecture, CPU
//! model, what KVM offered a vCPU (passed through: no CPU template) and Firecracker. On x86_64
//! that is the CPUID features, XSAVE layout, TSC rate and saved MSR set; on aarch64 the ID
//! registers, counter frequency, saved register list, SVE vector length and vGIC. Checkpoints
//! and migrations pin their template and check what the saving host's Firecracker saved: its
//! MSRs and effective TSC rate, or its registers. Topology, cache and leaf-limit words are not
//! compared: Firecracker rewrites the first, the rest do not change what the guest can run.
//!
//! Records from before aarch64 have no `arch` and read as x86_64; an x86_64 record is written
//! exactly as before, so a template's content id does not change. A record from one
//! architecture is refused on the other.
use std::collections::BTreeSet;
use std::fs::File;
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use serde::{de::Error as _, Deserialize, Deserializer, Serialize, Serializer};
use serde_json::{Map, Value};

use crate::template::{hash_file, Stamp};
use crate::{bail, util::Result};

mod arm64;
mod x86;

pub use arm64::Arm64;
pub use x86::X86;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Arch {
    X86_64,
    Aarch64,
}

impl std::fmt::Display for Arch {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.write_str(match self {
            Arch::X86_64 => "x86_64",
            Arch::Aarch64 => "aarch64",
        })
    }
}

impl Arch {
    /// A record's `arch`; one without is from before aarch64, so x86_64.
    fn of(record: &Map<String, Value>) -> std::result::Result<Self, serde_json::Error> {
        record.get("arch").map_or(Ok(Arch::X86_64), Arch::deserialize)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Compat {
    X86_64(X86),
    Aarch64(Arm64),
}

/// An x86_64 record as before, with no tag; an aarch64 one tagged `"arch": "aarch64"`.
impl Serialize for Compat {
    fn serialize<S: Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        #[derive(Serialize)]
        struct Tagged<'a, T> {
            arch: Arch,
            #[serde(flatten)]
            record: &'a T,
        }
        match self {
            Compat::X86_64(c) => c.serialize(s),
            Compat::Aarch64(c) => Tagged { arch: Arch::Aarch64, record: c }.serialize(s),
        }
    }
}

impl<'de> Deserialize<'de> for Compat {
    fn deserialize<D: Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        let record = Map::deserialize(d)?;
        match Arch::of(&record).map_err(D::Error::custom)? {
            Arch::X86_64 => serde_json::from_value(Value::Object(record)).map(Compat::X86_64),
            Arch::Aarch64 => serde_json::from_value(Value::Object(record)).map(Compat::Aarch64),
        }
        .map_err(D::Error::custom)
    }
}

impl Compat {
    pub fn arch(&self) -> Arch {
        match self {
            Compat::X86_64(_) => Arch::X86_64,
            Compat::Aarch64(_) => Arch::Aarch64,
        }
    }

    pub fn check(&self, host: &Self) -> Result<()> {
        self.check_saved(host, &self.saved()).map(drop)
    }

    /// What a VM state freshly booted from this template carries.
    pub fn saved(&self) -> Saved {
        match self {
            Compat::X86_64(c) => Saved::X86_64 { tsc_khz: c.tsc_khz, msrs: c.msrs.clone() },
            Compat::Aarch64(c) => Saved::Aarch64 { regs: c.regs.clone() },
        }
    }

    /// Checks a VM state of this template, `saved` on whichever host, against `host`. Returns
    /// what the state carries once loaded there: on x86_64 Firecracker keeps the host's default
    /// TSC rate within 250 ppm and scales to the saved one beyond that.
    pub fn check_saved(&self, host: &Self, saved: &Saved) -> Result<Saved> {
        if self.arch() != host.arch() {
            bail!(
                "snapshot incompatible with this host: it is {}, this host is {}: a VM runs only on the architecture it was built on",
                self.arch(),
                host.arch()
            );
        }
        match (self, host, saved) {
            (Compat::X86_64(snapshot), Compat::X86_64(host), Saved::X86_64 { tsc_khz, msrs }) => {
                Ok(Saved::X86_64 { tsc_khz: snapshot.check_saved(host, *tsc_khz, msrs)?, msrs: msrs.clone() })
            }
            (Compat::Aarch64(snapshot), Compat::Aarch64(host), Saved::Aarch64 { regs }) => {
                snapshot.check_saved(host, regs)?;
                Ok(saved.clone())
            }
            _ => bail!("VM state saved on {} for a template built on {}", saved.arch(), self.arch()),
        }
    }

    /// What a VM state this host saves carries, `loaded` as `check_saved` returned it: the
    /// rate it runs at and what this host's Firecracker saves, which may be more than its template's.
    pub fn saves(&self, loaded: &Saved) -> Result<Saved> {
        Ok(match (self, loaded) {
            (Compat::X86_64(host), Saved::X86_64 { tsc_khz, .. }) => Saved::X86_64 { tsc_khz: *tsc_khz, msrs: host.msrs.clone() },
            (Compat::Aarch64(host), Saved::Aarch64 { .. }) => Saved::Aarch64 { regs: host.regs.clone() },
            _ => bail!("{} VM on an {} host", loaded.arch(), self.arch()),
        })
    }

    #[cfg(test)]
    pub fn x86_mut(&mut self) -> &mut X86 {
        match self {
            Compat::X86_64(c) => c,
            Compat::Aarch64(_) => panic!("not x86_64"),
        }
    }
}

/// What Firecracker saved with a VM state on the host that took it, which a loading host must support.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Saved {
    /// The effective vCPU TSC rate, which can differ from its template's, and the KVM MSRs.
    X86_64 { tsc_khz: u32, msrs: BTreeSet<u32> },
    /// The KVM_GET_REG_LIST registers. The counter frequency is the template's: arm64 cannot scale it.
    Aarch64 { regs: BTreeSet<u64> },
}

impl Saved {
    pub fn arch(&self) -> Arch {
        match self {
            Saved::X86_64 { .. } => Arch::X86_64,
            Saved::Aarch64 { .. } => Arch::Aarch64,
        }
    }

    /// Its fields named `{prefix}msrs` and `{prefix}tsc_khz` as before aarch64, or tagged.
    fn to_map(&self, prefix: &str) -> Map<String, Value> {
        let mut map = Map::new();
        match self {
            Saved::X86_64 { tsc_khz, msrs } => {
                map.insert(format!("{prefix}msrs"), serde_json::json!(msrs));
                map.insert(format!("{prefix}tsc_khz"), serde_json::json!(tsc_khz));
            }
            Saved::Aarch64 { regs } => {
                map.insert("arch".into(), serde_json::json!(Arch::Aarch64));
                map.insert(format!("{prefix}regs"), serde_json::json!(regs));
            }
        }
        map
    }

    fn of_map(map: &Map<String, Value>, prefix: &str) -> std::result::Result<Self, String> {
        fn field<T: serde::de::DeserializeOwned>(map: &Map<String, Value>, key: String) -> std::result::Result<T, String> {
            let value = map.get(&key).ok_or_else(|| format!("missing field `{key}`"))?;
            T::deserialize(value).map_err(|e| format!("bad {key}: {e}"))
        }
        Ok(match Arch::of(map).map_err(|e| format!("bad arch: {e}"))? {
            Arch::X86_64 => Saved::X86_64 { msrs: field(map, format!("{prefix}msrs"))?, tsc_khz: field(map, format!("{prefix}tsc_khz"))? },
            Arch::Aarch64 => Saved::Aarch64 { regs: field(map, format!("{prefix}regs"))? },
        })
    }

    /// As a migration request carries it: `msrs` and `tsc_khz` on x86_64, as before aarch64.
    pub fn to_request(&self) -> Map<String, Value> {
        self.to_map("")
    }

    pub fn of_request(req: &Value) -> Result<Self> {
        Ok(Self::of_map(req.as_object().ok_or("request is not an object")?, "")?)
    }
}

/// In a manifest, flattened: `saved_msrs` and `saved_tsc_khz` on x86_64, as before aarch64.
impl Serialize for Saved {
    fn serialize<S: Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        self.to_map("saved_").serialize(s)
    }
}

impl<'de> Deserialize<'de> for Saved {
    fn deserialize<D: Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        Self::of_map(&Map::deserialize(d)?, "saved_").map_err(D::Error::custom)
    }
}

/// The CPU model and Firecracker must be the same on both hosts.
fn check_identity(snapshot: [&String; 2], host: [&String; 2]) -> Result<()> {
    let hints = ["every host needs the same CPU model", "copy one Firecracker binary to every host; templates built with another must be rebuilt"];
    for (((what, snapshot), here), hint) in ["CPU", "Firecracker"].into_iter().zip(snapshot).zip(host).zip(hints) {
        if snapshot != here {
            bail!("snapshot incompatible with this host: {what} differs (snapshot: {snapshot}; host: {here}): {hint}");
        }
    }
    Ok(())
}

/// Identity of the host probe: this boot, this flexvm and Firecracker, and the KVM device
/// and modules by (device, inode), which a module reload changes and a ctime touch does not.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct HostKey {
    boot_id: String,
    microcode: Vec<String>,
    flexvm: Stamp,
    firecracker: Stamp,
    kvm: (u64, u64),
    modules: Vec<Option<(u64, u64)>>,
}

#[cfg(target_arch = "x86_64")]
const KVM_MODULES: &[&str] = &["kvm", "kvm_intel", "kvm_amd"];
#[cfg(not(target_arch = "x86_64"))]
const KVM_MODULES: &[&str] = &["kvm"];

fn node(m: &std::fs::Metadata) -> (u64, u64) {
    use std::os::unix::fs::MetadataExt;
    (m.dev(), m.ino())
}

impl HostKey {
    fn local(firecracker: Stamp) -> Result<Self> {
        let boot_id = std::fs::read_to_string("/proc/sys/kernel/random/boot_id")?;
        if boot_id.trim().is_empty() {
            bail!("empty boot id");
        }
        let mut modules = vec![None; KVM_MODULES.len()];
        for (slot, name) in modules.iter_mut().zip(KVM_MODULES) {
            match std::fs::metadata(format!("/sys/module/{name}")) {
                Ok(m) => *slot = Some(node(&m)),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(e.into()),
            }
        }
        let flexvm = Stamp::of(&std::fs::metadata("/proc/self/exe")?);
        // A late microcode load changes what the CPU reports; a host that shows no revision (a guest,
        // a non-x86 CPU) keeps an empty, still stable, key rather than probing every time.
        let mut microcode: Vec<_> = std::fs::read_to_string("/proc/cpuinfo")?
            .lines()
            .filter_map(|line| {
                let (key, value) = line.split_once(':')?;
                (key.trim() == "microcode").then(|| value.trim().to_string())
            })
            .collect();
        microcode.dedup();
        Ok(Self { boot_id, microcode, flexvm, firecracker, kvm: node(&std::fs::metadata("/dev/kvm")?), modules })
    }
}

#[derive(Serialize, Deserialize)]
struct HostCache {
    key: HostKey,
    compat: Compat,
}

/// Cache failures only cost another probe. Version the probe as well as its inputs
/// so a future change to the CPUID/MSR selection can invalidate older results.
fn host_compat(run: Option<&Path>, key: Option<&HostKey>, probe: impl FnOnce() -> Result<Compat>) -> Result<Compat> {
    let read = run.and_then(|d| std::fs::read(d.join("compat.json")).ok()).and_then(|b| serde_json::from_slice::<HostCache>(&b).ok());
    if let Some(cached) = read.filter(|c| Some(&c.key) == key) {
        return Ok(cached.compat);
    }
    let compat = probe()?;
    if let (Some(run), Some(key)) = (run, key) {
        let cached = HostCache { key: key.clone(), compat: compat.clone() };
        let _ = crate::util::write_file(run, "compat.json", &serde_json::to_vec(&cached)?, false);
    }
    Ok(compat)
}

/// Shared across VM processes and cached in-process while the host key is unchanged.
pub fn local(pid: u32) -> Result<Compat> {
    local_binary(&PathBuf::from(format!("/proc/{pid}/exe")))
}

/// Probe the host without starting a VM, using the binary a pull would boot.
pub fn local_binary(firecracker: &Path) -> Result<Compat> {
    static CACHE: Mutex<Option<(HostKey, Compat)>> = Mutex::new(None);
    let stamp = Stamp::of(&std::fs::metadata(firecracker)?);
    // If an identity cannot be read, probe rather than trust an unverifiable cache.
    let key = HostKey::local(stamp).ok();
    let mut cache = CACHE.lock().unwrap();
    if let Some((_, c)) = cache.as_ref().filter(|(k, _)| Some(k) == key.as_ref()) {
        return Ok(c.clone());
    }
    let run = crate::host::run_dir();
    let compat = host_compat(run, key.as_ref(), || {
        let (_, binary) = firecracker_id(firecracker, run)?;
        let kvm = File::open("/dev/kvm").map_err(|e| format!("/dev/kvm: {e}"))?;
        probe(&kvm, binary)
    })?;
    *cache = key.map(|key| (key, compat.clone()));
    Ok(compat)
}

#[cfg(target_arch = "x86_64")]
fn probe(kvm: &File, firecracker: String) -> Result<Compat> {
    x86::probe(kvm, firecracker).map(Compat::X86_64)
}

#[cfg(target_arch = "aarch64")]
fn probe(kvm: &File, firecracker: String) -> Result<Compat> {
    arm64::probe(kvm, firecracker).map(Compat::Aarch64)
}

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
fn probe(_: &File, _: String) -> Result<Compat> {
    bail!("no host compatibility probe for {}", std::env::consts::ARCH)
}

/// Shared across VM processes; an unreadable cache is only a miss.
fn firecracker_id(path: &Path, run: Option<&Path>) -> Result<(Stamp, String)> {
    let stamp = Stamp::of(&std::fs::metadata(path)?);
    if let Some(cached) = run
        .and_then(|d| std::fs::read(d.join("firecracker.json")).ok())
        .and_then(|b| serde_json::from_slice::<(Stamp, String)>(&b).ok())
        .filter(|(s, _)| *s == stamp)
    {
        return Ok(cached);
    }
    // As a VM process spawns Firecracker: signals unblocked, its open-file limit as found.
    let version = crate::util::unblock_signals_in(std::process::Command::new(path).arg("--version")).output()?;
    let version = String::from_utf8_lossy(&version.stdout);
    let version = version.lines().next().filter(|v| !v.is_empty()).ok_or("firecracker --version printed nothing")?;
    let binary = hash_file(path)?;
    let cached = (binary.metadata, format!("{version} (content {})", binary.hash));
    if let Some(run) = run {
        let _ = crate::util::write_file(run, "firecracker.json", &serde_json::to_vec(&cached)?, false);
    }
    Ok(cached)
}

#[cfg_attr(not(any(target_arch = "x86_64", target_arch = "aarch64")), allow(dead_code))]
fn ioctl(fd: &impl AsRawFd, request: libc::c_ulong, arg: libc::c_ulong, name: &str) -> Result<i32> {
    let value = unsafe { libc::ioctl(fd.as_raw_fd(), request, arg) };
    crate::syscall_check!(value < 0, "{name}");
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn host() -> Compat {
        Compat::X86_64(x86::tests::host())
    }

    fn host_key(root: &Path) -> HostKey {
        let m = std::fs::metadata(root).unwrap();
        let stamp = Stamp::of(&m);
        HostKey {
            boot_id: "boot-a".into(),
            microcode: vec!["0x1".into()],
            flexvm: stamp.clone(),
            firecracker: stamp,
            kvm: node(&m),
            modules: vec![Some(node(&m)), None, None],
        }
    }

    /// How many times `host_compat` probed the host (as `host()`) for `key`.
    fn probes(root: &Path, key: &HostKey) -> usize {
        let calls = std::cell::Cell::new(0);
        let compat = host_compat(Some(root), Some(key), || {
            calls.set(calls.get() + 1);
            Ok(host())
        });
        assert_eq!(compat.unwrap(), host());
        calls.get()
    }

    #[test]
    fn host_cache_miss_probes_and_hit_skips_probe() {
        let root = crate::test_util::TempDir::new("host-compat");
        let key = host_key(&root);
        let expected = host();
        assert_eq!(host_compat(Some(&root), Some(&key), || Ok(expected.clone())).unwrap(), expected);
        assert!(root.join("compat.json").is_file());
        assert_eq!(host_compat(Some(&root), Some(&key), || panic!("cache hit must not probe KVM")).unwrap(), expected);
        // A missing run directory or unverifiable host identity must still work.
        assert_eq!(host_compat(None, Some(&key), || Ok(expected.clone())).unwrap(), expected);
        let mut changed = expected.clone();
        changed.x86_mut().tsc_khz += 1;
        assert_eq!(host_compat(Some(&root), None, || Ok(changed.clone())).unwrap(), changed);
        assert_eq!(host_compat(Some(&root), Some(&key), || panic!("missing identity must not overwrite cache")).unwrap(), expected);
        // An aarch64 probe caches as well.
        let arm = Compat::Aarch64(arm64::tests::host());
        let other = HostKey { boot_id: "boot-arm".into(), ..key.clone() };
        assert_eq!(host_compat(Some(&root), Some(&other), || Ok(arm.clone())).unwrap(), arm);
        assert_eq!(host_compat(Some(&root), Some(&other), || panic!("cache hit must not probe KVM")).unwrap(), arm);
    }

    #[test]
    fn host_cache_invalidates_each_host_identity() {
        let root = crate::test_util::TempDir::new("host-compat-key");
        let key = host_key(&root);
        // A different inode provides a distinct stamp without relying on clock resolution.
        let replacement = root.join("replacement");
        std::fs::write(&replacement, b"replacement").unwrap();
        let m = std::fs::metadata(replacement).unwrap();
        let (stamp, inode) = (Stamp::of(&m), node(&m));
        let mut keys = vec![key.clone(); 10];
        keys[0].boot_id = "boot-b".into();
        keys[1].firecracker = stamp.clone();
        keys[2].kvm = inode;
        keys[3].modules[0] = Some(inode);
        keys[4].modules[1] = Some(inode);
        keys[5].modules[2] = Some(inode);
        keys[6].modules[0] = None;
        keys[7].flexvm = stamp;
        keys[8].microcode = vec!["0x2".into()];
        keys[9].modules.truncate(1);
        for changed in keys {
            host_compat(Some(&root), Some(&key), || Ok(host())).unwrap();
            assert_eq!(probes(&root, &changed), 1, "{changed:?}");
            host_compat(Some(&root), Some(&changed), || panic!("replacement must be cached")).unwrap();
        }
    }

    #[test]
    fn a_ctime_change_alone_keeps_the_node_identity() {
        let root = crate::test_util::TempDir::new("host-compat-ctime");
        let before = node(&std::fs::metadata(&root).unwrap());
        // chmod changes the ctime, not the device or inode.
        std::fs::set_permissions(&root, std::os::unix::fs::PermissionsExt::from_mode(0o700)).unwrap();
        assert_eq!(node(&std::fs::metadata(&root).unwrap()), before);
    }

    #[test]
    fn host_cache_reprobes_corrupt_and_incomplete_entries() {
        let root = crate::test_util::TempDir::new("host-compat-invalid");
        let key = host_key(&root);
        let cached = HostCache { key: key.clone(), compat: host() };
        let valid = serde_json::to_value(&cached).unwrap();
        let mut invalid = vec![b"broken".to_vec(), b"{}".to_vec()];
        for field in ["tsc_khz", "tsc_control", "msrs", "features", "xsave", "cpu", "firecracker"] {
            let mut value = valid.clone();
            value["compat"].as_object_mut().unwrap().remove(field);
            invalid.push(serde_json::to_vec(&value).unwrap());
        }
        let mut old_key = valid.clone();
        old_key["key"].as_object_mut().unwrap().remove("microcode");
        invalid.push(serde_json::to_vec(&old_key).unwrap());
        // An x86_64 record tagged aarch64 lacks the aarch64 fields.
        let mut mislabelled = valid.clone();
        mislabelled["compat"]["arch"] = "aarch64".into();
        invalid.push(serde_json::to_vec(&mislabelled).unwrap());
        for bytes in invalid {
            std::fs::write(root.join("compat.json"), bytes).unwrap();
            assert_eq!(probes(&root, &key), 1);
            host_compat(Some(&root), Some(&key), || panic!("repaired cache must hit")).unwrap();
        }
        std::fs::remove_file(root.join("compat.json")).unwrap();
        assert!(host_compat(Some(&root), Some(&key), || bail!("probe failed")).is_err());
        assert!(!root.join("compat.json").exists());
        std::fs::create_dir(root.join("compat.json")).unwrap();
        assert_eq!(host_compat(Some(&root), Some(&key), || Ok(host())).unwrap(), host());
    }

    #[test]
    fn host_cache_from_before_aarch64_still_hits() {
        // Its key had exactly three module slots and its record no arch.
        let root = crate::test_util::TempDir::new("host-compat-old");
        let key = host_key(&root);
        let mut old = serde_json::to_value(HostCache { key: key.clone(), compat: host() }).unwrap();
        assert!(old["compat"].get("arch").is_none() && old["key"]["modules"].as_array().unwrap().len() == 3);
        old["key"]["modules"] = serde_json::json!([old["key"]["modules"][0], null, null]);
        std::fs::write(root.join("compat.json"), serde_json::to_vec(&old).unwrap()).unwrap();
        assert_eq!(host_compat(Some(&root), Some(&key), || panic!("an old cache must still hit")).unwrap(), host());
    }

    #[test]
    fn x86_records_keep_their_form_and_untagged_ones_read_as_x86() {
        // As written before aarch64, which a template's content id hashes.
        let before = r#"{"cpu":"AuthenticAMD family 0x17 model 0x71","tsc_khz":2000000,"tsc_control":false,"msrs":[16,290,3488],"firecracker":"Firecracker v1.17.0 (content a)","features":{"0x1.0.ecx":4160238083,"0x1.0.edx":126614527,"0x7.0.ebx":563872171,"0x7.0.ecx":4194308,"0x7.0.edx":2818572288,"0x80000007.0.edx":256},"xsave":{"2":[256,576]}}"#;
        assert_eq!(serde_json::to_string(&host()).unwrap(), before);
        assert_eq!(serde_json::from_str::<Compat>(before).unwrap(), host());
        let mut tagged: Value = serde_json::from_str(before).unwrap();
        tagged["arch"] = "x86_64".into();
        assert_eq!(serde_json::from_value::<Compat>(tagged.clone()).unwrap(), host());
        tagged["arch"] = "riscv64".into();
        assert!(serde_json::from_value::<Compat>(tagged).unwrap_err().to_string().contains("riscv64"));
        // A missing field is named, not hidden behind an untagged-enum error.
        let mut incomplete: Value = serde_json::from_str(before).unwrap();
        incomplete.as_object_mut().unwrap().remove("xsave");
        assert!(serde_json::from_value::<Compat>(incomplete).unwrap_err().to_string().contains("xsave"));
    }

    #[test]
    fn aarch64_records_are_tagged_and_round_trip() {
        let arm = Compat::Aarch64(arm64::tests::host());
        let json = serde_json::to_value(&arm).unwrap();
        assert_eq!(json["arch"], "aarch64");
        assert!(json.get("tsc_khz").is_none() && json.get("msrs").is_none());
        assert!(serde_json::to_string(&arm).unwrap().starts_with(r#"{"arch":"aarch64","cpu":"#));
        assert_eq!(serde_json::from_value::<Compat>(json.clone()).unwrap(), arm);
        // Without its tag it is no x86_64 record.
        let mut untagged = json;
        untagged.as_object_mut().unwrap().remove("arch");
        assert!(serde_json::from_value::<Compat>(untagged).is_err());
    }

    #[test]
    fn a_record_from_one_arch_is_refused_on_the_other() {
        let (x86, arm) = (host(), Compat::Aarch64(arm64::tests::host()));
        for (snapshot, here) in [(&x86, &arm), (&arm, &x86)] {
            let error = snapshot.check(here).unwrap_err().to_string();
            assert!(error.contains(&format!("it is {}, this host is {}", snapshot.arch(), here.arch())), "{error}");
            assert!(here.saves(&snapshot.saved()).is_err());
        }
        // A VM state of the other arch than its template.
        let error = x86.check_saved(&x86, &arm.saved()).unwrap_err().to_string();
        assert!(error.contains("saved on aarch64 for a template built on x86_64"), "{error}");
        assert!(arm.check_saved(&arm, &x86.saved()).is_err());
        x86.check(&x86).unwrap();
        arm.check(&arm).unwrap();
    }

    #[test]
    fn a_saving_host_records_its_own_registers_and_the_loaded_rate() {
        let template = host();
        let mut source = template.clone();
        source.x86_mut().msrs.insert(0x3b);
        source.x86_mut().tsc_khz = 1_999_600;
        let loaded = template.check_saved(&source, &template.saved()).unwrap();
        assert_eq!(loaded, Saved::X86_64 { tsc_khz: 1_999_600, msrs: x86::tests::host().msrs });
        let saved = source.saves(&loaded).unwrap();
        assert_eq!(saved, Saved::X86_64 { tsc_khz: 1_999_600, msrs: [0x10, 0x3b, 0x122, 0xda0].into() });
        // A target without the MSR the source added cannot load it.
        assert!(template.check_saved(&template, &saved).unwrap_err().to_string().contains("saved MSRs 0x3b"));

        let arm = Compat::Aarch64(arm64::tests::host());
        let Compat::Aarch64(mut more) = arm.clone() else { unreachable!() };
        more.regs.insert(0x6030_0000_0013_c0a0);
        let more = Compat::Aarch64(more);
        let saved = more.saves(&arm.check_saved(&more, &arm.saved()).unwrap()).unwrap();
        assert!(arm.check_saved(&arm, &saved).unwrap_err().to_string().contains("saved registers"));
        arm.check_saved(&more, &saved).unwrap();
    }

    #[test]
    fn saved_records_keep_their_names_in_manifests_and_requests() {
        let x86 = Saved::X86_64 { tsc_khz: 2_000_000, msrs: [0x10].into() };
        assert_eq!(serde_json::to_string(&x86).unwrap(), r#"{"saved_msrs":[16],"saved_tsc_khz":2000000}"#);
        assert_eq!(Value::Object(x86.to_request()), serde_json::json!({"msrs": [16], "tsc_khz": 2000000}));
        let arm = Saved::Aarch64 { regs: [0x6030_0000_0013_c000].into() };
        assert_eq!(serde_json::to_string(&arm).unwrap(), r#"{"arch":"aarch64","saved_regs":[6931039826524487680]}"#);
        assert_eq!(Value::Object(arm.to_request()), serde_json::json!({"arch": "aarch64", "regs": [0x6030_0000_0013_c000u64]}));
        for saved in [&x86, &arm] {
            assert_eq!(&serde_json::from_str::<Saved>(&serde_json::to_string(saved).unwrap()).unwrap(), saved);
            assert_eq!(&Saved::of_request(&Value::Object(saved.to_request())).unwrap(), saved);
        }
        // What a source before aarch64 sends; a request missing either is refused by name.
        let old = serde_json::json!({"op": "migrate_in", "msrs": [16], "tsc_khz": 2000000});
        assert_eq!(Saved::of_request(&old).unwrap(), x86);
        let error = Saved::of_request(&serde_json::json!({"msrs": [16]})).unwrap_err().to_string();
        assert!(error.contains("tsc_khz"), "{error}");
        let error = Saved::of_request(&serde_json::json!({"msrs": "x", "tsc_khz": 1})).unwrap_err().to_string();
        assert!(error.contains("bad msrs"), "{error}");
        assert!(Saved::of_request(&serde_json::json!({"arch": "aarch64", "msrs": [16], "tsc_khz": 1})).is_err());
        assert!(serde_json::from_str::<Saved>(r#"{"saved_msrs":[16]}"#).unwrap_err().to_string().contains("saved_tsc_khz"));
    }

    #[test]
    fn firecracker_cache_hits_and_invalidates_on_stamp_changes() {
        use std::os::unix::fs::PermissionsExt;

        let root = crate::test_util::TempDir::new("compat");
        let binary = root.join("firecracker");
        let calls = root.join("firecracker.calls");
        let write = |version| {
            let temp = root.join("firecracker.tmp");
            std::fs::write(&temp, format!("#!/bin/sh\necho {version}\necho called >> \"$0.calls\"\n")).unwrap();
            std::fs::set_permissions(&temp, std::fs::Permissions::from_mode(0o700)).unwrap();
            // Publish the executable only after closing its write descriptor.
            std::fs::rename(&temp, &binary).unwrap();
        };
        write("v1");
        let first = firecracker_id(&binary, Some(&root)).unwrap();
        assert!(first.1.starts_with("v1 (content "));
        assert_eq!(firecracker_id(&binary, Some(&root)).unwrap(), first);
        assert_eq!(std::fs::read_to_string(&calls).unwrap().lines().count(), 1);
        // A replacement inode invalidates the cache even with identical bytes.
        std::fs::rename(&binary, root.join("old")).unwrap();
        write("v1");
        let replaced = firecracker_id(&binary, Some(&root)).unwrap();
        assert_ne!(replaced.0, first.0);
        assert_eq!(replaced.1, first.1);
        write("v2-longer");
        let changed = firecracker_id(&binary, Some(&root)).unwrap();
        assert_ne!(changed.0, replaced.0);
        assert!(changed.1.starts_with("v2-longer (content "));
        assert_eq!(firecracker_id(&binary, Some(&root)).unwrap(), changed);
        assert_eq!(std::fs::read_to_string(&calls).unwrap().lines().count(), 3);
        std::fs::write(root.join("firecracker.json"), b"broken").unwrap();
        assert_eq!(firecracker_id(&binary, Some(&root)).unwrap(), changed);
        std::fs::remove_file(root.join("firecracker.json")).unwrap();
        std::fs::create_dir(root.join("firecracker.json")).unwrap();
        assert_eq!(firecracker_id(&binary, Some(&root)).unwrap(), changed);
        assert_eq!(std::fs::read_to_string(calls).unwrap().lines().count(), 5);
    }
}
