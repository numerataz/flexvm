//! Builds flexvm-init (the guest crate) for the guest and hands its path to `include_bytes!`, and reads the
//! prebuilt artifacts release flexvm downloads from: its semver tag (vMAJOR.MINOR.PATCH in scripts/versions.sh)
//! and the sha256 pinned for each asset (scripts/checksums.sha256).

use std::os::fd::AsFd;
use std::path::{Path, PathBuf};
use std::process::Command;

/// The repository whose releases hold the prebuilt artifacts.
const REPO: &str = "numerataz/flexvm";
/// The assets flexvm downloads, and the `rustc-env`s each one's pin and its name in the release go in.
const ASSETS: [(&str, &str, &str); 4] = [
    ("firecracker", "FLEXVM_PIN_FIRECRACKER", "FLEXVM_ASSET_FIRECRACKER"),
    ("vmlinux", "FLEXVM_PIN_VMLINUX", "FLEXVM_ASSET_VMLINUX"),
    ("kernel-modules.tar.gz", "FLEXVM_PIN_MODULES", "FLEXVM_ASSET_MODULES"),
    ("kernel-sdk.tar.gz", "FLEXVM_PIN_KERNEL_SDK", "FLEXVM_ASSET_KERNEL_SDK"),
];

fn main() {
    let manifest = PathBuf::from(std::env::var_os("CARGO_MANIFEST_DIR").unwrap());
    let root = manifest.parent().unwrap().to_path_buf();
    for path in git_inputs(&root) {
        println!("cargo:rerun-if-changed={}", path.display());
    }
    let commit = git(&root, &["rev-parse", "HEAD"]).unwrap_or_else(|| "unknown".into());
    println!("cargo:rustc-env=FLEXVM_GIT_COMMIT={commit}");
    state_dir();
    pins(&root);
    init(&root);
}

/// Worktrees keep HEAD and refs outside their .git file. Missing inputs make Cargo
/// rerun forever; the reflog also catches commits when a branch has only a packed ref.
fn git_inputs(root: &Path) -> Vec<PathBuf> {
    let reference = git(root, &["symbolic-ref", "-q", "HEAD"]);
    [Some("HEAD"), Some("packed-refs"), Some("logs/HEAD"), reference.as_deref()]
        .into_iter()
        .flatten()
        .filter_map(|name| git(root, &["rev-parse", "--git-path", name]))
        .map(|path| root.join(path))
        .filter(|path| path.exists())
        .collect()
}

/// The default `--state`: `FLEXVM_STATE_DIR` at build time, else `/var/lib/flexvm`.
fn state_dir() {
    println!("cargo:rerun-if-env-changed=FLEXVM_STATE_DIR");
    let dir = std::env::var("FLEXVM_STATE_DIR").ok().filter(|d| !d.is_empty()).unwrap_or_else(|| "/var/lib/flexvm".into());
    let path = Path::new(&dir);
    assert!(
        path.is_absolute() && path.components().all(|c| matches!(c, std::path::Component::RootDir | std::path::Component::Normal(_))),
        "FLEXVM_STATE_DIR must be an absolute path without . or .. components, not {dir:?}"
    );
    assert!(!dir.contains(['\n', '\r']), "FLEXVM_STATE_DIR must not contain a newline");
    assert!(path.components().count() > 1, "FLEXVM_STATE_DIR must not be the root directory");
    println!("cargo:rustc-env=FLEXVM_DEFAULT_STATE={}", dir.trim_end_matches('/'));
}

fn git(root: &Path, args: &[&str]) -> Option<String> {
    let output = Command::new("git").args(args).current_dir(root).output().ok()?;
    output.status.success().then(|| String::from_utf8_lossy(&output.stdout).trim().to_string())
}

/// `NAME=${NAME:-value}` (or `NAME=value`) in a shell file: its default.
fn shell_default(text: &str, name: &str) -> Option<String> {
    let value = text.lines().find_map(|l| l.trim().strip_prefix(name)?.strip_prefix('='))?;
    let value = match value.strip_prefix(&format!("${{{name}:-")) {
        Some(v) => v.strip_suffix('}')?,
        None => value,
    };
    Some(value.trim_matches('"').to_string())
}

/// An asset's name in a release for an architecture, as asset() in scripts/versions.sh names it: x86_64's keep the
/// names of the releases that had no other architecture (v0.2.2 and older), the others' end in `-ARCH`.
fn release_name(asset: &str, arch: &str) -> String {
    if arch == "x86_64" {
        return asset.into();
    }
    for suffix in [".txt", ".tar.gz"] {
        if let Some(stem) = asset.strip_suffix(suffix) {
            return format!("{stem}-{arch}{suffix}");
        }
    }
    format!("{asset}-{arch}")
}

/// The same vMAJOR.MINOR.PATCH form as release.yml and pin-artifacts.sh.
fn valid_tag(tag: &str) -> bool {
    let Some(version) = tag.strip_prefix('v') else { return false };
    let parts: Vec<_> = version.split('.').collect();
    parts.len() == 3 && parts.iter().all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()))
}

fn pins(root: &Path) {
    let versions = root.join("scripts/versions.sh");
    let checksums = root.join("scripts/checksums.sha256");
    println!("cargo:rerun-if-changed={}", versions.display());
    println!("cargo:rerun-if-changed={}", checksums.display());
    let versions = std::fs::read_to_string(&versions).expect("scripts/versions.sh");
    let tag = shell_default(&versions, "ARTIFACTS_TAG").expect("ARTIFACTS_TAG in scripts/versions.sh");
    assert!(valid_tag(&tag), "bad ARTIFACTS_TAG {tag:?}");
    let base = format!("https://github.com/{REPO}/releases/download/{tag}");
    println!("cargo:rustc-env=FLEXVM_ARTIFACTS_BASE={base}");
    let checksums = std::fs::read_to_string(&checksums).expect("scripts/checksums.sha256");
    // The assets for the architecture flexvm is built for: it runs guests of its own.
    let arch = std::env::var("CARGO_CFG_TARGET_ARCH").unwrap();
    for (asset, var, name_var) in ASSETS {
        let name = release_name(asset, &arch);
        println!("cargo:rustc-env={name_var}={name}");
        let url = format!("{base}/{name}");
        // As pinned() in scripts/versions.sh: any non-comment line naming the URL is its pin, and must be `SHA256 URL`.
        let found: Vec<Vec<&str>> = checksums
            .lines()
            .filter(|l| !l.trim_start().starts_with('#'))
            .map(|l| l.split_whitespace().collect::<Vec<_>>())
            .filter(|fields| fields.contains(&url.as_str()))
            .collect();
        match &found[..] {
            [] => println!(
                "cargo:warning=scripts/checksums.sha256 pins no {url}: this flexvm cannot download {asset} (scripts/pin-artifacts.sh pins it once the release exists)"
            ),
            [fields] if matches!(fields[..], [hash, u] if u == url && hash.len() == 64 && hash.bytes().all(|b| b.is_ascii_hexdigit())) => {
                println!("cargo:rustc-env={var}={}", fields[0].to_ascii_lowercase())
            }
            _ => panic!("scripts/checksums.sha256 must pin {url} once, by its sha256"),
        }
    }
}

/// Shared cargo target directory for the nested `flexvm-init` build so `cargo check`, `cargo clippy`,
/// `cargo test`, and `build.rs` edits do not recompile `flexvm-init`'s dependencies for every `OUT_DIR` hash.
/// Debug/test builds and release builds use separate directories so their profile overrides never clash.
fn init_target_dir(out: &Path, release: bool) -> PathBuf {
    let name = if release { "init-target" } else { "init-target-dev" };
    // Cargo lays out OUT_DIR as `<target-dir>/<profile>/build/<pkg>-<hash>/out` (or with `<triple>` before `<profile>`).
    let mut dir = out;
    while let Some(parent) = dir.parent() {
        if dir.file_name().and_then(|n| n.to_str()) == Some("build") {
            if let Some(target_root) = parent.parent() {
                return target_root.join(name);
            }
        }
        dir = parent;
    }
    out.join(name)
}

/// flexvm-init, static (it runs in any image), built by a cargo of its own into OUT_DIR: release for release
/// builds (full LTO, single codegen unit), or fast un-LTO'd release for debug/test/clippy builds, and without
/// this build's flags or wrappers (clippy's included). `FLEXVM_INIT` names a prebuilt one instead.
fn init(root: &Path) {
    let out = PathBuf::from(std::env::var_os("OUT_DIR").unwrap());
    let dest = out.join("flexvm-init");
    println!("cargo:rerun-if-env-changed=FLEXVM_INIT");
    if let Some(prebuilt) = std::env::var_os("FLEXVM_INIT") {
        println!("cargo:rerun-if-changed={}", Path::new(&prebuilt).display());
        std::fs::copy(&prebuilt, &dest).unwrap_or_else(|e| panic!("FLEXVM_INIT={}: {e}", Path::new(&prebuilt).display()));
        return;
    }
    for input in ["guest/src", "guest/Cargo.toml", "Cargo.lock", "Cargo.toml"] {
        println!("cargo:rerun-if-changed={}", root.join(input).display());
    }
    // The guest runs on the same architecture as the flexvm binary that embeds it.
    let target = format!("{}-unknown-linux-gnu", std::env::var("CARGO_CFG_TARGET_ARCH").unwrap());
    let release = std::env::var("PROFILE").as_deref() == Ok("release");
    let target_dir = init_target_dir(&out, release);
    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let mut cmd = Command::new(cargo);
    cmd.current_dir(root)
        .args(["build", "--release", "--locked", "-p", "flexvm-init", "--target", &target, "--target-dir"])
        .arg(&target_dir)
        .env("CARGO_ENCODED_RUSTFLAGS", "-Ctarget-feature=+crt-static");
    if !release {
        // Avoid full LTO and single-CGU codegen during `cargo check`/`clippy`/`test`.
        cmd.args([
            "--config",
            "profile.release.lto=false",
            "--config",
            "profile.release.codegen-units=16",
            "--config",
            "profile.release.opt-level=0",
            "--config",
            "profile.release.strip=false",
        ]);
    }
    for var in
        ["RUSTFLAGS", "RUSTC_WORKSPACE_WRAPPER", "CARGO_TARGET_DIR", "CARGO_BUILD_TARGET_DIR", "CARGO_BUILD_RUSTFLAGS", "CLIPPY_ARGS", "CARGO_PRIMARY_PACKAGE"]
    {
        cmd.env_remove(var);
    }
    // Its output is never this script's: cargo would read a `cargo:` line in it as a directive.
    cmd.stdout(std::io::stderr().as_fd().try_clone_to_owned().expect("stderr"));
    let status = cmd.status().expect("running cargo to build flexvm-init");
    assert!(status.success(), "building flexvm-init failed ({status}); set FLEXVM_INIT to a prebuilt static flexvm-init to skip it");
    let built = target_dir.join(&target).join("release/flexvm-init");
    // Copied, not linked: OUT_DIR's file stays what this build embedded.
    std::fs::copy(&built, &dest).unwrap_or_else(|e| panic!("{}: {e}", built.display()));
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::{init_target_dir, release_name, valid_tag};

    #[test]
    fn init_target_dir_is_shared_under_cargo_target_root() {
        let out = Path::new("/repo/target/debug/build/flexvm-abc123/out");
        assert_eq!(init_target_dir(out, false), Path::new("/repo/target/init-target-dev"));
        assert_eq!(init_target_dir(out, true), Path::new("/repo/target/init-target"));

        let cross = Path::new("/repo/target/x86_64-unknown-linux-gnu/release/build/flexvm-abc123/out");
        assert_eq!(init_target_dir(cross, true), Path::new("/repo/target/x86_64-unknown-linux-gnu/init-target"));

        let fallback = Path::new("/tmp/custom-out");
        assert_eq!(init_target_dir(fallback, false), Path::new("/tmp/custom-out/init-target-dev"));
    }

    #[test]
    fn packed_refs_do_not_leave_missing_cargo_inputs() {
        let root = std::env::temp_dir().join(format!("build-refs-{}", std::process::id()));
        std::fs::create_dir(&root).unwrap();
        let run = |args: &[&str]| assert!(super::git(&root, args).is_some(), "{args:?}");
        run(&["init", "-q"]);
        run(&["-c", "user.name=Test", "-c", "user.email=test@example.invalid", "-c", "commit.gpgsign=false", "commit", "-q", "--allow-empty", "-m", "test"]);
        let before = super::git_inputs(&root);
        assert!(before.iter().all(|p| p.exists()));
        run(&["pack-refs", "--all", "--prune"]);
        let after = super::git_inputs(&root);
        assert!(after.iter().all(|p| p.exists()));
        assert!(after.iter().any(|p| p.ends_with("packed-refs")));
        assert!(after.iter().any(|p| p.ends_with("logs/HEAD")));
        assert!(before.iter().any(|p| !after.contains(p)));
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn release_names() {
        for (asset, arch, name) in [
            ("firecracker", "x86_64", "firecracker"),
            ("vmlinux", "x86_64", "vmlinux"),
            ("inputs.txt", "x86_64", "inputs.txt"),
            ("firecracker", "aarch64", "firecracker-aarch64"),
            ("vmlinux", "aarch64", "vmlinux-aarch64"),
            ("inputs.txt", "aarch64", "inputs-aarch64.txt"),
            ("kernel-modules.tar.gz", "x86_64", "kernel-modules.tar.gz"),
            ("kernel-sdk.tar.gz", "x86_64", "kernel-sdk.tar.gz"),
            ("kernel-modules.tar.gz", "aarch64", "kernel-modules-aarch64.tar.gz"),
            ("kernel-sdk.tar.gz", "aarch64", "kernel-sdk-aarch64.tar.gz"),
        ] {
            assert_eq!(release_name(asset, arch), name);
        }
    }

    #[test]
    fn release_tags() {
        for tag in ["v0.2.1", "v123.45.6", "v01.2.3"] {
            assert!(valid_tag(tag), "{tag}");
        }
        for tag in ["", "1.2.3", "artifacts-5", "v1.2", "v1.2.3.4", "v.2.3", "v1..3", "v1.2.", "v1.2.3-rc1", "v1.2.3+build", "v１.2.3", "v1.2.3\n"] {
            assert!(!valid_tag(tag), "{tag:?}");
        }
    }
}
