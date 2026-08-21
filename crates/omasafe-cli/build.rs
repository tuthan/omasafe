use sha2::{Digest, Sha256};
use std::env;
use std::fs;
use std::path::Path;
use std::process::Command;

fn main() {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let workspace_root = manifest_dir
        .parent()
        .and_then(Path::parent)
        .expect("omasafe-cli must be inside the workspace");

    println!(
        "cargo:rerun-if-changed={}",
        workspace_root.join("Cargo.lock").display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        workspace_root.join("rust-toolchain.toml").display()
    );
    println!("cargo:rerun-if-env-changed=OMASAFE_SOURCE_REVISION");

    let source_revision = env::var("OMASAFE_SOURCE_REVISION")
        .ok()
        .filter(|value| !value.is_empty())
        .or_else(|| git_revision(workspace_root))
        .unwrap_or_else(|| "unknown".to_owned());
    let lockfile_sha256 = sha256_file(&workspace_root.join("Cargo.lock"));
    let rust_toolchain = toolchain_channel(&workspace_root.join("rust-toolchain.toml"));
    let target = env::var("TARGET").unwrap_or_else(|_| "unknown".to_owned());

    println!("cargo:rustc-env=OMASAFE_SOURCE_REVISION={source_revision}");
    println!("cargo:rustc-env=OMASAFE_CARGO_LOCK_SHA256={lockfile_sha256}");
    println!("cargo:rustc-env=OMASAFE_RUST_TOOLCHAIN={rust_toolchain}");
    println!("cargo:rustc-env=OMASAFE_TARGET={target}");
}

fn git_revision(workspace_root: &Path) -> Option<String> {
    let output = Command::new("git")
        .args(["-C", workspace_root.to_str()?, "rev-parse", "HEAD"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let revision = String::from_utf8(output.stdout).ok()?.trim().to_owned();
    (!revision.is_empty()).then_some(revision)
}

fn sha256_file(path: &Path) -> String {
    let bytes = fs::read(path).unwrap_or_default();
    format!("{:x}", Sha256::digest(bytes))
}

fn toolchain_channel(path: &Path) -> String {
    fs::read_to_string(path)
        .ok()
        .and_then(|contents| {
            contents.lines().find_map(|line| {
                let (key, value) = line.split_once('=')?;
                (key.trim() == "channel").then(|| value.trim().trim_matches('"').to_owned())
            })
        })
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "unknown".to_owned())
}
