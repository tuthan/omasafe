use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

pub fn source_fingerprint(src: &Path) -> std::io::Result<(String, Vec<PathBuf>)> {
    let mut files = Vec::new();
    collect(src, src, &mut files)?;
    files.sort();
    let mut hasher = Sha256::new();
    feed(&mut hasher, b"omasafe.core-logic.v1");
    for path in &files {
        let relative = path.strip_prefix(src).expect("source path is rooted");
        let bytes = std::fs::read(path)?;
        feed(&mut hasher, relative.to_string_lossy().as_bytes());
        feed(&mut hasher, &bytes);
    }
    Ok((hex(&hasher.finalize()), files))
}

/// Return every directory traversed while collecting package runtime sources.
/// Directory watches make additions/removals observable to Cargo; file-only
/// watches cover the initial tree but do not reliably retrigger for a new
/// module under an existing directory.
pub fn source_directories(src: &Path) -> std::io::Result<Vec<PathBuf>> {
    let mut directories = Vec::new();
    collect_directories(src, &mut directories)?;
    directories.sort();
    directories.dedup();
    Ok(directories)
}

fn collect(root: &Path, dir: &Path, out: &mut Vec<PathBuf>) -> std::io::Result<()> {
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            collect(root, &path, out)?;
        } else if path.extension().is_some_and(|ext| ext == "rs") && include(root, &path) {
            out.push(path);
        }
    }
    Ok(())
}

fn collect_directories(dir: &Path, out: &mut Vec<PathBuf>) -> std::io::Result<()> {
    out.push(dir.to_owned());
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            collect_directories(&path, out)?;
        }
    }
    Ok(())
}

fn include(root: &Path, path: &Path) -> bool {
    let relative = path.strip_prefix(root).ok();
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("");
    !relative.is_some_and(|value| {
        value
            .components()
            .any(|part| matches!(part.as_os_str().to_str(), Some("tests" | "golden")))
    }) && !name.ends_with("_tests.rs")
}

fn feed(hasher: &mut Sha256, bytes: &[u8]) {
    hasher.update((bytes.len() as u64).to_le_bytes());
    hasher.update(bytes);
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
