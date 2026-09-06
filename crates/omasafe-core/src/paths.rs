use std::env;
use std::path::PathBuf;

use crate::error::{Error, Result};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XdgPaths {
    pub config: PathBuf,
    pub state: PathBuf,
    pub cache: PathBuf,
}

impl XdgPaths {
    pub fn discover() -> Result<Self> {
        let home = env::var_os("HOME")
            .map(PathBuf::from)
            .ok_or_else(|| Error::InvalidPath("HOME is not set".into()))?;
        Ok(Self {
            config: xdg_dir("XDG_CONFIG_HOME", home.join(".config")).join("omasafe"),
            state: xdg_dir("XDG_STATE_HOME", home.join(".local/state")).join("omasafe"),
            cache: xdg_dir("XDG_CACHE_HOME", home.join(".cache")).join("omasafe"),
        })
    }

    pub fn ensure(&self) -> Result<()> {
        for path in [&self.config, &self.state, &self.cache] {
            ensure_private_directory(path)?;
        }
        Ok(())
    }

    /// Ensure the configuration and state roots needed for a normal scan.
    /// Cache setup is intentionally separate so a cache-only failure can be
    /// reported additively without changing scan/state behavior.
    pub fn ensure_scan_roots(&self) -> Result<()> {
        for path in [&self.config, &self.state] {
            ensure_private_directory(path)?;
        }
        Ok(())
    }

    pub fn ensure_cache(&self) -> Result<()> {
        ensure_private_directory(&self.cache)
    }

    pub fn scan_snapshots(&self) -> PathBuf {
        self.cache.join("scan-snapshots")
    }
}

fn ensure_private_directory(path: &std::path::Path) -> Result<()> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
            return Err(Error::InvalidPath(format!(
                "{} is not a private directory",
                path.display()
            )));
        }
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            std::fs::create_dir_all(path)?;
        }
        Err(error) => return Err(error.into()),
    }
    let metadata = std::fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(Error::InvalidPath(format!(
            "{} is not a private directory",
            path.display()
        )));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if metadata.uid() != unsafe { libc::geteuid() } {
            return Err(Error::InvalidPath(format!(
                "{} is not owned by the current user",
                path.display()
            )));
        }
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

fn xdg_dir(variable: &str, fallback: PathBuf) -> PathBuf {
    env::var_os(variable)
        .map(PathBuf::from)
        .filter(|path| path.is_absolute())
        .unwrap_or(fallback)
}
