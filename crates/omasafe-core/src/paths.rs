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
            std::fs::create_dir_all(path)?;
        }
        Ok(())
    }
}

fn xdg_dir(variable: &str, fallback: PathBuf) -> PathBuf {
    env::var_os(variable)
        .map(PathBuf::from)
        .filter(|path| path.is_absolute())
        .unwrap_or(fallback)
}
