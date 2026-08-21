use std::collections::BTreeMap;
use std::fs;
use std::path::Path;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::SourceIdentity;

pub const HISTORY_SCHEMA_VERSION: u64 = 1;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("trust history I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("trust history is malformed at {path}: {source}")]
    Json {
        path: String,
        source: serde_json::Error,
    },
    #[error("scan state is malformed at {path}: {source}")]
    ScanStateJson {
        path: String,
        source: serde_json::Error,
    },
    #[error("state serialization failed: {0}")]
    Serialize(#[from] serde_json::Error),
    #[error("unsupported {kind} schema version {version}; expected {expected}")]
    Schema {
        kind: &'static str,
        version: u64,
        expected: u64,
    },
    #[error("state lock is busy for {path}; retry later")]
    LockBusy { path: String },
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TrustHistory {
    pub schema_version: u64,
    pub records: Vec<TrustRecord>,
    #[serde(default)]
    pub decisions: Vec<ReviewDecision>,
    #[serde(default)]
    pub revoked_plugins: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TrustRecord {
    pub plugin_id: String,
    pub accepted: SourceIdentity,
    pub accepted_at: String,
    pub note: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ReviewDecision {
    pub plugin_id: String,
    pub action: String,
    pub scope: String,
    pub reason: String,
    pub created_at: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ScanState {
    pub schema_version: u64,
    #[serde(default)]
    pub alerts: BTreeMap<String, String>,
}

impl Default for TrustHistory {
    fn default() -> Self {
        Self {
            schema_version: HISTORY_SCHEMA_VERSION,
            records: Vec::new(),
            decisions: Vec::new(),
            revoked_plugins: Vec::new(),
        }
    }
}

impl Default for ScanState {
    fn default() -> Self {
        Self {
            schema_version: HISTORY_SCHEMA_VERSION,
            alerts: BTreeMap::new(),
        }
    }
}

impl TrustHistory {
    pub fn load(path: &Path) -> Result<Self, Error> {
        if !path.exists() {
            return Ok(Self {
                schema_version: HISTORY_SCHEMA_VERSION,
                records: Vec::new(),
                decisions: Vec::new(),
                revoked_plugins: Vec::new(),
            });
        }
        let history: Self =
            serde_json::from_slice(&fs::read(path)?).map_err(|source| Error::Json {
                path: path.display().to_string(),
                source,
            })?;
        if history.schema_version != HISTORY_SCHEMA_VERSION {
            return Err(Error::Schema {
                kind: "trust history",
                version: history.schema_version,
                expected: HISTORY_SCHEMA_VERSION,
            });
        }
        Ok(history)
    }

    pub fn accept(&mut self, record: TrustRecord) {
        self.schema_version = HISTORY_SCHEMA_VERSION;
        self.revoked_plugins.retain(|id| id != &record.plugin_id);
        self.records.push(record);
    }

    pub fn revoke(&mut self, plugin_id: &str) {
        self.schema_version = HISTORY_SCHEMA_VERSION;
        if !self.revoked_plugins.iter().any(|id| id == plugin_id) {
            self.revoked_plugins.push(plugin_id.to_owned());
        }
    }

    pub fn is_revoked(&self, plugin_id: &str) -> bool {
        self.revoked_plugins.iter().any(|id| id == plugin_id)
    }

    pub fn latest(&self, plugin_id: &str) -> Option<&TrustRecord> {
        if self.is_revoked(plugin_id) {
            return None;
        }
        self.records
            .iter()
            .rev()
            .find(|record| record.plugin_id == plugin_id)
    }

    pub fn write_atomic(&self, path: &Path) -> Result<(), Error> {
        let parent = path.parent().unwrap_or_else(|| Path::new("."));
        fs::create_dir_all(parent)?;
        let _lock = acquire_lock(path)?;
        self.write_atomic_locked(path)
    }

    pub fn write_atomic_locked(&self, path: &Path) -> Result<(), Error> {
        let parent = path.parent().unwrap_or_else(|| Path::new("."));
        fs::create_dir_all(parent)?;
        let temporary = path.with_extension(format!("tmp-{}", std::process::id()));
        let mut file = fs::File::create(&temporary)?;
        std::io::Write::write_all(&mut file, &serde_json::to_vec_pretty(self)?)?;
        file.sync_all()?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&temporary, fs::Permissions::from_mode(0o600))?;
        }
        fs::rename(temporary, path)?;
        sync_parent(parent)?;
        Ok(())
    }
}

impl ScanState {
    pub fn load(path: &Path) -> Result<Self, Error> {
        if !path.exists() {
            return Ok(Self {
                schema_version: HISTORY_SCHEMA_VERSION,
                alerts: BTreeMap::new(),
            });
        }
        let state: Self =
            serde_json::from_slice(&fs::read(path)?).map_err(|source| Error::ScanStateJson {
                path: path.display().to_string(),
                source,
            })?;
        if state.schema_version != HISTORY_SCHEMA_VERSION {
            return Err(Error::Schema {
                kind: "scan state",
                version: state.schema_version,
                expected: HISTORY_SCHEMA_VERSION,
            });
        }
        Ok(state)
    }

    pub fn is_new(&self, key: &str) -> bool {
        !self.alerts.contains_key(key)
    }

    pub fn record(&mut self, key: String, emitted_at: String) {
        self.schema_version = HISTORY_SCHEMA_VERSION;
        self.alerts.insert(key, emitted_at);
    }

    pub fn write_atomic(&self, path: &Path) -> Result<(), Error> {
        let parent = path.parent().unwrap_or_else(|| Path::new("."));
        fs::create_dir_all(parent)?;
        let _lock = acquire_lock(path)?;
        self.write_atomic_locked(path)
    }

    pub fn write_atomic_locked(&self, path: &Path) -> Result<(), Error> {
        let parent = path.parent().unwrap_or_else(|| Path::new("."));
        fs::create_dir_all(parent)?;
        let temporary = path.with_extension(format!("tmp-{}", std::process::id()));
        let mut file = fs::File::create(&temporary)?;
        std::io::Write::write_all(&mut file, &serde_json::to_vec_pretty(self)?)?;
        file.sync_all()?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&temporary, fs::Permissions::from_mode(0o600))?;
        }
        fs::rename(temporary, path)?;
        sync_parent(parent)?;
        Ok(())
    }
}

pub struct StateLock {
    _file: fs::File,
}

pub fn lock(path: &Path) -> Result<StateLock, Error> {
    let lock_path = path.with_extension("lock");
    let mut options = fs::OpenOptions::new();
    options.read(true).write(true).truncate(false).create(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let file = options.open(&lock_path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        use std::os::unix::io::AsRawFd;
        fs::set_permissions(&lock_path, fs::Permissions::from_mode(0o600))?;
        let mut acquired = false;
        for _ in 0..20 {
            let result = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
            if result == 0 {
                acquired = true;
                break;
            }
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() != Some(libc::EWOULDBLOCK) {
                return Err(error.into());
            }
            std::thread::sleep(Duration::from_millis(25));
        }
        if !acquired {
            return Err(Error::LockBusy {
                path: path.display().to_string(),
            });
        }
    }
    Ok(StateLock { _file: file })
}

fn acquire_lock(path: &Path) -> Result<StateLock, Error> {
    lock(path)
}

fn sync_parent(parent: &Path) -> Result<(), Error> {
    let directory = fs::File::open(parent)?;
    directory.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn history_round_trips_and_keeps_previous_trust() {
        let path = std::env::temp_dir().join(format!("omasafe-trust-{}.json", std::process::id()));
        let identity = SourceIdentity {
            plugin_id: "io.example.test".into(),
            repository: None,
            head: Some("head".into()),
            tree: Some("tree".into()),
            content_digest: Some("digest".into()),
            file_count: 1,
            limitations: Vec::new(),
            file_digests: std::collections::BTreeMap::new(),
        };
        let mut history = TrustHistory::default();
        history.accept(TrustRecord {
            plugin_id: identity.plugin_id.clone(),
            accepted: identity.clone(),
            accepted_at: "first".into(),
            note: "first trust".into(),
        });
        history.write_atomic(&path).unwrap();
        fs::write(path.with_extension("lock"), b"stale marker").unwrap();
        history.write_atomic(&path).unwrap();
        let loaded = TrustHistory::load(&path).unwrap();
        assert_eq!(
            loaded.latest("io.example.test").unwrap().accepted_at,
            "first"
        );
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(path.with_extension("lock"));
    }

    #[test]
    fn revoking_hides_a_baseline_until_it_is_trusted_again() {
        let identity = SourceIdentity {
            plugin_id: "io.example.revocable".into(),
            repository: None,
            head: Some("head".into()),
            tree: Some("tree".into()),
            content_digest: Some("digest".into()),
            file_count: 1,
            limitations: Vec::new(),
            file_digests: std::collections::BTreeMap::new(),
        };
        let mut history = TrustHistory::default();
        history.accept(TrustRecord {
            plugin_id: identity.plugin_id.clone(),
            accepted: identity.clone(),
            accepted_at: "first".into(),
            note: "first trust".into(),
        });
        assert!(history.latest(&identity.plugin_id).is_some());

        history.revoke(&identity.plugin_id);
        assert!(history.latest(&identity.plugin_id).is_none());

        history.accept(TrustRecord {
            plugin_id: identity.plugin_id.clone(),
            accepted: identity,
            accepted_at: "second".into(),
            note: "trusted again".into(),
        });
        assert!(history.latest("io.example.revocable").is_some());
    }

    #[test]
    fn scan_state_deduplicates_the_same_alert_key() {
        let mut state = ScanState::default();
        assert!(state.is_new("drift:plugin:identity"));
        state.record("drift:plugin:identity".into(), "now".into());
        assert!(!state.is_new("drift:plugin:identity"));
    }
}
