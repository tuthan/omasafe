use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
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

/// Interrupted-state record for a reviewed update in flight. Written before
/// the first mutation and removed only when the flow reaches a terminal
/// state; a leftover file means the process died mid-flow and manual checks
/// are required before trusting the plugin again.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateFlowRecord {
    pub schema_version: u64,
    pub plugin_id: String,
    pub candidate_commit: String,
    pub started_at: String,
    /// Flow phase at last write: delegating | verifying | finished.
    pub phase: String,
    /// Quiescing actions taken before mutation: "bar-switched", "disabled".
    #[serde(default)]
    pub quiesced: Vec<String>,
    /// Durable recovery for the hardened-config swap window. Written and
    /// fsync'd BEFORE the installed `.git/config` is swapped, so a SIGKILL or
    /// power loss mid-window leaves a recoverable copy of the audited original
    /// on disk instead of only in the dead process's memory. A subsequent run
    /// reconciles `config_target` from `config_backup` before proceeding.
    /// All optional and `serde(default)` for back-compat with older records.
    #[serde(default)]
    pub config_backup: Option<String>,
    /// Absolute path of the `.git/config` that was swapped, restored from the
    /// backup during reconciliation.
    #[serde(default)]
    pub config_target: Option<String>,
    /// Original file mode of `config_target`, preserved across restore so the
    /// audited original is put back with its own permissions, not the
    /// hardened snapshot's.
    #[serde(default)]
    pub config_original_mode: Option<u32>,
}

impl UpdateFlowRecord {
    pub fn load(path: &Path) -> Result<Option<Self>, Error> {
        let bytes = match fs::read(path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        let record: UpdateFlowRecord =
            serde_json::from_slice(&bytes).map_err(|source| Error::Json {
                path: path.display().to_string(),
                source,
            })?;
        Ok(Some(record))
    }

    pub fn store(&self, path: &Path) -> Result<(), Error> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let mut bytes = serde_json::to_vec_pretty(self)?;
        bytes.push(b'\n');
        // Durable write: the recovery record must survive a hard kill or power
        // loss, otherwise the config-swap backup reference it carries could be
        // lost exactly when it is needed. A random, exclusively-created,
        // non-following temp (never a predictable `.tmp` opened with
        // create/O_FOLLOW) is fsync'd, atomically renamed, and the parent
        // fsync'd — so a concurrent same-user writer cannot pre-plant a symlink
        // at the temp path and have this overwrite an arbitrary target.
        durable_replace(path, &bytes)?;
        Ok(())
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ScanState {
    pub schema_version: u64,
    #[serde(default)]
    pub alerts: BTreeMap<String, String>,
    /// Per-plugin last-analysis snapshot for S5 event separation
    /// (additive; older state files load without it).
    #[serde(default)]
    pub analysis_events: BTreeMap<String, AnalysisEventRecord>,
}

/// What the last opted-in analysis of a plugin observed. Source identity,
/// policy identity, and fingerprint together drive the distinct-event
/// classification: source changed = drift, policy changed = re-evaluation,
/// both unchanged but fingerprint moved = nondeterminism error.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AnalysisEventRecord {
    pub source_identity: String,
    pub policy_identity: String,
    pub fingerprint: String,
    #[serde(default)]
    pub finding_rule_ids: Vec<String>,
    #[serde(default)]
    pub capability_kinds: Vec<String>,
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
            analysis_events: BTreeMap::new(),
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
        // Secure temp (create-new + O_NOFOLLOW, random name, mode 0o600) so a
        // pre-planted symlink at a predictable `tmp-<pid>` name cannot redirect
        // this write onto another same-user file.
        durable_replace(path, &serde_json::to_vec_pretty(self)?)
    }
}

impl ScanState {
    pub fn load(path: &Path) -> Result<Self, Error> {
        if !path.exists() {
            return Ok(Self {
                schema_version: HISTORY_SCHEMA_VERSION,
                alerts: BTreeMap::new(),
                analysis_events: BTreeMap::new(),
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
        // Secure temp (create-new + O_NOFOLLOW, random name, mode 0o600) so a
        // pre-planted symlink at a predictable `tmp-<pid>` name cannot redirect
        // this write onto another same-user file.
        durable_replace(path, &serde_json::to_vec_pretty(self)?)
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

/// Atomically installs `bytes` at `path` (mode 0o600) via a random,
/// exclusively-created, non-following temporary in the SAME directory, then
/// fsync + rename + parent fsync. `create_new` (O_CREAT|O_EXCL) plus
/// O_NOFOLLOW means a pre-planted symlink or file at the temp path fails the
/// open instead of being followed or overwritten — a predictable `.tmp`
/// sibling opened with plain `File::create` would follow such a symlink and
/// overwrite an arbitrary same-user target.
fn durable_replace(path: &Path, bytes: &[u8]) -> Result<(), Error> {
    let dir = path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .to_path_buf();
    let mut last_error: Option<std::io::Error> = None;
    for _ in 0..8 {
        let temp = dir.join(format!(".omasafe-state.{:016x}", random_u64()));
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
        }
        let mut file = match options.open(&temp) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                last_error = Some(error);
                continue;
            }
            Err(error) => return Err(error.into()),
        };
        if let Err(error) = file.write_all(bytes).and_then(|()| file.sync_all()) {
            let _ = fs::remove_file(&temp);
            return Err(error.into());
        }
        drop(file);
        if let Err(error) = fs::rename(&temp, path) {
            let _ = fs::remove_file(&temp);
            return Err(error.into());
        }
        sync_parent(&dir)?;
        return Ok(());
    }
    Err(last_error
        .unwrap_or_else(|| std::io::Error::new(std::io::ErrorKind::AlreadyExists, "temp collision"))
        .into())
}

/// 64 bits from the OS CSPRNG for unpredictable temp names. Falls back to a
/// time/PID mix only if `getrandom` is unavailable; `create_new` still
/// guarantees exclusivity regardless of name quality.
fn random_u64() -> u64 {
    #[cfg(unix)]
    {
        let mut buffer = [0u8; 8];
        let read =
            unsafe { libc::getrandom(buffer.as_mut_ptr() as *mut libc::c_void, buffer.len(), 0) };
        if read == buffer.len() as isize {
            return u64::from_ne_bytes(buffer);
        }
    }
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos() as u64)
        .unwrap_or(0);
    nanos ^ ((std::process::id() as u64) << 32)
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
