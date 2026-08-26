//! Scoped analysis suppressions (v0.2 S5).
//!
//! A suppression records that one rule's findings are accepted for a scope:
//! a plugin target and optionally a path within it, always with a human
//! reason and creation time. Suppressions are presentation/enforcement
//! filters only: they never alter stored findings, fingerprints, or the
//! analyzer output. Records are append-only — reinstating flags a record
//! inactive instead of deleting it, so the audit trail survives.

use std::fs;
use std::path::Path;
use std::time::Duration;

use serde::{Deserialize, Serialize};

pub const SUPPRESSION_SCHEMA_VERSION: u64 = 1;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("suppression state I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("suppression state is malformed at {path}: {source}")]
    Json {
        path: String,
        source: serde_json::Error,
    },
    #[error("suppression serialization failed: {0}")]
    Serialize(#[from] serde_json::Error),
    #[error("unsupported suppressions schema version {version}; expected {expected}")]
    Schema { version: u64, expected: u64 },
    #[error("suppression lock is busy for {path}; retry later")]
    LockBusy { path: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SuppressionRecord {
    pub rule_id: String,
    /// Plugin target; `None` means every analysis context (`scan-plugin`
    /// included). Records scoped to a plugin apply only when that plugin is
    /// the known analysis subject.
    #[serde(default)]
    pub plugin_id: Option<String>,
    /// Path prefix within the analyzed target; `None` means whole target.
    /// Segment-exact: `assets` never matches `assets_backup/…`.
    #[serde(default)]
    pub path_scope: Option<String>,
    pub reason: String,
    pub created_at: String,
    #[serde(default = "default_active")]
    pub active: bool,
    #[serde(default)]
    pub reinstated_at: Option<String>,
}

fn default_active() -> bool {
    true
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct SuppressionState {
    pub schema_version: u64,
    #[serde(default)]
    pub suppressions: Vec<SuppressionRecord>,
}

impl SuppressionState {
    pub fn load(path: &Path) -> Result<Self, Error> {
        if !path.exists() {
            return Ok(Self {
                schema_version: SUPPRESSION_SCHEMA_VERSION,
                suppressions: Vec::new(),
            });
        }
        let state: Self =
            serde_json::from_slice(&fs::read(path)?).map_err(|source| Error::Json {
                path: path.display().to_string(),
                source,
            })?;
        if state.schema_version != SUPPRESSION_SCHEMA_VERSION {
            return Err(Error::Schema {
                version: state.schema_version,
                expected: SUPPRESSION_SCHEMA_VERSION,
            });
        }
        Ok(state)
    }

    pub fn write_atomic(&self, path: &Path) -> Result<(), Error> {
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

    pub fn add(&mut self, record: SuppressionRecord) {
        self.schema_version = SUPPRESSION_SCHEMA_VERSION;
        self.suppressions.push(record);
    }

    /// Flags matching active records inactive. Returns how many records were
    /// flipped; records are never removed, so the audit trail persists.
    pub fn reinstate(
        &mut self,
        rule_id: &str,
        plugin_id: Option<&str>,
        path_scope: Option<&str>,
    ) -> usize {
        self.schema_version = SUPPRESSION_SCHEMA_VERSION;
        let mut flipped = 0;
        for record in &mut self.suppressions {
            if !record.active
                || record.rule_id != rule_id
                || record.plugin_id.as_deref() != plugin_id
                || record.path_scope.as_deref() != path_scope
            {
                continue;
            }
            record.active = false;
            record.reinstated_at = Some(now_stamp());
            flipped += 1;
        }
        flipped
    }

    pub fn active(&self) -> impl Iterator<Item = &SuppressionRecord> {
        self.suppressions.iter().filter(|record| record.active)
    }

    /// True when any active record covers this finding in this context.
    /// `plugin_context` is the analyzed plugin id, or `None` for contexts
    /// without a plugin identity (plain `scan-plugin --path`); plugin-scoped
    /// records can never match such contexts.
    pub fn matches(
        &self,
        rule_id: &str,
        plugin_context: Option<&str>,
        relative_path: &str,
    ) -> bool {
        self.active().any(|record| {
            record.rule_id == rule_id
                && match &record.plugin_id {
                    None => true,
                    Some(target) => plugin_context == Some(target.as_str()),
                }
                && match &record.path_scope {
                    None => true,
                    Some(scope) => path_matches_scope(relative_path, scope),
                }
        })
    }
}

/// Creation-time validation for CLI input: non-empty rule id, human reason,
/// and a relative segment-safe path scope without traversal.
pub fn validate_new(rule_id: &str, reason: &str, path_scope: Option<&str>) -> Result<(), String> {
    if rule_id.trim().is_empty() {
        return Err("suppression requires --rule RULE_ID".into());
    }
    if reason.trim().is_empty() {
        return Err("suppression requires a non-empty --reason".into());
    }
    if let Some(scope) = path_scope {
        validate_path_scope(scope)?;
    }
    Ok(())
}

fn validate_path_scope(scope: &str) -> Result<(), String> {
    if scope.starts_with('/') {
        return Err("suppression --path must be relative to the target root".into());
    }
    let normalized = scope.trim_end_matches('/');
    if normalized.is_empty() {
        return Err("suppression --path cannot be empty".into());
    }
    for segment in normalized.split('/') {
        if segment.is_empty() || segment == "." || segment == ".." {
            return Err(format!(
                "suppression --path segment `{segment}` is not allowed"
            ));
        }
    }
    Ok(())
}

/// Segment-exact prefix containment: `assets` matches `assets/x.qml` but
/// never `assets_backup/x.qml`.
fn path_matches_scope(path: &str, scope: &str) -> bool {
    let scope = scope.trim_end_matches('/');
    if scope.is_empty() {
        return true;
    }
    path == scope || path.starts_with(&format!("{scope}/"))
}

fn now_stamp() -> String {
    let duration = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    format!("{}-unix", duration.as_secs())
}

pub struct StateLock {
    _file: fs::File,
}

pub fn acquire_lock(path: &Path) -> Result<StateLock, Error> {
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

fn sync_parent(parent: &Path) -> Result<(), Error> {
    let directory = fs::File::open(parent)?;
    directory.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_path(name: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "omasafe-suppress-{name}-{}.json",
            std::process::id()
        ))
    }

    fn record(rule: &str, plugin: Option<&str>, scope: Option<&str>) -> SuppressionRecord {
        SuppressionRecord {
            rule_id: rule.to_owned(),
            plugin_id: plugin.map(str::to_owned),
            path_scope: scope.map(str::to_owned),
            reason: "reviewed".to_owned(),
            created_at: "t0".to_owned(),
            active: true,
            reinstated_at: None,
        }
    }

    #[test]
    fn round_trips_through_disk_and_lock_file_survives() {
        let path = temp_path("roundtrip");
        let mut state = SuppressionState::default();
        state.add(record(
            "oma.qml.polkit-agent-ui",
            Some("io.example.x"),
            None,
        ));
        state.write_atomic(&path).unwrap();
        let loaded = SuppressionState::load(&path).unwrap();
        assert_eq!(loaded.suppressions.len(), 1);
        assert_eq!(loaded.suppressions[0].rule_id, "oma.qml.polkit-agent-ui");
        assert!(path.with_extension("lock").exists());
        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(path.with_extension("lock"));
    }

    #[test]
    fn reinstate_flags_without_deleting_and_resuppress_appends() {
        let mut state = SuppressionState::default();
        state.add(record("oma.qml.session-lock", None, None));
        assert_eq!(state.active().count(), 1);

        assert_eq!(state.reinstate("oma.qml.session-lock", None, None), 1);
        assert_eq!(state.active().count(), 0);
        assert_eq!(state.suppressions.len(), 1);
        assert!(!state.suppressions[0].active);
        assert!(state.suppressions[0].reinstated_at.is_some());

        // Reinstating an already-inactive record flips nothing.
        assert_eq!(state.reinstate("oma.qml.session-lock", None, None), 0);

        // Re-suppression appends a new active record; both remain auditable.
        state.add(record("oma.qml.session-lock", None, None));
        assert_eq!(state.suppressions.len(), 2);
        assert_eq!(state.active().count(), 1);
    }

    #[test]
    fn matching_is_rule_plugin_and_segment_exact() {
        let mut state = SuppressionState::default();
        // Global rule-wide.
        state.add(record("oma.qml.session-lock", None, None));
        // Plugin-scoped with path.
        state.add(record(
            "oma.qml.dynamic-code",
            Some("io.example.y"),
            Some("vendor"),
        ));

        // Global matches any context.
        assert!(state.matches("oma.qml.session-lock", Some("io.a"), "Main.qml"));
        assert!(state.matches("oma.qml.session-lock", None, "Main.qml"));
        // Wrong rule never matches.
        assert!(!state.matches("oma.qml.polkit-agent-ui", None, "Main.qml"));
        // Plugin-scoped needs exactly that plugin context.
        assert!(
            state.matches(
                "oma.qml.dynamic-code",
                Some("io.example.y"),
                "vendor/dyn.js"
            ),
            "plugin+path record matches its context"
        );
        assert!(
            !state.matches("oma.qml.dynamic-code", None, "vendor/dyn.js"),
            "plugin-scoped records never match plugin-less contexts"
        );
        assert!(!state.matches("oma.qml.dynamic-code", Some("io.other"), "vendor/dyn.js"));
        // Segment-exactness: sibling prefixes do not leak.
        assert!(!state.matches(
            "oma.qml.dynamic-code",
            Some("io.example.y"),
            "vendor_backup/dyn.js"
        ));
        assert!(state.matches("oma.qml.dynamic-code", Some("io.example.y"), "vendor"));
    }

    #[test]
    fn validation_rejects_bad_scopes_and_empty_fields() {
        assert!(validate_new("", "reason", None).is_err());
        assert!(validate_new("oma.rule", "  ", None).is_err());
        assert!(validate_new("oma.rule", "reason", Some("/etc")).is_err());
        assert!(validate_new("oma.rule", "reason", Some("a/../b")).is_err());
        assert!(validate_new("oma.rule", "reason", Some("./x")).is_err());
        assert!(validate_new("oma.rule", "reason", Some("a//b")).is_err());
        assert!(validate_new("oma.rule", "reason", None).is_ok());
        assert!(validate_new("oma.rule", "reason", Some("assets")).is_ok());
        assert!(validate_new("oma.rule", "reason", Some("assets/deep/")).is_ok());
    }
}
