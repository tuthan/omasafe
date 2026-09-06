//! The CLI-owned persistent installed-scan snapshot.
//!
//! This module deliberately contains no analyzer or plugin-trust dependency.
//! It owns the private cache schema, bounded reader, canonical fingerprints,
//! profile lock, generation reservation, and atomic replacement primitive.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::paths::XdgPaths;

pub const SNAPSHOT_SCHEMA: &str = "omasafe.scan-snapshot.v1";
pub const REPORT_SCHEMA: &str = "omasafe.report.v1";
pub const INVENTORY_FINGERPRINT_SCHEMA: &str = "omasafe.inventory-fingerprint.v1";
pub const CONTEXT_FINGERPRINT_SCHEMA: &str = "omasafe.scan-context.v1";
pub const CACHE_RESULT_SCHEMA: &str = "omasafe.scan-cache-result.v1";
pub const MAX_SNAPSHOT_BYTES: usize = 256 * 1024;
pub const MAX_CACHED_ALERTS: usize = 4096;
pub const MAX_CACHED_STRING_BYTES: usize = 16 * 1024;
pub const MAX_LIMITATIONS: usize = 128;
pub const GENERATION_COUNTER_BYTES: usize = 32;
pub const GENERATION_COUNTER_MAX: u64 = u64::MAX - 1;
pub const PROFILE_LOCK_RETRIES: usize = 20;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ScanProfile {
    InstalledBasic,
    InstalledAnalysis,
}

impl ScanProfile {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InstalledBasic => "installed-basic",
            Self::InstalledAnalysis => "installed-analysis",
        }
    }

    pub const fn filename(self) -> &'static str {
        match self {
            Self::InstalledBasic => "installed-basic.json",
            Self::InstalledAnalysis => "installed-analysis.json",
        }
    }

    pub const fn lock_filename(self) -> &'static str {
        match self {
            Self::InstalledBasic => "installed-basic.lock",
            Self::InstalledAnalysis => "installed-analysis.lock",
        }
    }

    pub const fn generation_filename(self) -> &'static str {
        match self {
            Self::InstalledBasic => "installed-basic.generation",
            Self::InstalledAnalysis => "installed-analysis.generation",
        }
    }
}

impl std::str::FromStr for ScanProfile {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "installed-basic" => Ok(Self::InstalledBasic),
            "installed-analysis" => Ok(Self::InstalledAnalysis),
            _ => Err(format!("unsupported scan profile: {value}")),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Fingerprint {
    pub schema: String,
    pub digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContextFingerprint {
    pub schema: String,
    pub digest: String,
    pub components: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CachedScanAlert {
    pub key: String,
    pub plugin_id: String,
    pub kind: String,
    pub severity: String,
    pub reason_code: String,
    pub message: String,
    pub post_change: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CachedEnforcementDecision {
    pub plugin_id: String,
    pub evaluation_state: String,
    pub outcome: String,
    pub authorization_basis: Option<String>,
    pub evaluated_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CachedEnforcementSummary {
    pub schema: String,
    pub available: bool,
    pub decisions: Vec<CachedEnforcementDecision>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScanSnapshot {
    pub schema: String,
    pub report_schema: String,
    pub producer_cli_version: String,
    pub generation: u64,
    pub generated_at: String,
    pub valid_until: Option<String>,
    pub scan_profile: ScanProfile,
    pub inventory_fingerprint: Fingerprint,
    pub scan_context_fingerprint: ContextFingerprint,
    pub alerts: Vec<CachedScanAlert>,
    pub new_at_generation: usize,
    pub enforcement_summary: CachedEnforcementSummary,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SnapshotRead {
    Missing,
    Loaded(Box<ScanSnapshot>),
    Incompatible(String),
    Corrupt(String),
}

#[derive(Debug, thiserror::Error)]
pub enum CacheError {
    #[error("cache I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("cache JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("cache is oversized")]
    Oversized,
    #[error("cache contains duplicate object keys")]
    DuplicateKeys,
    #[error("cache path is not a private regular file")]
    UnsafePath,
    #[error("cache generation counter is malformed or exhausted")]
    Generation,
    #[error("cache profile lock is busy")]
    LockBusy,
    #[error("cache snapshot is incompatible: {0}")]
    Incompatible(String),
    #[error("cache snapshot is corrupt: {0}")]
    Corrupt(String),
}

pub struct ProfileLock {
    _file: File,
}

impl ProfileLock {
    fn acquire(dir: &Path, profile: ScanProfile) -> Result<Self, CacheError> {
        ensure_private_dir(dir)?;
        let path = dir.join(profile.lock_filename());
        reject_unsafe_existing(&path, true)?;
        let mut options = OpenOptions::new();
        options.read(true).write(true).create(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
        }
        let file = options.open(&path)?;
        set_private_file_mode(&path)?;
        #[cfg(unix)]
        {
            use std::os::fd::AsRawFd;
            let mut acquired = false;
            for _ in 0..PROFILE_LOCK_RETRIES {
                let result =
                    unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
                if result == 0 {
                    acquired = true;
                    break;
                }
                let error = std::io::Error::last_os_error();
                if error.raw_os_error() != Some(libc::EWOULDBLOCK) {
                    return Err(error.into());
                }
                std::thread::sleep(std::time::Duration::from_millis(25));
            }
            if !acquired {
                return Err(CacheError::LockBusy);
            }
        }
        Ok(Self { _file: file })
    }
}

/// Reserve a profile-local ordering number before doing scan work. A skipped
/// reservation is harmless after a crash; reusing a number is not.
pub fn reserve_generation(paths: &XdgPaths, profile: ScanProfile) -> Result<u64, CacheError> {
    let dir = paths.scan_snapshots();
    let _lock = ProfileLock::acquire(&dir, profile)?;
    let counter_path = dir.join(profile.generation_filename());
    let next = read_small_counter(&counter_path)?.unwrap_or(1);
    if next == 0 || next >= GENERATION_COUNTER_MAX {
        return Err(CacheError::Generation);
    }
    write_private_file(&counter_path, format!("{}\n", next + 1).as_bytes())?;
    Ok(next)
}

/// Replace a profile snapshot only when its reserved generation is newer than
/// the currently installed one. The caller supplies already bounded JSON.
pub fn replace_snapshot(
    paths: &XdgPaths,
    profile: ScanProfile,
    generation: u64,
    bytes: &[u8],
) -> Result<bool, CacheError> {
    if bytes.len() > MAX_SNAPSHOT_BYTES {
        return Err(CacheError::Oversized);
    }
    let dir = paths.scan_snapshots();
    let _lock = ProfileLock::acquire(&dir, profile)?;
    let final_path = dir.join(profile.filename());
    reject_unsafe_existing(&final_path, true)?;
    if let SnapshotRead::Loaded(current) = read_snapshot_path(&final_path, Some(profile))?
        && current.generation >= generation
    {
        return Ok(false);
    }

    let mut last_error = None;
    for attempt in 0..8u32 {
        let temp = dir.join(format!(
            ".{}.{}.{}.tmp",
            profile.as_str(),
            std::process::id(),
            unique_nonce() ^ u64::from(attempt)
        ));
        let mut options = OpenOptions::new();
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
        let result = file.write_all(bytes).and_then(|()| file.sync_all());
        drop(file);
        if let Err(error) = result {
            let _ = fs::remove_file(&temp);
            return Err(error.into());
        }
        if let Err(error) = fs::rename(&temp, &final_path) {
            let _ = fs::remove_file(&temp);
            return Err(error.into());
        }
        set_private_file_mode(&final_path)?;
        sync_directory(&dir)?;
        return Ok(true);
    }
    Err(last_error
        .unwrap_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::AlreadyExists, "temporary collision")
        })
        .into())
}

pub fn read_snapshot(paths: &XdgPaths, profile: ScanProfile) -> Result<SnapshotRead, CacheError> {
    read_snapshot_path(
        &paths.scan_snapshots().join(profile.filename()),
        Some(profile),
    )
}

fn read_snapshot_path(
    path: &Path,
    expected_profile: Option<ScanProfile>,
) -> Result<SnapshotRead, CacheError> {
    let bytes = match read_bounded(path, MAX_SNAPSHOT_BYTES) {
        Ok(Some(bytes)) => bytes,
        Ok(None) => return Ok(SnapshotRead::Missing),
        Err(CacheError::UnsafePath) => {
            return Ok(SnapshotRead::Corrupt("unsafe cache path".into()));
        }
        Err(CacheError::Oversized) => {
            return Ok(SnapshotRead::Corrupt("snapshot exceeds byte bound".into()));
        }
        Err(error) => return Ok(SnapshotRead::Corrupt(error.to_string())),
    };
    if reject_duplicate_keys(&bytes).is_err() {
        return Ok(SnapshotRead::Corrupt("duplicate JSON object keys".into()));
    }
    let snapshot: ScanSnapshot = match serde_json::from_slice(&bytes) {
        Ok(snapshot) => snapshot,
        Err(error) => {
            return Ok(SnapshotRead::Corrupt(format!(
                "malformed snapshot: {error}"
            )));
        }
    };
    match validate_snapshot(snapshot, expected_profile) {
        Ok(snapshot) => Ok(SnapshotRead::Loaded(Box::new(snapshot))),
        Err(CacheError::Incompatible(reason)) => Ok(SnapshotRead::Incompatible(reason)),
        Err(error) => Ok(SnapshotRead::Corrupt(error.to_string())),
    }
}

fn validate_snapshot(
    mut snapshot: ScanSnapshot,
    expected_profile: Option<ScanProfile>,
) -> Result<ScanSnapshot, CacheError> {
    if snapshot.schema != SNAPSHOT_SCHEMA || snapshot.report_schema != REPORT_SCHEMA {
        return Err(CacheError::Incompatible(
            "unsupported cache or report schema".into(),
        ));
    }
    if snapshot.inventory_fingerprint.schema != INVENTORY_FINGERPRINT_SCHEMA
        || snapshot.scan_context_fingerprint.schema != CONTEXT_FINGERPRINT_SCHEMA
    {
        return Err(CacheError::Incompatible(
            "unsupported fingerprint schema".into(),
        ));
    }
    if !producer_compatible(&snapshot.producer_cli_version) {
        return Err(CacheError::Incompatible(
            "unsupported producer CLI version".into(),
        ));
    }
    if expected_profile.is_some_and(|profile| snapshot.scan_profile != profile) {
        return Err(CacheError::Incompatible(
            "snapshot profile does not match requested profile".into(),
        ));
    }
    if snapshot.generation == 0
        || !valid_digest(&snapshot.inventory_fingerprint.digest)
        || !valid_digest(&snapshot.scan_context_fingerprint.digest)
        || snapshot.scan_context_fingerprint.components.len() != 6
        || snapshot
            .scan_context_fingerprint
            .components
            .keys()
            .any(|key| {
                !matches!(
                    key.as_str(),
                    "inventory"
                        | "trust"
                        | "marketplace"
                        | "analysis_policy"
                        | "enforcement"
                        | "runtime"
                )
            })
        || snapshot
            .scan_context_fingerprint
            .components
            .values()
            .any(|digest| !valid_digest(digest))
    {
        return Err(CacheError::Corrupt(
            "invalid generation or fingerprint".into(),
        ));
    }
    validate_timestamp(&snapshot.generated_at, true)?;
    if let Some(valid_until) = &snapshot.valid_until {
        validate_timestamp(valid_until, false)?;
    }
    if snapshot.alerts.len() > MAX_CACHED_ALERTS {
        return Err(CacheError::Corrupt("too many cached alerts".into()));
    }
    for alert in &snapshot.alerts {
        for value in [
            &alert.key,
            &alert.plugin_id,
            &alert.kind,
            &alert.severity,
            &alert.reason_code,
            &alert.message,
        ] {
            if value.len() > MAX_CACHED_STRING_BYTES || value.contains('\0') {
                return Err(CacheError::Corrupt(
                    "cached alert field exceeds bound".into(),
                ));
            }
        }
        if !matches!(
            alert.severity.as_str(),
            "info" | "low" | "medium" | "warning" | "error" | "high" | "critical"
        ) {
            return Err(CacheError::Corrupt("unknown cached severity".into()));
        }
        if !known_reason_code(&alert.reason_code) {
            return Err(CacheError::Corrupt("unknown cached reason code".into()));
        }
    }
    if snapshot.new_at_generation > snapshot.alerts.len() {
        return Err(CacheError::Corrupt(
            "new alert count exceeds alert count".into(),
        ));
    }
    if snapshot.enforcement_summary.schema != "omasafe.enforcement-summary.v1" {
        return Err(CacheError::Incompatible(
            "unsupported enforcement summary schema".into(),
        ));
    }
    if snapshot.enforcement_summary.decisions.len() > MAX_CACHED_ALERTS {
        return Err(CacheError::Corrupt("too many enforcement decisions".into()));
    }
    for decision in &snapshot.enforcement_summary.decisions {
        if decision.plugin_id.len() > MAX_CACHED_STRING_BYTES
            || decision.evaluated_at.len() > MAX_CACHED_STRING_BYTES
            || !matches!(
                decision.evaluation_state.as_str(),
                "evaluated" | "not-evaluated"
            )
            || !matches!(decision.outcome.as_str(), "allow" | "block")
            || decision
                .authorization_basis
                .as_deref()
                .is_some_and(|basis| !matches!(basis, "policy" | "override"))
        {
            return Err(CacheError::Corrupt("invalid enforcement summary".into()));
        }
        validate_timestamp(&decision.evaluated_at, false)?;
    }
    snapshot.alerts.sort_by(|left, right| {
        severity_rank(&right.severity)
            .cmp(&severity_rank(&left.severity))
            .then_with(|| left.plugin_id.cmp(&right.plugin_id))
            .then_with(|| left.kind.cmp(&right.kind))
            .then_with(|| left.key.cmp(&right.key))
    });
    let mut keys = BTreeSet::new();
    if snapshot
        .alerts
        .iter()
        .any(|alert| !keys.insert(alert.key.clone()))
    {
        return Err(CacheError::Corrupt("duplicate cached alert key".into()));
    }
    Ok(snapshot)
}

pub fn canonical_digest(domain: &str, version: &str, value: &serde_json::Value) -> String {
    let canonical = canonical_json(value);
    let mut material = format!("omasafe:{domain}:{version}\0").into_bytes();
    material.extend_from_slice(canonical.as_bytes());
    format!("{:x}", Sha256::digest(material))
}

pub fn canonical_json(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::Object(object) => {
            let ordered: BTreeMap<&String, String> = object
                .iter()
                .map(|(key, value)| (key, canonical_json(value)))
                .collect();
            let fields = ordered
                .into_iter()
                .map(|(key, value)| {
                    format!("{}:{value}", serde_json::to_string(key).expect("JSON key"))
                })
                .collect::<Vec<_>>();
            format!("{{{}}}", fields.join(","))
        }
        serde_json::Value::Array(values) => format!(
            "[{}]",
            values
                .iter()
                .map(canonical_json)
                .collect::<Vec<_>>()
                .join(",")
        ),
        _ => serde_json::to_string(value).expect("JSON scalar"),
    }
}

pub fn validate_timestamp(value: &str, reject_future: bool) -> Result<(), CacheError> {
    let bytes = value.as_bytes();
    if bytes.len() != 20
        || bytes[4] != b'-'
        || bytes[7] != b'-'
        || bytes[10] != b'T'
        || bytes[13] != b':'
        || bytes[16] != b':'
        || bytes[19] != b'Z'
        || !bytes.iter().enumerate().all(|(index, byte)| {
            matches!(index, 4 | 7 | 10 | 13 | 16 | 19) || byte.is_ascii_digit()
        })
    {
        return Err(CacheError::Corrupt("invalid timestamp".into()));
    }
    let year = value[0..4].parse::<i64>().unwrap_or(0);
    let month = value[5..7].parse::<i64>().unwrap_or(0);
    let day = value[8..10].parse::<i64>().unwrap_or(0);
    let hour = value[11..13].parse::<i64>().unwrap_or(99);
    let minute = value[14..16].parse::<i64>().unwrap_or(99);
    let second = value[17..19].parse::<i64>().unwrap_or(99);
    if !(1..=12).contains(&month)
        || !(1..=days_in_month(year, month)).contains(&day)
        || hour > 23
        || minute > 59
        || second > 59
    {
        return Err(CacheError::Corrupt("invalid timestamp".into()));
    }
    if reject_future {
        let timestamp =
            days_from_civil(year, month, day) * 86_400 + hour * 3_600 + minute * 60 + second;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |duration| duration.as_secs() as i64);
        if timestamp > now + 300 {
            return Err(CacheError::Corrupt(
                "timestamp is implausibly in the future".into(),
            ));
        }
    }
    Ok(())
}

fn producer_compatible(value: &str) -> bool {
    let mut parts = value.split('.');
    matches!((parts.next(), parts.next(), parts.next(), parts.next()), (Some("0"), Some("2"), Some(patch), None) if !patch.is_empty() && patch.bytes().all(|byte| byte.is_ascii_digit()))
}

fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value.bytes().all(|byte| byte.is_ascii_hexdigit())
        && value == value.to_ascii_lowercase()
}

fn known_reason_code(value: &str) -> bool {
    matches!(
        value,
        "inventory"
            | "plugin-unscannable"
            | "partial-coverage"
            | "source-drift"
            | "missing-plugin"
            | "marketplace"
            | "bar-replacement"
            | "provenance-conflict"
            | "analysis"
            | "trust-history"
            | "unknown"
    )
}

pub fn known_reason_code_for_cli(value: &str) -> bool {
    known_reason_code(value)
}

fn severity_rank(value: &str) -> u8 {
    match value {
        "info" => 1,
        "low" => 2,
        "warning" => 3,
        "medium" => 4,
        "error" => 5,
        "high" => 6,
        "critical" => 7,
        _ => 0,
    }
}

fn ensure_private_dir(path: &Path) -> Result<(), CacheError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if !metadata.is_dir() || !owned_by_current_user(&metadata) {
                return Err(CacheError::UnsafePath);
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            fs::create_dir_all(path)?;
        }
        Err(error) => return Err(error.into()),
    }
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_dir() || !owned_by_current_user(&metadata) {
        return Err(CacheError::UnsafePath);
    }
    #[cfg(unix)]
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    Ok(())
}

fn reject_unsafe_existing(path: &Path, allow_missing: bool) -> Result<(), CacheError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || !owned_by_current_user(&metadata) {
                return Err(CacheError::UnsafePath);
            }
            if !metadata.is_file() && !metadata.is_dir() {
                return Err(CacheError::UnsafePath);
            }
        }
        Err(error) if allow_missing && error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    Ok(())
}

fn set_private_file_mode(path: &Path) -> Result<(), CacheError> {
    reject_unsafe_existing(path, false)?;
    #[cfg(unix)]
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(())
}

fn write_private_file(path: &Path, bytes: &[u8]) -> Result<(), CacheError> {
    reject_unsafe_existing(path, true)?;
    let mut options = OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    let mut file = options.open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    set_private_file_mode(path)?;
    sync_directory(path.parent().unwrap_or_else(|| Path::new(".")))?;
    Ok(())
}

fn read_small_counter(path: &Path) -> Result<Option<u64>, CacheError> {
    let Some(bytes) = read_bounded(path, GENERATION_COUNTER_BYTES)? else {
        return Ok(None);
    };
    let value = std::str::from_utf8(&bytes)
        .map_err(|_| CacheError::Generation)?
        .trim();
    let value = value.parse::<u64>().map_err(|_| CacheError::Generation)?;
    Ok(Some(value))
}

fn read_bounded(path: &Path, cap: usize) -> Result<Option<Vec<u8>>, CacheError> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    if metadata.file_type().is_symlink() || !metadata.is_file() || !owned_by_current_user(&metadata)
    {
        return Err(CacheError::UnsafePath);
    }
    if metadata.len() > cap as u64 {
        return Err(CacheError::Oversized);
    }
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    let mut file = options.open(path)?;
    let mut bytes = Vec::with_capacity(metadata.len() as usize + 1);
    Read::by_ref(&mut file)
        .take(cap as u64 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > cap {
        return Err(CacheError::Oversized);
    }
    Ok(Some(bytes))
}

fn sync_directory(path: &Path) -> Result<(), CacheError> {
    let directory = File::open(path)?;
    directory.sync_all()?;
    Ok(())
}

fn owned_by_current_user(metadata: &std::fs::Metadata) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        metadata.uid() == unsafe { libc::geteuid() }
    }
    #[cfg(not(unix))]
    {
        let _ = metadata;
        true
    }
}

fn unique_nonce() -> u64 {
    #[cfg(unix)]
    {
        let mut bytes = [0u8; 8];
        if unsafe { libc::getrandom(bytes.as_mut_ptr().cast(), bytes.len(), 0) }
            == bytes.len() as isize
        {
            return u64::from_ne_bytes(bytes);
        }
    }
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_nanos() as u64)
        ^ ((std::process::id() as u64) << 32)
}

fn reject_duplicate_keys(bytes: &[u8]) -> Result<(), ()> {
    struct Scanner<'a> {
        bytes: &'a [u8],
        index: usize,
    }
    impl<'a> Scanner<'a> {
        fn ws(&mut self) {
            while self
                .bytes
                .get(self.index)
                .is_some_and(|byte| byte.is_ascii_whitespace())
            {
                self.index += 1;
            }
        }
        fn string(&mut self) -> Result<String, ()> {
            let start = self.index;
            if self.bytes.get(self.index) != Some(&b'"') {
                return Err(());
            }
            self.index += 1;
            let mut escaped = false;
            while let Some(&byte) = self.bytes.get(self.index) {
                self.index += 1;
                if escaped {
                    escaped = false;
                    continue;
                }
                if byte == b'\\' {
                    escaped = true;
                    continue;
                }
                if byte == b'"' {
                    return serde_json::from_slice(&self.bytes[start..self.index]).map_err(|_| ());
                }
                if byte < 0x20 {
                    return Err(());
                }
            }
            Err(())
        }
        fn value(&mut self) -> Result<(), ()> {
            self.ws();
            match self.bytes.get(self.index) {
                Some(b'{') => self.object(),
                Some(b'[') => {
                    self.index += 1;
                    self.ws();
                    if self.bytes.get(self.index) == Some(&b']') {
                        self.index += 1;
                        return Ok(());
                    }
                    loop {
                        self.value()?;
                        self.ws();
                        match self.bytes.get(self.index) {
                            Some(b',') => self.index += 1,
                            Some(b']') => {
                                self.index += 1;
                                return Ok(());
                            }
                            _ => return Err(()),
                        }
                    }
                }
                Some(b'"') => {
                    self.string()?;
                    Ok(())
                }
                Some(_) => {
                    let start = self.index;
                    while self.bytes.get(self.index).is_some_and(
                        |byte| !matches!(byte, b',' | b']' | b'}' if !byte.is_ascii_whitespace()),
                    ) {
                        self.index += 1;
                    }
                    if self.index == start { Err(()) } else { Ok(()) }
                }
                None => Err(()),
            }
        }
        fn object(&mut self) -> Result<(), ()> {
            self.index += 1;
            self.ws();
            let mut keys = BTreeSet::new();
            if self.bytes.get(self.index) == Some(&b'}') {
                self.index += 1;
                return Ok(());
            }
            loop {
                self.ws();
                let key = self.string()?;
                if !keys.insert(key) {
                    return Err(());
                }
                self.ws();
                if self.bytes.get(self.index) != Some(&b':') {
                    return Err(());
                }
                self.index += 1;
                self.value()?;
                self.ws();
                match self.bytes.get(self.index) {
                    Some(b',') => self.index += 1,
                    Some(b'}') => {
                        self.index += 1;
                        return Ok(());
                    }
                    _ => return Err(()),
                }
            }
        }
    }
    let mut scanner = Scanner { bytes, index: 0 };
    scanner.value()?;
    scanner.ws();
    (scanner.index == bytes.len()).then_some(()).ok_or(())
}

fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let year = year - i64::from(month <= 2);
    let era = if year >= 0 { year } else { year - 399 }.div_euclid(400);
    let yoe = year - era * 400;
    let month = month + if month > 2 { -3 } else { 9 };
    let doy = (153 * month + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146097 + doe - 719468
}

fn days_in_month(year: i64, month: i64) -> i64 {
    match month {
        2 if year % 4 == 0 && (year % 100 != 0 || year % 400 == 0) => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn paths() -> (TempDir, XdgPaths) {
        let root = TempDir::new().unwrap();
        let paths = XdgPaths {
            config: root.path().join("config"),
            state: root.path().join("state"),
            cache: root.path().join("cache"),
        };
        (root, paths)
    }

    #[test]
    fn canonical_digest_is_object_order_invariant() {
        let left = serde_json::json!({"b": 2, "a": ["x", "y"]});
        let right = serde_json::json!({"a": ["x", "y"], "b": 2});
        assert_eq!(
            canonical_digest("test", "v1", &left),
            canonical_digest("test", "v1", &right)
        );
    }

    #[test]
    fn duplicate_key_scanner_rejects_nested_duplicates() {
        assert!(reject_duplicate_keys(br#"{"a":{"b":1,"b":2}}"#).is_err());
        assert!(reject_duplicate_keys(br#"{"a":[{"b":1},{"b":2}]}"#).is_ok());
    }

    #[test]
    fn replacement_is_private_and_round_trips() {
        let (_root, paths) = paths();
        let profile = ScanProfile::InstalledBasic;
        let snapshot = ScanSnapshot {
            schema: SNAPSHOT_SCHEMA.into(),
            report_schema: REPORT_SCHEMA.into(),
            producer_cli_version: "0.2.3".into(),
            generation: 1,
            generated_at: "2026-09-04T00:00:00Z".into(),
            valid_until: None,
            scan_profile: profile,
            inventory_fingerprint: Fingerprint {
                schema: INVENTORY_FINGERPRINT_SCHEMA.into(),
                digest: "a".repeat(64),
            },
            scan_context_fingerprint: ContextFingerprint {
                schema: CONTEXT_FINGERPRINT_SCHEMA.into(),
                digest: "b".repeat(64),
                components: [
                    "inventory",
                    "trust",
                    "marketplace",
                    "analysis_policy",
                    "enforcement",
                    "runtime",
                ]
                .into_iter()
                .map(|key| (key.into(), "c".repeat(64)))
                .collect(),
            },
            alerts: vec![],
            new_at_generation: 0,
            enforcement_summary: CachedEnforcementSummary {
                schema: "omasafe.enforcement-summary.v1".into(),
                available: true,
                decisions: vec![],
                error: None,
            },
        };
        let bytes = serde_json::to_vec(&snapshot).unwrap();
        assert!(reserve_generation(&paths, profile).is_ok());
        assert!(replace_snapshot(&paths, profile, 1, &bytes).unwrap());
        assert!(matches!(
            read_snapshot(&paths, profile).unwrap(),
            SnapshotRead::Loaded(_)
        ));
        #[cfg(unix)]
        assert_eq!(
            fs::metadata(paths.scan_snapshots().join(profile.filename()))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }

    #[test]
    fn generation_counter_exhaustion_is_an_error_not_an_overflow() {
        let (_root, paths) = paths();
        let profile = ScanProfile::InstalledBasic;
        let directory = paths.scan_snapshots();
        fs::create_dir_all(&directory).unwrap();
        fs::write(
            directory.join(profile.generation_filename()),
            format!("{}\n", GENERATION_COUNTER_MAX),
        )
        .unwrap();
        assert!(matches!(
            reserve_generation(&paths, profile),
            Err(CacheError::Generation)
        ));
    }
}
