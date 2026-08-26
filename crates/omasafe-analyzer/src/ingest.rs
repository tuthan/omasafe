//! Safe payload ingestion for analysis targets.
//!
//! Three frontends feed one shared bounded inventory pass:
//! - installed plugin trees and local directories (filesystem walk), and
//! - immutable Git revisions, read as raw objects from a bare repository
//!   (`ls-tree` + `cat-file`): no checkout, no smudge/clean filters, no
//!   submodules, no LFS, no hooks, argv-only Git under hard budgets.
//!
//! Every relevant entry receives an inventory record even when its content
//! cannot be ingested; coverage loss is always visible in `limitations`.
//! Never executes, sources, or renders anything from a target.

use std::fs;
use std::io;
use std::io::Read;
use std::io::Seek;
use std::io::SeekFrom;
use std::path::Path;
use std::path::PathBuf;
use std::time::Instant;

use serde::Serialize;
use sha2::Digest;

use omasafe_core::bounds::{
    GIT_PROCESS_BUDGET, MAX_CACHE_BYTES, MAX_FILE_BYTES, MAX_FILES,
    MAX_PROCESS_OUTPUT_BYTES_PER_STREAM, MAX_TOTAL_BYTES, MAX_TREE_DEPTH, SAMPLE_BYTES, TimeBudget,
    run_bounded_capped,
};
use omasafe_core::git;

use crate::payload::{
    ContentDigester, CoverageState, PayloadEntry, PayloadInventory, PayloadKind,
    classify_regular_file,
};

const SNIFF_WINDOW: usize = 64 * 1024;
const READ_CHUNK: usize = 64 * 1024;

/// Where an analyzed target came from; recorded in reports as provenance.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum TargetSource {
    InstalledPlugin { id: String },
    LocalDirectory,
    PinnedRevision { url: String, revision: String },
}

/// Active limits for one inventory pass. Runtime defaults come from
/// [`omasafe_core::bounds`]; tests shrink them to stay cheap. The canonical
/// policy-identity fingerprint always hashes the defaults, never instances.
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    pub max_files: usize,
    pub max_file_bytes: u64,
    pub max_total_bytes: u64,
    pub max_tree_depth: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_files: MAX_FILES,
            max_file_bytes: MAX_FILE_BYTES,
            max_total_bytes: MAX_TOTAL_BYTES,
            max_tree_depth: MAX_TREE_DEPTH,
        }
    }
}

/// Failures from any ingestion frontend.
#[derive(Debug, thiserror::Error)]
pub enum IngestError {
    #[error("analysis target is not a directory")]
    NotADirectory,
    #[error("analysis repository URL must be HTTPS and cannot start with '-'")]
    InvalidUrl,
    #[error("analysis revision must be 40 or 64 hexadecimal characters")]
    InvalidRevision,
    #[error("analysis cache exceeds its {0} byte quota; remove stale repositories")]
    CacheQuotaExceeded(u64),
    #[error("analysis Git operation failed: {0}")]
    Git(String),
    #[error("analysis time budget exhausted")]
    BudgetExhausted,
    #[error("analysis I/O error: {0}")]
    Io(#[from] io::Error),
}

/// Ingests a filesystem tree (installed plugin or local directory).
pub fn ingest_filesystem(
    root: &Path,
    limits: Limits,
    budget: TimeBudget,
) -> Result<PayloadInventory, IngestError> {
    let metadata = fs::symlink_metadata(root)?;
    if !metadata.is_dir() {
        return Err(IngestError::NotADirectory);
    }
    let mut walker = Walker::new(limits, budget);
    walker.walk_dir(root, "", 0)?;
    Ok(walker.finish())
}

// ---------------------------------------------------------------------------
// Filesystem walker
// ---------------------------------------------------------------------------

struct Walker {
    limits: Limits,
    budget: TimeBudget,
    entries: Vec<PayloadEntry>,
    files_seen: usize,
    total_bytes: u64,
    limitations: Vec<String>,
}

impl Walker {
    fn new(limits: Limits, budget: TimeBudget) -> Self {
        Self {
            limits,
            budget,
            entries: Vec::new(),
            files_seen: 0,
            total_bytes: 0,
            limitations: Vec::new(),
        }
    }

    fn note(&mut self, limitation: &str) {
        if !self
            .limitations
            .iter()
            .any(|existing| existing == limitation)
        {
            self.limitations.push(limitation.to_owned());
        }
    }

    fn out_of_budget(&mut self) -> bool {
        if self.budget.expired() {
            self.note("time_budget_exhausted");
            return true;
        }
        false
    }

    fn finish(self) -> PayloadInventory {
        let mut inventory = PayloadInventory {
            entries: self.entries,
            total_files_seen: self.files_seen,
            total_bytes_ingested: self.total_bytes,
            limitations: self.limitations,
        };
        inventory.sort_entries();
        inventory
    }

    fn walk_dir(&mut self, dir: &Path, prefix: &str, depth: usize) -> Result<(), IngestError> {
        if depth > self.limits.max_tree_depth {
            self.note("tree_depth_limit_exceeded");
            return Ok(());
        }
        if self.out_of_budget() {
            return Ok(());
        }
        // Entry-bomb bound: stop collecting a single huge directory at a hard
        // deterministic cap instead of materializing unbounded listings. The
        // whole directory is then skipped with visible loss.
        let child_cap = self.limits.max_files.saturating_mul(4).max(4096);
        let mut children: Vec<PathBuf> = Vec::new();
        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            if children.len() >= child_cap || self.entries.len() >= child_cap {
                self.note("directory_entry_limit_exceeded");
                return Ok(());
            }
            children.push(entry.path());
        }
        if self.entries.len() >= child_cap {
            self.note("file_limit_exceeded");
            return Ok(());
        }
        children.sort();

        for path in children {
            if self.out_of_budget() {
                return Ok(());
            }
            let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
                self.note("non_utf8_entry_name_skipped");
                continue;
            };
            let name = name.to_owned();
            let relative = if prefix.is_empty() {
                name
            } else {
                format!("{prefix}/{name}")
            };

            let Ok(metadata) = fs::symlink_metadata(&path) else {
                self.note("metadata_unavailable");
                continue;
            };
            let file_type = metadata.file_type();

            if file_type.is_symlink() {
                let target = fs::read_link(&path)
                    .map(|target| target.to_string_lossy().into_owned())
                    .unwrap_or_default();
                self.entries.push(PayloadEntry {
                    link_target: Some(target),
                    ..non_content_entry(&relative, PayloadKind::Symlink, &metadata)
                });
                continue;
            }

            if file_type.is_dir() {
                self.entries.push(non_content_entry(
                    &relative,
                    PayloadKind::Directory,
                    &metadata,
                ));
                self.walk_dir(&path, &relative, depth + 1)?;
                continue;
            }

            if !file_type.is_file() {
                self.note("special_file_present");
                let mut entry = non_content_entry(&relative, PayloadKind::Special, &metadata);
                entry.coverage_state = CoverageState::Skipped;
                self.entries.push(entry);
                continue;
            }

            self.files_seen += 1;
            if self.files_seen > self.limits.max_files {
                // Enumeration stops; everything beyond is disclosed as loss.
                self.note("file_limit_exceeded");
                return Ok(());
            }

            let entry = self.ingest_regular_file(&path, &relative, &metadata);
            self.entries.push(entry);
        }
        Ok(())
    }

    fn ingest_regular_file(
        &mut self,
        path: &Path,
        relative: &str,
        metadata: &fs::Metadata,
    ) -> PayloadEntry {
        let size = metadata.len();
        let mode = file_mode(metadata);
        let executable = mode & 0o111 != 0;

        if size > self.limits.max_file_bytes || self.total_bytes >= self.limits.max_total_bytes {
            let reason = if size > self.limits.max_file_bytes {
                "oversize_file_skipped"
            } else {
                "aggregate_byte_limit_reached"
            };
            return self.sampled_entry(path, relative, size, mode, executable, reason);
        }

        let mut file = match fs::File::open(path) {
            Ok(file) => file,
            Err(_) => {
                self.note("unreadable_file");
                return PayloadEntry {
                    coverage_state: CoverageState::Truncated,
                    ..base_entry(relative, size, mode, executable)
                };
            }
        };

        let mut digester = ContentDigester::new();
        // Classification window retained in memory; hashing covers everything read.
        let mut window = Vec::with_capacity(SNIFF_WINDOW.min(size as usize));
        let mut buffer = vec![0u8; READ_CHUNK];
        let mut truncated = false;
        loop {
            if self.budget.expired() {
                self.note("time_budget_exhausted");
                truncated = true;
                break;
            }
            // Never read past the aggregate allowance: the requested window
            // shrinks to what remains, so byte accounting stays exact.
            let room = (self.limits.max_total_bytes - self.total_bytes) as usize;
            if room == 0 {
                self.note("aggregate_byte_limit_reached");
                truncated = true;
                break;
            }
            let want = buffer.len().min(room);
            match file.read(&mut buffer[..want]) {
                Ok(0) => break,
                Ok(read) => {
                    if window.len() < SNIFF_WINDOW {
                        let take = (SNIFF_WINDOW - window.len()).min(read);
                        window.extend_from_slice(&buffer[..take]);
                    }
                    digester.update(&buffer[..read]);
                    self.total_bytes += read as u64;
                }
                Err(_) => {
                    self.note("read_error");
                    truncated = true;
                    break;
                }
            }
        }
        let (digest_hex, _) = digester.finish_hex();
        PayloadEntry {
            kind: classify_regular_file(relative, mode, &window),
            sha256_sampled: Some(digest_hex),
            sampled_digest: truncated,
            coverage_state: if truncated {
                CoverageState::Truncated
            } else {
                CoverageState::Unsupported
            },
            ..base_entry(relative, size, mode, executable)
        }
    }

    /// Records an oversize or budget-exhausted file by digesting only
    /// head/tail samples so later re-checks can still detect changes.
    fn sampled_entry(
        &mut self,
        path: &Path,
        relative: &str,
        size: u64,
        mode: u32,
        executable: bool,
        reason: &str,
    ) -> PayloadEntry {
        self.note(reason);
        // One shared allowance split between head and tail so sampling can
        // never consume the aggregate budget twice.
        let sample_allowance =
            SAMPLE_BYTES.min(self.limits.max_total_bytes.saturating_sub(self.total_bytes));
        let head_want = (sample_allowance / 2).min(SAMPLE_BYTES);
        let tail_want = sample_allowance.saturating_sub(head_want);
        let mut head = Vec::new();
        let mut tail = Vec::new();
        let mut bytes_read = 0u64;
        if sample_allowance > 0 {
            if let Ok(mut file) = fs::File::open(path) {
                let want = head_want.min(size) as usize;
                read_up_to(&mut file, &mut head, want);
                bytes_read += head.len() as u64;
                if size > head.len() as u64 && tail_want > 0 {
                    let tail_len = tail_want.min(size.saturating_sub(head.len() as u64)) as i64;
                    if file.seek(SeekFrom::End(-tail_len)).is_ok() {
                        read_up_to(&mut file, &mut tail, tail_want as usize);
                        bytes_read += tail.len() as u64;
                    }
                }
            } else {
                self.note("unreadable_file");
            }
        }
        self.total_bytes += bytes_read;

        let mut digester = ContentDigester::new();
        digester.update(&head);
        digester.update(&tail);
        let (digest_hex, _) = digester.finish_hex();
        PayloadEntry {
            kind: classify_regular_file(relative, mode, &head),
            sha256_sampled: Some(digest_hex),
            sampled_digest: true,
            coverage_state: CoverageState::Skipped,
            ..base_entry(relative, size, mode, executable)
        }
    }
}

fn read_up_to(file: &mut fs::File, sink: &mut Vec<u8>, mut want: usize) {
    let mut chunk = [0u8; 8192];
    while want > 0 {
        let take = want.min(chunk.len());
        match file.read(&mut chunk[..take]) {
            Ok(0) => break,
            Ok(read) => {
                sink.extend_from_slice(&chunk[..read]);
                want -= read;
            }
            Err(_) => break,
        }
    }
}

fn base_entry(relative: &str, size: u64, mode: u32, executable: bool) -> PayloadEntry {
    PayloadEntry {
        relative_path: relative.to_owned(),
        kind: PayloadKind::TextFile,
        mode,
        size,
        sha256_sampled: None,
        sampled_digest: false,
        executable,
        coverage_state: CoverageState::Unsupported,
        link_target: None,
        invocation_target: false,
        object_id: None,
    }
}

fn non_content_entry(relative: &str, kind: PayloadKind, metadata: &fs::Metadata) -> PayloadEntry {
    PayloadEntry {
        kind,
        mode: file_mode(metadata),
        size: 0,
        ..base_entry(relative, 0, file_mode(metadata), false)
    }
}

#[cfg(unix)]
fn file_mode(metadata: &fs::Metadata) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    metadata.permissions().mode()
}

#[cfg(not(unix))]
fn file_mode(metadata: &fs::Metadata) -> u32 {
    u32::from(metadata.permissions().readonly()) * 0o444
}

// ---------------------------------------------------------------------------
// Immutable Git revision frontend
// ---------------------------------------------------------------------------

/// Ensures `url`/`commit` is fetched into a private bare cache repository and
/// returns its path. No hooks, tags, or credential prompts; every Git child
/// runs under [`run_bounded`] with the remaining budget. URLs carrying
/// credentials are rejected outright so nothing secret reaches Git config,
/// cache layout, or reports. The cache-quota check runs both before and after
/// the fetch, under an exclusive advisory lock so concurrent scans cannot each
/// pass the same pre-check and then all fetch.
pub fn ensure_pinned_repository(
    cache_root: &Path,
    url: &str,
    revision: &str,
) -> Result<PathBuf, IngestError> {
    if !url.starts_with("https://") || url.starts_with('-') {
        return Err(IngestError::InvalidUrl);
    }
    let authority = url["https://".len()..].split('/').next().unwrap_or("");
    if authority.contains('@') {
        // user:token@host URLs would leak secrets into config and reports.
        return Err(IngestError::InvalidUrl);
    }
    if !omasafe_marketplace_valid_revision(revision) {
        return Err(IngestError::InvalidRevision);
    }
    fs::create_dir_all(cache_root)?;
    enforce_cache_quota(cache_root)?;

    let slug = cache_slug(url);
    let repository_dir = cache_root.join(format!("{slug}.git"));
    // One lock for the entire analysis cache: the quota is global, so per-
    // repository locks would still allow concurrent fetches to race it.
    let _lock = CacheLock::acquire(cache_root)?;
    enforce_cache_quota(cache_root)?;

    if !repository_dir.exists() {
        let display = repository_dir.to_string_lossy().into_owned();
        // Match the object format to the pinned revision so SHA-256 remotes
        // can be fetched at all.
        let object_format = if revision.len() == 64 {
            "sha256"
        } else {
            "sha1"
        };
        run_git(
            cache_root,
            &["init", "--bare", "--object-format", object_format, &display],
        )?;
    }
    if run_git(&repository_dir, &["remote", "get-url", "origin"]).is_err() {
        run_git(&repository_dir, &["remote", "add", "origin", url])?;
    }
    run_git(
        &repository_dir,
        &["fetch", "--no-tags", "--quiet", "origin", revision],
    )?;
    // The fetch itself is the unbounded write. On violation, remove the
    // offending repository we just wrote so the quota genuinely bounds disk
    // use (transient overshoot is bounded by one repository), then fail
    // visibly.
    if enforce_cache_quota(cache_root).is_err() {
        let _ = fs::remove_dir_all(&repository_dir);
        return Err(IngestError::CacheQuotaExceeded(MAX_CACHE_BYTES));
    }
    Ok(repository_dir)
}

/// Advisory whole-cache lock serializing fetch/quota decisions.
#[cfg(unix)]
struct CacheLock {
    _file: fs::File,
}

#[cfg(unix)]
impl CacheLock {
    fn acquire(cache_root: &Path) -> Result<Self, IngestError> {
        use std::os::unix::io::AsRawFd;
        let lock_path = cache_root.join("omasafe-analysis.lock");
        let file = fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(&lock_path)?;
        let deadline = Instant::now() + GIT_PROCESS_BUDGET;
        loop {
            let result = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
            if result == 0 {
                return Ok(Self { _file: file });
            }
            if io::Error::last_os_error().kind() != io::ErrorKind::WouldBlock {
                return Err(IngestError::Io(io::Error::last_os_error()));
            }
            if Instant::now() >= deadline {
                return Err(IngestError::BudgetExhausted);
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
    }
}

#[cfg(not(unix))]
struct CacheLock;

#[cfg(not(unix))]
impl CacheLock {
    fn acquire(_cache_root: &Path) -> Result<Self, IngestError> {
        Ok(Self)
    }
}

fn omasafe_marketplace_valid_revision(revision: &str) -> bool {
    (revision.len() == 40 || revision.len() == 64)
        && revision.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn cache_slug(url: &str) -> String {
    use sha2::Sha256;
    let digest = Sha256::digest(url.as_bytes());
    digest
        .iter()
        .take(8)
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn enforce_cache_quota(cache_root: &Path) -> Result<(), IngestError> {
    let mut total = 0u64;
    let mut stack = vec![cache_root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(children) = fs::read_dir(&dir) else {
            continue;
        };
        for child in children.flatten() {
            // Symlink-aware: never follow links while measuring the quota,
            // so a planted link cannot explode the walk or hide outside.
            let Ok(metadata) = fs::symlink_metadata(child.path()) else {
                continue;
            };
            if metadata.is_dir() {
                stack.push(child.path());
            } else {
                total = total.saturating_add(metadata.len());
            }
            if total > MAX_CACHE_BYTES {
                return Err(IngestError::CacheQuotaExceeded(MAX_CACHE_BYTES));
            }
        }
    }
    Ok(())
}

/// Ingests the full tree of `revision` from a bare repository by reading
/// objects directly (`ls-tree -l -z` + per-object `cat-file`). Nothing is
/// checked out; filters, hooks, and submodules cannot run. All shared limits
/// (files, aggregate bytes, tree depth, elapsed time) are enforced against the
/// caller's budget; oversize blobs become sampled `Skipped` entries instead of
/// aborting the scan.
pub fn ingest_pinned_tree(
    repository_dir: &Path,
    revision: &str,
    limits: Limits,
    budget: TimeBudget,
) -> Result<PayloadInventory, IngestError> {
    if !omasafe_marketplace_valid_revision(revision) {
        return Err(IngestError::InvalidRevision);
    }
    let mut walker = Walker::new(limits, budget);
    if walker.out_of_budget() {
        return Err(IngestError::BudgetExhausted);
    }
    let (listing, listing_truncated) = run_git_capped_within(
        repository_dir,
        &["ls-tree", "-r", "-l", "-z", revision],
        LS_TREE_OUTPUT_CAP_BYTES,
        &mut walker,
    )?;
    if listing_truncated {
        return Err(IngestError::Git(
            "tree listing exceeded its capture cap; refusing an incomplete inventory".to_owned(),
        ));
    }
    for record in split_nul_records(&listing) {
        if walker.out_of_budget() {
            break;
        }
        let Some((meta_bytes, path_bytes)) = SplitOnceBytes::split_once(record, b'\t') else {
            walker.note("malformed_ls_tree_record_skipped");
            continue;
        };
        // Meta fields are always ASCII octal/hash/type/size; paths may be any bytes.
        let Ok(meta) = std::str::from_utf8(meta_bytes) else {
            walker.note("malformed_ls_tree_record_skipped");
            continue;
        };
        let mut fields = meta.split_ascii_whitespace();
        let (Some(mode_raw), Some(object_type), Some(oid)) =
            (fields.next(), fields.next(), fields.next())
        else {
            walker.note("malformed_ls_tree_record_skipped");
            continue;
        };
        let mode = u32::from_str_radix(mode_raw, 8).unwrap_or(0);
        let declared_size: Option<u64> = fields.next().and_then(|size| size.parse().ok());
        let relative = match std::str::from_utf8(path_bytes) {
            Ok(path) => match normalize_git_path(path) {
                Ok(relative) => relative,
                Err(error) => {
                    walker.note(&error.to_string());
                    continue;
                }
            },
            Err(_) => {
                walker.note("non_utf8_path_lossily_named");
                let lossy = String::from_utf8_lossy(path_bytes).into_owned();
                match normalize_git_path(&lossy) {
                    Ok(relative) => relative,
                    Err(_) => continue,
                }
            }
        };
        if relative.split('/').count() > walker.limits.max_tree_depth + 1 {
            walker.note("tree_depth_limit_exceeded");
            continue;
        }

        match object_type {
            "blob" if mode == 0o120_000 => {
                let (raw_target, truncated) = run_git_capped_within(
                    repository_dir,
                    &["cat-file", "blob", oid],
                    SYMLINK_TARGET_CAP_BYTES,
                    &mut walker,
                )?;
                if truncated {
                    walker.note("symlink_target_truncated");
                }
                let target = String::from_utf8_lossy(&raw_target).into_owned();
                let size = target.len() as u64;
                walker.entries.push(PayloadEntry {
                    kind: PayloadKind::Symlink,
                    mode,
                    size,
                    link_target: Some(target),
                    executable: false,
                    coverage_state: CoverageState::Unsupported,
                    object_id: Some(oid.to_owned()),
                    ..base_entry(&relative, size, mode, false)
                });
            }
            "blob" => {
                walker.files_seen += 1;
                if walker.files_seen > limits.max_files {
                    walker.note("file_limit_exceeded");
                    break;
                }
                let executable = mode & 0o111 != 0;
                let remaining_aggregate = limits.max_total_bytes.saturating_sub(walker.total_bytes);
                let oversize = matches!(declared_size, Some(size) if size > limits.max_file_bytes)
                    || matches!(declared_size, Some(size) if size > remaining_aggregate)
                    || declared_size.is_none();
                let entry = if oversize {
                    walker.note(match declared_size {
                        Some(size) if size > limits.max_file_bytes => "oversize_file_skipped",
                        _ => "aggregate_byte_limit_reached",
                    });
                    // Head sample only: git objects have no seekable tail without
                    // extra plumbing, and the sample is enough for classification.
                    let sample_cap = SAMPLE_BYTES.min(remaining_aggregate) as usize;
                    let (content, _truncated_expected) = run_git_capped_within(
                        repository_dir,
                        &["cat-file", "blob", oid],
                        sample_cap,
                        &mut walker,
                    )?;
                    walker.total_bytes += content.len() as u64;
                    let mut digester = ContentDigester::new();
                    digester.update(&content);
                    let (digest_hex, _) = digester.finish_hex();
                    let window_end = content.len().min(SNIFF_WINDOW);
                    PayloadEntry {
                        kind: classify_regular_file(&relative, mode, &content[..window_end]),
                        sha256_sampled: Some(digest_hex),
                        sampled_digest: true,
                        coverage_state: CoverageState::Skipped,
                        size: declared_size.unwrap_or(content.len() as u64),
                        object_id: Some(oid.to_owned()),
                        ..base_entry(
                            &relative,
                            declared_size.unwrap_or(content.len() as u64),
                            mode,
                            executable,
                        )
                    }
                } else {
                    let want_u64 = declared_size.unwrap_or(0);
                    let want = want_u64 as usize;
                    let (content, truncated) = run_git_capped_within(
                        repository_dir,
                        &["cat-file", "blob", oid],
                        want + 1,
                        &mut walker,
                    )?;
                    if truncated || (content.len() as u64) != want_u64 {
                        return Err(IngestError::Git(format!(
                            "blob {oid} did not match its recorded size; refusing the inventory"
                        )));
                    }
                    walker.total_bytes += content.len() as u64;
                    let mut digester = ContentDigester::new();
                    digester.update(&content);
                    let (digest_hex, _) = digester.finish_hex();
                    let window_end = content.len().min(SNIFF_WINDOW);
                    PayloadEntry {
                        kind: classify_regular_file(&relative, mode, &content[..window_end]),
                        sha256_sampled: Some(digest_hex),
                        sampled_digest: false,
                        coverage_state: CoverageState::Unsupported,
                        object_id: Some(oid.to_owned()),
                        ..base_entry(&relative, want as u64, mode, executable)
                    }
                };
                walker.entries.push(entry);
            }
            "commit" => {
                walker.note("submodule_present_not_followed");
                walker.entries.push(PayloadEntry {
                    kind: PayloadKind::Special,
                    mode,
                    coverage_state: CoverageState::Skipped,
                    object_id: Some(oid.to_owned()),
                    ..base_entry(&relative, 0, mode, false)
                });
            }
            _ => {
                walker.note("unexpected_ls_tree_type_skipped");
            }
        }
        if walker.out_of_budget() {
            break;
        }
    }
    let mut inventory = walker.finish();
    // Filesystem walks see directories; object reads do not. Both shapes are
    // valid inventories — disclosure lives in coverage, not absence.
    inventory.sort_entries();
    Ok(inventory)
}

const SYMLINK_TARGET_CAP_BYTES: usize = 4096;
const LS_TREE_OUTPUT_CAP_BYTES: usize = MAX_PROCESS_OUTPUT_BYTES_PER_STREAM;

fn split_nul_records(bytes: &[u8]) -> impl Iterator<Item = &[u8]> {
    bytes
        .split(|byte| *byte == 0)
        .filter(|record| !record.is_empty())
}

trait SplitOnceBytes {
    fn split_once(&self, separator: u8) -> Option<(&[u8], &[u8])>;
}

impl SplitOnceBytes for [u8] {
    fn split_once(&self, separator: u8) -> Option<(&[u8], &[u8])> {
        let position = self.iter().position(|byte| *byte == separator)?;
        Some((&self[..position], &self[position + 1..]))
    }
}

/// Git tree paths are already forward-slashed and relative; refuse anything
/// that pretends otherwise instead of normalizing silently. The message is a
/// limitation string, never a panic on untrusted input.
fn normalize_git_path(path: &str) -> Result<String, IngestError> {
    if path.starts_with('/') || path.split('/').any(|segment| segment == "..") {
        return Err(IngestError::Git(
            "git produced an unsafe tree path: refusing to inventory it".to_owned(),
        ));
    }
    Ok(path.to_owned())
}

fn run_git(dir: &Path, args: &[&str]) -> Result<String, IngestError> {
    let (stdout, truncated) = run_git_capped(dir, args, MAX_PROCESS_OUTPUT_BYTES_PER_STREAM)?;
    if truncated {
        return Err(IngestError::Git(
            "git output exceeded the capture cap".to_owned(),
        ));
    }
    String::from_utf8(stdout)
        .map_err(|_| IngestError::Git("git returned non-UTF-8 output".to_owned()))
}

/// Returns `(output, hit_cap)`; callers decide whether a cap hit is fatal or a
/// disclosed degradation.
fn run_git_capped(dir: &Path, args: &[&str], cap: usize) -> Result<(Vec<u8>, bool), IngestError> {
    let mut command = git::command();
    command.current_dir(dir);
    command.arg("-c").arg("core.quotePath=false");
    command.args(args);
    let captured = run_bounded_capped(&mut command, GIT_PROCESS_BUDGET, cap)
        .map_err(IngestError::Io)?
        .ok_or(IngestError::BudgetExhausted)?;
    if !captured.status.success() {
        let message = String::from_utf8_lossy(&captured.stderr).trim().to_owned();
        return Err(IngestError::Git(if message.is_empty() {
            "git exited unsuccessfully".to_owned()
        } else {
            message
        }));
    }
    Ok((captured.stdout, captured.truncated))
}

/// Like [`run_git_capped`] but charged against the walker's remaining time
/// budget so one slow object cannot extend the whole scan.
fn run_git_capped_within(
    dir: &Path,
    args: &[&str],
    cap: usize,
    walker: &mut Walker,
) -> Result<(Vec<u8>, bool), IngestError> {
    if walker.out_of_budget() {
        return Err(IngestError::BudgetExhausted);
    }
    let remaining = walker.budget.remaining();
    let mut command = git::command();
    command.current_dir(dir);
    command.arg("-c").arg("core.quotePath=false");
    command.args(args);
    let captured = run_bounded_capped(&mut command, remaining, cap).map_err(IngestError::Io)?;
    let Some(captured) = captured else {
        walker.note("time_budget_exhausted");
        return Err(IngestError::BudgetExhausted);
    };
    // A capped read closes the pipe once full, so git may die by SIGPIPE;
    // that is the expected consequence of our own cap, not a failure.
    if !captured.status.success() && !captured.truncated {
        let message = String::from_utf8_lossy(&captured.stderr).trim().to_owned();
        return Err(IngestError::Git(if message.is_empty() {
            "git exited unsuccessfully".to_owned()
        } else {
            message
        }));
    }
    Ok((captured.stdout, captured.truncated))
}
