pub mod manifest;

use std::fs;
use std::io::Read;
use std::path::Path;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use omasafe_core::bounds::{
    GIT_PROCESS_BUDGET, MAX_METADATA_BYTES, MAX_PROCESS_OUTPUT_BYTES_PER_STREAM, run_bounded_capped,
};

pub const MAX_CATALOG_BYTES: usize = 32 * 1024 * 1024;
pub const OFFICIAL_REPOSITORY: &str = "https://github.com/omacom/omarchy-plugin-marketplace";
pub const DISCLAIMER: &str = "Marketplace fields are claims made by the named registry snapshot, not local security guarantees.";

pub fn valid_commit(value: &str) -> bool {
    (value.len() == 40 || value.len() == 64) && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("catalog exceeds the {MAX_CATALOG_BYTES} byte limit")]
    Oversized,
    #[error("catalog JSON is malformed: {0}")]
    Json(#[from] serde_json::Error),
    #[error("catalog I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("catalog Git operation failed: {0}")]
    Git(String),
    #[error("catalog commit is not a valid hexadecimal revision")]
    InvalidCommit,
    #[error("catalog revision is older or unrelated to the last accepted snapshot")]
    Rollback,
    #[error("catalog JSON has no recognized entry list")]
    InvalidShape,
    #[error("marketplace cache is not cryptographically reverified")]
    UnverifiedCache,
    #[error("no marketplace entry matched plugin ID {0}")]
    MissingCandidate(String),
    #[error("multiple marketplace entries matched plugin ID {0}")]
    AmbiguousCandidate(String),
    #[error("marketplace entry {0} has no usable repository")]
    MissingRepository(String),
    #[error("unsupported-marketplace-repository: {0}")]
    UnsupportedRepository(String),
    #[error("marketplace entry {0} has no valid listingValidatedCommit")]
    MissingListingCommit(String),
    #[error("marketplace entry {0} declares an unsupported repository layout")]
    UnsupportedLayout(String),
}

#[derive(Debug, Clone, Serialize)]
pub struct CatalogSnapshot {
    pub repository: String,
    pub repository_commit: String,
    pub file_digest: String,
    pub retrieved_at: String,
    pub generation_time: Option<String>,
    #[serde(skip)]
    pub verified: bool,
    pub entries: Vec<CatalogEntry>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CatalogEntry {
    pub id: Option<String>,
    pub repo: Option<String>,
    #[serde(rename = "verificationStatus")]
    pub verification_status: Option<String>,
    #[serde(rename = "listingValidatedCommit")]
    pub listing_validated_commit: Option<String>,
    #[serde(rename = "upstreamObservedCommit")]
    pub upstream_observed_commit: Option<String>,
    #[serde(rename = "upstreamCheckStatus")]
    pub upstream_check_status: Option<String>,
    #[serde(rename = "repositoryLayout")]
    pub repository_layout: Option<String>,
    pub kind: Option<String>,
    #[serde(flatten)]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Correlation {
    pub plugin_id: String,
    pub status: String,
    pub registry_claim: Option<RegistryClaim>,
    pub disclaimer: &'static str,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct RegistryClaim {
    pub registry_repository: String,
    pub registry_commit: String,
    pub retrieved_at: String,
    pub generation_time: Option<String>,
    pub repository: Option<String>,
    pub verification_status: Option<String>,
    pub listing_validated_commit: Option<String>,
    pub upstream_observed_commit: Option<String>,
    pub upstream_moved: Option<bool>,
    pub installed_matches_listing: Option<bool>,
    pub repository_layout: Option<String>,
}

/// Exact, catalog-controlled identity used by the marketplace candidate
/// scanner.
#[derive(Debug, Clone, Serialize)]
pub struct Candidate {
    pub plugin_id: String,
    pub listed_repository: String,
    pub effective_repository_url: String,
    pub listing_validated_commit: String,
    pub repository_layout: String,
    pub claim: CandidateClaim,
}

#[derive(Debug, Clone, Serialize)]
pub struct CandidateClaim {
    pub registry_repository: String,
    pub registry_commit: String,
    pub catalog_file_digest: String,
    pub retrieved_at: String,
    pub generation_time: Option<String>,
    pub listed_repository: String,
    pub effective_repository_url: String,
    pub verification_status: Option<String>,
    pub listing_validated_commit: String,
    pub upstream_observed_commit: Option<String>,
    pub repository_layout: String,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum CatalogDocument {
    Entries(Vec<CatalogEntry>),
    Wrapped {
        entries: Option<Vec<CatalogEntry>>,
        plugins: Option<Vec<CatalogEntry>>,
        generation_time: Option<String>,
        #[serde(rename = "generatedAt")]
        generated_at: Option<String>,
    },
}

pub fn parse_catalog(
    bytes: &[u8],
    repository: String,
    repository_commit: String,
    retrieved_at: String,
) -> Result<CatalogSnapshot, Error> {
    if bytes.len() > MAX_CATALOG_BYTES {
        return Err(Error::Oversized);
    }
    let document: CatalogDocument = serde_json::from_slice(bytes)?;
    let (entries, generation_time) = match document {
        CatalogDocument::Entries(entries) => (entries, None),
        CatalogDocument::Wrapped {
            entries,
            plugins,
            generation_time,
            generated_at,
        } => (
            match entries.or(plugins) {
                Some(entries) => entries,
                None => return Err(Error::InvalidShape),
            },
            generation_time.or(generated_at),
        ),
    };
    Ok(CatalogSnapshot {
        repository,
        repository_commit,
        file_digest: hex_digest(bytes),
        retrieved_at,
        generation_time,
        verified: false,
        entries,
    })
}

pub fn load_catalog(
    path: &Path,
    repository: String,
    repository_commit: String,
    retrieved_at: String,
) -> Result<CatalogSnapshot, Error> {
    let size = fs::metadata(path)?.len();
    if size > MAX_CATALOG_BYTES as u64 {
        return Err(Error::Oversized);
    }
    let bytes = fs::read(path)?;
    parse_catalog(
        bytes.as_slice(),
        repository,
        repository_commit,
        retrieved_at,
    )
}

pub fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), Error> {
    if bytes.len() > MAX_CATALOG_BYTES {
        return Err(Error::Oversized);
    }
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent)?;
    let temporary = path.with_extension(format!("tmp-{}", std::process::id()));
    fs::write(&temporary, bytes)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&temporary, fs::Permissions::from_mode(0o600))?;
    }
    fs::rename(temporary, path)?;
    Ok(())
}

pub fn resolve_latest_commit(repository_url: &str) -> Result<String, Error> {
    validate_https_repository(repository_url)?;
    omasafe_core::git::resolve_remote_head(repository_url)
        .map(|head| head.revision)
        .map_err(|error| Error::Git(error.to_string()))
}

/// Resolves one listing only from a verified cached snapshot. Catalog text is
/// retained separately from the effective fetch URL so a GitHub SSH
/// conversion remains visible provenance rather than a silent rewrite.
pub fn resolve_candidate(snapshot: &CatalogSnapshot, plugin_id: &str) -> Result<Candidate, Error> {
    if !snapshot.verified {
        return Err(Error::UnverifiedCache);
    }
    let matches: Vec<&CatalogEntry> = snapshot
        .entries
        .iter()
        .filter(|entry| entry.id.as_deref() == Some(plugin_id))
        .collect();
    let entry = match matches.as_slice() {
        [] => return Err(Error::MissingCandidate(plugin_id.to_owned())),
        [entry] => *entry,
        _ => return Err(Error::AmbiguousCandidate(plugin_id.to_owned())),
    };
    let listed_repository = entry
        .repo
        .clone()
        .ok_or_else(|| Error::MissingRepository(plugin_id.to_owned()))?;
    let effective_repository_url = effective_repository_url(&listed_repository)?;
    let listing_validated_commit = entry
        .listing_validated_commit
        .clone()
        .filter(|commit| valid_commit(commit))
        .ok_or_else(|| Error::MissingListingCommit(plugin_id.to_owned()))?;
    let repository_layout = entry
        .repository_layout
        .clone()
        .ok_or_else(|| Error::UnsupportedLayout(plugin_id.to_owned()))?;
    if !matches!(
        repository_layout.as_str(),
        "root-plugin" | "monorepo" | "suite"
    ) {
        return Err(Error::UnsupportedLayout(plugin_id.to_owned()));
    }
    Ok(Candidate {
        plugin_id: plugin_id.to_owned(),
        listed_repository: listed_repository.clone(),
        effective_repository_url: effective_repository_url.clone(),
        listing_validated_commit: listing_validated_commit.clone(),
        repository_layout: repository_layout.clone(),
        claim: CandidateClaim {
            registry_repository: snapshot.repository.clone(),
            registry_commit: snapshot.repository_commit.clone(),
            catalog_file_digest: snapshot.file_digest.clone(),
            retrieved_at: snapshot.retrieved_at.clone(),
            generation_time: snapshot.generation_time.clone(),
            listed_repository,
            effective_repository_url,
            verification_status: entry.verification_status.clone(),
            listing_validated_commit,
            upstream_observed_commit: entry.upstream_observed_commit.clone(),
            repository_layout,
        },
    })
}

fn effective_repository_url(value: &str) -> Result<String, Error> {
    if let Some(rest) = value.strip_prefix("https://") {
        let authority_end = rest
            .find('/')
            .ok_or_else(|| Error::UnsupportedRepository("HTTPS repository has no path".into()))?;
        let authority = &rest[..authority_end];
        if authority.is_empty()
            || authority.contains(['@', ':', '?', '#'])
            || value.bytes().any(|byte| byte < 0x20 || byte == 0x7f)
        {
            return Err(Error::UnsupportedRepository(
                "HTTPS repository contains credentials, a port, or control characters".into(),
            ));
        }
        let path = &rest[authority_end + 1..];
        if path.contains(['?', '#']) || path.ends_with("//") {
            return Err(Error::UnsupportedRepository(
                "HTTPS repository must not contain a query, fragment, or repeated trailing slash"
                    .into(),
            ));
        }
        let path = path.strip_suffix('/').unwrap_or(path);
        let segments: Vec<&str> = path.split('/').collect();
        if segments.len() != 2
            || !segments
                .iter()
                .all(|segment| repository_segment_is_safe(segment))
        {
            return Err(Error::UnsupportedRepository(
                "HTTPS repository must identify exactly OWNER/REPOSITORY".into(),
            ));
        }
        let repository = segments[1].strip_suffix(".git").unwrap_or(segments[1]);
        if !repository_segment_is_safe(repository) || repository.ends_with(".git") {
            return Err(Error::UnsupportedRepository(
                "HTTPS repository must identify exactly OWNER/REPOSITORY".into(),
            ));
        }
        return Ok(format!(
            "https://{}/{}/{}.git",
            authority.to_ascii_lowercase(),
            segments[0],
            repository
        ));
    }
    let (owner_repo, supported) = if let Some(value) = value.strip_prefix("git@github.com:") {
        (value, true)
    } else if let Some(value) = value.strip_prefix("ssh://git@github.com/") {
        (value, true)
    } else {
        (value, false)
    };
    if supported {
        if owner_repo.ends_with("//") {
            return Err(Error::UnsupportedRepository(
                "GitHub SSH repository must not contain a repeated trailing slash".into(),
            ));
        }
        let path = owner_repo.strip_suffix('/').unwrap_or(owner_repo);
        let segments: Vec<&str> = path.split('/').collect();
        if segments.len() != 2
            || !segments
                .iter()
                .all(|segment| repository_segment_is_safe(segment))
        {
            return Err(Error::UnsupportedRepository(
                "GitHub SSH repository must identify exactly OWNER/REPOSITORY".into(),
            ));
        }
        let repository = segments[1].strip_suffix(".git").unwrap_or(segments[1]);
        if !repository_segment_is_safe(repository) || repository.ends_with(".git") {
            return Err(Error::UnsupportedRepository(
                "GitHub SSH repository must identify exactly OWNER/REPOSITORY".into(),
            ));
        }
        return Ok(format!(
            "https://github.com/{}/{}.git",
            segments[0], repository
        ));
    }
    Err(Error::UnsupportedRepository(
        "only credential-free HTTPS or public GitHub SSH/scp repositories are supported".into(),
    ))
}

fn repository_segment_is_safe(segment: &str) -> bool {
    !segment.is_empty()
        && segment != "."
        && segment != ".."
        && !segment.contains(['?', '#', '@', '\\'])
        && segment
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
}

fn validate_https_repository(repository_url: &str) -> Result<(), Error> {
    if !repository_url.starts_with("https://") || repository_url.starts_with('-') {
        return Err(Error::Git("catalog repository must be an HTTPS URL".into()));
    }
    Ok(())
}

pub fn fetch_pinned_catalog(
    cache_dir: &Path,
    repository_url: &str,
    repository_commit: &str,
    retrieved_at: String,
) -> Result<CatalogSnapshot, Error> {
    if !valid_commit(repository_commit) {
        return Err(Error::InvalidCommit);
    }
    validate_https_repository(repository_url)?;
    fs::create_dir_all(cache_dir)?;
    let repository_dir = cache_dir.join("catalog.git");
    match fs::symlink_metadata(&repository_dir) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            return Err(Error::Git(
                "catalog cache repository path is a symlink".into(),
            ));
        }
        Ok(metadata) if !metadata.is_dir() => {
            return Err(Error::Git(
                "catalog cache repository path is not a directory".into(),
            ));
        }
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            run_git(
                cache_dir,
                &[
                    "init",
                    "--bare",
                    repository_dir
                        .to_str()
                        .ok_or_else(|| Error::Git("catalog cache path is not UTF-8".into()))?,
                ],
            )?;
        }
        Err(error) => return Err(error.into()),
    }
    match run_git_output(&repository_dir, &["remote", "get-url", "origin"]) {
        Ok(remote) if String::from_utf8_lossy(&remote).trim() == repository_url => {}
        Ok(_) => {
            run_git(
                &repository_dir,
                &["remote", "set-url", "origin", repository_url],
            )?;
        }
        Err(_) => {
            run_git(
                &repository_dir,
                &["remote", "add", "origin", repository_url],
            )?;
        }
    }
    run_git(
        &repository_dir,
        &["fetch", "--no-tags", "origin", repository_commit],
    )?;
    let metadata_path = cache_dir.join("catalog.meta.json");
    if let Ok(metadata) = fs::read(&metadata_path)
        && let Ok(previous) = serde_json::from_slice::<CacheMetadata>(&metadata)
        && previous.repository_url.as_deref() == Some(repository_url)
        && previous.repository_commit != repository_commit
        && !is_ancestor(
            &repository_dir,
            &previous.repository_commit,
            repository_commit,
        )?
    {
        return Err(Error::Rollback);
    }
    let output = run_git_output(
        &repository_dir,
        &["show", &format!("{repository_commit}:site/catalog.json")],
    )?;
    let retrieved_at_for_cache = retrieved_at.clone();
    let snapshot = parse_catalog(
        &output,
        repository_url.to_owned(),
        repository_commit.to_owned(),
        retrieved_at,
    )?;
    let mut snapshot = snapshot;
    snapshot.verified = true;
    write_atomic(&cache_dir.join("catalog.json"), &output)?;
    let metadata = serde_json::to_vec(&CacheMetadata {
        repository_commit: repository_commit.into(),
        repository_url: Some(repository_url.into()),
        retrieved_at: Some(retrieved_at_for_cache),
        file_digest: Some(snapshot.file_digest.clone()),
    })?;
    write_atomic(&metadata_path, &metadata)?;
    Ok(snapshot)
}

pub fn correlate(
    plugin_id: &str,
    installed_repository: Option<&str>,
    installed_head: Option<&str>,
    snapshot: &CatalogSnapshot,
) -> Correlation {
    let id_matches: Vec<&CatalogEntry> = snapshot
        .entries
        .iter()
        .filter(|entry| entry.id.as_deref() == Some(plugin_id))
        .collect();
    let repo = installed_repository.map(normalize_repository);
    let matches: Vec<&CatalogEntry> = id_matches
        .iter()
        .copied()
        .filter(|entry| match (&repo, entry.repo.as_deref()) {
            (Some(installed), Some(listed)) => normalize_repository(listed) == *installed,
            (None, None) => true,
            _ => false,
        })
        .collect();

    let entry = if matches.len() == 1 {
        Some(matches[0])
    } else {
        None
    };
    if entry.is_none() {
        let reason = if id_matches.is_empty() {
            "no catalog entry matched the plugin ID"
        } else if matches.is_empty() {
            "plugin ID matched, but repository identity conflicted or was unavailable"
        } else {
            "multiple catalog entries matched; selection was refused"
        };
        return Correlation {
            plugin_id: plugin_id.into(),
            status: if id_matches.is_empty() {
                "unlisted".into()
            } else {
                "conflict".into()
            },
            registry_claim: None,
            disclaimer: DISCLAIMER,
            reason: Some(reason.into()),
        };
    }
    let entry = entry.unwrap();
    let installed_matches_listing =
        match (installed_head, entry.listing_validated_commit.as_deref()) {
            (Some(installed), Some(listed)) => Some(installed == listed),
            _ => None,
        };
    let upstream_moved = match (
        entry.upstream_observed_commit.as_deref(),
        entry.listing_validated_commit.as_deref(),
    ) {
        (Some(observed), Some(validated)) => Some(observed != validated),
        _ => None,
    };
    let status = if entry
        .repository_layout
        .as_deref()
        .is_some_and(|layout| !matches!(layout, "root-plugin" | "monorepo" | "suite"))
    {
        "incomplete"
    } else if installed_matches_listing == Some(false) {
        "installed-differs"
    } else {
        "listed"
    };
    Correlation {
        plugin_id: plugin_id.into(),
        status: status.into(),
        registry_claim: Some(RegistryClaim {
            registry_repository: snapshot.repository.clone(),
            registry_commit: snapshot.repository_commit.clone(),
            retrieved_at: snapshot.retrieved_at.clone(),
            generation_time: snapshot.generation_time.clone(),
            repository: entry.repo.clone(),
            verification_status: entry.verification_status.clone(),
            listing_validated_commit: entry.listing_validated_commit.clone(),
            upstream_observed_commit: entry.upstream_observed_commit.clone(),
            upstream_moved,
            installed_matches_listing,
            repository_layout: entry.repository_layout.clone(),
        }),
        disclaimer: DISCLAIMER,
        reason: None,
    }
}

pub fn normalize_repository(repository: &str) -> String {
    let mut value = repository.trim().to_ascii_lowercase();
    if let Some(stripped) = value.strip_prefix("https://") {
        value = stripped.into();
    } else if let Some(stripped) = value.strip_prefix("http://") {
        value = stripped.into();
    } else if let Some(stripped) = value.strip_prefix("ssh://git@") {
        value = stripped.into();
    } else if let Some(stripped) = value.strip_prefix("git@") {
        value = stripped.replacen(':', "/", 1);
    }
    if let Some(stripped) = value.strip_prefix("www.") {
        value = stripped.into();
    }
    value
        .trim_end_matches('/')
        .trim_end_matches(".git")
        .to_owned()
}

fn hex_digest(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn run_git(directory: &Path, args: &[&str]) -> Result<(), Error> {
    run_git_output(directory, args).map(|_| ())
}

fn run_git_output(directory: &Path, args: &[&str]) -> Result<Vec<u8>, Error> {
    let mut command = if args.first().copied() == Some("fetch") {
        omasafe_core::git::remote_https()
    } else {
        omasafe_core::git::offline()
    };
    command.args(args).current_dir(directory);
    let output = run_bounded_capped(
        &mut command,
        GIT_PROCESS_BUDGET,
        MAX_PROCESS_OUTPUT_BYTES_PER_STREAM,
    )
    .map_err(|error| Error::Git(error.to_string()))?
    .ok_or_else(|| Error::Git("catalog Git operation exceeded its time budget".into()))?;
    if output.status.success() && !output.truncated {
        Ok(output.stdout)
    } else {
        Err(Error::Git(
            "catalog Git operation failed or exceeded its output bound".into(),
        ))
    }
}

#[derive(Debug, Deserialize, Serialize)]
struct CacheMetadata {
    repository_commit: String,
    #[serde(default)]
    repository_url: Option<String>,
    #[serde(default)]
    retrieved_at: Option<String>,
    #[serde(default)]
    file_digest: Option<String>,
}

pub fn load_cached_catalog(cache_dir: &Path) -> Result<Option<CatalogSnapshot>, Error> {
    let metadata_path = cache_dir.join("catalog.meta.json");
    let catalog_path = cache_dir.join("catalog.json");
    let metadata_stat = match fs::symlink_metadata(&metadata_path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    if metadata_stat.file_type().is_symlink() || !metadata_stat.is_file() {
        return Err(Error::Io(std::io::Error::other(
            "catalog metadata is not a regular file",
        )));
    }
    if metadata_stat.len() > MAX_METADATA_BYTES as u64 {
        return Err(Error::Oversized);
    }
    let metadata_file = fs::File::open(&metadata_path)?;
    let mut metadata_bytes = Vec::with_capacity(metadata_stat.len() as usize + 1);
    metadata_file
        .take(MAX_METADATA_BYTES as u64 + 1)
        .read_to_end(&mut metadata_bytes)?;
    if metadata_bytes.len() > MAX_METADATA_BYTES {
        return Err(Error::Oversized);
    }
    let metadata: CacheMetadata = serde_json::from_slice(&metadata_bytes)?;
    let catalog_metadata = fs::symlink_metadata(&catalog_path)?;
    if catalog_metadata.file_type().is_symlink() || !catalog_metadata.is_file() {
        return Err(Error::Io(std::io::Error::other(
            "catalog cache file is not a regular file",
        )));
    }
    let size = catalog_metadata.len();
    if size > MAX_CATALOG_BYTES as u64 {
        return Err(Error::Oversized);
    }
    let bytes = fs::read(&catalog_path)?;
    let repository = metadata
        .repository_url
        .clone()
        .unwrap_or_else(|| OFFICIAL_REPOSITORY.into());
    let mut snapshot = parse_catalog(
        &bytes,
        repository,
        metadata.repository_commit,
        metadata.retrieved_at.unwrap_or_else(|| "unknown".into()),
    )?;
    let file_matches = metadata
        .file_digest
        .as_deref()
        .is_some_and(|digest| digest == snapshot.file_digest);
    let repository_cache = cache_dir.join("catalog.git");
    let repo_matches = metadata.repository_url.as_deref() == Some(OFFICIAL_REPOSITORY)
        && fs::symlink_metadata(&repository_cache)
            .is_ok_and(|metadata| metadata.is_dir() && !metadata.file_type().is_symlink());
    let commit_matches = valid_commit(&snapshot.repository_commit)
        && repo_matches
        && run_git_output(
            &repository_cache,
            &[
                "show",
                &format!("{}:site/catalog.json", snapshot.repository_commit),
            ],
        )
        .is_ok_and(|cached| cached == bytes);
    snapshot.verified = file_matches && commit_matches;
    Ok(Some(snapshot))
}

fn is_ancestor(directory: &Path, previous: &str, current: &str) -> Result<bool, Error> {
    let mut command = git_command();
    command
        .args(["merge-base", "--is-ancestor", previous, current])
        .current_dir(directory);
    let output = run_bounded_capped(
        &mut command,
        GIT_PROCESS_BUDGET,
        MAX_PROCESS_OUTPUT_BYTES_PER_STREAM,
    )
    .map_err(|error| Error::Git(error.to_string()))?
    .ok_or_else(|| Error::Git("catalog Git operation exceeded its time budget".into()))?;
    if output.status.success() {
        Ok(true)
    } else if output.status.code() == Some(1) {
        Ok(false)
    } else {
        Err(Error::Git("catalog ancestry check failed".into()))
    }
}

fn git_command() -> std::process::Command {
    omasafe_core::git::command()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn snapshot() -> CatalogSnapshot {
        parse_catalog(
            br#"[{"id":"io.example.widget","repo":"git@github.com:Example/Widget.git","verificationStatus":"verified","listingValidatedCommit":"abc","upstreamObservedCommit":"def","repositoryLayout":"root-plugin"}]"#,
            "https://github.com/example/marketplace".into(),
            "registry-commit".into(),
            "2026-08-20T00:00:00Z".into(),
        )
        .unwrap()
    }

    #[test]
    fn normalizes_common_git_repository_forms() {
        assert_eq!(
            normalize_repository("https://github.com/Example/Widget.git/"),
            "github.com/example/widget"
        );
        assert_eq!(
            normalize_repository("git@github.com:Example/Widget.git"),
            "github.com/example/widget"
        );
    }

    #[test]
    fn correlates_by_id_and_repository_with_provenance() {
        let result = correlate(
            "io.example.widget",
            Some("https://github.com/example/widget"),
            Some("abc"),
            &snapshot(),
        );
        assert_eq!(result.status, "listed");
        let claim = result.registry_claim.unwrap();
        assert_eq!(claim.installed_matches_listing, Some(true));
        assert_eq!(claim.upstream_moved, Some(true));
        assert_eq!(claim.registry_commit, "registry-commit");
    }

    #[test]
    fn refuses_repository_conflicts_and_marks_unknown_layout_incomplete() {
        let conflict = correlate(
            "io.example.widget",
            Some("https://github.com/other/widget"),
            None,
            &snapshot(),
        );
        assert_eq!(conflict.status, "conflict");
        let mut unknown = snapshot();
        unknown.entries[0].repository_layout = Some("future-layout".into());
        let result = correlate(
            "io.example.widget",
            Some("git@github.com:example/widget.git"),
            None,
            &unknown,
        );
        assert_eq!(result.status, "incomplete");
    }

    #[test]
    fn rejects_oversized_catalogs() {
        let bytes = vec![b' '; MAX_CATALOG_BYTES + 1];
        assert!(matches!(
            parse_catalog(&bytes, "repo".into(), "commit".into(), "now".into()),
            Err(Error::Oversized)
        ));
    }

    #[test]
    fn rejects_wrapped_catalog_without_entries() {
        assert!(matches!(
            parse_catalog(
                br#"{"pluginList":[]}"#,
                "repo".into(),
                "commit".into(),
                "now".into()
            ),
            Err(Error::InvalidShape)
        ));
    }

    #[test]
    fn candidate_resolution_requires_verified_snapshot_and_preserves_ssh_case() {
        let commit = "0123456789abcdef0123456789abcdef01234567";
        let mut snapshot = parse_catalog(
            format!(
                r#"[{{"id":"io.example.widget","repo":"git@github.com:MixedCase/Plugin.git","listingValidatedCommit":"{commit}","repositoryLayout":"monorepo"}}]"#
            )
            .as_bytes(),
            "https://github.com/omacom/omarchy-plugin-marketplace".into(),
            commit.into(),
            "2026-09-04T00:00:00Z".into(),
        )
        .unwrap();
        assert!(matches!(
            resolve_candidate(&snapshot, "io.example.widget"),
            Err(Error::UnverifiedCache)
        ));
        snapshot.verified = true;
        let candidate = resolve_candidate(&snapshot, "io.example.widget").unwrap();
        assert_eq!(
            candidate.listed_repository,
            "git@github.com:MixedCase/Plugin.git"
        );
        assert_eq!(
            candidate.effective_repository_url,
            "https://github.com/MixedCase/Plugin.git"
        );
    }

    #[test]
    fn candidate_resolution_rejects_private_repository_forms() {
        let commit = "0123456789abcdef0123456789abcdef01234567";
        for repo in [
            "git@gitlab.com:owner/plugin.git",
            "ssh://git@github.com:22/owner/plugin.git",
            "https://github.com/owner/plugin?ref=main",
        ] {
            let mut snapshot = parse_catalog(
                format!(
                    r#"[{{"id":"io.example.widget","repo":"{repo}","listingValidatedCommit":"{commit}","repositoryLayout":"root-plugin"}}]"#
                )
                .as_bytes(),
                "registry".into(),
                commit.into(),
                "now".into(),
            )
            .unwrap();
            snapshot.verified = true;
            assert!(matches!(
                resolve_candidate(&snapshot, "io.example.widget"),
                Err(Error::UnsupportedRepository(_))
            ));
        }
    }

    #[test]
    fn candidate_resolution_canonicalizes_https_repository_forms() {
        let commit = "0123456789abcdef0123456789abcdef01234567";
        for repo in [
            "https://GitHub.com/MixedCase/Plugin",
            "https://github.com/MixedCase/Plugin/",
            "https://github.com/MixedCase/Plugin.git",
        ] {
            let mut snapshot = parse_catalog(
                format!(
                    r#"[{{"id":"io.example.widget","repo":"{repo}","listingValidatedCommit":"{commit}","repositoryLayout":"root-plugin"}}]"#
                )
                .as_bytes(),
                "registry".into(),
                commit.into(),
                "now".into(),
            )
            .unwrap();
            snapshot.verified = true;
            let candidate = resolve_candidate(&snapshot, "io.example.widget").unwrap();
            assert_eq!(
                candidate.effective_repository_url,
                "https://github.com/MixedCase/Plugin.git"
            );
        }
    }

    #[test]
    fn atomic_cache_replacement_writes_private_file() {
        let directory = std::env::temp_dir().join(format!("omasafe-cache-{}", std::process::id()));
        let path = directory.join("catalog.json");
        write_atomic(&path, br#"[]"#).unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"[]");
        let _ = std::fs::remove_dir_all(directory);
    }
}
