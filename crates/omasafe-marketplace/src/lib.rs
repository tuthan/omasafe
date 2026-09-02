pub mod manifest;

use std::fs;
use std::path::Path;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

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
    let output = git_command()
        .args([
            "ls-remote",
            "--exit-code",
            "--symref",
            repository_url,
            "HEAD",
        ])
        .output()
        .map_err(|error| Error::Git(error.to_string()))?;
    if !output.status.success() {
        return Err(git_error(
            &output.stderr,
            "catalog remote did not advertise a default branch",
        ));
    }
    parse_remote_head(&output.stdout)
}

fn parse_remote_head(output: &[u8]) -> Result<String, Error> {
    let text = std::str::from_utf8(output)
        .map_err(|_| Error::Git("catalog remote returned non-UTF-8 output".into()))?;
    let mut lines = text.lines().filter(|line| !line.trim().is_empty());
    let symref_line = lines
        .next()
        .ok_or_else(|| Error::Git("catalog remote omitted its default branch".into()))?;
    let mut symref_fields = symref_line.split_ascii_whitespace();
    let marker = symref_fields.next();
    let branch_ref = symref_fields.next();
    let head = symref_fields.next();
    if marker != Some("ref:")
        || head != Some("HEAD")
        || symref_fields.next().is_some()
        || !branch_ref.is_some_and(|value| {
            value.starts_with("refs/heads/") && value.len() > "refs/heads/".len()
        })
    {
        return Err(Error::Git(
            "catalog remote omitted a valid default branch".into(),
        ));
    }

    let commit_line = lines
        .next()
        .ok_or_else(|| Error::Git("catalog remote omitted the default branch commit".into()))?;
    let mut commit_fields = commit_line.split_ascii_whitespace();
    let commit = commit_fields
        .next()
        .ok_or_else(|| Error::Git("catalog remote response omitted the commit".into()))?;
    let reference = commit_fields
        .next()
        .ok_or_else(|| Error::Git("catalog remote response omitted the ref".into()))?;
    if commit_fields.next().is_some() || reference != "HEAD" || !valid_commit(commit) {
        return Err(Error::Git(
            "catalog remote response was not an exact HEAD commit mapping".into(),
        ));
    }
    if lines.next().is_some() {
        return Err(Error::Git(
            "catalog remote HEAD resolution returned multiple revisions".into(),
        ));
    }
    Ok(commit.to_ascii_lowercase())
}

fn validate_https_repository(repository_url: &str) -> Result<(), Error> {
    if !repository_url.starts_with("https://") || repository_url.starts_with('-') {
        return Err(Error::Git("catalog repository must be an HTTPS URL".into()));
    }
    Ok(())
}

fn git_error(stderr: &[u8], fallback: &str) -> Error {
    let message = String::from_utf8_lossy(stderr).trim().to_owned();
    Error::Git(if message.is_empty() {
        fallback.into()
    } else {
        message
    })
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
    if !repository_dir.exists() {
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
    let output = git_command()
        .args(args)
        .current_dir(directory)
        .output()
        .map_err(|error| Error::Git(error.to_string()))?;
    if output.status.success() {
        Ok(output.stdout)
    } else {
        Err(Error::Git(
            String::from_utf8_lossy(&output.stderr).trim().to_owned(),
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
    if !metadata_path.exists() || !catalog_path.exists() {
        return Ok(None);
    }
    let metadata: CacheMetadata = serde_json::from_slice(&fs::read(&metadata_path)?)?;
    let size = fs::metadata(&catalog_path)?.len();
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
    let repo_matches = metadata.repository_url.as_deref() == Some(OFFICIAL_REPOSITORY)
        && cache_dir.join("catalog.git").is_dir();
    let commit_matches = valid_commit(&snapshot.repository_commit)
        && repo_matches
        && run_git_output(
            &cache_dir.join("catalog.git"),
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
    let output = git_command()
        .args(["merge-base", "--is-ancestor", previous, current])
        .current_dir(directory)
        .output()
        .map_err(|error| Error::Git(error.to_string()))?;
    if output.status.success() {
        Ok(true)
    } else if output.status.code() == Some(1) {
        Ok(false)
    } else {
        Err(Error::Git(
            String::from_utf8_lossy(&output.stderr).trim().to_owned(),
        ))
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
    fn parses_only_an_exact_remote_head_commit_mapping() {
        let commit = "ABCDEF0123456789ABCDEF0123456789ABCDEF01";
        assert_eq!(
            parse_remote_head(format!("ref: refs/heads/master HEAD\n{commit}\tHEAD\n").as_bytes(),)
                .unwrap(),
            commit.to_ascii_lowercase()
        );
        assert!(parse_remote_head(b"abc\tHEAD\n").is_err());
        assert!(
            parse_remote_head(format!("ref: refs/tags/v1 HEAD\n{commit}\tHEAD\n").as_bytes())
                .is_err()
        );
        assert!(
            parse_remote_head(
                format!("ref: refs/heads/main HEAD\n{commit}\tHEAD\n{commit}\tHEAD\n").as_bytes(),
            )
            .is_err()
        );
    }

    #[test]
    fn supplies_a_message_when_git_returns_no_stderr() {
        assert!(matches!(
            git_error(b"", "default branch lookup failed"),
            Error::Git(message) if message == "default branch lookup failed"
        ));
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
    fn atomic_cache_replacement_writes_private_file() {
        let directory = std::env::temp_dir().join(format!("omasafe-cache-{}", std::process::id()));
        let path = directory.join("catalog.json");
        write_atomic(&path, br#"[]"#).unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"[]");
        let _ = std::fs::remove_dir_all(directory);
    }
}
