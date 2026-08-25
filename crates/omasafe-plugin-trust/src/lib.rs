use std::collections::BTreeMap;
use std::fs;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;
use std::process::Command;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use omasafe_core::bounds::{
    MAX_FILE_BYTES, MAX_FILES, MAX_METADATA_BYTES, MAX_TOTAL_BYTES, SAMPLE_BYTES,
};

/// Public re-export preserving the v0.1 API surface.
pub use omasafe_core::bounds::MAX_DIFF_BYTES;

pub mod baseline;

#[derive(Debug, Default, Serialize)]
pub struct Inventory {
    pub plugins: Vec<PluginRecord>,
    pub active_full_bar: Option<String>,
    pub active_full_bars: Vec<String>,
    pub bar_conflict: bool,
    pub non_builtin_bar_replaces_bar: bool,
    pub coverage: Coverage,
}

#[derive(Debug, Serialize)]
pub struct PluginRecord {
    pub id: String,
    pub path: String,
    pub classification: String,
    pub enabled: Option<bool>,
    pub active: Option<bool>,
    pub first_party: Option<bool>,
    pub kinds: Vec<String>,
    pub repository: Option<String>,
    pub head: Option<String>,
    pub tree: Option<String>,
    pub dirty: Option<bool>,
    pub content_digest: Option<String>,
    pub content_file_count: Option<usize>,
    pub classification_reason: Option<String>,
    pub limitations: Vec<String>,
    pub file_digests: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SourceIdentity {
    pub plugin_id: String,
    pub repository: Option<String>,
    pub head: Option<String>,
    pub tree: Option<String>,
    pub content_digest: Option<String>,
    pub file_count: usize,
    pub limitations: Vec<String>,
    #[serde(default)]
    pub file_digests: BTreeMap<String, String>,
}

impl PartialEq for SourceIdentity {
    fn eq(&self, other: &Self) -> bool {
        self.identity_material() == other.identity_material()
    }
}

impl Eq for SourceIdentity {}

impl SourceIdentity {
    pub fn identity_material(&self) -> Vec<u8> {
        serde_json::to_vec(&(
            &self.plugin_id,
            &self.repository,
            &self.head,
            &self.tree,
            &self.content_digest,
            self.file_count,
            &self.limitations,
        ))
        .expect("source identity serialization cannot fail")
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct DiffResult {
    pub available: bool,
    pub text: Option<String>,
    pub truncated: bool,
    pub limitation: Option<String>,
}

#[derive(Debug, Default, Serialize)]
pub struct Coverage {
    pub limitations: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct ShellPlugin {
    id: String,
    #[serde(default)]
    enabled: Option<bool>,
    #[serde(default)]
    active: Option<bool>,
    #[serde(rename = "firstParty", default)]
    first_party: Option<bool>,
    #[serde(rename = "clonedFrom", default)]
    cloned_from: Option<String>,
    #[serde(default)]
    kinds: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct Manifest {
    #[serde(rename = "schemaVersion")]
    schema_version: Option<u64>,
    id: Option<String>,
    #[serde(default)]
    kinds: Vec<String>,
}

pub fn collect(plugin_root: &Path, shell_json: Option<&str>) -> Inventory {
    collect_internal(plugin_root, shell_json, None)
}

pub fn collect_one(plugin_root: &Path, plugin_id: &str, shell_json: Option<&str>) -> Inventory {
    collect_internal(plugin_root, shell_json, Some(plugin_id))
}

fn collect_internal(
    plugin_root: &Path,
    shell_json: Option<&str>,
    target_id: Option<&str>,
) -> Inventory {
    let shell = parse_shell_inventory(shell_json);
    let mut inventory = Inventory::default();
    inventory.coverage.limitations.extend(shell.limitations);

    let entries = match fs::read_dir(plugin_root) {
        Ok(entries) => entries,
        Err(error) => {
            inventory.coverage.limitations.push(format!(
                "plugin directory is unavailable: {} ({error})",
                plugin_root.display()
            ));
            return inventory;
        }
    };

    let mut shell_by_id: BTreeMap<String, ShellPlugin> = shell
        .plugins
        .into_iter()
        .map(|plugin| (plugin.id.clone(), plugin))
        .collect();
    for plugin in shell_by_id.values().filter(|plugin| {
        plugin.active == Some(true) && plugin.kinds.iter().any(|kind| kind == "bar")
    }) {
        register_active_bar(&mut inventory, &plugin.id, plugin.first_party != Some(true));
    }

    for entry in entries {
        let entry = match entry {
            Ok(entry) => entry,
            Err(error) => {
                inventory
                    .coverage
                    .limitations
                    .push(format!("directory entry unreadable: {error}"));
                continue;
            }
        };
        let path = entry.path();
        let name = entry.file_name().to_string_lossy().into_owned();
        let backup = is_backup(&name);
        let manifest_id = manifest_id(&path);
        // Backups frequently retain a copy of the live manifest. They must
        // never consume the shell record for that live plugin, or the same
        // plugin ID appears twice with a spurious directory-ID limitation.
        let shell_key = if backup {
            None
        } else {
            manifest_id
                .as_deref()
                .filter(|id| shell_by_id.contains_key(*id))
                .map(str::to_owned)
                .or_else(|| Some(name.clone()))
        };
        let shell_plugin = shell_key.and_then(|key| shell_by_id.remove(&key));
        if let Some(target_id) = target_id
            && manifest_id.as_deref() != Some(target_id)
            && name != target_id
            && shell_plugin
                .as_ref()
                .is_none_or(|plugin| plugin.id != target_id)
        {
            continue;
        }
        let mut record = inspect_plugin(&path, &name, shell_plugin.as_ref());
        if record.id != name && record.classification != "unscannable" {
            record.limitations.push("directory_id_mismatch".into());
            record.limitations.sort();
            record.limitations.dedup();
        }
        if record.active == Some(true) && record.kinds.iter().any(|kind| kind == "bar") {
            register_active_bar(&mut inventory, &record.id, record.first_party != Some(true));
        }
        inventory.plugins.push(record);
    }

    for plugin in shell_by_id.values() {
        if plugin.cloned_from.as_deref() == Some("") || plugin.first_party == Some(true) {
            continue;
        }
        inventory.coverage.limitations.push(format!(
            "shell reports plugin {} but its directory was not found",
            plugin.id
        ));
    }
    inventory.bar_conflict = inventory.active_full_bars.len() > 1;
    inventory
        .plugins
        .sort_by(|left, right| left.id.cmp(&right.id));
    inventory
}

fn register_active_bar(inventory: &mut Inventory, id: &str, non_builtin: bool) {
    if !inventory.active_full_bars.iter().any(|active| active == id) {
        inventory.active_full_bars.push(id.to_owned());
    }
    if inventory.active_full_bar.is_none() {
        inventory.active_full_bar = Some(id.to_owned());
    }
    inventory.non_builtin_bar_replaces_bar |= non_builtin;
}

fn manifest_id(path: &Path) -> Option<String> {
    let contents = fs::read(path.join("manifest.json")).ok()?;
    serde_json::from_slice::<Manifest>(&contents).ok()?.id
}

pub fn query_shell() -> (Option<String>, Option<String>) {
    let output = Command::new("omarchy")
        .args(["plugin", "list", "--json"])
        .output();
    match output {
        Ok(output) if output.status.success() => (
            Some(String::from_utf8_lossy(&output.stdout).into_owned()),
            None,
        ),
        Ok(output) => (
            None,
            Some(format!(
                "omarchy plugin list --json failed with {}",
                output.status
            )),
        ),
        Err(error) => (
            None,
            Some(format!("omarchy plugin list --json unavailable: {error}")),
        ),
    }
}

fn parse_shell_inventory(shell_json: Option<&str>) -> ShellInventory {
    let Some(json) = shell_json else {
        return ShellInventory {
            limitations: vec!["Omarchy shell inventory unavailable; using filesystem only".into()],
            ..ShellInventory::default()
        };
    };
    match serde_json::from_str::<Vec<ShellPlugin>>(json) {
        Ok(plugins) => ShellInventory {
            plugins,
            ..ShellInventory::default()
        },
        Err(error) => ShellInventory {
            limitations: vec![format!("Omarchy shell inventory was malformed: {error}")],
            ..ShellInventory::default()
        },
    }
}

#[derive(Default)]
struct ShellInventory {
    plugins: Vec<ShellPlugin>,
    limitations: Vec<String>,
}

fn inspect_plugin(path: &Path, name: &str, shell: Option<&ShellPlugin>) -> PluginRecord {
    let base = PluginRecord {
        id: shell.map_or_else(|| name.to_owned(), |plugin| plugin.id.clone()),
        path: path.display().to_string(),
        classification: "unscannable".into(),
        enabled: shell.and_then(|plugin| plugin.enabled),
        active: shell.and_then(|plugin| plugin.active),
        first_party: shell.and_then(|plugin| plugin.first_party),
        kinds: shell.map_or_else(Vec::new, |plugin| plugin.kinds.clone()),
        repository: shell
            .and_then(|plugin| plugin.cloned_from.as_deref())
            .filter(|repository| !repository.is_empty())
            .map(str::to_owned),
        head: None,
        tree: None,
        dirty: None,
        content_digest: None,
        content_file_count: None,
        classification_reason: None,
        limitations: Vec::new(),
        file_digests: BTreeMap::new(),
    };
    if fs::symlink_metadata(path)
        .map(|metadata| metadata.file_type().is_symlink())
        .unwrap_or(true)
    {
        return with_reason(base, "plugin directory is a symlink");
    }
    if is_backup(name) {
        return PluginRecord {
            classification: "backup".into(),
            ..base
        };
    }

    let manifest_path = path.join("manifest.json");
    let manifest = match fs::read_to_string(&manifest_path) {
        Ok(contents) => match serde_json::from_str::<Manifest>(&contents) {
            Ok(manifest) if manifest.schema_version == Some(1) && manifest.id.is_some() => manifest,
            Ok(_) => {
                return with_reason(
                    base,
                    "manifest does not satisfy schema version 1 and required ID",
                );
            }
            Err(error) => return with_reason(base, &format!("manifest is malformed: {error}")),
        },
        Err(error) => return with_reason(base, &format!("manifest is unavailable: {error}")),
    };
    let id = manifest.id.clone().unwrap_or_else(|| name.to_owned());
    let mut record = PluginRecord {
        id,
        kinds: if manifest.kinds.is_empty() {
            base.kinds
        } else {
            manifest.kinds
        },
        classification: if shell.is_some_and(|plugin| {
            plugin.first_party == Some(true) || plugin.cloned_from.as_deref() == Some("")
        }) {
            "built-in".into()
        } else {
            "cloned/local".into()
        },
        ..base
    };
    if has_git(path) {
        record.classification = "Git-managed".into();
        let git = git_metadata(path);
        record.repository = git.repository;
        record.head = git.head;
        record.tree = git.tree;
        record.dirty = git.dirty;
        record.classification_reason = git.reason;
    }
    let source = source_identity(
        &record.id,
        path,
        record.repository.clone(),
        record.head.clone(),
        record.tree.clone(),
    );
    record.content_digest = source.content_digest;
    record.content_file_count = Some(source.file_count);
    record.limitations = source.limitations.clone();
    record.file_digests = source.file_digests.clone();
    if !source.limitations.is_empty() {
        record.classification_reason = Some(source.limitations.join(", "));
    }
    record
}

fn with_reason(mut record: PluginRecord, reason: &str) -> PluginRecord {
    record.classification_reason = Some(reason.into());
    record
}

fn has_git(path: &Path) -> bool {
    path.join(".git").is_dir() || path.join(".git").is_file()
}

fn is_backup(name: &str) -> bool {
    name.ends_with(".bak")
        || name.contains(".bak.")
        || name.ends_with(".backup")
        || name.ends_with("~")
}

struct GitMetadata {
    repository: Option<String>,
    head: Option<String>,
    tree: Option<String>,
    dirty: Option<bool>,
    reason: Option<String>,
}

fn git_metadata(path: &Path) -> GitMetadata {
    let head = git(path, &["rev-parse", "HEAD"]);
    let tree = git(path, &["rev-parse", "HEAD^{tree}"]);
    let repository = git(path, &["config", "--get", "remote.origin.url"]);
    let status = git_status(path);
    let reason = if head.is_none() || tree.is_none() {
        Some("Git repository has no readable HEAD/tree identity".into())
    } else if status.is_none() {
        Some("Git working-tree status is unavailable".into())
    } else {
        None
    };
    GitMetadata {
        repository,
        head,
        tree,
        dirty: status.map(|value| !value.is_empty()),
        reason,
    }
}

fn git(path: &Path, args: &[&str]) -> Option<String> {
    git_command()
        .args(args)
        .current_dir(path)
        .output()
        .ok()
        .filter(|output| output.status.success())
        .map(|output| String::from_utf8_lossy(&output.stdout).trim().to_owned())
        .filter(|value| !value.is_empty())
}

fn git_status(path: &Path) -> Option<String> {
    git_command()
        .args(["status", "--porcelain", "--untracked-files=all"])
        .current_dir(path)
        .output()
        .ok()
        .filter(|output| output.status.success())
        .map(|output| String::from_utf8_lossy(&output.stdout).into_owned())
}

fn git_command() -> Command {
    omasafe_core::git::command()
}

pub fn source_identity(
    plugin_id: &str,
    root: &Path,
    repository: Option<String>,
    head: Option<String>,
    tree: Option<String>,
) -> SourceIdentity {
    let mut entries = Vec::new();
    let mut limitations = Vec::new();
    let mut total_bytes = 0;
    collect_entries(root, root, &mut entries, &mut total_bytes, &mut limitations);
    entries.sort_by(|left, right| left.path.cmp(&right.path));
    limitations.sort();
    limitations.dedup();
    let mut hasher = Sha256::new();
    let mut file_digests = BTreeMap::new();
    for entry in &entries {
        hasher.update((entry.path.len() as u64).to_be_bytes());
        hasher.update(entry.path.as_bytes());
        hasher.update([entry.kind]);
        hasher.update(entry.mode.to_be_bytes());
        hasher.update((entry.data.len() as u64).to_be_bytes());
        hasher.update(&entry.data);
        let mut file_hasher = Sha256::new();
        file_hasher.update([entry.kind]);
        file_hasher.update(entry.mode.to_be_bytes());
        file_hasher.update(&entry.data);
        file_digests.insert(entry.path.clone(), format!("{:x}", file_hasher.finalize()));
    }
    SourceIdentity {
        plugin_id: plugin_id.into(),
        repository,
        head,
        tree,
        content_digest: Some(format!("{:x}", hasher.finalize())),
        file_count: entries.len(),
        limitations,
        file_digests,
    }
}

pub fn git_diff(root: &Path, ref_a: &str, ref_b: &str) -> DiffResult {
    if !valid_ref(ref_a) || !valid_ref(ref_b) {
        return unavailable_diff("diff reference contains unsupported characters");
    }
    let range = format!("{ref_a}..{ref_b}");
    let mut command = git_command();
    command.args([
        "diff",
        "--no-ext-diff",
        "--binary",
        "--unified=3",
        "--no-renames",
    ]);
    if ref_b == "WORKTREE" {
        command.args(["--end-of-options", ref_a, "--"]);
    } else {
        command.args(["--end-of-options", &range, "--"]);
    }
    let output = command.current_dir(root).output();
    let Ok(output) = output else {
        return unavailable_diff("Git diff could not be started");
    };
    if !output.status.success() {
        return unavailable_diff("Git diff was unavailable for the requested identity");
    }
    let mut bytes = output.stdout;
    let truncated = bytes.len() > MAX_DIFF_BYTES;
    bytes.truncate(MAX_DIFF_BYTES);
    DiffResult {
        available: true,
        text: Some(String::from_utf8_lossy(&bytes).into_owned()),
        truncated,
        limitation: truncated.then(|| format!("diff output was bounded at {MAX_DIFF_BYTES} bytes")),
    }
}

fn valid_ref(reference: &str) -> bool {
    !reference.is_empty()
        && !reference.starts_with('-')
        && reference.len() <= 256
        && reference.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'/' | b'.' | b'-' | b'^' | b'~')
        })
}

fn unavailable_diff(limitation: &str) -> DiffResult {
    DiffResult {
        available: false,
        text: None,
        truncated: false,
        limitation: Some(limitation.into()),
    }
}

struct ContentEntry {
    path: String,
    kind: u8,
    mode: u32,
    data: Vec<u8>,
}

fn collect_entries(
    root: &Path,
    directory: &Path,
    entries: &mut Vec<ContentEntry>,
    total_bytes: &mut u64,
    limitations: &mut Vec<String>,
) {
    if directory.file_name().is_some_and(|name| name == ".git") {
        return;
    }
    let read_dir = match fs::read_dir(directory) {
        Ok(read_dir) => read_dir,
        Err(error) => {
            let _ = error;
            limitations.push("unreadable_directory".into());
            return;
        }
    };
    let mut children = Vec::new();
    for item in read_dir {
        match item {
            Ok(entry) => children.push(entry),
            Err(_) => limitations.push("directory_entry_unreadable".into()),
        }
    }
    children.sort_by_key(|entry| entry.file_name());
    for entry in children {
        if entries.len() >= MAX_FILES {
            limitations.push("file_limit".into());
            return;
        }
        let path = entry.path();
        if path.file_name().is_some_and(|name| name == ".git") {
            if path.is_dir() {
                collect_git_metadata(root, &path, entries, limitations);
            } else if let Ok(metadata) = fs::symlink_metadata(&path) {
                let relative = path
                    .strip_prefix(root)
                    .unwrap_or(&path)
                    .to_string_lossy()
                    .replace('\\', "/");
                entries.push(ContentEntry {
                    path: relative,
                    kind: b'g',
                    mode: file_mode(&metadata),
                    data: bounded_file_bytes(&path),
                });
            }
            continue;
        }
        let Ok(metadata) = fs::symlink_metadata(&path) else {
            limitations.push("metadata_unavailable".into());
            continue;
        };
        let relative = path
            .strip_prefix(root)
            .unwrap_or(&path)
            .to_string_lossy()
            .replace('\\', "/");
        let mode = file_mode(&metadata);
        let file_type = metadata.file_type();
        if file_type.is_symlink() {
            let data = fs::read_link(&path)
                .map(|target| target.to_string_lossy().into_owned().into_bytes())
                .unwrap_or_default();
            entries.push(ContentEntry {
                path: relative,
                kind: b'l',
                mode,
                data,
            });
        } else if file_type.is_dir() {
            entries.push(ContentEntry {
                path: relative,
                kind: b'd',
                mode,
                data: Vec::new(),
            });
            collect_entries(root, &path, entries, total_bytes, limitations);
        } else if file_type.is_file() {
            if *total_bytes >= MAX_TOTAL_BYTES {
                limitations.push("aggregate_byte_limit".into());
                entries.push(ContentEntry {
                    path: relative,
                    kind: b'x',
                    mode,
                    data: metadata.len().to_be_bytes().to_vec(),
                });
                continue;
            }
            if metadata.len() > MAX_FILE_BYTES {
                limitations.push("oversize_file".into());
                let (data, sampled) = skipped_file_digest(
                    &path,
                    metadata.len(),
                    MAX_TOTAL_BYTES.saturating_sub(*total_bytes),
                );
                *total_bytes = total_bytes.saturating_add(sampled);
                entries.push(ContentEntry {
                    path: relative,
                    kind: b'x',
                    mode,
                    data,
                });
                continue;
            }
            if total_bytes.saturating_add(metadata.len()) > MAX_TOTAL_BYTES {
                limitations.push("aggregate_byte_limit".into());
                let (data, sampled) = skipped_file_digest(
                    &path,
                    metadata.len(),
                    MAX_TOTAL_BYTES.saturating_sub(*total_bytes),
                );
                *total_bytes = total_bytes.saturating_add(sampled);
                entries.push(ContentEntry {
                    path: relative,
                    kind: b'x',
                    mode,
                    data,
                });
                continue;
            }
            match fs::read(&path) {
                Ok(data) => {
                    *total_bytes += data.len() as u64;
                    entries.push(ContentEntry {
                        path: relative,
                        kind: b'f',
                        mode,
                        data,
                    });
                }
                Err(_) => {
                    limitations.push("unreadable_file".into());
                    entries.push(ContentEntry {
                        path: relative,
                        kind: b'x',
                        mode,
                        data: Vec::new(),
                    });
                }
            }
        } else {
            limitations.push("special_file".into());
            entries.push(ContentEntry {
                path: relative,
                kind: b'x',
                mode,
                data: Vec::new(),
            });
        }
    }
}

fn collect_git_metadata(
    root: &Path,
    git: &Path,
    entries: &mut Vec<ContentEntry>,
    limitations: &mut Vec<String>,
) {
    for name in ["config", "HEAD", "packed-refs"] {
        let path = git.join(name);
        if let Ok(metadata) = fs::symlink_metadata(&path)
            && metadata.is_file()
        {
            let relative = path
                .strip_prefix(root)
                .unwrap_or(&path)
                .to_string_lossy()
                .replace('\\', "/");
            let data = bounded_file_bytes(&path);
            entries.push(ContentEntry {
                path: relative,
                kind: b'g',
                mode: file_mode(&metadata),
                data,
            });
        }
    }
    let hooks = git.join("hooks");
    if let Ok(items) = fs::read_dir(&hooks) {
        for item in items.flatten() {
            let item_path = item.path();
            if let Ok(metadata) = fs::symlink_metadata(&item_path) {
                let relative = item_path
                    .strip_prefix(root)
                    .unwrap_or(&item_path)
                    .to_string_lossy()
                    .replace('\\', "/");
                entries.push(ContentEntry {
                    path: relative,
                    kind: b'h',
                    mode: file_mode(&metadata),
                    data: bounded_file_bytes(&item_path),
                });
            }
        }
    } else if hooks.exists() {
        limitations.push("git_hooks_unreadable".into());
    }
}

fn skipped_file_digest(path: &Path, size: u64, budget: u64) -> (Vec<u8>, u64) {
    let mut hasher = Sha256::new();
    hasher.update(size.to_be_bytes());
    let mut sampled = 0;
    if budget > 0
        && let Ok(mut file) = fs::File::open(path)
    {
        let sample_limit = SAMPLE_BYTES.min(budget);
        let mut buffer = Vec::new();
        let first = file
            .by_ref()
            .take(sample_limit)
            .read_to_end(&mut buffer)
            .unwrap_or(0);
        hasher.update(&buffer);
        sampled += first as u64;
        if size > sample_limit && sample_limit > 1 {
            let tail = sample_limit / 2;
            let _ = file.seek(SeekFrom::End(-(tail as i64)));
            buffer.clear();
            let last = file.take(tail).read_to_end(&mut buffer).unwrap_or(0);
            hasher.update(&buffer);
            sampled += last as u64;
        }
    }
    (hasher.finalize().to_vec(), sampled)
}

fn bounded_file_bytes(path: &Path) -> Vec<u8> {
    let Ok(mut file) = fs::File::open(path) else {
        return Vec::new();
    };
    let mut bytes = Vec::new();
    let _ = file
        .by_ref()
        .take((MAX_METADATA_BYTES + 1) as u64)
        .read_to_end(&mut bytes);
    bytes
}

#[cfg(unix)]
fn file_mode(metadata: &fs::Metadata) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    metadata.permissions().mode()
}

#[cfg(not(unix))]
fn file_mode(metadata: &fs::Metadata) -> u32 {
    u32::from(metadata.permissions().readonly())
}

#[cfg(test)]
mod tests {
    use super::{collect, git_diff, git_metadata, source_identity};
    use std::fs;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn fixture_root() -> PathBuf {
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!("omasafe-inventory-{suffix}"));
        fs::create_dir_all(&path).unwrap();
        path
    }

    fn manifest(path: &PathBuf, id: &str, kinds: &[&str]) {
        fs::create_dir_all(path).unwrap();
        fs::write(
            path.join("manifest.json"),
            format!(
                r#"{{"schemaVersion":1,"id":"{id}","kinds":["{}"]}}"#,
                kinds[0]
            ),
        )
        .unwrap();
    }

    #[test]
    fn inventories_valid_non_git_and_malformed_plugins() {
        let root = fixture_root();
        manifest(
            &root.join("io.example.widget"),
            "io.example.widget",
            &["bar-widget"],
        );
        fs::create_dir_all(root.join("broken")).unwrap();
        fs::write(root.join("broken/manifest.json"), "not json").unwrap();

        let inventory = collect(&root, None);
        assert_eq!(inventory.plugins.len(), 2);
        let broken = inventory
            .plugins
            .iter()
            .find(|plugin| plugin.id == "broken")
            .unwrap();
        let valid = inventory
            .plugins
            .iter()
            .find(|plugin| plugin.id == "io.example.widget")
            .unwrap();
        assert_eq!(broken.classification, "unscannable");
        assert_eq!(valid.classification, "cloned/local");
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn reconciles_shell_metadata_by_manifest_id_when_directory_name_differs() {
        let root = fixture_root();
        manifest(
            &root.join("local-name"),
            "io.example.manifest",
            &["bar-widget"],
        );
        let inventory = collect(
            &root,
            Some(
                r#"[{"id":"io.example.manifest","enabled":true,"active":true,"firstParty":false,"clonedFrom":"https://example.test/repo","kinds":["bar"]}]"#,
            ),
        );
        let record = &inventory.plugins[0];
        assert_eq!(record.id, "io.example.manifest");
        assert_eq!(record.enabled, Some(true));
        assert_eq!(
            record.repository.as_deref(),
            Some("https://example.test/repo")
        );
        assert!(
            record
                .limitations
                .iter()
                .any(|limitation| limitation == "directory_id_mismatch")
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn backup_manifest_does_not_consume_live_shell_plugin_record() {
        let root = fixture_root();
        let backup = root.join(".io.example.widget.bak.20260821");
        manifest(&backup, "io.example.widget", &["bar-widget"]);
        manifest(
            &root.join("io.example.widget"),
            "io.example.widget",
            &["bar-widget"],
        );
        let inventory = collect(
            &root,
            Some(
                r#"[{"id":"io.example.widget","enabled":true,"active":true,"firstParty":false,"kinds":["bar-widget"]}]"#,
            ),
        );
        let backup = inventory
            .plugins
            .iter()
            .find(|plugin| plugin.classification == "backup")
            .unwrap();
        let live = inventory
            .plugins
            .iter()
            .find(|plugin| plugin.id == "io.example.widget")
            .unwrap();
        assert_eq!(backup.id, ".io.example.widget.bak.20260821");
        assert_eq!(live.enabled, Some(true));
        assert_eq!(
            inventory
                .plugins
                .iter()
                .filter(|plugin| plugin.id == "io.example.widget")
                .count(),
            1
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn reconciles_shell_state_and_discloses_full_bar_replacement() {
        let root = fixture_root();
        manifest(&root.join("io.example.bar"), "io.example.bar", &["bar"]);
        let shell = r#"[{"id":"io.example.bar","enabled":true,"active":true,"firstParty":false,"kinds":["bar"]}]"#;

        let inventory = collect(&root, Some(shell));
        assert_eq!(inventory.active_full_bar.as_deref(), Some("io.example.bar"));
        assert!(inventory.non_builtin_bar_replaces_bar);
        assert_eq!(inventory.plugins[0].enabled, Some(true));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn records_git_identity_and_dirty_state_without_a_remote() {
        use std::process::Command;

        let root = fixture_root();
        let plugin = root.join("io.example.git");
        manifest(&plugin, "io.example.git", &["bar-widget"]);
        fs::write(plugin.join("main.qml"), "Item {}\n").unwrap();
        for args in [
            vec!["init"],
            vec!["add", "."],
            vec![
                "-c",
                "user.name=OmaSafe Test",
                "-c",
                "user.email=test@example.invalid",
                "commit",
                "-m",
                "fixture",
            ],
        ] {
            assert!(
                Command::new("git")
                    .args(args)
                    .current_dir(&plugin)
                    .status()
                    .unwrap()
                    .success()
            );
        }
        let baseline_head = git_metadata(&plugin).head.unwrap();
        fs::write(
            plugin.join("main.qml"),
            "Item { property bool changed: true }\n",
        )
        .unwrap();

        let inventory = collect(&root, None);
        let record = inventory
            .plugins
            .iter()
            .find(|plugin| plugin.id == "io.example.git")
            .unwrap();
        assert_eq!(record.classification, "Git-managed");
        assert!(record.head.is_some());
        assert!(record.tree.is_some());
        assert_eq!(record.repository, None);
        assert_eq!(record.dirty, Some(true));
        let diff = git_diff(&plugin, &baseline_head, "WORKTREE");
        assert!(diff.available);
        assert!(diff.text.unwrap().contains("main.qml"));
        assert!(!git_diff(&plugin, "--bad", "HEAD").available);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn content_digest_changes_for_relevant_content_and_is_deterministic() {
        let root = fixture_root();
        let plugin = root.join("io.example.digest");
        manifest(&plugin, "io.example.digest", &["bar-widget"]);
        fs::write(plugin.join("main.qml"), "Item {}\n").unwrap();
        let first = source_identity("io.example.digest", &plugin, None, None, None);
        let second = source_identity("io.example.digest", &plugin, None, None, None);
        assert_eq!(first, second);
        fs::write(
            plugin.join("main.qml"),
            "Item { property bool changed: true }\n",
        )
        .unwrap();
        let changed = source_identity("io.example.digest", &plugin, None, None, None);
        assert_ne!(first.content_digest, changed.content_digest);
        assert!(changed.file_digests.contains_key("main.qml"));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn derived_file_maps_do_not_change_source_identity_equality() {
        let root = fixture_root();
        let mut left = source_identity("io.example.compat", &root, None, None, None);
        let mut right = left.clone();
        left.file_digests.clear();
        right
            .file_digests
            .insert("main.qml".into(), "digest".into());
        assert_eq!(left, right);
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn mode_changes_are_reviewable_file_changes() {
        use std::os::unix::fs::PermissionsExt;
        let root = fixture_root();
        let plugin = root.join("io.example.mode");
        manifest(&plugin, "io.example.mode", &["bar-widget"]);
        let file = plugin.join("payload.sh");
        fs::write(&file, "payload\n").unwrap();
        let first = source_identity("io.example.mode", &plugin, None, None, None);
        fs::set_permissions(&file, fs::Permissions::from_mode(0o755)).unwrap();
        let second = source_identity("io.example.mode", &plugin, None, None, None);
        assert_ne!(
            first.file_digests.get("payload.sh"),
            second.file_digests.get("payload.sh")
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn limited_files_still_have_a_digest_and_content_changes_are_visible() {
        let root = fixture_root();
        let plugin = root.join("io.example.limited");
        manifest(&plugin, "io.example.limited", &["bar-widget"]);
        let large = plugin.join("asset.bin");
        let data = vec![b'a'; 16 * 1024 * 1024 + 1];
        fs::write(&large, &data).unwrap();
        for name in [
            "code_a.qml",
            "code_b.qml",
            "code_c.qml",
            "code_d.qml",
            "code_e.qml",
            "code_f.qml",
            "code_g.qml",
        ] {
            fs::write(plugin.join(name), "Item {}\n").unwrap();
        }
        let first = source_identity("io.example.limited", &plugin, None, None, None);
        fs::write(&large, vec![b'b'; 16 * 1024 * 1024 + 1]).unwrap();
        let second = source_identity("io.example.limited", &plugin, None, None, None);
        assert!(first.content_digest.is_some());
        assert!(!first.limitations.is_empty());
        assert_ne!(first.content_digest, second.content_digest);
        assert!(first.file_digests.contains_key("code_g.qml"));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn git_trust_files_are_part_of_identity() {
        let root = fixture_root();
        let plugin = root.join("io.example.git-config");
        manifest(&plugin, "io.example.git-config", &["bar-widget"]);
        fs::create_dir_all(plugin.join(".git")).unwrap();
        fs::write(plugin.join(".git/config"), "[core]\n").unwrap();
        let first = source_identity("io.example.git-config", &plugin, None, None, None);
        fs::write(plugin.join(".git/config"), "[core]\n\tfsmonitor = true\n").unwrap();
        let second = source_identity("io.example.git-config", &plugin, None, None, None);
        assert_ne!(first.content_digest, second.content_digest);
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_plugin_is_not_followed() {
        use std::os::unix::fs::symlink;

        let root = fixture_root();
        let target = root.join("real");
        manifest(&target, "io.example.real", &["bar-widget"]);
        symlink(&target, root.join("io.example.link")).unwrap();

        let inventory = collect(&root, None);
        let link = inventory
            .plugins
            .iter()
            .find(|plugin| plugin.id == "io.example.link")
            .unwrap();
        assert_eq!(link.classification, "unscannable");
        assert!(
            link.classification_reason
                .as_deref()
                .unwrap()
                .contains("symlink")
        );
        fs::remove_dir_all(root).unwrap();
    }
}
