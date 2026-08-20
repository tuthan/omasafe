use std::collections::BTreeMap;
use std::fs;
use std::path::Path;
use std::process::Command;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub mod baseline;

#[derive(Debug, Default, Serialize)]
pub struct Inventory {
    pub plugins: Vec<PluginRecord>,
    pub active_full_bar: Option<String>,
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
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct SourceIdentity {
    pub plugin_id: String,
    pub repository: Option<String>,
    pub head: Option<String>,
    pub tree: Option<String>,
    pub content_digest: Option<String>,
    pub file_count: usize,
    pub limitations: Vec<String>,
}

const MAX_FILES: usize = 10_000;
const MAX_FILE_BYTES: u64 = 16 * 1024 * 1024;
const MAX_TOTAL_BYTES: u64 = 64 * 1024 * 1024;
pub const MAX_DIFF_BYTES: usize = 128 * 1024;

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
    if let Some(plugin) = shell_by_id
        .values()
        .find(|plugin| plugin.active == Some(true) && plugin.kinds.iter().any(|kind| kind == "bar"))
    {
        inventory.active_full_bar = Some(plugin.id.clone());
        inventory.non_builtin_bar_replaces_bar = plugin.first_party != Some(true);
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
        let shell_plugin = shell_by_id.remove(&name);
        let record = inspect_plugin(&path, &name, shell_plugin.as_ref());
        if record.active == Some(true) && record.kinds.iter().any(|kind| kind == "bar") {
            inventory.active_full_bar = Some(record.id.clone());
            inventory.non_builtin_bar_replaces_bar = record.first_party != Some(true);
        }
        inventory.plugins.push(record);
    }

    for plugin in shell_by_id.values() {
        inventory.coverage.limitations.push(format!(
            "shell reports plugin {} but its directory was not found",
            plugin.id
        ));
    }
    inventory
        .plugins
        .sort_by(|left, right| left.id.cmp(&right.id));
    inventory
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
        repository: None,
        head: None,
        tree: None,
        dirty: None,
        content_digest: None,
        content_file_count: None,
        reason: None,
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
        classification: if shell.map_or(false, |plugin| plugin.first_party == Some(true))
            || name.starts_with("omarchy.")
        {
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
        if git.reason.is_some() {
            record.reason = git.reason;
        }
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
    if !source.limitations.is_empty() {
        record.reason = Some(source.limitations.join("; "));
    }
    record
}

fn with_reason(mut record: PluginRecord, reason: &str) -> PluginRecord {
    record.reason = Some(reason.into());
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
    Command::new("git")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_OPTIONAL_LOCKS", "0")
        .args(args)
        .current_dir(path)
        .output()
        .ok()
        .filter(|output| output.status.success())
        .map(|output| String::from_utf8_lossy(&output.stdout).trim().to_owned())
        .filter(|value| !value.is_empty())
}

fn git_status(path: &Path) -> Option<String> {
    Command::new("git")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_OPTIONAL_LOCKS", "0")
        .args(["status", "--porcelain", "--untracked-files=all"])
        .current_dir(path)
        .output()
        .ok()
        .filter(|output| output.status.success())
        .map(|output| String::from_utf8_lossy(&output.stdout).into_owned())
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
    let mut hasher = Sha256::new();
    for entry in &entries {
        hasher.update((entry.path.len() as u64).to_be_bytes());
        hasher.update(entry.path.as_bytes());
        hasher.update([entry.kind]);
        hasher.update(entry.mode.to_be_bytes());
        hasher.update((entry.data.len() as u64).to_be_bytes());
        hasher.update(&entry.data);
    }
    SourceIdentity {
        plugin_id: plugin_id.into(),
        repository,
        head,
        tree,
        content_digest: if limitations.is_empty() {
            Some(format!("{:x}", hasher.finalize()))
        } else {
            None
        },
        file_count: entries.len(),
        limitations,
    }
}

pub fn git_diff(root: &Path, ref_a: &str, ref_b: &str) -> DiffResult {
    if !valid_ref(ref_a) || !valid_ref(ref_b) {
        return unavailable_diff("diff reference contains unsupported characters");
    }
    let range = format!("{ref_a}..{ref_b}");
    let mut command = Command::new("git");
    command
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_OPTIONAL_LOCKS", "0")
        .args(["diff", "--no-ext-diff", "--binary", "--unified=3"]);
    if ref_b == "WORKTREE" {
        command.args([ref_a, "--"]);
    } else {
        command.args([&range, "--"]);
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
            limitations.push(format!("unreadable path {}: {error}", directory.display()));
            return;
        }
    };
    for entry in read_dir {
        if entries.len() >= MAX_FILES {
            limitations.push(format!("file limit of {MAX_FILES} exceeded"));
            return;
        }
        let Ok(entry) = entry else {
            limitations.push("directory entry could not be read".into());
            continue;
        };
        let path = entry.path();
        if path.file_name().is_some_and(|name| name == ".git") {
            continue;
        }
        let Ok(metadata) = fs::symlink_metadata(&path) else {
            limitations.push(format!("metadata unavailable: {}", path.display()));
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
            if metadata.len() > MAX_FILE_BYTES {
                limitations.push(format!("file exceeds {MAX_FILE_BYTES} bytes: {relative}"));
                continue;
            }
            if total_bytes.saturating_add(metadata.len()) > MAX_TOTAL_BYTES {
                limitations.push(format!(
                    "aggregate file limit of {MAX_TOTAL_BYTES} bytes exceeded"
                ));
                return;
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
                Err(error) => limitations.push(format!("file unreadable {relative}: {error}")),
            }
        } else {
            limitations.push(format!("special file skipped: {relative}"));
        }
    }
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
        assert!(link.reason.as_deref().unwrap().contains("symlink"));
        fs::remove_dir_all(root).unwrap();
    }
}
