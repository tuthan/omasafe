//! Omarchy plugin-manifest validation (v0.2 S6 / M5 parity surface).
//!
//! Mirrors the checks `omarchy plugin validate` (recorded version
//! [`RECORDED_OMARCHY_VERSION`]) enforces before the shell will load a
//! plugin: schema version, required fields, safe relative entry points that
//! exist on disk, one entry point per kind that needs one, no symlinks, and
//! an id outside reserved namespaces. The parity canary runs both validators
//! over the pinned corpus and fails on disagreement for the recorded
//! version; a runtime Omarchy newer than the recorded version degrades
//! validator coverage visibly instead of silently passing.

use std::fs;
use std::path::Path;

/// The Omarchy release this validation was verified against.
pub const RECORDED_OMARCHY_VERSION: &str = "4.0.1";

/// Kind → required `entryPoints` key. A declared kind without its entry
/// point installs, enables, and silently loads nothing; the native validator
/// refuses it and so do we.
const KIND_ENTRY_POINTS: &[(&str, &str)] = &[
    ("bar", "bar"),
    ("bar-widget", "barWidget"),
    ("menu", "menu"),
    ("overlay", "overlay"),
    ("panel", "panel"),
    ("service", "service"),
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManifestIssue {
    /// Stable machine-readable slug for report aggregation.
    pub code: &'static str,
    /// Human explanation mirroring the native validator's wording.
    pub message: String,
}

impl std::fmt::Display for ManifestIssue {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}: {}", self.code, self.message)
    }
}

fn issue(code: &'static str, message: impl Into<String>) -> ManifestIssue {
    ManifestIssue {
        code,
        message: message.into(),
    }
}

/// Validates one plugin folder. Returns every issue found (empty = valid).
/// Structural problems (missing folder/manifest) yield a single issue so the
/// parity canary can compare verdicts, not prose.
pub fn validate_plugin_folder(folder: &Path) -> Vec<ManifestIssue> {
    let manifest_path = folder.join("manifest.json");
    if !folder.is_dir() {
        return vec![issue("plugin-folder-missing", "plugin folder not found")];
    }
    if !manifest_path.is_file() {
        return vec![issue(
            "manifest-missing",
            format!("missing manifest.json in {}", folder.display()),
        )];
    }
    let raw = match fs::read(&manifest_path) {
        Ok(raw) => raw,
        Err(error) => {
            return vec![issue(
                "manifest-unreadable",
                format!("manifest.json could not be read: {error}"),
            )];
        }
    };
    // Size bound first: manifests are small configuration files, never data.
    if raw.len() > 1024 * 1024 {
        return vec![issue("manifest-oversized", "manifest.json exceeds 1 MiB")];
    }
    let manifest: serde_json::Value = match serde_json::from_slice(&raw) {
        Ok(value) => value,
        Err(error) => {
            return vec![issue(
                "manifest-invalid-json",
                format!("manifest.json is not valid JSON: {error}"),
            )];
        }
    };
    let mut issues = Vec::new();

    // schemaVersion must be exactly the JSON number 1; the string "1" is
    // rejected just like the registry's type-aware comparison.
    if manifest
        .get("schemaVersion")
        .and_then(serde_json::Value::as_i64)
        != Some(1)
    {
        issues.push(issue(
            "schema-version",
            "unsupported or missing schemaVersion (expected 1)",
        ));
    }

    for field in ["id", "name", "version", "kinds", "entryPoints"] {
        if manifest.get(field).is_none() {
            issues.push(issue(
                "missing-field",
                format!("manifest missing required field '{field}'"),
            ));
        }
    }

    let id = manifest
        .get("id")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("");
    if id.is_empty() {
        issues.push(issue("empty-id", "manifest 'id' is empty"));
    } else {
        // The native check rejects ".." anywhere and enforces the character
        // set; both matter independently (dots are legal, runs of them are
        // not).
        if !valid_plugin_id(id) || id.contains("..") {
            issues.push(issue("invalid-id", format!("invalid plugin id '{id}'")));
        }
        if id.starts_with("omarchy.") {
            issues.push(issue(
                "reserved-id",
                format!("plugin id '{id}' uses the reserved omarchy.* namespace"),
            ));
        }
    }

    let kinds_valid = manifest
        .get("kinds")
        .and_then(serde_json::Value::as_array)
        .is_some_and(|kinds| !kinds.is_empty());
    if manifest.get("kinds").is_some() && !kinds_valid {
        issues.push(issue("kinds-shape", "'kinds' must be a non-empty array"));
    }

    if manifest.get("entryPoints").is_some()
        && !manifest
            .get("entryPoints")
            .is_some_and(|entry| entry.is_object())
    {
        issues.push(issue(
            "entry-points-shape",
            "'entryPoints' must be an object",
        ));
    }

    if let Some(section) = manifest
        .get("barWidget")
        .filter(|value| value.is_object())
        .and_then(|bar_widget| bar_widget.get("defaultSection"))
    {
        match section.as_str() {
            Some("left" | "center" | "right") => {}
            _ => issues.push(issue(
                "bar-section",
                "'barWidget.defaultSection' must be left, center, or right",
            )),
        }
    }

    if let Some(entry_points) = manifest
        .get("entryPoints")
        .and_then(serde_json::Value::as_object)
    {
        for (key, value) in entry_points {
            let Some(path) = value.as_str() else {
                issues.push(issue(
                    "entry-point-type",
                    format!("entry point '{key}' must be a string path"),
                ));
                continue;
            };
            if path.is_empty() {
                issues.push(issue("entry-point-empty", "entry point path is empty"));
                continue;
            }
            if path.contains('\n') {
                issues.push(issue(
                    "entry-point-newline",
                    format!("entry point '{key}' may not contain a newline"),
                ));
                continue;
            }
            if path.starts_with('/') {
                issues.push(issue(
                    "entry-point-absolute",
                    format!("entry point must be a relative path: '{path}'"),
                ));
                continue;
            }
            if path.contains("..") {
                issues.push(issue(
                    "entry-point-traversal",
                    format!("entry point may not contain '..': '{path}'"),
                ));
                continue;
            }
            if !folder.join(path).is_file() {
                issues.push(issue(
                    "entry-point-missing",
                    format!("entry point file not found: '{path}'"),
                ));
            }
        }
    }

    let declared_kinds: Vec<&str> = manifest
        .get("kinds")
        .and_then(serde_json::Value::as_array)
        .map(|values| {
            values
                .iter()
                .filter_map(serde_json::Value::as_str)
                .collect()
        })
        .unwrap_or_default();
    for (kind, entry_point) in KIND_ENTRY_POINTS {
        if !declared_kinds.contains(kind) {
            continue;
        }
        let covered = manifest
            .get("entryPoints")
            .and_then(serde_json::Value::as_object)
            .is_some_and(|entry| entry.contains_key(*entry_point));
        if !covered {
            issues.push(issue(
                "kind-entry-point",
                format!("kind '{kind}' requires an 'entryPoints.{entry_point}' to load"),
            ));
        }
    }

    // Refuse any symlink anywhere inside the folder except git internals:
    // a symlink could point an installed plugin back at arbitrary files.
    if let Some(link) = first_symlink(folder) {
        issues.push(issue(
            "symlink-present",
            format!(
                "symlinks are not allowed inside a plugin folder: {}",
                link.display()
            ),
        ));
    }

    issues
}

fn valid_plugin_id(id: &str) -> bool {
    let mut chars = id.chars();
    matches!(chars.next(), Some(first) if first.is_ascii_alphanumeric())
        && chars.all(|char| char.is_ascii_alphanumeric() || matches!(char, '.' | '_' | '-'))
}

fn first_symlink(folder: &Path) -> Option<std::path::PathBuf> {
    fn walk(dir: &Path, depth: usize) -> Option<std::path::PathBuf> {
        if depth > 16 {
            return None;
        }
        let mut entries: Vec<_> = fs::read_dir(dir)
            .ok()?
            .collect::<Result<Vec<_>, _>>()
            .ok()?;
        entries.sort_by_key(|entry| entry.file_name());
        for entry in entries {
            let path = entry.path();
            let file_type = entry.file_type().ok()?;
            if file_type.is_symlink() {
                return Some(path);
            }
            if file_type.is_dir() {
                if path.file_name().is_some_and(|name| name == ".git") {
                    continue;
                }
                if let Some(found) = walk(&path, depth + 1) {
                    return Some(found);
                }
            }
        }
        None
    }
    walk(folder, 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_manifest(dir: &Path, json: &str) {
        fs::create_dir_all(dir).unwrap();
        fs::write(dir.join("manifest.json"), json).unwrap();
    }

    const VALID: &str = r#"{
        "schemaVersion": 1,
        "id": "io.test.valid",
        "name": "Valid",
        "version": "1.0.0",
        "kinds": ["bar-widget"],
        "entryPoints": {"barWidget": "widget.qml"}
    }"#;

    #[test]
    fn accepts_a_complete_root_plugin() {
        let dir = std::env::temp_dir().join(format!("omasafe-manifest-ok-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        write_manifest(&dir, VALID);
        fs::write(dir.join("widget.qml"), "Item {}\n").unwrap();
        assert!(
            validate_plugin_folder(&dir).is_empty(),
            "{:?}",
            validate_plugin_folder(&dir)
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn rejects_schema_string_reserved_ids_and_dangling_entry_points() {
        let dir = std::env::temp_dir().join(format!("omasafe-manifest-bad-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        write_manifest(
            &dir,
            r#"{"schemaVersion":"1","name":"x","version":"1","kinds":["bar-widget"],"entryPoints":{"barWidget":"w.qml"},"id":"omarchy.evil"}"#,
        );
        let codes: Vec<&str> = validate_plugin_folder(&dir)
            .iter()
            .map(|issue| issue.code)
            .collect();
        assert_eq!(
            codes,
            vec!["schema-version", "reserved-id", "entry-point-missing"]
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn rejects_missing_fields_and_uncovered_kinds() {
        let dir =
            std::env::temp_dir().join(format!("omasafe-manifest-miss-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        write_manifest(
            &dir,
            r#"{"schemaVersion":1,"name":"x","version":"1","kinds":["service"],"entryPoints":{}}"#,
        );
        let codes: Vec<&str> = validate_plugin_folder(&dir)
            .iter()
            .map(|issue| issue.code)
            .collect();
        assert!(codes.contains(&"missing-field"), "{codes:?}");
        assert!(codes.contains(&"kind-entry-point"), "{codes:?}");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn rejects_traversal_absolute_and_missing_entry_points() {
        let dir = std::env::temp_dir().join(format!("omasafe-manifest-ep-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        write_manifest(
            &dir,
            r#"{"schemaVersion":1,"id":"a.b","name":"x","version":"1","kinds":[],"entryPoints":{"one":"/etc/passwd","two":"../out","three":"gone.qml","four":""}}"#,
        );
        let codes: Vec<&str> = validate_plugin_folder(&dir)
            .iter()
            .map(|issue| issue.code)
            .collect();
        for expected in [
            "entry-point-absolute",
            "entry-point-traversal",
            "entry-point-missing",
            "entry-point-empty",
        ] {
            assert!(codes.contains(&expected), "{codes:?}");
        }
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn rejects_symlinks_outside_git_internals() {
        let dir =
            std::env::temp_dir().join(format!("omasafe-manifest-link-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        write_manifest(&dir, VALID);
        fs::write(dir.join("widget.qml"), "Item {}\n").unwrap();
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink("/etc", dir.join("link")).unwrap();
            let codes: Vec<&str> = validate_plugin_folder(&dir)
                .iter()
                .map(|issue| issue.code)
                .collect();
            assert!(codes.contains(&"symlink-present"), "{codes:?}");
        }
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn missing_folder_and_manifest_are_single_structural_issues() {
        let absent =
            std::env::temp_dir().join(format!("omasafe-manifest-absent-{}", std::process::id()));
        let _ = fs::remove_dir_all(&absent);
        assert_eq!(validate_plugin_folder(&absent).len(), 1);

        let dir =
            std::env::temp_dir().join(format!("omasafe-manifest-nomf-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        assert_eq!(validate_plugin_folder(&dir)[0].code, "manifest-missing");
        let _ = fs::remove_dir_all(&dir);
    }
}
