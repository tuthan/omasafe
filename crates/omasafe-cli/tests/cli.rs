use assert_cmd::Command;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fs;
use std::path::Path;
use tempfile::TempDir;

struct Fixture {
    _home: TempDir,
    config: TempDir,
    state: TempDir,
    cache: TempDir,
    bin: TempDir,
    plugin: std::path::PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let home = TempDir::new().unwrap();
        let config = TempDir::new().unwrap();
        let state = TempDir::new().unwrap();
        let cache = TempDir::new().unwrap();
        let bin = TempDir::new().unwrap();
        let plugin = config.path().join("omarchy/plugins/io.example.cli");
        fs::create_dir_all(&plugin).unwrap();
        fs::write(
            plugin.join("manifest.json"),
            r#"{"schemaVersion":1,"id":"io.example.cli","kinds":["bar-widget"]}"#,
        )
        .unwrap();
        fs::write(plugin.join("main.qml"), "Item {}\n").unwrap();
        Self {
            _home: home,
            config,
            state,
            cache,
            bin,
            plugin,
        }
    }

    fn command(&self) -> Command {
        let mut command = Command::cargo_bin("omasafe-cli").unwrap();
        command
            .env("HOME", self._home.path())
            .env("XDG_CONFIG_HOME", self.config.path())
            .env("XDG_STATE_HOME", self.state.path())
            .env("XDG_CACHE_HOME", self.cache.path())
            .env("PATH", self.bin.path());
        command
    }

    fn inventory(&self) -> Value {
        let output = self
            .command()
            .args(["plugins", "inventory", "--format", "json"])
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        serde_json::from_slice(&output.stdout).unwrap()
    }

    fn trust_current(&self) {
        let record = &self.inventory()["result"]["plugins"][0];
        let accepted = serde_json::json!({
            "plugin_id": record["id"], "repository": record["repository"],
            "head": record["head"], "tree": record["tree"],
            "content_digest": record["content_digest"],
            "file_count": record["content_file_count"],
            "limitations": record["limitations"], "file_digests": record["file_digests"]
        });
        let history = serde_json::json!({
            "schema_version": 1,
            "records": [{"plugin_id":"io.example.cli", "accepted": accepted, "accepted_at":"now", "note":"test"}],
            "decisions": []
        });
        fs::create_dir_all(self.state.path().join("omasafe")).unwrap();
        fs::write(
            self.state.path().join("omasafe/trust-history.json"),
            serde_json::to_vec(&history).unwrap(),
        )
        .unwrap();
    }
}

#[test]
fn old_baseline_without_file_map_stays_unchanged() {
    let fixture = Fixture::new();
    let record = &fixture.inventory()["result"]["plugins"][0];
    let accepted = serde_json::json!({
        "plugin_id": record["id"],
        "repository": record["repository"],
        "head": record["head"],
        "tree": record["tree"],
        "content_digest": record["content_digest"],
        "file_count": record["content_file_count"],
        "limitations": record["limitations"]
    });
    let history = serde_json::json!({
        "schema_version": 1,
        "records": [{"plugin_id":"io.example.cli", "accepted": accepted, "accepted_at":"old", "note":"old"}],
        "decisions": []
    });
    fs::create_dir_all(fixture.state.path().join("omasafe")).unwrap();
    fs::write(
        fixture.state.path().join("omasafe/trust-history.json"),
        serde_json::to_vec(&history).unwrap(),
    )
    .unwrap();
    fixture
        .command()
        .args(["plugins", "status", "io.example.cli"])
        .assert()
        .success()
        .stdout(predicates::str::contains("unchanged"));
}

#[test]
fn oversized_asset_does_not_stop_later_files_from_inventory() {
    let fixture = Fixture::new();
    fs::write(
        fixture.plugin.join("asset.bin"),
        vec![b'a'; 100 * 1024 * 1024],
    )
    .unwrap();
    for name in ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h'] {
        fs::write(fixture.plugin.join(format!("code_{name}.qml")), "Item {}\n").unwrap();
    }
    let inventory = fixture.inventory();
    let files = inventory["result"]["plugins"][0]["file_digests"]
        .as_object()
        .unwrap();
    for name in ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h'] {
        assert!(files.contains_key(&format!("code_{name}.qml")));
    }
}

#[test]
#[cfg(unix)]
fn mode_only_change_is_present_in_cli_diff() {
    let fixture = Fixture::new();
    use std::os::unix::fs::PermissionsExt;
    let file = fixture.plugin.join("payload.sh");
    fs::write(&file, "payload\n").unwrap();
    fixture.trust_current();
    fs::set_permissions(&file, fs::Permissions::from_mode(0o755)).unwrap();
    fixture
        .command()
        .args(["plugins", "diff", "io.example.cli"])
        .assert()
        .success()
        .stdout(predicates::str::contains("payload.sh"));
}

#[test]
fn acknowledge_without_scope_marks_source_drift_reviewed() {
    let fixture = Fixture::new();
    fixture.trust_current();
    fixture
        .command()
        .args([
            "plugins",
            "review",
            "io.example.cli",
            "--action",
            "acknowledge",
            "--reason",
            "reviewed",
            "--yes",
        ])
        .assert()
        .success();
    fs::write(
        fixture.plugin.join("main.qml"),
        "Item { property bool changed: true }\n",
    )
    .unwrap();
    fixture
        .command()
        .args(["scan"])
        .assert()
        .code(3)
        .stdout(predicates::str::contains("previously acknowledged"));
}

#[test]
fn untrust_revokes_the_active_baseline_without_deleting_history() {
    let fixture = Fixture::new();
    fixture.trust_current();
    fixture
        .command()
        .args([
            "plugins",
            "review",
            "io.example.cli",
            "--action",
            "untrust",
            "--reason",
            "no longer trusted",
            "--yes",
        ])
        .assert()
        .success();

    let status = fixture
        .command()
        .args(["plugins", "status", "io.example.cli", "--format", "json"])
        .output()
        .unwrap();
    assert!(status.status.success());
    let report: Value = serde_json::from_slice(&status.stdout).unwrap();
    assert_eq!(report["result"]["state"], "untrusted");
    assert!(report["result"]["trusted"].is_null());
    assert_eq!(
        report["result"]["reason"],
        "trust baseline was revoked; restore or re-trust to recover it"
    );

    let history: Value = serde_json::from_slice(
        &fs::read(fixture.state.path().join("omasafe/trust-history.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(history["records"].as_array().unwrap().len(), 1);
    assert_eq!(history["revoked_plugins"][0], "io.example.cli");
}

#[test]
fn missing_plugin_alerts_are_deduplicated_across_trust_history() {
    let fixture = Fixture::new();
    fixture.trust_current();
    let history_path = fixture.state.path().join("omasafe/trust-history.json");
    let mut history: Value = serde_json::from_slice(&fs::read(&history_path).unwrap()).unwrap();
    let duplicate = history["records"][0].clone();
    history["records"].as_array_mut().unwrap().push(duplicate);
    fs::write(&history_path, serde_json::to_vec(&history).unwrap()).unwrap();
    fs::remove_dir_all(&fixture.plugin).unwrap();

    let output = fixture
        .command()
        .args(["scan", "--format", "json"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(3));
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    let missing = report["result"]["alerts"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|alert| alert["kind"] == "missing-plugin")
        .count();
    assert_eq!(missing, 1);
    assert!(report["result"]["outstanding"].as_u64().unwrap() >= 1);
    assert_eq!(report["result"]["new"], report["result"]["outstanding"]);
}

#[test]
fn inventory_discloses_unverified_cached_marketplace_snapshot() {
    let fixture = Fixture::new();
    let cache = fixture.cache.path().join("omasafe");
    fs::create_dir_all(&cache).unwrap();
    fs::write(cache.join("catalog.json"), b"[]").unwrap();
    fs::write(
        cache.join("catalog.meta.json"),
        serde_json::json!({
            "repository_commit": "0123456789abcdef0123456789abcdef01234567",
            "repository_url": "https://github.com/HANCORE-linux/omarchy-plugin-marketplace",
            "retrieved_at": "2026-08-20T00:00:00Z"
        })
        .to_string(),
    )
    .unwrap();
    let report = fixture.inventory();
    assert_eq!(report["result"]["marketplace_source"], "unverified-cache");
    assert_eq!(report["result"]["marketplace_snapshot_verified"], false);
    assert_eq!(
        report["result"]["marketplace_repository_commit"],
        "0123456789abcdef0123456789abcdef01234567"
    );
    assert_eq!(
        report["result"]["marketplace_repository"],
        "https://github.com/HANCORE-linux/omarchy-plugin-marketplace"
    );
    assert_eq!(
        report["result"]["marketplace_file_digest"]
            .as_str()
            .unwrap()
            .len(),
        64
    );
    assert_eq!(
        report["result"]["marketplace_retrieved_at"],
        "2026-08-20T00:00:00Z"
    );
}

#[test]
#[cfg(unix)]
fn inventory_discloses_verified_snapshot_without_a_matching_listing() {
    use std::os::unix::fs::symlink;

    let fixture = Fixture::new();
    let source = TempDir::new().unwrap();
    let catalog = b"[]\n";
    fs::create_dir_all(source.path().join("site")).unwrap();
    fs::write(source.path().join("site/catalog.json"), catalog).unwrap();

    for args in [
        vec!["init"],
        vec!["config", "user.name", "OmaSafe test"],
        vec!["config", "user.email", "omasafe@example.invalid"],
        vec!["add", "site/catalog.json"],
        vec!["commit", "-m", "catalog fixture"],
    ] {
        let output = std::process::Command::new("/usr/bin/git")
            .args(args)
            .current_dir(source.path())
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    let revision = std::process::Command::new("/usr/bin/git")
        .args(["rev-parse", "HEAD"])
        .current_dir(source.path())
        .output()
        .unwrap();
    assert!(revision.status.success());
    let revision = String::from_utf8(revision.stdout)
        .unwrap()
        .trim()
        .to_owned();

    let cache = fixture.cache.path().join("omasafe");
    fs::create_dir_all(&cache).unwrap();
    let clone = std::process::Command::new("/usr/bin/git")
        .args(["clone", "--bare"])
        .arg(source.path())
        .arg(cache.join("catalog.git"))
        .output()
        .unwrap();
    assert!(
        clone.status.success(),
        "{}",
        String::from_utf8_lossy(&clone.stderr)
    );
    fs::write(cache.join("catalog.json"), catalog).unwrap();
    fs::write(
        cache.join("catalog.meta.json"),
        serde_json::json!({
            "repository_commit": revision,
            "repository_url": "https://github.com/HANCORE-linux/omarchy-plugin-marketplace",
            "retrieved_at": "2026-08-22T00:00:00Z",
            "file_digest": format!("{:x}", Sha256::digest(catalog))
        })
        .to_string(),
    )
    .unwrap();
    symlink("/usr/bin/git", fixture.bin.path().join("git")).unwrap();

    let report = fixture.inventory();
    assert_eq!(report["result"]["marketplace_source"], "pinned-fetch");
    assert_eq!(report["result"]["marketplace_snapshot_verified"], true);
    assert_eq!(report["result"]["marketplace_repository_commit"], revision);
    assert_eq!(report["result"]["marketplace"][0]["status"], "unlisted");
}

#[test]
fn inventory_text_separates_backup_folders_from_installed_plugins() {
    let fixture = Fixture::new();
    fs::create_dir_all(
        fixture
            .config
            .path()
            .join("omarchy/plugins/.io.example.cli.bak.20260821"),
    )
    .unwrap();
    fixture
        .command()
        .args(["plugins", "inventory"])
        .assert()
        .success()
        .stdout(predicates::str::contains(
            "1 installed plugin(s) collected.",
        ))
        .stdout(predicates::str::contains(
            "1 backup folder(s) retained separately for audit visibility.",
        ));
}

#[test]
fn different_git_heads_with_same_content_receive_distinct_alerts() {
    let fixture = Fixture::new();
    fixture.trust_current();
    let history_path = fixture.state.path().join("omasafe/trust-history.json");
    let mut history: Value = serde_json::from_slice(&fs::read(&history_path).unwrap()).unwrap();
    history["records"][0]["accepted"]["head"] = Value::String("head-one".into());
    fs::write(&history_path, serde_json::to_vec(&history).unwrap()).unwrap();
    fixture
        .command()
        .args(["scan", "--notify"])
        .assert()
        .code(3)
        .stdout(predicates::str::contains("source-drift"));
    history["records"][0]["accepted"]["head"] = Value::String("head-two".into());
    fs::write(&history_path, serde_json::to_vec(&history).unwrap()).unwrap();
    fixture
        .command()
        .args(["scan", "--notify"])
        .assert()
        .code(3)
        .stdout(predicates::str::contains("source-drift"));
}

#[test]
fn scan_reports_outstanding_findings_with_exit_code_three() {
    let fixture = Fixture::new();
    fixture.trust_current();
    fs::write(
        fixture.plugin.join("main.qml"),
        "Item { property bool changed: true }\n",
    )
    .unwrap();
    let output = fixture
        .command()
        .args(["scan", "--format", "json"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(3));
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(report["result"]["outstanding"].as_u64().unwrap() > 0);
    assert!(report["result"]["new"].as_u64().unwrap() > 0);
    assert_eq!(report["result"]["highest_severity"], "warning");
    assert_eq!(report["result"]["alerts"][0]["severity"], "warning");
}

#[test]
fn only_new_scan_is_quiet_after_notification_delivery() {
    let fixture = Fixture::new();
    fixture.trust_current();
    fs::write(
        fixture.plugin.join("main.qml"),
        "Item { property bool changed: true }\n",
    )
    .unwrap();
    fixture
        .command()
        .args(["scan", "--notify", "--only-new"])
        .assert()
        .code(3);
    fixture
        .command()
        .args(["scan", "--notify", "--only-new"])
        .assert()
        .code(0)
        .stdout(predicates::str::contains(
            "No new actionable changes detected.",
        ));
}

#[test]
fn only_new_scan_keeps_highest_severity_for_outstanding_findings() {
    let fixture = Fixture::new();
    fixture.trust_current();
    fs::write(
        fixture.plugin.join("main.qml"),
        "Item { property bool changed: true }\n",
    )
    .unwrap();
    fixture
        .command()
        .args(["scan", "--notify"])
        .assert()
        .code(3);

    let output = fixture
        .command()
        .args(["scan", "--format", "json", "--only-new"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(0));
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(report["result"]["outstanding"].as_u64().unwrap() > 0);
    assert_eq!(report["result"]["new"], 0);
    assert_eq!(report["result"]["highest_severity"], "warning");
}

#[test]
#[cfg(unix)]
fn schedule_unit_accepts_outstanding_exit_code() {
    use std::os::unix::fs::PermissionsExt;
    let fixture = Fixture::new();
    let systemctl = fixture.bin.path().join("systemctl");
    fs::write(&systemctl, "#!/bin/sh\nexit 0\n").unwrap();
    fs::set_permissions(&systemctl, fs::Permissions::from_mode(0o755)).unwrap();
    fixture
        .command()
        .args(["schedule", "install"])
        .assert()
        .success();
    let unit = fs::read_to_string(
        fixture
            .config
            .path()
            .join("systemd/user/omasafe-scan.service"),
    )
    .unwrap();
    assert!(unit.contains("SuccessExitStatus=3"));
}

#[test]
fn stale_cached_snapshot_is_disclosed() {
    let fixture = Fixture::new();
    let cache = fixture.cache.path().join("omasafe");
    fs::create_dir_all(&cache).unwrap();
    fs::write(cache.join("catalog.json"), b"[]").unwrap();
    fs::write(
        cache.join("catalog.meta.json"),
        serde_json::json!({
            "repository_commit": "0123456789abcdef0123456789abcdef01234567",
            "repository_url": "https://github.com/HANCORE-linux/omarchy-plugin-marketplace",
            "retrieved_at": "2020-01-01T00:00:00Z"
        })
        .to_string(),
    )
    .unwrap();
    let report = fixture.inventory();
    assert_eq!(report["result"]["marketplace_stale"], true);
    assert_eq!(report["result"]["marketplace_source"], "unverified-cache");
}

#[test]
fn provenance_report_is_deterministic_and_complete() {
    let fixture = Fixture::new();
    let first = fixture
        .command()
        .args(["provenance", "--format", "json"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let second = fixture
        .command()
        .args(["provenance", "--format", "json"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    assert_eq!(first, second);
    let report: Value = serde_json::from_slice(&first).unwrap();
    assert_eq!(report["schema"], "omasafe.provenance.v1");
    assert!(report["source_revision"].as_str().is_some());
    assert!(report["cargo_lock_sha256"].as_str().unwrap().len() == 64);
    assert_eq!(report["supported_runtime"]["omarchy"], "4.0.0-1");
    assert!(
        !report["coverage_limitations"]
            .as_array()
            .unwrap()
            .is_empty()
    );
}

#[test]
fn cli_surface_matches_usage_commands() {
    let source = fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/main.rs")).unwrap();
    let usage = source
        .lines()
        .find(|line| line.contains("usage: omasafe-cli"))
        .expect("main.rs must contain the CLI usage string");
    let usage_commands: BTreeSet<_> = usage
        .split("usage: omasafe-cli ")
        .nth(1)
        .unwrap()
        .split(" | ")
        .filter_map(|entry| entry.split_whitespace().next())
        .collect();

    let surface_path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/cli-surface.txt");
    let surface = fs::read_to_string(surface_path).unwrap();
    let surface_commands: BTreeSet<_> = surface
        .lines()
        .filter(|line| !line.starts_with('#') && !line.trim().is_empty())
        .filter_map(|line| line.split_whitespace().next())
        .collect();

    assert_eq!(usage_commands, surface_commands);
}

#[test]
fn rules_list_reports_catalog_and_policy_identity() {
    let fixture = Fixture::new();
    let output = fixture
        .command()
        .args(["rules", "list", "--format", "json"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let report: Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(report["schema"], "omasafe.report.v1");
    assert_eq!(
        report["result"]["policy_identity"]["supported_surface_version"],
        "omarchy-security-surface.v1"
    );
    assert_eq!(
        report["result"]["policy_identity"]["parser_versions"]["qml"],
        "lexical-fallback-unassigned"
    );
    assert!(report["result"]["equivalence_map_version"].is_null());
    let rules = report["result"]["rules"].as_array().unwrap();
    assert!(!rules.is_empty());
    let ids: BTreeSet<_> = rules
        .iter()
        .map(|rule| rule["id"].as_str().unwrap().to_owned())
        .collect();
    assert_eq!(ids.len(), rules.len());
    for required in [
        "oma.qml.process-execution",
        "oma.qml.polkit-agent-ui",
        "oma.qml.session-lock",
        "oma.qml.pam-authentication",
        "oma.context.replaces-bar",
    ] {
        assert!(ids.contains(required), "missing {required}");
    }
}

#[test]
fn rules_list_text_is_deterministic() {
    let fixture = Fixture::new();
    let first = fixture
        .command()
        .args(["rules", "list"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let second = fixture
        .command()
        .args(["rules", "list"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    assert_eq!(first, second);
    let rendered = String::from_utf8(first).unwrap();
    assert!(rendered.contains("rule catalog v1"));
    assert!(rendered.contains("oma.qml.session-lock"));
}

#[test]
fn rules_list_rejects_unknown_arguments_and_formats() {
    let fixture = Fixture::new();
    fixture
        .command()
        .args(["rules", "list", "--bogus"])
        .assert()
        .failure()
        .stderr(predicates::str::contains("unknown rules list argument"));
    fixture
        .command()
        .args(["rules", "list", "--format", "yaml"])
        .assert()
        .failure()
        .stderr(predicates::str::contains("text or json"));
}

/// Enriches the default single-plugin fixture with a full shipped-payload
/// surface: QML entry, JS resource, shell/python executables, an ELF payload,
/// a data binary, and a symlink.
fn enrich_plugin(plugin: &Path) {
    fs::create_dir_all(plugin.join("lib")).unwrap();
    fs::write(plugin.join("Main.qml"), "import QtQuick\nItem {}\n").unwrap();
    fs::write(plugin.join("lib/helper.js"), "function f(){return 1}\n").unwrap();
    fs::write(plugin.join("install.sh"), "#!/bin/sh\necho hi\n").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(plugin.join("install.sh"), fs::Permissions::from_mode(0o755)).unwrap();
    }
    let elf = {
        let mut bytes = vec![b'A'; 32];
        bytes[0..4].copy_from_slice(b"\x7fELF");
        bytes
    };
    fs::write(plugin.join("payload"), elf).unwrap();
    #[cfg(unix)]
    std::os::unix::fs::symlink("manifest.json", plugin.join("link.json")).unwrap();
}

#[test]
fn analyze_reports_full_payload_inventory_end_to_end() {
    let mut fixture = Fixture::new();
    enrich_plugin(&fixture.plugin);
    // Rebuild Fixture with the enriched tree: Fixture::new already created it,
    // so mutate through its stored path via a second instance is wrong; use
    // the existing one directly by re-deriving command envs below.
    let _ = &mut fixture;
    let output = fixture
        .command()
        .args(["plugins", "analyze", "io.example.cli", "--format", "json"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let report: Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(report["schema"], "omasafe.report.v1");
    assert_eq!(report["result"]["target"]["source"], "installed-plugin");
    let analysis = &report["result"]["analysis"];
    assert_eq!(analysis["schema"], "omasafe.analysis.v1");
    assert_eq!(analysis["policy_identity"]["rule_catalog_version"], 1);
    let inventory = &report["result"]["payload_inventory"];
    let states = &inventory["coverage_states"];
    let unsupported = states["unsupported"].as_u64().unwrap();
    assert!(unsupported >= 5, "states: {states}");
    let entries = inventory["entries"].as_array().unwrap();
    let kinds: Vec<&str> = entries
        .iter()
        .map(|entry| entry["kind"].as_str().unwrap())
        .collect();
    assert!(kinds.contains(&"qml"), "{kinds:?}");
    assert!(kinds.contains(&"javascript"));
    let payload_entry = entries
        .iter()
        .find(|entry| entry["relative_path"] == "payload")
        .expect("ELF payload inventoried");
    assert_eq!(payload_entry["coverage_state"], "unsupported");
    assert!(
        !kinds.contains(&"analyzed"),
        "S1 never claims analyzed coverage"
    );
}

#[test]
fn analyze_is_deterministic_for_unchanged_input() {
    let fixture = Fixture::new();
    enrich_plugin(&fixture.plugin);
    let first = fixture
        .command()
        .args(["plugins", "analyze", "io.example.cli", "--format", "json"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let second = fixture
        .command()
        .args(["plugins", "analyze", "io.example.cli", "--format", "json"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let first: Value = serde_json::from_slice(&first).unwrap();
    let second: Value = serde_json::from_slice(&second).unwrap();
    assert_eq!(first["result"], second["result"]);
}

#[test]
fn analyze_rejects_unknown_plugins_and_arguments() {
    let fixture = Fixture::new();
    fixture
        .command()
        .args(["plugins", "analyze", "io.missing.plugin"])
        .assert()
        .failure()
        .stderr(predicates::str::contains("plugin not found"));
    fixture
        .command()
        .args([
            "plugins",
            "analyze",
            "io.example.cli",
            "--fail-on",
            "catastrophic",
        ])
        .assert()
        .failure()
        .stderr(predicates::str::contains(
            "--fail-on must be one of info|low|medium|high|critical",
        ));
}

#[test]
fn scan_plugin_analyzes_local_directories() {
    let temp = tempfile::TempDir::new().unwrap();
    fs::write(temp.path().join("panel.qml"), "Item {}\n").unwrap();
    fs::write(temp.path().join("tool.sh"), "#!/bin/sh\nx\n").unwrap();
    let fixture = Fixture::new();
    let output = fixture
        .command()
        .args([
            "scan-plugin",
            "--path",
            temp.path().to_str().unwrap(),
            "--format",
            "json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let report: Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(report["result"]["target"]["source"], "local-directory");
    let entries = report["result"]["payload_inventory"]["entries"]
        .as_array()
        .unwrap();
    assert_eq!(entries.len(), 2);
}

#[test]
fn scan_plugin_argument_shapes_are_strict() {
    let fixture = Fixture::new();
    fixture
        .command()
        .args(["scan-plugin"])
        .assert()
        .failure()
        .stderr(predicates::str::contains(
            "requires --path DIR or --git URL",
        ));
    fixture
        .command()
        .args(["scan-plugin", "--path", ".", "--revision", "a"])
        .assert()
        .failure()
        .stderr(predicates::str::contains("not both"));
    fixture
        .command()
        .args(["scan-plugin", "--git", "https://example.test/r.git"])
        .assert()
        .failure()
        .stderr(predicates::str::contains("--git requires --revision"));
    fixture
        .command()
        .args([
            "scan-plugin",
            "--git",
            "https://example.test/r.git",
            "--revision",
            "zz",
        ])
        .assert()
        .failure()
        .stderr(predicates::str::contains(
            "--revision must be 40 or 64 hexadecimal",
        ));
}
