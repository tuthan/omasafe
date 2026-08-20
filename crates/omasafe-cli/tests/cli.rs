use assert_cmd::Command;
use serde_json::Value;
use std::fs;
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
fn inventory_uses_verified_cached_marketplace_snapshot_by_default() {
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
    assert_eq!(
        report["result"]["marketplace_retrieved_at"],
        "2026-08-20T00:00:00Z"
    );
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
