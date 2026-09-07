#[path = "../build_support.rs"]
mod build_support;

use std::fs;

fn write_source(root: &std::path::Path, relative: &str, contents: &str) {
    let path = root.join(relative);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, contents).unwrap();
}

#[test]
fn fingerprints_are_relocation_stable_and_exclude_tests() {
    let first = tempfile::tempdir().unwrap();
    let second = tempfile::tempdir().unwrap();
    for root in [first.path(), second.path()] {
        write_source(root, "nested/runtime.rs", "pub fn stable() {}");
        write_source(root, "tests/ignored.rs", "different");
        write_source(root, "golden/ignored.rs", "different");
        write_source(root, "inline_tests.rs", "different");
    }
    let (left, _) = build_support::source_fingerprint(first.path()).unwrap();
    let (right, _) = build_support::source_fingerprint(second.path()).unwrap();
    assert_eq!(left, right);
}

#[test]
fn runtime_addition_changes_the_fingerprint() {
    let root = tempfile::tempdir().unwrap();
    write_source(root.path(), "lib.rs", "pub fn stable() {}");
    let (before, _) = build_support::source_fingerprint(root.path()).unwrap();
    write_source(root.path(), "new.rs", "pub fn added() {}");
    let (after, _) = build_support::source_fingerprint(root.path()).unwrap();
    assert_ne!(before, after);
}

#[test]
fn watched_directories_include_nested_runtime_paths_and_new_directories() {
    let root = tempfile::tempdir().unwrap();
    write_source(root.path(), "nested/runtime.rs", "pub fn stable() {}");
    let initial = build_support::source_directories(root.path()).unwrap();
    assert!(initial.contains(&root.path().to_path_buf()));
    assert!(initial.contains(&root.path().join("nested")));

    fs::create_dir(root.path().join("new")).unwrap();
    let updated = build_support::source_directories(root.path()).unwrap();
    assert!(updated.contains(&root.path().join("new")));
}
