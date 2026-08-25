//! S2 measurement harness: parse the pinned entry-point corpus with
//! tree-sitter-qmljs and record coverage numbers for the ADR.
//!
//! For each manifest plugin the pinned revision is fetched through the
//! production `ensure_pinned_repository` path into a disposable bare cache,
//! then QML blobs are read as raw objects (no checkout) and measured. The
//! JSON report is written to --output; stdout gets a human summary including
//! the kill-criterion percentages.
//!
//! Usage:
//!   cargo run -p omasafe-analyzer --features qml-parser --example qml-coverage -- \
//!     --manifest corpus/entry-points.json --output corpus/coverage-report.json

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;
use std::process::Command;
use std::time::Instant;

use serde::Serialize;

use omasafe_analyzer::qml::{measure_qml_coverage, qml_parser_identity};
use omasafe_analyzer::{Limits, ensure_pinned_repository};
use omasafe_core::bounds::{GIT_PROCESS_BUDGET, MAX_FILE_BYTES, run_bounded_capped};

const LS_TREE_CAP: usize = 8 * 1024 * 1024;
const MANIFEST_BLOB_CAP: usize = 256 * 1024;

#[derive(Debug, Serialize)]
struct FileRecord {
    path: String,
    total_bytes: u64,
    covered_bytes: u64,
    non_whitespace_gap_bytes: u64,
    total_lines: u64,
    lines_with_gaps: u64,
    error_nodes: usize,
    missing_items: usize,
    clean_parse: bool,
    entry_point: bool,
}

#[derive(Debug, Serialize)]
struct PluginRecord {
    id: String,
    repo: String,
    revision: String,
    layout: Option<String>,
    status: String,
    detail: Option<String>,
    qml_files: usize,
    entry_point_files: usize,
    clean_qml_files: usize,
    clean_entry_files: usize,
    total_bytes: u64,
    covered_bytes: u64,
    non_whitespace_gap_bytes: u64,
    files: Vec<FileRecord>,
}

#[derive(Debug, Serialize)]
struct Totals {
    plugins_total: usize,
    plugins_ingested: usize,
    plugins_failed: usize,
    qml_files_total: usize,
    qml_files_clean: usize,
    entry_files_total: usize,
    entry_files_clean: usize,
    bytes_total: u64,
    bytes_covered: u64,
    non_whitespace_gap_bytes: u64,
}

#[derive(Debug, Serialize)]
struct Report {
    report_version: u32,
    parser: omasafe_analyzer::qml::QmlParserIdentity,
    manifest_source: serde_json::Value,
    selection_rule: String,
    elapsed_seconds: f64,
    totals: Totals,
    plugins: Vec<PluginRecord>,
}

fn git_bytes(dir: &Path, args: &[&str], cap: usize) -> Result<(Vec<u8>, bool), String> {
    let mut command = Command::new("git");
    command.current_dir(dir);
    command.args(args);
    command.env("GIT_CONFIG_GLOBAL", "/dev/null");
    command.env("GIT_CONFIG_SYSTEM", "/dev/null");
    match run_bounded_capped(&mut command, GIT_PROCESS_BUDGET, cap)
        .map_err(|error| error.to_string())?
    {
        Some(captured) => {
            if !captured.status.success() && !captured.truncated {
                return Err(format!("git {args:?} failed"));
            }
            Ok((captured.stdout, captured.truncated))
        }
        None => Err(format!("git {args:?} exceeded its budget")),
    }
}

/// Parse `ls-tree -r -l -z` records into (oid, size, path).
fn parse_ls_tree(records: &[u8]) -> Vec<(String, u64, String)> {
    let mut entries = Vec::new();
    for record in records.split(|byte| *byte == 0) {
        if record.is_empty() {
            continue;
        }
        let Some(tab) = record.iter().position(|byte| *byte == b'\t') else {
            continue;
        };
        let (meta, path) = (&record[..tab], &record[tab + 1..]);
        // Size is space-padded to a fixed width, so collapse runs of spaces.
        let parts: Vec<&[u8]> = meta
            .split(|byte| *byte == b' ')
            .filter(|part| !part.is_empty())
            .collect();
        if parts.len() != 4 {
            continue;
        }
        let (mode, kind, oid, size) = (parts[0], parts[1], parts[2], Some(parts[3]));
        if mode != b"100644" && mode != b"100755" {
            continue;
        }
        if kind != b"blob" {
            continue;
        }
        let size = size
            .and_then(|raw| std::str::from_utf8(raw).ok())
            .and_then(|raw| raw.parse::<u64>().ok())
            .unwrap_or(0);
        entries.push((
            String::from_utf8_lossy(oid).into_owned(),
            size,
            String::from_utf8_lossy(path).into_owned(),
        ));
    }
    entries
}

fn is_qml_path(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    lower.ends_with(".qml") && !lower.ends_with("ui.qml.tmp")
}

fn normalize_relative(base: &str, value: &str) -> Option<String> {
    if value.split('/').any(|segment| segment == "..") || value.starts_with('/') {
        return None;
    }
    if base.is_empty() {
        Some(value.trim_start_matches("./").to_owned())
    } else {
        Some(format!("{}/{}", base.trim_end_matches('/'), value))
    }
}

/// Extract entry-point QML paths from one manifest.json blob content.
fn entry_points_from_manifest(content: &[u8], manifest_dir: &str) -> Vec<String> {
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(content) else {
        return Vec::new();
    };
    let Some(entry_points) = value.get("entryPoints") else {
        return Vec::new();
    };
    let mut paths = Vec::new();
    if let Some(map) = entry_points.as_object() {
        for (_, target) in map {
            if let Some(path) = target
                .as_str()
                .and_then(|relative| normalize_relative(manifest_dir, relative))
            {
                paths.push(path);
            }
        }
    } else if let Some(path) = entry_points
        .as_str()
        .and_then(|single| normalize_relative(manifest_dir, single))
    {
        paths.push(path);
    }
    paths
}

fn measure_plugin(plugin: &serde_json::Value, cache_root: &Path, limits: Limits) -> PluginRecord {
    let id = plugin["id"].as_str().unwrap_or_default().to_owned();
    let repo = plugin["repo"].as_str().unwrap_or_default().to_owned();
    let revision = plugin["upstreamObservedCommit"]
        .as_str()
        .unwrap_or_default()
        .to_owned();
    let layout = plugin["repositoryLayout"].as_str().map(str::to_owned);

    let mut record = PluginRecord {
        id: id.clone(),
        repo: repo.clone(),
        revision: revision.clone(),
        layout: layout.clone(),
        status: "ingested".into(),
        detail: None,
        qml_files: 0,
        entry_point_files: 0,
        clean_qml_files: 0,
        clean_entry_files: 0,
        total_bytes: 0,
        covered_bytes: 0,
        non_whitespace_gap_bytes: 0,
        files: Vec::new(),
    };

    // ensure_pinned_repository manages its own slug, lock, and quota; the
    // returned bare repository is all this harness needs for reads. Large
    // suites can sit at the default time-budget edge on a slow link, so a
    // transient exhaustion gets exactly one retry before being reported.
    let slug_dir = {
        let mut attempt = 0;
        loop {
            match ensure_pinned_repository(cache_root, &repo, &revision) {
                Ok(dir) => break dir,
                Err(omasafe_analyzer::IngestError::BudgetExhausted) if attempt == 0 => {
                    attempt += 1;
                    eprintln!("  retrying {id} after budget exhaustion");
                }
                Err(error) => {
                    record.status = "clone_failed".into();
                    record.detail = Some(error.to_string());
                    return record;
                }
            }
        }
    };

    let (listing, truncated) = match git_bytes(
        &slug_dir,
        &["ls-tree", "-r", "-l", "-z", &revision],
        LS_TREE_CAP,
    ) {
        Ok(result) => result,
        Err(error) => {
            record.status = "tree_failed".into();
            record.detail = Some(error);
            return record;
        }
    };
    if truncated {
        record.status = "tree_truncated".into();
        record.detail = Some("ls-tree exceeded its capture cap".into());
        return record;
    }

    let blobs = parse_ls_tree(&listing);
    if blobs.len() > limits.max_files {
        record.status = "file_limit_exceeded".into();
        record.detail = Some(format!("{} blobs exceed the limit", blobs.len()));
        return record;
    }

    // Entry-point discovery from every manifest.json in the tree.
    let mut entry_paths: BTreeMap<String, ()> = BTreeMap::new();
    let mut manifests_seen = 0usize;
    for (oid, size, path) in &blobs {
        let is_manifest = path == "manifest.json" || path.ends_with("/manifest.json");
        if !is_manifest || *size as usize > MANIFEST_BLOB_CAP {
            continue;
        }
        manifests_seen += 1;
        if let Ok((content, _)) =
            git_bytes(&slug_dir, &["cat-file", "blob", oid], MANIFEST_BLOB_CAP)
        {
            let directory = path.rsplit_once('/').map_or("", |(dir, _)| dir);
            for entry in entry_points_from_manifest(&content, directory) {
                entry_paths.insert(entry, ());
            }
        }
    }
    if manifests_seen == 0 {
        record.status = "no_manifest".into();
        record.detail = Some("no manifest.json found in tree".into());
    }

    for (oid, size, path) in &blobs {
        if !is_qml_path(path) {
            continue;
        }
        if *size > MAX_FILE_BYTES {
            record.files.push(FileRecord {
                path: path.clone(),
                total_bytes: *size,
                covered_bytes: 0,
                non_whitespace_gap_bytes: 0,
                total_lines: 0,
                lines_with_gaps: 0,
                error_nodes: 0,
                missing_items: 0,
                clean_parse: false,
                entry_point: false,
            });
            record.qml_files += 1;
            continue;
        }
        let blob = match git_bytes(&slug_dir, &["cat-file", "blob", oid], *size as usize + 1) {
            Ok((content, false)) => Some(content),
            Ok((_, true)) => {
                record.detail = Some(format!("truncated read of {path}"));
                None
            }
            Err(error) => {
                record.detail = Some(format!("{path}: {error}"));
                None
            }
        };
        let Some(content) = blob else { continue };
        let metrics = measure_qml_coverage(&content);
        let entry_point = entry_paths.contains_key(path);
        if metrics.parses_cleanly() {
            record.clean_qml_files += 1;
            if entry_point {
                record.clean_entry_files += 1;
            }
        }
        record.qml_files += 1;
        if entry_point {
            record.entry_point_files += 1;
        }
        record.total_bytes += metrics.total_bytes;
        record.covered_bytes += metrics.covered_bytes;
        record.non_whitespace_gap_bytes += metrics.non_whitespace_gap_bytes;
        record.files.push(FileRecord {
            path: path.clone(),
            total_bytes: metrics.total_bytes,
            covered_bytes: metrics.covered_bytes,
            non_whitespace_gap_bytes: metrics.non_whitespace_gap_bytes,
            total_lines: metrics.total_lines,
            lines_with_gaps: metrics.lines_with_gaps,
            error_nodes: metrics.error_node_count,
            missing_items: metrics.missing_item_count,
            clean_parse: metrics.parses_cleanly(),
            entry_point,
        });
    }
    record
}

fn main() {
    let mut manifest_path = None;
    let mut output_path = None;
    let mut arguments = std::env::args().skip(1);
    while let Some(argument) = arguments.next() {
        match argument.as_str() {
            "--manifest" => manifest_path = arguments.next(),
            "--output" => output_path = arguments.next(),
            other => {
                eprintln!("unexpected argument: {other}");
                std::process::exit(2);
            }
        }
    }
    let (Some(manifest_path), Some(output_path)) = (manifest_path, output_path) else {
        eprintln!("usage: qml-coverage --manifest PATH --output PATH");
        std::process::exit(2);
    };

    let manifest_bytes = fs::read(&manifest_path).expect("manifest readable");
    let manifest: serde_json::Value =
        serde_json::from_slice(&manifest_bytes).expect("manifest is valid JSON");
    let plugins = manifest["plugins"].as_array().cloned().unwrap_or_default();

    let started = Instant::now();
    let cache_guard = tempfile::tempdir().expect("temporary cache");
    let limits = Limits::default();

    let mut records = Vec::new();
    for (index, plugin) in plugins.iter().enumerate() {
        let id = plugin["id"].as_str().unwrap_or("?").to_owned();
        println!("[{}/{}] {}", index + 1, plugins.len(), id);
        records.push(measure_plugin(plugin, cache_guard.path(), limits));
    }

    let mut totals = Totals {
        plugins_total: records.len(),
        plugins_ingested: 0,
        plugins_failed: 0,
        qml_files_total: 0,
        qml_files_clean: 0,
        entry_files_total: 0,
        entry_files_clean: 0,
        bytes_total: 0,
        bytes_covered: 0,
        non_whitespace_gap_bytes: 0,
    };
    for record in &records {
        if record.status == "ingested" || record.status == "no_manifest" {
            totals.plugins_ingested += 1;
        } else {
            totals.plugins_failed += 1;
        }
        totals.qml_files_total += record.qml_files;
        totals.qml_files_clean += record.clean_qml_files;
        totals.entry_files_total += record.entry_point_files;
        totals.entry_files_clean += record.clean_entry_files;
        totals.bytes_total += record.total_bytes;
        totals.bytes_covered += record.covered_bytes;
        totals.non_whitespace_gap_bytes += record.non_whitespace_gap_bytes;
    }

    let report = Report {
        report_version: 1,
        parser: qml_parser_identity(),
        manifest_source: manifest["source"].clone(),
        selection_rule: manifest["selectionRule"]
            .as_str()
            .unwrap_or_default()
            .to_owned(),
        elapsed_seconds: started.elapsed().as_secs_f64(),
        totals,
        plugins: records,
    };

    let rendered = serde_json::to_vec_pretty(&report).expect("report serializes");
    fs::write(&output_path, rendered).expect("report writable");

    let t = &report.totals;
    println!("\n=== coverage summary ===");
    println!(
        "plugins ingested: {} / {} (failed: {})",
        t.plugins_ingested, t.plugins_total, t.plugins_failed
    );
    println!(
        "entry-point files clean: {}/{} ({:.2}%)",
        t.entry_files_clean,
        t.entry_files_total,
        percentage(t.entry_files_clean, t.entry_files_total)
    );
    println!(
        "all QML files clean:      {}/{} ({:.2}%)",
        t.qml_files_clean,
        t.qml_files_total,
        percentage(t.qml_files_clean, t.qml_files_total)
    );
    println!(
        "non-whitespace gap bytes: {} / {} ({:.3}%)",
        t.non_whitespace_gap_bytes,
        t.bytes_total,
        percentage(t.non_whitespace_gap_bytes as usize, t.bytes_total as usize)
    );
}

fn percentage(part: usize, whole: usize) -> f64 {
    if whole == 0 {
        0.0
    } else {
        part as f64 * 100.0 / whole as f64
    }
}
