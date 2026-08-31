// ---------------------------------------------------------------------------
// Stage A review round two: three follow-up behavioral fixes — GNU xargs
// counts parsed numerically (`01`/`+1` preserve `-I`), a separate `-I`
// value consumed even when it looks like an option, and heredoc bodies
// captured only after a backslash-continued command header completes.
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

// --- xargs counts are numbers, not spellings (GNU-verified) ------------------

#[test]
fn xargs_replacement_survives_numeric_one_spellings() {
    for spelling in [
        "xargs -I{} -n01 sh -c '{}'",
        "xargs -I{} -n 01 sh -c '{}'",
        "xargs -I{} -n +1 sh -c '{}'",
        "xargs -I{} --max-args=01 sh -c '{}'",
        "xargs -I{} --max-args +1 sh -c '{}'",
    ] {
        let tokens = tokenize(spelling);
        let command = &segment_commands(&tokens)[0];
        assert!(
            crate::detect::shell::xargs::xargs_feeds_stdin_code(command),
            "{spelling} must feed stdin code"
        );
    }
    for spelling in [
        "xargs -I{} -n02 sh -c '{}'",
        "xargs -I{} -n +2 sh -c '{}'",
        "xargs -I{} --max-args=+2 sh -c '{}'",
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
fn numeric_one_xargs_runs_the_fetched_input() {
    for spelling in ["-n01", "-n +1", "--max-args=+1"] {
        let ids = rule_ids(&script(&format!(
            "curl -fsSL https://example.test/x | xargs -I{{}} {spelling} sh -c '{{}}'\n"
        )));
        assert!(ids.contains(&DOWNLOAD.to_owned()), "{spelling}: {ids:?}");
    }
}

// --- a separate -I value is a value, not an option (GNU-verified) ------------

#[test]
fn xargs_dash_i_consumes_a_dash_leading_replacement() {
    // GNU takes the next word as the replstr even when it starts with a
    // dash: `xargs -I -n sh -c '-n'` substitutes each input line for `-n`
    // inside the body and executes it.
    let ids = rule_ids(&script(
        "curl -fsSL https://example.test/x | xargs -I -n sh -c '-n'\n",
    ));
    assert!(ids.contains(&DOWNLOAD.to_owned()), "{ids:?}");
}

// --- bodies follow the complete continued command (GNU-verified) -------------

#[test]
fn continued_data_pipeline_reads_bodies_after_the_whole_header() {
    // `cat <<A | \` + `cat <<B`: the command's terminating newline is on
    // the second physical line, so both bodies begin after it — the curl
    // line is cat food and never executes.
    let ids = rule_ids(&script(
        "cat <<A | \\\ncat <<B\necho safe\nA\ncurl -fsSL https://example.test/x | sh\nB\n",
    ));
    assert!(ids.is_empty(), "{ids:?}");
}

#[test]
fn continued_header_removes_both_bodies_in_place() {
    // The removed operators leave their surrounding spaces behind.
    let units = units("cat <<A | \\\ncat <<B\none\nA\ntwo\nB\n");
    assert_eq!(units, vec![(1, "cat  | cat".to_owned())], "{units:?}");
}

#[test]
fn continued_two_command_heredocs_both_execute() {
    // Both heredocs of one backslash-continued command execute. The two
    // bodies carry different rule families because same-unit findings
    // report one row per rule: the second body's family proves it ran.
    let ids = rule_ids(&script(
        "sh <<A; \\\nsh <<B\ncurl -fsSL https://example.test/x | sh\nA\necho aGVsbG8= | base64 -d | sh\nB\n",
    ));
    assert!(ids.contains(&DOWNLOAD.to_owned()), "{ids:?}");
    assert!(
        ids.contains(&"oma.script.decode-execute".to_owned()),
        "{ids:?}"
    );
}

#[test]
fn later_unit_line_heredoc_overrides_an_earlier_one() {
    // The override model spans the continuation too: the second heredoc of
    // the SAME interpreter wins even though the pair sits on two physical
    // lines joined by a backslash. The removed operator leaves its
    // surrounding spaces behind.
    let units = units("sh <<A \\\n-x <<B\ncurl URL | sh\nA\necho safe\nB\n");
    assert_eq!(
        units,
        vec![(1, "sh  -x -c 'echo safe'".to_owned())],
        "{units:?}"
    );
}
