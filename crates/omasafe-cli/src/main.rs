use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use omasafe_core::{TOOL_VERSION, paths::XdgPaths};
use omasafe_marketplace::{Correlation, correlate, load_catalog};
use omasafe_plugin_trust::{
    DiffResult, SourceIdentity,
    baseline::{ReviewDecision, ScanState, TrustHistory, TrustRecord},
    collect, git_diff, query_shell,
};
use omasafe_report::Report;

fn main() {
    if let Err(error) = run(std::env::args().skip(1).collect()) {
        eprintln!("omasafe: {error}");
        std::process::exit(1);
    }
}

fn run(args: Vec<String>) -> Result<(), Box<dyn std::error::Error>> {
    match args.as_slice() {
        [] => {
            println!("omasafe-cli {TOOL_VERSION}");
        }
        [flag] if flag == "--version" || flag == "-V" => {
            println!("omasafe-cli {TOOL_VERSION}");
        }
        [command] if command == "paths" => print_paths()?,
        [command, subcommand, rest @ ..] if command == "plugins" && subcommand == "inventory" => {
            inventory(rest)?
        }
        [command, subcommand, id, rest @ ..] if command == "plugins" && subcommand == "trust" => {
            trust(id, rest)?
        }
        [command, subcommand, id, rest @ ..] if command == "plugins" && subcommand == "status" => {
            status(id, rest)?
        }
        [command, subcommand, id, rest @ ..] if command == "plugins" && subcommand == "diff" => {
            diff(id, rest)?
        }
        [command, subcommand, id, rest @ ..] if command == "plugins" && subcommand == "review" => {
            review(id, rest)?
        }
        [command] if command == "scan" => scan(&[])?,
        [command, rest @ ..] if command == "scan" => scan(rest)?,
        [command, subcommand, rest @ ..] if command == "schedule" && subcommand == "install" => {
            schedule_install(rest)?
        }
        _ => {
            eprintln!(
                "usage: omasafe-cli plugins ... | scan [--format text|json] [--notify] | schedule install | paths"
            );
            std::process::exit(2);
        }
    }
    Ok(())
}

fn trust(id: &str, args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let mut yes = false;
    let mut expected_head = None;
    let mut expected_tree = None;
    let mut expected_digest = None;
    let mut note = "accepted by user".to_owned();
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--yes" => {
                yes = true;
                index += 1;
            }
            "--expected-head" => {
                expected_head = Some(args.get(index + 1).ok_or("missing expected HEAD")?.clone());
                index += 2;
            }
            "--expected-tree" => {
                expected_tree = Some(args.get(index + 1).ok_or("missing expected tree")?.clone());
                index += 2;
            }
            "--expected-digest" => {
                expected_digest = Some(
                    args.get(index + 1)
                        .ok_or("missing expected digest")?
                        .clone(),
                );
                index += 2;
            }
            "--note" => {
                note = args.get(index + 1).ok_or("missing note")?.clone();
                index += 2;
            }
            value => return Err(format!("unknown trust argument: {value}").into()),
        }
    }
    let plugin_root = home()?.join(".config/omarchy/plugins");
    let (shell_json, _shell_error) = query_shell();
    let inventory = collect(&plugin_root, shell_json.as_deref());
    let record = inventory
        .plugins
        .iter()
        .find(|plugin| plugin.id == id)
        .ok_or_else(|| format!("plugin not found: {id}"))?;
    let identity = SourceIdentity {
        plugin_id: record.id.clone(),
        repository: record.repository.clone(),
        head: record.head.clone(),
        tree: record.tree.clone(),
        content_digest: record.content_digest.clone(),
        file_count: record.content_file_count.unwrap_or_default(),
        limitations: record.reason.clone().into_iter().collect(),
    };
    println!(
        "Plugin: {}\nPath: {}\nIdentity: {}",
        record.id,
        record.path,
        serde_json::to_string_pretty(&identity)?
    );
    if yes {
        if expected_head.is_none() && expected_tree.is_none() && expected_digest.is_none() {
            return Err("unattended trust requires an expected identity and --yes".into());
        }
        if !expected_component(identity.head.as_deref(), expected_head.as_deref())
            || !expected_component(identity.tree.as_deref(), expected_tree.as_deref())
            || !expected_component(
                identity.content_digest.as_deref(),
                expected_digest.as_deref(),
            )
        {
            return Err("current identity does not exactly match the expected identity".into());
        }
    } else {
        eprint!("Type 'trust' to accept this exact identity: ");
        let mut answer = String::new();
        std::io::stdin().read_line(&mut answer)?;
        if answer.trim() != "trust" {
            return Err("trust not accepted".into());
        }
    }
    let paths = XdgPaths::discover()?;
    paths.ensure()?;
    let history_path = paths.state.join("trust-history.json");
    let mut history = TrustHistory::load(&history_path)?;
    history.accept(TrustRecord {
        plugin_id: id.into(),
        accepted: identity,
        accepted_at: now(),
        note,
    });
    history.write_atomic(&history_path)?;
    println!("Trusted identity recorded in {}", history_path.display());
    Ok(())
}

fn expected_component(current: Option<&str>, expected: Option<&str>) -> bool {
    match (current, expected) {
        (Some(current), Some(expected)) => current == expected,
        (None, None) => true,
        _ => false,
    }
}

#[derive(serde::Serialize)]
struct ScanAlert {
    plugin_id: String,
    kind: String,
    message: String,
    post_change: bool,
}

#[derive(serde::Serialize)]
struct ScanResult {
    alerts: Vec<ScanAlert>,
    quiet: bool,
    post_change_detection: bool,
}

fn scan(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let mut format = "text";
    let mut notify = false;
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--notify" => {
                notify = true;
                index += 1;
            }
            "--format" => {
                format = args
                    .get(index + 1)
                    .map(String::as_str)
                    .ok_or("missing format")?;
                index += 2;
            }
            value => return Err(format!("unknown scan argument: {value}").into()),
        }
    }
    if !matches!(format, "text" | "json") {
        return Err(format!("unsupported format: {format}").into());
    }
    let paths = XdgPaths::discover()?;
    paths.ensure()?;
    let plugin_root = home()?.join(".config/omarchy/plugins");
    let (shell_json, shell_error) = query_shell();
    let mut inventory = collect(&plugin_root, shell_json.as_deref());
    if let Some(error) = shell_error {
        inventory.coverage.limitations.push(error);
    }
    let history = TrustHistory::load(&paths.state.join("trust-history.json"))?;
    let mut state = ScanState::load(&paths.state.join("scan-state.json"))?;
    let mut alerts = Vec::new();
    for plugin in &inventory.plugins {
        let Some(trusted) = history.latest(&plugin.id).map(|record| &record.accepted) else {
            continue;
        };
        let current = SourceIdentity {
            plugin_id: plugin.id.clone(),
            repository: plugin.repository.clone(),
            head: plugin.head.clone(),
            tree: plugin.tree.clone(),
            content_digest: plugin.content_digest.clone(),
            file_count: plugin.content_file_count.unwrap_or_default(),
            limitations: plugin.reason.clone().into_iter().collect(),
        };
        if current != *trusted {
            let key = format!("drift:{}:{}", plugin.id, serde_json::to_string(&current)?);
            let alert = ScanAlert {
                plugin_id: plugin.id.clone(),
                kind: "source-drift".into(),
                message: "installed source differs from the trusted baseline; review is required"
                    .into(),
                post_change: true,
            };
            if state.is_new(&key) {
                if notify {
                    notify_user(&alert);
                }
                state.record(key, now());
                alerts.push(alert);
            }
        }
        if plugin.classification == "unscannable" {
            let key = format!(
                "coverage:{}:{}",
                plugin.id,
                plugin.reason.as_deref().unwrap_or("unknown")
            );
            let alert = ScanAlert {
                plugin_id: plugin.id.clone(),
                kind: "lost-coverage".into(),
                message: "plugin can no longer be scanned".into(),
                post_change: false,
            };
            if state.is_new(&key) {
                if notify {
                    notify_user(&alert);
                }
                state.record(key, now());
                alerts.push(alert);
            }
        }
    }
    for trusted in history
        .records
        .iter()
        .filter(|record| record.plugin_id != "")
    {
        if !inventory
            .plugins
            .iter()
            .any(|plugin| plugin.id == trusted.plugin_id)
        {
            let key = format!("missing:{}", trusted.plugin_id);
            let alert = ScanAlert {
                plugin_id: trusted.plugin_id.clone(),
                kind: "missing-plugin".into(),
                message: "trusted plugin is missing or unavailable".into(),
                post_change: true,
            };
            if state.is_new(&key) {
                if notify {
                    notify_user(&alert);
                }
                state.record(key, now());
                alerts.push(alert);
            }
        }
    }
    if inventory
        .coverage
        .limitations
        .iter()
        .any(|limitation| !limitation.starts_with("shell reports plugin "))
    {
        let key = format!(
            "coverage:inventory:{}",
            inventory.coverage.limitations.len()
        );
        if state.is_new(&key) {
            let alert = ScanAlert {
                plugin_id: "inventory".into(),
                kind: "lost-coverage".into(),
                message: "inventory coverage is limited; review the scan report".into(),
                post_change: false,
            };
            if notify {
                notify_user(&alert);
            }
            state.record(key, now());
            alerts.push(alert);
        }
    }
    state.write_atomic(&paths.state.join("scan-state.json"))?;
    let result = ScanResult {
        quiet: alerts.is_empty(),
        post_change_detection: true,
        alerts,
    };
    if format == "json" {
        println!(
            "{}",
            serde_json::to_string_pretty(&Report::new(TOOL_VERSION, now(), result))?
        );
    } else if result.quiet {
        println!("No new actionable changes detected.");
    } else {
        for alert in result.alerts {
            println!("{}: {}", alert.kind, alert.message);
        }
    }
    Ok(())
}

fn notify_user(alert: &ScanAlert) {
    let body = format!("{}: {}", alert.plugin_id, alert.message);
    let result = std::process::Command::new("notify-send")
        .args(["--urgency=critical", "OmaSafe", &body])
        .status();
    if result.is_err() {
        eprintln!("OmaSafe notification unavailable: {body}");
    }
}

fn schedule_install(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    if !args.is_empty() {
        return Err("schedule install takes no arguments".into());
    }
    let home = home()?;
    let config_home = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| home.join(".config"));
    let unit_dir = config_home.join("systemd/user");
    std::fs::create_dir_all(&unit_dir)?;
    let executable = std::env::current_exe()?;
    std::fs::write(
        unit_dir.join("omasafe-scan.service"),
        format!(
            "[Unit]\nDescription=OmaSafe plugin drift scan\n\n[Service]\nType=oneshot\nExecStart={} scan --notify\n",
            executable.display()
        ),
    )?;
    std::fs::write(
        unit_dir.join("omasafe-scan.timer"),
        "[Unit]\nDescription=Daily OmaSafe plugin drift scan\n\n[Timer]\nOnCalendar=daily\nPersistent=true\nUnit=omasafe-scan.service\n\n[Install]\nWantedBy=timers.target\n",
    )?;
    for args in [
        vec!["--user", "daemon-reload"],
        vec!["--user", "enable", "--now", "omasafe-scan.timer"],
    ] {
        let status = std::process::Command::new("systemctl")
            .args(args)
            .status()?;
        if !status.success() {
            return Err("systemd user timer installation failed".into());
        }
    }
    println!("Installed and enabled daily OmaSafe scan timer.");
    Ok(())
}

#[derive(serde::Serialize)]
struct StatusResult {
    plugin_id: String,
    state: String,
    current: SourceIdentity,
    trusted: Option<SourceIdentity>,
    reason: Option<String>,
}

fn review(id: &str, args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let mut action = None;
    let mut reason = None;
    let mut scope = None;
    let mut yes = false;
    let mut expected_head = None;
    let mut expected_tree = None;
    let mut expected_digest = None;
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--action" => {
                action = Some(args.get(index + 1).ok_or("missing review action")?.clone());
                index += 2;
            }
            "--reason" => {
                reason = Some(args.get(index + 1).ok_or("missing review reason")?.clone());
                index += 2;
            }
            "--scope" => {
                scope = Some(args.get(index + 1).ok_or("missing review scope")?.clone());
                index += 2;
            }
            "--yes" => {
                yes = true;
                index += 1;
            }
            "--expected-head" => {
                expected_head = Some(args.get(index + 1).ok_or("missing expected HEAD")?.clone());
                index += 2;
            }
            "--expected-tree" => {
                expected_tree = Some(args.get(index + 1).ok_or("missing expected tree")?.clone());
                index += 2;
            }
            "--expected-digest" => {
                expected_digest = Some(
                    args.get(index + 1)
                        .ok_or("missing expected digest")?
                        .clone(),
                );
                index += 2;
            }
            value => return Err(format!("unknown review argument: {value}").into()),
        }
    }
    if !yes {
        return Err("review actions require --yes after explicit preview".into());
    }
    let action = action.ok_or("--action is required")?;
    let reason = reason.ok_or("--reason is required")?;
    let scope = scope.unwrap_or_else(|| "plugin".into());
    if action == "exclude" && scope == "plugin" {
        return Err("exclude requires a narrow --scope".into());
    }
    let paths = XdgPaths::discover()?;
    paths.ensure()?;
    let path = paths.state.join("trust-history.json");
    let mut history = TrustHistory::load(&path)?;
    if action == "rebaseline" || action == "restore" {
        let accepted = if action == "restore" {
            history
                .records
                .iter()
                .rev()
                .filter(|record| record.plugin_id == id)
                .nth(1)
                .ok_or("no previous baseline exists to restore")?
                .accepted
                .clone()
        } else {
            let (_, current) = current_identity(id)?;
            if !expected_component(current.head.as_deref(), expected_head.as_deref())
                || !expected_component(current.tree.as_deref(), expected_tree.as_deref())
                || !expected_component(
                    current.content_digest.as_deref(),
                    expected_digest.as_deref(),
                )
            {
                return Err("current identity does not exactly match the expected identity".into());
            }
            current
        };
        history.accept(TrustRecord {
            plugin_id: id.into(),
            accepted,
            accepted_at: now(),
            note: reason,
        });
    } else if matches!(action.as_str(), "acknowledge" | "exclude") {
        history.decisions.push(ReviewDecision {
            plugin_id: id.into(),
            action,
            scope,
            reason,
            created_at: now(),
        });
    } else {
        return Err("action must be acknowledge, rebaseline, restore, or exclude".into());
    }
    history.write_atomic(&path)?;
    println!("Review decision recorded in {}", path.display());
    Ok(())
}

fn status(id: &str, args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let format = format_arg(args)?;
    let (_record, current) = current_identity(id)?;
    let history = TrustHistory::load(&XdgPaths::discover()?.state.join("trust-history.json"))?;
    let trusted = history.latest(id).map(|record| record.accepted.clone());
    let state = match trusted.as_ref() {
        None => "untrusted",
        Some(identity) if identity == &current => "unchanged",
        Some(_) => "changed",
    };
    let result = StatusResult {
        plugin_id: id.into(),
        state: state.into(),
        current,
        trusted,
        reason: (state == "untrusted").then(|| "no trust baseline exists".into()),
    };
    if format == "json" {
        println!(
            "{}",
            serde_json::to_string_pretty(&Report::new(TOOL_VERSION, now(), result))?
        );
    } else {
        println!("{}: {}", result.plugin_id, result.state);
        if let Some(reason) = result.reason {
            println!("Reason: {reason}");
        }
    }
    Ok(())
}

#[derive(serde::Serialize)]
struct DiffReport {
    plugin_id: String,
    from: Option<String>,
    to: Option<String>,
    source_changed: bool,
    diff: DiffResult,
    limitation: Option<String>,
}

fn diff(id: &str, args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let (record, current) = current_identity(id)?;
    let history = TrustHistory::load(&XdgPaths::discover()?.state.join("trust-history.json"))?;
    let trusted = history.latest(id).map(|record| record.accepted.clone());
    let Some(trusted) = trusted else {
        return Err(format!("no trust baseline exists for {id}").into());
    };
    let range_arg = args
        .iter()
        .find(|arg| !arg.starts_with("--") && arg.as_str() != "json");
    let (ref_a, ref_b) = if let Some(range) = range_arg {
        range
            .split_once("..")
            .ok_or("diff range must be REF_A..REF_B")?
    } else {
        (
            trusted
                .head
                .as_deref()
                .ok_or("trusted baseline has no Git HEAD")?,
            if record.dirty == Some(true) {
                "WORKTREE"
            } else {
                current
                    .head
                    .as_deref()
                    .ok_or("installed plugin has no Git HEAD")?
            },
        )
    };
    let git = git_diff(PathBuf::from(&record.path).as_path(), ref_a, ref_b);
    let report = DiffReport {
        plugin_id: id.into(),
        from: Some(ref_a.into()),
        to: Some(ref_b.into()),
        source_changed: current != trusted,
        limitation: git.limitation.clone(),
        diff: git,
    };
    if args.iter().any(|arg| arg == "--format=json") {
        println!(
            "{}",
            serde_json::to_string_pretty(&Report::new(TOOL_VERSION, now(), report))?
        );
    } else {
        println!(
            "{}: source_changed={}",
            report.plugin_id, report.source_changed
        );
        if let Some(text) = report.diff.text {
            print!("{text}");
        }
        if let Some(limitation) = report.limitation {
            println!("\nLimitation: {limitation}");
        }
    }
    Ok(())
}

fn format_arg(args: &[String]) -> Result<&str, Box<dyn std::error::Error>> {
    match args {
        [] => Ok("text"),
        [flag, format] if flag == "--format" && matches!(format.as_str(), "text" | "json") => {
            Ok(format)
        }
        _ => Err("expected optional --format text|json".into()),
    }
}

fn current_identity(
    id: &str,
) -> Result<(omasafe_plugin_trust::PluginRecord, SourceIdentity), Box<dyn std::error::Error>> {
    let plugin_root = home()?.join(".config/omarchy/plugins");
    let (shell_json, _shell_error) = query_shell();
    let inventory = collect(&plugin_root, shell_json.as_deref());
    let record = inventory
        .plugins
        .into_iter()
        .find(|plugin| plugin.id == id)
        .ok_or_else(|| format!("plugin not found: {id}"))?;
    let identity = SourceIdentity {
        plugin_id: record.id.clone(),
        repository: record.repository.clone(),
        head: record.head.clone(),
        tree: record.tree.clone(),
        content_digest: record.content_digest.clone(),
        file_count: record.content_file_count.unwrap_or_default(),
        limitations: record.reason.clone().into_iter().collect(),
    };
    Ok((record, identity))
}

fn inventory(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let mut format = "text";
    let mut catalog_path = None;
    let mut catalog_commit = None;
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--format" => {
                format = args
                    .get(index + 1)
                    .map(String::as_str)
                    .ok_or("missing format")?;
                index += 2;
            }
            "--catalog" => {
                catalog_path = Some(PathBuf::from(
                    args.get(index + 1).ok_or("missing catalog path")?,
                ));
                index += 2;
            }
            "--catalog-commit" => {
                catalog_commit = Some(args.get(index + 1).ok_or("missing catalog commit")?.clone());
                index += 2;
            }
            value => return Err(format!("unknown inventory argument: {value}").into()),
        }
    }
    if !matches!(format, "text" | "json") {
        return Err(format!("unsupported format: {format}").into());
    }
    if catalog_path.is_some() && catalog_commit.is_none() {
        return Err("--catalog requires --catalog-commit".into());
    }

    let plugin_root = home()?.join(".config/omarchy/plugins");
    let (shell_json, shell_error) = query_shell();
    let mut result = collect(&plugin_root, shell_json.as_deref());
    if let Some(error) = shell_error {
        result.coverage.limitations.push(error);
    }
    let correlations = match (catalog_path, catalog_commit) {
        (Some(path), Some(commit)) => {
            let snapshot = load_catalog(
                &path,
                "https://github.com/HANCORE-linux/omarchy-plugin-marketplace".into(),
                commit,
                now(),
            )?;
            Some(
                result
                    .plugins
                    .iter()
                    .map(|plugin| {
                        correlate(
                            &plugin.id,
                            plugin.repository.as_deref(),
                            plugin.head.as_deref(),
                            &snapshot,
                        )
                    })
                    .collect::<Vec<Correlation>>(),
            )
        }
        _ => None,
    };

    if format == "json" {
        let output = if let Some(correlations) = correlations {
            let mut value = serde_json::to_value(&result)?;
            value
                .as_object_mut()
                .unwrap()
                .insert("marketplace".into(), serde_json::to_value(correlations)?);
            value
        } else {
            serde_json::to_value(&result)?
        };
        let report = Report::new(TOOL_VERSION, now(), output);
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!("{} plugin record(s) collected.", result.plugins.len());
        for limitation in result.coverage.limitations {
            println!("Coverage limitation: {limitation}");
        }
        if let Some(correlations) = correlations {
            for correlation in correlations {
                println!(
                    "Marketplace {}: {}",
                    correlation.plugin_id, correlation.status
                );
            }
        }
    }
    Ok(())
}

fn print_paths() -> Result<(), Box<dyn std::error::Error>> {
    let paths = XdgPaths::discover()?;
    println!(
        "config={}\nstate={}\ncache={}",
        paths.config.display(),
        paths.state.display(),
        paths.cache.display()
    );
    Ok(())
}

fn home() -> Result<PathBuf, Box<dyn std::error::Error>> {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .ok_or_else(|| "HOME is not set".into())
}

fn now() -> String {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs().to_string())
        .unwrap_or_else(|_| "0".into())
}
