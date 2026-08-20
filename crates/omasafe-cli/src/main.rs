use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use omasafe_core::{TOOL_VERSION, paths::XdgPaths};
use omasafe_marketplace::{Correlation, correlate, load_catalog};
use omasafe_plugin_trust::{collect, query_shell};
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
        _ => {
            eprintln!(
                "usage: omasafe-cli plugins inventory [--format text|json] [--catalog PATH --catalog-commit COMMIT] | paths"
            );
            std::process::exit(2);
        }
    }
    Ok(())
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
