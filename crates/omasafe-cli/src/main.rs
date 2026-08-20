use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use omasafe_core::{TOOL_VERSION, paths::XdgPaths};
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
        [command, subcommand] if command == "plugins" && subcommand == "inventory" => {
            inventory("text")?
        }
        [command, subcommand, format_flag, format]
            if command == "plugins" && subcommand == "inventory" && format_flag == "--format" =>
        {
            inventory(format)?
        }
        _ => {
            eprintln!("usage: omasafe-cli plugins inventory [--format text|json] | paths");
            std::process::exit(2);
        }
    }
    Ok(())
}

fn inventory(format: &str) -> Result<(), Box<dyn std::error::Error>> {
    if !matches!(format, "text" | "json") {
        return Err(format!("unsupported format: {format}").into());
    }

    let plugin_root = home()?.join(".config/omarchy/plugins");
    let (shell_json, shell_error) = query_shell();
    let mut result = collect(&plugin_root, shell_json.as_deref());
    if let Some(error) = shell_error {
        result.coverage.limitations.push(error);
    }

    if format == "json" {
        let report = Report::new(TOOL_VERSION, now(), result);
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!("No plugin inventory collected.");
        for limitation in result.coverage.limitations {
            println!("Coverage limitation: {limitation}");
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
