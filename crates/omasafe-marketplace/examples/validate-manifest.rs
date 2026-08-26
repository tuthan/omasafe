//! Dev harness: validate one plugin folder with OmaSafe's mirror of the
//! Omarchy manifest schema. Exit code mirrors `omarchy plugin validate`
//! (0 valid, 1 invalid) so the parity canary can compare verdicts directly.
//!
//! Usage: cargo run -p omasafe-marketplace --example validate-manifest <dir>

use std::process::ExitCode;

fn main() -> ExitCode {
    let Some(folder) = std::env::args().nth(1) else {
        eprintln!("usage: validate-manifest <plugin-folder>");
        return ExitCode::from(2);
    };
    let issues =
        omasafe_marketplace::manifest::validate_plugin_folder(std::path::Path::new(&folder));
    if issues.is_empty() {
        println!("VALID");
        ExitCode::SUCCESS
    } else {
        for issue in issues {
            eprintln!("omasafe-validate-manifest: {issue}");
        }
        ExitCode::FAILURE
    }
}
