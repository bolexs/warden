use std::io::{self, Read};
use std::process::ExitCode;

use clap::{Parser, Subcommand};

use warden::claude;

#[derive(Parser)]
#[command(
    name = "warden",
    version,
    about = "Allow or deny shell commands and file writes, with a reason"
)]
struct Cli {
    #[command(subcommand)]
    command: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    #[command(
        about = "Judge one Claude Code pre-tool hook request read from stdin",
        long_about = "Reads one PreToolUse hook request as JSON on stdin.\n\
            Allow: prints nothing and exits 0.\n\
            Deny: prints the hook decision JSON on stdout and exits 2.\n\
            Unreadable or unjudged input: warns on stderr, exits 0, and the tool runs."
    )]
    Check,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match cli.command {
        Cmd::Check => check(),
    }
}

fn check() -> ExitCode {
    let mut raw = String::new();
    if io::stdin().read_to_string(&mut raw).is_err() {
        eprintln!("warden: could not read stdin");
        return ExitCode::SUCCESS;
    }
    let input: claude::HookInput = match serde_json::from_str(&raw) {
        Ok(input) => input,
        Err(e) => {
            eprintln!("warden: unreadable hook input: {e}");
            return ExitCode::SUCCESS;
        }
    };
    let Some(request) = claude::request_from(input) else {
        return ExitCode::SUCCESS;
    };
    let decision = warden::decide(&request);
    match claude::response(&decision) {
        Some(json) => {
            println!("{json}");
            ExitCode::from(2)
        }
        None => ExitCode::SUCCESS,
    }
}
