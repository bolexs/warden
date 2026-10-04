use std::io::{self, Read};
use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};

use warden::{approvals, claude, evidence};

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
            Unreadable input: warns on stderr, exits 0, and the tool runs.\n\
            A tool warden does not judge: silent, exits 0, and the tool runs."
    )]
    Check,
    #[command(
        about = "Record the user's approval of writes to the given paths for one session",
        long_about = "Records that the user approved rewriting each path, in their own words, \
            for the given session. A later check in that session allows the same path for 12 hours. \
            Relative paths resolve against the current directory."
    )]
    Approve {
        #[arg(long)]
        session: String,
        words: String,
        #[arg(required = true)]
        paths: Vec<PathBuf>,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match cli.command {
        Cmd::Check => check(),
        Cmd::Approve {
            session,
            words,
            paths,
        } => approve(&session, &words, &paths),
    }
}

fn approve(session: &str, words: &str, paths: &[PathBuf]) -> ExitCode {
    let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    for path in paths {
        let abs = evidence::canon(path, &cwd);
        if let Err(e) = approvals::record(session, &abs, words) {
            eprintln!("warden: could not record the approval: {e}");
            return ExitCode::FAILURE;
        }
        println!("approved: {}", abs.display());
    }
    ExitCode::SUCCESS
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
