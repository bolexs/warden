use std::io::{self, Read};
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Instant;

use clap::{Parser, Subcommand};

use warden::{Decision, approvals, claude, evidence, log, shadow};

pub const SHADOW_VAR: &str = "WARDEN_SHADOW";

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
            A tool warden does not judge: silent, exits 0, and the tool runs.\n\
            WARDEN_SHADOW=1: the decision is logged but the answer is always allow."
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
    #[command(about = "Compare shadow-mode decisions with the kit hub's write-guard denials")]
    ShadowReport {
        #[arg(long)]
        hub: Option<PathBuf>,
        #[arg(long, default_value_t = 7)]
        since_days: u64,
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
        Cmd::ShadowReport { hub, since_days } => shadow_report(hub, since_days),
    }
}

fn shadow_report(hub: Option<PathBuf>, since_days: u64) -> ExitCode {
    let hub = hub
        .or_else(|| std::env::var_os("CLAUDE_CHANGELOG_HUB").map(PathBuf::from))
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".claude/changelog")))
        .unwrap_or_else(|| PathBuf::from("."));
    let since = log::now().saturating_sub(since_days.saturating_mul(86_400));
    let entries = log::read(&approvals::state_dir());
    let denials = shadow::hub_denials(&hub, "write-guard", since);
    print!(
        "{}",
        shadow::render(&shadow::compare(&entries, &denials, since), since_days)
    );
    ExitCode::SUCCESS
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
    let started = Instant::now();
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
    let shadow = std::env::var_os(SHADOW_VAR).is_some_and(|v| v == "1");
    let answer = if shadow {
        Decision::Allow
    } else {
        decision.clone()
    };
    let code = match claude::response(&answer) {
        Some(json) => {
            println!("{json}");
            ExitCode::from(2)
        }
        None => ExitCode::SUCCESS,
    };
    let entry = log::Entry {
        at: log::now(),
        session: request.session.clone(),
        actor: request.actor.name.clone(),
        cwd: request.cwd.clone(),
        mode: request.mode,
        action: request.action.clone(),
        decision,
        shadow,
        elapsed_ms: started.elapsed().as_millis() as u64,
    };
    if let Err(e) = log::record(&approvals::state_dir(), &entry) {
        eprintln!("warden: could not write the decision log: {e}");
    }
    code
}
