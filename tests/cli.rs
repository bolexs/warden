use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};

static CALLS: AtomicU64 = AtomicU64::new(0);

fn fresh_state_dir() -> PathBuf {
    std::env::temp_dir().join(format!(
        "warden-cli-state-{}-{}",
        std::process::id(),
        CALLS.fetch_add(1, Ordering::SeqCst)
    ))
}

fn check(stdin: &str) -> (i32, String, String) {
    check_with_env(stdin, &[])
}

fn check_with_env(stdin: &str, env: &[(&str, &str)]) -> (i32, String, String) {
    let state = fresh_state_dir();
    let result = run_check(stdin, &state, env);
    let _ = std::fs::remove_dir_all(&state);
    result
}

fn run_check(stdin: &str, state: &PathBuf, env: &[(&str, &str)]) -> (i32, String, String) {
    let mut child = Command::new(env!("CARGO_BIN_EXE_warden"))
        .arg("check")
        .env("WARDEN_STATE_DIR", state)
        .envs(env.iter().copied())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn warden");
    child
        .stdin
        .take()
        .expect("stdin handle")
        .write_all(stdin.as_bytes())
        .expect("write stdin");
    let out = child.wait_with_output().expect("wait for warden");
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

#[test]
fn check_help_states_the_exit_code_contract() {
    let out = Command::new(env!("CARGO_BIN_EXE_warden"))
        .args(["check", "--help"])
        .output()
        .expect("run warden check --help");
    let help = String::from_utf8_lossy(&out.stdout);
    for line in [
        "Allow: prints nothing and exits 0.",
        "Deny: prints the hook decision JSON on stdout and exits 2.",
        "Unreadable input: warns on stderr, exits 0, and the tool runs.",
        "A tool warden does not judge: silent, exits 0, and the tool runs.",
        "WARDEN_SHADOW=1: the decision is logged but the answer is always allow.",
    ] {
        assert!(help.contains(line), "help is missing: {line}");
    }
}

#[test]
fn an_allowed_command_is_silent_and_exits_zero() {
    let (code, stdout, stderr) = check(
        r#"{"session_id":"s","cwd":"/tmp","tool_name":"Bash","tool_input":{"command":"ls"}}"#,
    );
    assert_eq!(code, 0);
    assert_eq!(stdout, "");
    assert_eq!(stderr, "");
}

#[test]
fn a_shell_rewrite_of_a_tracked_file_is_denied_with_json_and_exit_two() {
    let dir = std::env::temp_dir().join(format!("warden-cli-deny-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    for args in [
        vec!["init", "-q", "-b", "main"],
        vec!["config", "user.email", "t@t"],
        vec!["config", "user.name", "t"],
    ] {
        assert!(
            Command::new("git")
                .arg("-C")
                .arg(&dir)
                .args(&args)
                .status()
                .unwrap()
                .success()
        );
    }
    std::fs::write(dir.join("tracked.txt"), "x\n").unwrap();
    for args in [vec!["add", "-A"], vec!["commit", "-q", "-m", "i"]] {
        assert!(
            Command::new("git")
                .arg("-C")
                .arg(&dir)
                .args(&args)
                .status()
                .unwrap()
                .success()
        );
    }
    let input = format!(
        r#"{{"session_id":"s","cwd":"{}","tool_name":"Bash","tool_input":{{"command":"echo y > tracked.txt"}}}}"#,
        dir.display()
    );
    let (code, stdout, stderr) = check(&input);
    assert_eq!(code, 2);
    assert_eq!(stderr, "");
    assert!(stdout.starts_with(r#"{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":""#));
    assert!(stdout.contains("tracked.txt is tracked by git"));

    let (code, stdout, _) = check_with_env(&input, &[("WARDEN_ALLOW_SHELL_WRITES", "1")]);
    assert_eq!(code, 0, "the override lets the same command through");
    assert_eq!(stdout, "");

    let state = dir.join("state");
    let state_env = [("WARDEN_STATE_DIR", state.to_str().unwrap())];
    let (code, _, _) = check_with_env(&input, &state_env);
    assert_eq!(code, 2, "no approval yet");
    let out = Command::new(env!("CARGO_BIN_EXE_warden"))
        .current_dir(&dir)
        .envs(state_env.iter().copied())
        .args([
            "approve",
            "--session",
            "s",
            "user said: yes, overwrite it",
            "tracked.txt",
        ])
        .output()
        .expect("run warden approve");
    assert!(out.status.success());
    assert!(String::from_utf8_lossy(&out.stdout).starts_with("approved: "));
    let (code, stdout, _) = check_with_env(&input, &state_env);
    assert_eq!(code, 0, "the approved path is allowed in the same session");
    assert_eq!(stdout, "");

    let shadow_env = [
        ("WARDEN_STATE_DIR", state.to_str().unwrap()),
        ("WARDEN_SHADOW", "1"),
    ];
    let unapproved = input.replace(r#""session_id":"s""#, r#""session_id":"shadow""#);
    let (code, stdout, stderr) = check_with_env(&unapproved, &shadow_env);
    assert_eq!(code, 0, "shadow mode never blocks");
    assert_eq!(stdout, "");
    assert_eq!(stderr, "");
    let log = std::fs::read_to_string(state.join("decisions.jsonl")).unwrap();
    let last = log.lines().last().unwrap();
    assert!(
        last.contains(r#""decision":"deny""#),
        "the real decision is logged: {last}"
    );
    assert!(last.contains(r#""shadow":true"#));
    assert!(last.contains(r#""session":"shadow""#));
    assert!(last.contains(r#""elapsed_ms":"#));

    let hub = state.join("hub");
    std::fs::create_dir_all(&hub).unwrap();
    let report = Command::new(env!("CARGO_BIN_EXE_warden"))
        .envs(state_env.iter().copied())
        .args(["shadow-report", "--hub"])
        .arg(&hub)
        .args(["--since-days", "1"])
        .output()
        .expect("run warden shadow-report");
    let text = String::from_utf8_lossy(&report.stdout);
    let _ = std::fs::remove_dir_all(&dir);
    assert!(report.status.success());
    assert!(text.contains("warden checks: 3"), "{text}");
    assert!(
        text.contains("bash write-guard denials: 0 (0 with no warden check alongside)"),
        "{text}"
    );
    assert!(
        text.contains("warden would deny, bash did not: 2"),
        "{text}"
    );
}

#[test]
fn an_unjudged_tool_is_silent_and_exits_zero() {
    let (code, stdout, stderr) = check(r#"{"tool_name":"Grep","tool_input":{"pattern":"x"}}"#);
    assert_eq!(code, 0);
    assert_eq!(stdout, "");
    assert_eq!(stderr, "");
}

#[test]
fn unreadable_input_warns_and_lets_the_tool_run() {
    for bad in ["not json", ""] {
        let (code, stdout, stderr) = check(bad);
        assert_eq!(code, 0);
        assert_eq!(stdout, "");
        assert!(stderr.starts_with("warden: unreadable hook input"));
    }
}
