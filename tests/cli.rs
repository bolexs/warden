use std::io::Write;
use std::process::{Command, Stdio};

fn check(stdin: &str) -> (i32, String, String) {
    let mut child = Command::new(env!("CARGO_BIN_EXE_warden"))
        .arg("check")
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
