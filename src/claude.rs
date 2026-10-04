use std::path::PathBuf;

use serde::Deserialize;
use serde_json::{Value, json};

use crate::{Action, Actor, Decision, Mode, Request};

#[derive(Debug, Deserialize)]
pub struct HookInput {
    pub tool_name: String,
    #[serde(default)]
    pub tool_input: Value,
    pub session_id: Option<String>,
    pub cwd: Option<PathBuf>,
    pub scratchpad_dir: Option<PathBuf>,
    pub permission_mode: Option<String>,
    pub agent_type: Option<String>,
}

pub fn request_from(input: HookInput) -> Option<Request> {
    let action = match input.tool_name.as_str() {
        "Bash" => Action::Command {
            text: text_field(&input.tool_input, "command")?,
        },
        "Edit" | "Write" | "MultiEdit" => Action::Write {
            path: path_field(&input.tool_input, "file_path")?,
        },
        "NotebookEdit" => Action::Write {
            path: path_field(&input.tool_input, "notebook_path")?,
        },
        "Read" => Action::Read {
            path: path_field(&input.tool_input, "file_path")?,
        },
        _ => return None,
    };
    let mode = match input.permission_mode.as_deref() {
        Some("plan") => Mode::Plan,
        _ => Mode::Act,
    };
    Some(Request {
        action,
        actor: Actor {
            name: input.agent_type.unwrap_or_else(|| "main".into()),
            read_only: false,
        },
        session: input.session_id.unwrap_or_else(|| "nosession".into()),
        cwd: input.cwd.unwrap_or_else(|| PathBuf::from(".")),
        scratch: input.scratchpad_dir,
        mode,
    })
}

pub fn response(decision: &Decision) -> Option<String> {
    match decision {
        Decision::Allow => None,
        Decision::Deny { reason, .. } => Some(
            json!({
                "hookSpecificOutput": {
                    "hookEventName": "PreToolUse",
                    "permissionDecision": "deny",
                    "permissionDecisionReason": reason,
                }
            })
            .to_string(),
        ),
    }
}

fn text_field(v: &Value, key: &str) -> Option<String> {
    let s = v.get(key)?.as_str()?;
    if s.is_empty() {
        None
    } else {
        Some(s.to_string())
    }
}

fn path_field(v: &Value, key: &str) -> Option<PathBuf> {
    text_field(v, key).map(PathBuf::from)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn input(v: Value) -> HookInput {
        serde_json::from_value(v).unwrap()
    }

    #[test]
    fn bash_becomes_a_command() {
        let r = request_from(input(json!({
            "tool_name": "Bash",
            "tool_input": {"command": "ls"},
            "session_id": "s1",
            "cwd": "/w"
        })))
        .unwrap();
        assert_eq!(r.action, Action::Command { text: "ls".into() });
        assert_eq!(r.session, "s1");
        assert_eq!(r.cwd, PathBuf::from("/w"));
        assert_eq!(r.mode, Mode::Act);
        assert_eq!(r.actor.name, "main");
    }

    #[test]
    fn edit_and_write_become_a_write() {
        for tool in ["Edit", "Write", "MultiEdit"] {
            let r = request_from(input(json!({
                "tool_name": tool,
                "tool_input": {"file_path": "/w/a.tf"}
            })))
            .unwrap();
            assert_eq!(
                r.action,
                Action::Write {
                    path: "/w/a.tf".into()
                }
            );
        }
    }

    #[test]
    fn notebook_edit_uses_notebook_path() {
        let r = request_from(input(json!({
            "tool_name": "NotebookEdit",
            "tool_input": {"notebook_path": "/w/n.ipynb"}
        })))
        .unwrap();
        assert_eq!(
            r.action,
            Action::Write {
                path: "/w/n.ipynb".into()
            }
        );
    }

    #[test]
    fn read_is_a_read() {
        let r = request_from(input(json!({
            "tool_name": "Read",
            "tool_input": {"file_path": "/w/a.tf"}
        })))
        .unwrap();
        assert_eq!(
            r.action,
            Action::Read {
                path: "/w/a.tf".into()
            }
        );
    }

    #[test]
    fn other_tools_and_empty_commands_are_not_judged() {
        assert!(
            request_from(input(json!({
                "tool_name": "Grep",
                "tool_input": {"pattern": "x"}
            })))
            .is_none()
        );
        assert!(
            request_from(input(json!({
                "tool_name": "Bash",
                "tool_input": {"command": ""}
            })))
            .is_none()
        );
    }

    #[test]
    fn plan_mode_agent_and_scratch_are_carried() {
        let r = request_from(input(json!({
            "tool_name": "Bash",
            "tool_input": {"command": "ls"},
            "permission_mode": "plan",
            "agent_type": "deep-reviewer",
            "scratchpad_dir": "/tmp/s"
        })))
        .unwrap();
        assert_eq!(r.mode, Mode::Plan);
        assert_eq!(r.actor.name, "deep-reviewer");
        assert_eq!(r.scratch, Some(PathBuf::from("/tmp/s")));
    }

    #[test]
    fn allow_is_silent() {
        assert_eq!(response(&Decision::Allow), None);
    }

    #[test]
    fn deny_is_the_hook_json() {
        let d = Decision::Deny {
            guard: "write".into(),
            reason: "no".into(),
        };
        assert_eq!(
            response(&d).unwrap(),
            r#"{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"no"}}"#
        );
    }
}
