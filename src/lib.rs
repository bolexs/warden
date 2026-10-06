use std::path::PathBuf;

use serde::{Deserialize, Serialize};

pub mod approvals;
pub mod claude;
pub mod evidence;
pub mod log;
pub mod policy;
pub mod shadow;
pub mod shell;

pub use policy::decide;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Action {
    Command { text: String },
    Write { path: PathBuf },
    Read { path: PathBuf },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Actor {
    pub name: String,
    pub read_only: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    Plan,
    Act,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Request {
    pub action: Action,
    pub actor: Actor,
    pub session: String,
    pub cwd: PathBuf,
    pub scratch: Option<PathBuf>,
    pub mode: Mode,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "decision", rename_all = "snake_case")]
pub enum Decision {
    Allow,
    Deny { guard: String, reason: String },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deny_serialises_with_a_decision_tag() {
        let d = Decision::Deny {
            guard: "write".into(),
            reason: "tracked file".into(),
        };
        let json = serde_json::to_string(&d).unwrap();
        assert_eq!(
            json,
            r#"{"decision":"deny","guard":"write","reason":"tracked file"}"#
        );
    }

    #[test]
    fn allow_serialises_to_a_bare_tag() {
        let json = serde_json::to_string(&Decision::Allow).unwrap();
        assert_eq!(json, r#"{"decision":"allow"}"#);
    }
}
