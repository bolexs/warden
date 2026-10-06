use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::{Action, Decision, Mode};

pub const FILE_NAME: &str = "decisions.jsonl";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entry {
    pub at: u64,
    pub session: String,
    pub actor: String,
    pub cwd: PathBuf,
    pub mode: Mode,
    #[serde(flatten)]
    pub action: Action,
    #[serde(flatten)]
    pub decision: Decision,
    pub shadow: bool,
    pub elapsed_ms: u64,
}

pub fn record(dir: &Path, entry: &Entry) -> std::io::Result<()> {
    fs::create_dir_all(dir)?;
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(dir.join(FILE_NAME))?;
    let line = format!("{}\n", serde_json::to_string(entry)?);
    file.write_all(line.as_bytes())
}

pub fn read(dir: &Path) -> Vec<Entry> {
    let Ok(text) = fs::read_to_string(dir.join(FILE_NAME)) else {
        return Vec::new();
    };
    text.lines()
        .filter_map(|line| serde_json::from_str(line).ok())
        .collect()
}

pub fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dir(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("warden-log-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        d
    }

    fn entry(decision: Decision, shadow: bool) -> Entry {
        Entry {
            at: now(),
            session: "s1".into(),
            actor: "main".into(),
            cwd: "/w".into(),
            mode: Mode::Act,
            action: Action::Command {
                text: "echo x > a.txt".into(),
            },
            decision,
            shadow,
            elapsed_ms: 7,
        }
    }

    #[test]
    fn a_deny_line_carries_the_action_and_the_reason_flat() {
        let d = dir("flat");
        let e = entry(
            Decision::Deny {
                guard: "write".into(),
                reason: "tracked".into(),
            },
            false,
        );
        record(&d, &e).unwrap();
        let text = fs::read_to_string(d.join(FILE_NAME)).unwrap();
        assert!(text.contains(r#""kind":"command""#));
        assert!(text.contains(r#""text":"echo x > a.txt""#));
        assert!(text.contains(r#""decision":"deny""#));
        assert!(text.contains(r#""guard":"write""#));
        assert!(text.contains(r#""shadow":false"#));
        assert_eq!(read(&d), vec![e]);
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn entries_append_in_order_and_a_damaged_line_is_skipped() {
        let d = dir("order");
        record(&d, &entry(Decision::Allow, true)).unwrap();
        fs::OpenOptions::new()
            .append(true)
            .open(d.join(FILE_NAME))
            .unwrap()
            .write_all(b"garbage\n")
            .unwrap();
        record(
            &d,
            &entry(
                Decision::Deny {
                    guard: "write".into(),
                    reason: "r".into(),
                },
                true,
            ),
        )
        .unwrap();
        let all = read(&d);
        assert_eq!(all.len(), 2);
        assert_eq!(all[0].decision, Decision::Allow);
        assert!(all[0].shadow);
        assert!(matches!(all[1].decision, Decision::Deny { .. }));
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn a_missing_log_reads_as_empty() {
        assert!(read(Path::new("/nonexistent-warden-log-dir")).is_empty());
    }
}
