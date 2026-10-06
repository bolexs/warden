use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

pub const TTL_SECS: u64 = 12 * 60 * 60;
pub const STATE_DIR_VAR: &str = "WARDEN_STATE_DIR";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Approval {
    pub session: String,
    pub path: PathBuf,
    pub at: u64,
    pub words: String,
}

pub fn state_dir() -> PathBuf {
    if let Some(dir) = std::env::var_os(STATE_DIR_VAR) {
        return PathBuf::from(dir);
    }
    match std::env::var_os("HOME") {
        Some(home) => PathBuf::from(home).join(".warden"),
        None => std::env::temp_dir().join("warden"),
    }
}

pub fn record(session: &str, path: &Path, words: &str) -> std::io::Result<()> {
    record_in(&state_dir(), session, path, words)
}

pub fn approved(session: &str, path: &Path) -> bool {
    approved_in(&state_dir(), session, path)
}

pub fn record_in(dir: &Path, session: &str, path: &Path, words: &str) -> std::io::Result<()> {
    fs::create_dir_all(dir)?;
    let approval = Approval {
        session: session.to_string(),
        path: path.to_path_buf(),
        at: now(),
        words: words.to_string(),
    };
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(dir.join("approvals.jsonl"))?;
    let line = format!("{}\n", serde_json::to_string(&approval)?);
    file.write_all(line.as_bytes())
}

pub fn approved_in(dir: &Path, session: &str, path: &Path) -> bool {
    let Ok(text) = fs::read_to_string(dir.join("approvals.jsonl")) else {
        return false;
    };
    let now = now();
    text.lines()
        .filter_map(|line| serde_json::from_str::<Approval>(line).ok())
        .any(|a| a.session == session && a.path == path && now.saturating_sub(a.at) <= TTL_SECS)
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dir(name: &str) -> PathBuf {
        let d =
            std::env::temp_dir().join(format!("warden-approvals-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        d
    }

    #[test]
    fn an_approval_is_per_session_and_per_path() {
        let d = dir("scope");
        let p = Path::new("/repo/infra/main.tf");
        assert!(!approved_in(&d, "s1", p));
        record_in(&d, "s1", p, "user said: approved, write it").unwrap();
        assert!(approved_in(&d, "s1", p));
        assert!(!approved_in(&d, "s2", p));
        assert!(!approved_in(&d, "s1", Path::new("/repo/infra/other.tf")));
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn an_approval_expires_after_twelve_hours() {
        let d = dir("expiry");
        fs::create_dir_all(&d).unwrap();
        let stale = Approval {
            session: "s1".into(),
            path: "/repo/a".into(),
            at: now() - TTL_SECS - 1,
            words: "old".into(),
        };
        fs::write(
            d.join("approvals.jsonl"),
            format!("{}\n", serde_json::to_string(&stale).unwrap()),
        )
        .unwrap();
        assert!(!approved_in(&d, "s1", Path::new("/repo/a")));
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn a_damaged_line_does_not_break_the_others() {
        let d = dir("damaged");
        fs::create_dir_all(&d).unwrap();
        fs::write(d.join("approvals.jsonl"), "not json\n").unwrap();
        record_in(&d, "s1", Path::new("/repo/a"), "ok").unwrap();
        assert!(approved_in(&d, "s1", Path::new("/repo/a")));
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn the_record_keeps_the_users_words() {
        let d = dir("words");
        record_in(&d, "s1", Path::new("/repo/a"), "user said: go ahead").unwrap();
        let text = fs::read_to_string(d.join("approvals.jsonl")).unwrap();
        let a: Approval = serde_json::from_str(text.lines().next().unwrap()).unwrap();
        assert_eq!(a.words, "user said: go ahead");
        assert_eq!(a.session, "s1");
        let _ = fs::remove_dir_all(&d);
    }
}
