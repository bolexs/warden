use std::fs;
use std::path::Path;

use serde_json::Value;

use crate::log::Entry;
use crate::{Action, Decision};

pub const PAIR_WINDOW_SECS: u64 = 2;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BashDeny {
    pub at: u64,
    pub session: String,
    pub reason: String,
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct Report {
    pub checks: usize,
    pub bash_denials: usize,
    pub agreed_denials: usize,
    pub warden_only: Vec<(Entry, String)>,
    pub bash_only: Vec<BashDeny>,
}

pub fn hub_denials(hub: &Path, guard: &str, since: u64) -> Vec<BashDeny> {
    let Ok(dir) = fs::read_dir(hub) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for entry in dir.flatten() {
        let path = entry.path();
        let is_hub_file = path
            .file_name()
            .and_then(|n| n.to_str())
            .is_some_and(|n| n.starts_with("commands-") && n.ends_with(".jsonl"));
        if !is_hub_file {
            continue;
        }
        let Ok(text) = fs::read_to_string(&path) else {
            continue;
        };
        for line in text.lines() {
            let Ok(v) = serde_json::from_str::<Value>(line) else {
                continue;
            };
            if v["kind"] != "deny" || v["guard"] != guard {
                continue;
            }
            let Some(at) = v["ts"].as_str().and_then(parse_iso_seconds) else {
                continue;
            };
            if at < since {
                continue;
            }
            out.push(BashDeny {
                at,
                session: v["session"].as_str().unwrap_or("").to_string(),
                reason: v["reason"].as_str().unwrap_or("").to_string(),
            });
        }
    }
    out.sort_by_key(|d| d.at);
    out
}

pub fn compare(entries: &[Entry], bash: &[BashDeny], since: u64) -> Report {
    let mut report = Report {
        bash_denials: bash.len(),
        ..Report::default()
    };
    let mut matched = vec![false; bash.len()];
    let judged: Vec<&Entry> = entries
        .iter()
        .filter(|e| e.at >= since && matches!(e.action, Action::Command { .. }))
        .collect();
    report.checks = judged.len();
    for entry in &judged {
        let Decision::Deny { reason, .. } = &entry.decision else {
            continue;
        };
        match nearest_unmatched(bash, &matched, entry) {
            Some(i) => {
                matched[i] = true;
                report.agreed_denials += 1;
            }
            None => report.warden_only.push(((*entry).clone(), reason.clone())),
        }
    }
    for entry in &judged {
        if entry.decision != Decision::Allow {
            continue;
        }
        if let Some(i) = nearest_unmatched(bash, &matched, entry) {
            matched[i] = true;
            report.bash_only.push(bash[i].clone());
        }
    }
    report
}

fn nearest_unmatched(bash: &[BashDeny], matched: &[bool], entry: &Entry) -> Option<usize> {
    bash.iter()
        .enumerate()
        .filter(|(i, d)| {
            !matched[*i]
                && d.session == entry.session
                && d.at.abs_diff(entry.at) <= PAIR_WINDOW_SECS
        })
        .min_by_key(|(_, d)| d.at.abs_diff(entry.at))
        .map(|(i, _)| i)
}

pub fn render(report: &Report, since_days: u64) -> String {
    let mut out = format!(
        "warden shadow report, last {since_days} day(s)\n  warden checks: {}\n  bash write-guard denials: {} ({} with no warden check alongside)\n  agreed denials: {}\n  warden would deny, bash did not: {}\n  bash denied, warden would not: {}\n",
        report.checks,
        report.bash_denials,
        report.bash_denials - report.agreed_denials - report.bash_only.len(),
        report.agreed_denials,
        report.warden_only.len(),
        report.bash_only.len()
    );
    for (entry, reason) in &report.warden_only {
        if let Action::Command { text } = &entry.action {
            out.push_str(&format!(
                "\n- warden only [{}]: {}\n    {}\n",
                entry.session, text, reason
            ));
        }
    }
    for deny in &report.bash_only {
        out.push_str(&format!(
            "\n- bash only [{}]: {}\n",
            deny.session, deny.reason
        ));
    }
    out
}

pub fn parse_iso_seconds(ts: &str) -> Option<u64> {
    let b = ts.as_bytes();
    if b.len() < 19
        || !b[..19].is_ascii()
        || b[4] != b'-'
        || b[7] != b'-'
        || b[10] != b'T'
        || b[13] != b':'
        || b[16] != b':'
    {
        return None;
    }
    let num = |s: &str| s.parse::<i64>().ok();
    let (y, m, d) = (num(&ts[0..4])?, num(&ts[5..7])?, num(&ts[8..10])?);
    let (hh, mm, ss) = (num(&ts[11..13])?, num(&ts[14..16])?, num(&ts[17..19])?);
    let days = days_from_civil(y, m, d);
    let secs = days * 86_400 + hh * 3_600 + mm * 60 + ss;
    u64::try_from(secs).ok()
}

fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Mode;

    fn entry(at: u64, session: &str, text: &str, decision: Decision) -> Entry {
        Entry {
            at,
            session: session.into(),
            actor: "main".into(),
            cwd: "/w".into(),
            mode: Mode::Act,
            action: Action::Command { text: text.into() },
            decision,
            shadow: true,
            elapsed_ms: 5,
        }
    }

    fn deny() -> Decision {
        Decision::Deny {
            guard: "write".into(),
            reason: "tracked".into(),
        }
    }

    #[test]
    fn iso_timestamps_parse_to_unix_seconds() {
        assert_eq!(parse_iso_seconds("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(
            parse_iso_seconds("2026-10-03T21:31:38Z"),
            Some(1_791_063_098)
        );
        assert_eq!(parse_iso_seconds("not a time"), None);
    }

    #[test]
    fn denials_pair_by_session_within_the_window() {
        let bash = vec![
            BashDeny {
                at: 1000,
                session: "a".into(),
                reason: "bash said no".into(),
            },
            BashDeny {
                at: 2000,
                session: "a".into(),
                reason: "bash said no again".into(),
            },
        ];
        let entries = vec![
            entry(999, "a", "ls", Decision::Allow),
            entry(1001, "a", "echo x > t", deny()),
            entry(1500, "a", "echo y > u", deny()),
            entry(2001, "a", "cat t", Decision::Allow),
            entry(3000, "b", "ls", Decision::Allow),
        ];
        let r = compare(&entries, &bash, 0);
        assert_eq!(r.checks, 5);
        assert_eq!(r.bash_denials, 2);
        assert_eq!(
            r.agreed_denials, 1,
            "the deny claims the denial, not the allow logged just before it"
        );
        assert_eq!(r.warden_only.len(), 1);
        assert_eq!(r.warden_only[0].1, "tracked");
        assert_eq!(r.bash_only.len(), 1);
        assert_eq!(r.bash_only[0].reason, "bash said no again");
    }

    #[test]
    fn a_non_ascii_timestamp_is_skipped_not_fatal() {
        assert_eq!(parse_iso_seconds("2026-10-03T21:31:3éZ"), None);
        assert_eq!(
            parse_iso_seconds("2026-10-03T21:31:38Z"),
            Some(1_791_063_098)
        );
    }

    #[test]
    fn a_different_session_never_pairs() {
        let bash = vec![BashDeny {
            at: 1000,
            session: "other".into(),
            reason: "r".into(),
        }];
        let r = compare(&[entry(1000, "a", "echo x > t", deny())], &bash, 0);
        assert_eq!(r.agreed_denials, 0);
        assert_eq!(r.warden_only.len(), 1);
    }

    #[test]
    fn hub_files_are_filtered_by_guard_and_time() {
        let d = std::env::temp_dir().join(format!("warden-hub-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        fs::write(
            d.join("commands-2026-10.jsonl"),
            concat!(
                r#"{"ts":"2026-10-03T21:31:38Z","kind":"deny","guard":"write-guard","session":"s","reason":"old"}"#,
                "\n",
                r#"{"ts":"2026-10-05T10:00:00Z","kind":"deny","guard":"write-guard","session":"s","reason":"recent"}"#,
                "\n",
                r#"{"ts":"2026-10-05T10:00:01Z","kind":"deny","guard":"push-guard","session":"s","reason":"other guard"}"#,
                "\n",
                r#"{"ts":"2026-10-05T10:00:02Z","kind":"command","cmd":"ls","session":"s"}"#,
                "\n",
                "garbage\n",
            ),
        )
        .unwrap();
        fs::write(d.join("notes.txt"), "ignored").unwrap();
        let since = parse_iso_seconds("2026-10-04T00:00:00Z").unwrap();
        let found = hub_denials(&d, "write-guard", since);
        let _ = fs::remove_dir_all(&d);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].reason, "recent");
    }

    #[test]
    fn the_report_reads_as_counts_then_cases() {
        let r = compare(&[entry(1, "a", "echo x > t", deny())], &[], 0);
        let text = render(&r, 7);
        assert!(text.contains("warden checks: 1"));
        assert!(text.contains("bash write-guard denials: 0 (0 with no warden check alongside)"));
        assert!(text.contains("warden would deny, bash did not: 1"));
        assert!(text.contains("warden only [a]: echo x > t"));
    }
}
