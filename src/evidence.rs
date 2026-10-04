use std::collections::HashMap;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::Command;

pub fn canon(path: &Path, base: &Path) -> PathBuf {
    let p = expand_home(path);
    let p = if p.is_absolute() { p } else { base.join(p) };
    let mut existing = p.as_path();
    let mut missing: Vec<OsString> = Vec::new();
    while !existing.exists() {
        let Some(parent) = existing.parent() else {
            break;
        };
        if let Some(name) = existing.file_name() {
            missing.push(name.to_owned());
        }
        existing = parent;
    }
    let mut out = existing
        .canonicalize()
        .unwrap_or_else(|_| existing.to_path_buf());
    for name in missing.iter().rev() {
        out.push(name);
    }
    out
}

pub fn repo_root(path: &Path) -> Option<PathBuf> {
    let mut dir = path;
    while !dir.is_dir() {
        dir = dir.parent()?;
    }
    let out = Command::new("git")
        .args(["-C"])
        .arg(dir)
        .args(["rev-parse", "--show-toplevel"])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let root = String::from_utf8(out.stdout).ok()?;
    let root = root.trim_end();
    if root.is_empty() {
        return None;
    }
    Some(PathBuf::from(root))
}

pub fn is_tracked_file(path: &Path) -> bool {
    !tracked_files(&[path.to_path_buf()]).is_empty()
}

pub fn tracked_files(paths: &[PathBuf]) -> Vec<PathBuf> {
    let mut groups: HashMap<&Path, Vec<(&Path, &PathBuf)>> = HashMap::new();
    for path in paths {
        if path.is_dir() {
            continue;
        }
        let Some(dir) = existing_ancestor_dir(path) else {
            continue;
        };
        let Ok(rel) = path.strip_prefix(dir) else {
            continue;
        };
        groups.entry(dir).or_default().push((rel, path));
    }
    let mut out = Vec::new();
    for (dir, items) in groups {
        let Ok(output) = Command::new("git")
            .arg("-C")
            .arg(dir)
            .args(["ls-files", "-z", "--"])
            .args(items.iter().map(|(rel, _)| *rel))
            .output()
        else {
            continue;
        };
        if !output.status.success() {
            continue;
        }
        let listed: Vec<&[u8]> = output.stdout.split(|b| *b == 0).collect();
        for (rel, abs) in items {
            if listed.contains(&rel.as_os_str().as_encoded_bytes()) {
                out.push((*abs).clone());
            }
        }
    }
    out
}

fn existing_ancestor_dir(path: &Path) -> Option<&Path> {
    let mut dir = path.parent()?;
    while !dir.is_dir() {
        dir = dir.parent()?;
    }
    Some(dir)
}

pub fn is_tracked(repo: &Path, path: &Path) -> bool {
    let Ok(rel) = path.strip_prefix(repo) else {
        return false;
    };
    Command::new("git")
        .arg("-C")
        .arg(repo)
        .args(["ls-files", "--error-unmatch", "--"])
        .arg(rel)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn expand_home(path: &Path) -> PathBuf {
    let Some(home) = std::env::var_os("HOME") else {
        return path.to_path_buf();
    };
    let s = path.to_string_lossy();
    for prefix in ["~/", "$HOME/", "${HOME}/"] {
        if let Some(rest) = s.strip_prefix(prefix) {
            return Path::new(&home).join(rest);
        }
    }
    if s == "~" || s == "$HOME" || s == "${HOME}" {
        return PathBuf::from(home);
    }
    path.to_path_buf()
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::fs;

    pub struct TempRepo(pub PathBuf);

    impl TempRepo {
        pub fn new(name: &str) -> Self {
            let dir = std::env::temp_dir().join(format!(
                "warden-{name}-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            fs::create_dir_all(&dir).unwrap();
            git(&dir, &["init", "-q", "-b", "main"]);
            git(&dir, &["config", "user.email", "t@t"]);
            git(&dir, &["config", "user.name", "t"]);
            TempRepo(dir.canonicalize().unwrap())
        }

        pub fn commit_file(&self, rel: &str, content: &str) {
            let p = self.0.join(rel);
            fs::create_dir_all(p.parent().unwrap()).unwrap();
            fs::write(&p, content).unwrap();
            git(&self.0, &["add", "-A"]);
            git(&self.0, &["commit", "-q", "-m", "add"]);
        }
    }

    impl Drop for TempRepo {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn git(dir: &Path, args: &[&str]) {
        let ok = Command::new("git")
            .arg("-C")
            .arg(dir)
            .args(args)
            .status()
            .unwrap()
            .success();
        assert!(ok, "git {args:?} failed in {}", dir.display());
    }

    #[test]
    fn canon_resolves_relative_paths_against_the_base() {
        let r = TempRepo::new("canon");
        r.commit_file("infra/main.tf", "x");
        assert_eq!(
            canon(Path::new("infra/main.tf"), &r.0),
            r.0.join("infra/main.tf")
        );
    }

    #[test]
    fn canon_keeps_the_missing_tail_of_a_path_that_does_not_exist_yet() {
        let r = TempRepo::new("canon-missing");
        assert_eq!(
            canon(Path::new(".claude/changelog/x.md"), &r.0),
            r.0.join(".claude/changelog/x.md")
        );
    }

    #[test]
    fn canon_expands_home() {
        let home = PathBuf::from(std::env::var_os("HOME").unwrap());
        assert_eq!(
            canon(Path::new("~/.zshrc"), Path::new("/")),
            home.join(".zshrc")
        );
        assert_eq!(
            canon(Path::new("$HOME/.zshrc"), Path::new("/")),
            home.join(".zshrc")
        );
    }

    #[test]
    fn repo_root_is_found_from_a_file_and_from_a_missing_nested_path() {
        let r = TempRepo::new("root");
        r.commit_file("src/a.ts", "x");
        assert_eq!(repo_root(&r.0.join("src/a.ts")), Some(r.0.clone()));
        assert_eq!(
            repo_root(&r.0.join("src/new/deeper/b.ts")),
            Some(r.0.clone())
        );
    }

    #[test]
    fn outside_any_repository_there_is_no_root() {
        let dir = std::env::temp_dir().join(format!("warden-norepo-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        assert_eq!(repo_root(&dir.join("f.txt")), None);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_tracked_file_is_found_in_one_call_from_its_own_directory() {
        let r = TempRepo::new("tracked-file");
        r.commit_file("src/a.ts", "x");
        fs::write(r.0.join("untracked.txt"), "new").unwrap();
        assert!(is_tracked_file(&r.0.join("src/a.ts")));
        assert!(!is_tracked_file(&r.0.join("untracked.txt")));
        assert!(!is_tracked_file(&r.0.join("src/new/deeper/b.ts")));
        assert!(!is_tracked_file(&r.0.join("src")));
        assert!(!is_tracked_file(Path::new(
            "/nonexistent-root-dir-xyz/a.ts"
        )));
    }

    #[test]
    fn many_paths_are_checked_in_one_call_per_directory() {
        let r = TempRepo::new("tracked-many");
        r.commit_file("src/a.ts", "x");
        r.commit_file("src/b.ts", "y");
        r.commit_file("Makefile", "all:\n");
        fs::write(r.0.join("src/new.ts"), "new").unwrap();
        let found = tracked_files(&[
            r.0.join("src/new.ts"),
            r.0.join("src/b.ts"),
            r.0.join("Makefile"),
            r.0.join("src"),
            r.0.join("nope/deeper/c.ts"),
        ]);
        assert_eq!(found.len(), 2);
        assert!(found.contains(&r.0.join("src/b.ts")));
        assert!(found.contains(&r.0.join("Makefile")));
    }

    #[test]
    fn tracked_means_committed_or_staged_not_merely_present() {
        let r = TempRepo::new("tracked");
        r.commit_file("src/a.ts", "x");
        fs::write(r.0.join("untracked.txt"), "new").unwrap();
        assert!(is_tracked(&r.0, &r.0.join("src/a.ts")));
        assert!(!is_tracked(&r.0, &r.0.join("untracked.txt")));
        assert!(!is_tracked(&r.0, &r.0.join("src/missing.ts")));
        assert!(!is_tracked(&r.0, Path::new("/elsewhere/a.ts")));
    }
}
