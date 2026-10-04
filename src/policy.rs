use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::LazyLock;

use regex::Regex;

use crate::shell::{self, SimpleCommand, Word};
use crate::{Action, Decision, Request};
use crate::{approvals, evidence};

const GUARD: &str = "write";
const INTERPRETERS: [&str; 6] = ["python", "python3", "perl", "node", "ruby", "php"];
const PROGRAM_FLAGS: [&str; 6] = ["-c", "-e", "-", "-r", "--eval", "-p"];
const WRAPPERS: [&str; 7] = [
    "sudo", "env", "command", "nohup", "nice", "timeout", "xargs",
];
const SHELLS: [&str; 5] = ["bash", "sh", "zsh", "dash", "ksh"];

static WRITE_TARGET: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(concat!(
        r#"open\(\s*([A-Za-z_][A-Za-z0-9_]*|'[^']*'|"[^"]*")\s*,\s*['"][wax]"#,
        "|",
        r#"Path\(\s*([A-Za-z_][A-Za-z0-9_]*|'[^']*'|"[^"]*")\s*\)\s*\.\s*(?:write_text|write_bytes|unlink|replace)\s*\("#,
        "|",
        r#"(?:writeFileSync|writeFile|appendFileSync|appendFile)\s*\(\s*([A-Za-z_][A-Za-z0-9_]*|'[^']*'|"[^"]*")"#,
    ))
    .expect("write-target pattern compiles")
});

static ASSIGNMENT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?m)^\s*(?:const\s+|let\s+|var\s+|my\s+)?\$?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*('[^']*'|"[^"]*")"#)
        .expect("assignment pattern compiles")
});

pub const OVERRIDE_VAR: &str = "WARDEN_ALLOW_SHELL_WRITES";

pub fn decide(request: &Request) -> Decision {
    match &request.action {
        Action::Command { text } => {
            if std::env::var_os(OVERRIDE_VAR).is_some_and(|v| v == "1") {
                return Decision::Allow;
            }
            let mut judge = Judge {
                session: request.session.clone(),
            };
            judge
                .command(text, Some(request.cwd.clone()))
                .unwrap_or(Decision::Allow)
        }
        Action::Write { .. } | Action::Read { .. } => Decision::Allow,
    }
}

struct Judge {
    session: String,
}

impl Judge {
    fn command(&mut self, text: &str, cwd: Option<PathBuf>) -> Option<Decision> {
        let parsed = shell::parse(text);
        let mut bases: HashMap<u32, Option<PathBuf>> = HashMap::new();
        bases.insert(0, cwd);
        for raw in &parsed.commands {
            let cmd = unwrap_wrappers(raw);
            let top = bases.get(&0).cloned().flatten();
            let base = bases.entry(raw.scope).or_insert(top);
            if let Some(next) = cd_target(&cmd, base.as_deref()) {
                *base = next;
            }
            let base = base.clone();
            if let Some(script) = inline_script(&cmd) {
                if let Some(decision) = self.command(&script, base.clone()) {
                    return Some(decision);
                }
            }
            if let Some(abs) = self.first_tracked(&write_targets(&cmd), base.as_deref()) {
                return Some(
                    self.deny_rewrite(&abs, "this command would rewrite it through the shell"),
                );
            }
            if let Some(abs) = self.first_tracked(&interpreter_targets(&cmd), base.as_deref()) {
                return Some(self.deny_rewrite(&abs, "this program would rewrite it"));
            }
        }
        None
    }

    fn deny_rewrite(&self, abs: &Path, how: &str) -> Decision {
        deny(format!(
            "{path} is tracked by git, and {how}. Use the file-edit tools, one file at a time, \
             so the change is shown as a diff and recorded. If the user has approved this, run: \
             warden approve --session {session} \"<their words>\" '{path}'",
            path = abs.display(),
            session = self.session,
        ))
    }

    fn first_tracked(&mut self, targets: &[String], base: Option<&Path>) -> Option<PathBuf> {
        if targets.is_empty() {
            return None;
        }
        let candidates: Vec<PathBuf> = targets
            .iter()
            .filter_map(|t| resolve(t, base))
            .filter(|p| !p.is_dir())
            .collect();
        evidence::tracked_files(&candidates)
            .into_iter()
            .find(|abs| !approvals::approved(&self.session, abs))
    }
}

fn deny(reason: String) -> Decision {
    Decision::Deny {
        guard: GUARD.into(),
        reason,
    }
}

fn anchored(target: &str) -> bool {
    target.starts_with('/')
        || target.starts_with('~')
        || target.starts_with("$HOME")
        || target.starts_with("${HOME}")
}

fn resolve(target: &str, base: Option<&Path>) -> Option<PathBuf> {
    if target.is_empty() || target.contains(['*', '?', '[']) {
        return None;
    }
    if anchored(target) {
        return Some(evidence::canon(Path::new(target), Path::new("/")));
    }
    base.map(|b| evidence::canon(Path::new(target), b))
}

fn program(cmd: &SimpleCommand) -> Option<&str> {
    Path::new(cmd.name.as_deref()?).file_name()?.to_str()
}

fn operands(cmd: &SimpleCommand) -> impl Iterator<Item = &Word> {
    cmd.args.iter().filter(|w| !w.text.starts_with('-'))
}

fn unwrap_wrappers(cmd: &SimpleCommand) -> SimpleCommand {
    let mut cur = cmd.clone();
    loop {
        let Some(name) = program(&cur) else {
            return cur;
        };
        if !WRAPPERS.contains(&name) {
            return cur;
        }
        let takes_value: &[&str] = match name {
            "sudo" => &["-u", "-g", "-p", "-C", "-h", "-D", "-R", "-T"],
            "nice" => &["-n"],
            "timeout" => &["-s", "-k"],
            "xargs" => &["-I", "-n", "-P", "-L", "-s", "-d", "-E", "-a"],
            "env" => &["-u", "-C", "-S"],
            _ => &[],
        };
        let mut skip_operands = usize::from(name == "timeout");
        let mut words = cur.args.iter();
        let mut next: Option<(String, Vec<Word>)> = None;
        while let Some(w) = words.next() {
            let t = w.text.as_str();
            if t.starts_with('-') && t != "-" {
                if takes_value.contains(&t) {
                    words.next();
                }
                continue;
            }
            if name == "env" && t.contains('=') {
                continue;
            }
            if skip_operands > 0 {
                skip_operands -= 1;
                continue;
            }
            next = Some((t.to_string(), words.cloned().collect()));
            break;
        }
        match next {
            Some((name, args)) => {
                cur.name = Some(name);
                cur.args = args;
            }
            None => return cur,
        }
    }
}

fn cd_target(cmd: &SimpleCommand, base: Option<&Path>) -> Option<Option<PathBuf>> {
    if !matches!(program(cmd)?, "cd" | "pushd") {
        return None;
    }
    let Some(arg) = operands(cmd).next() else {
        return Some(std::env::var_os("HOME").map(PathBuf::from));
    };
    let t = arg.text.as_str();
    if anchored(t) {
        return Some(Some(evidence::canon(Path::new(t), Path::new("/"))));
    }
    if t == "-" || t.contains('$') {
        return Some(None);
    }
    Some(base.map(|b| evidence::canon(Path::new(t), b)))
}

fn inline_script(cmd: &SimpleCommand) -> Option<String> {
    let name = program(cmd)?;
    if name == "eval" {
        let joined = cmd
            .args
            .iter()
            .map(|w| w.text.as_str())
            .collect::<Vec<_>>()
            .join(" ");
        return (!joined.is_empty()).then_some(joined);
    }
    if !SHELLS.contains(&name) {
        return None;
    }
    let mut words = cmd.args.iter();
    while let Some(w) = words.next() {
        let t = w.text.as_str();
        if t.starts_with('-') && !t.starts_with("--") && t.ends_with('c') {
            return words.next().map(|s| s.text.clone());
        }
    }
    (!cmd.heredocs.is_empty()).then(|| cmd.heredocs.join("\n"))
}

fn write_targets(cmd: &SimpleCommand) -> Vec<String> {
    let mut out = Vec::new();
    for r in &cmd.redirects {
        let t = r.target.text.as_str();
        let writes = match r.op.as_str() {
            ">" | ">>" | ">|" | "&>" | "&>>" => true,
            ">&" => !t.is_empty() && t != "-" && !t.chars().all(|c| c.is_ascii_digit()),
            _ => false,
        };
        if writes && !t.is_empty() && !t.starts_with("/dev/") {
            out.push(t.to_string());
        }
    }
    let Some(name) = program(cmd) else {
        return out;
    };
    match name {
        "cp" | "mv" | "install" | "ln" | "rsync" => {
            let ops: Vec<&Word> = operands(cmd).collect();
            if let Some((dest, sources)) = ops.split_last() {
                out.push(dest.text.clone());
                for src in sources {
                    if let Some(file) = Path::new(&src.text).file_name() {
                        out.push(
                            Path::new(&dest.text)
                                .join(file)
                                .to_string_lossy()
                                .into_owned(),
                        );
                    }
                }
            }
        }
        "dd" => out.extend(
            cmd.args
                .iter()
                .filter_map(|w| w.text.strip_prefix("of=").map(str::to_string)),
        ),
        "curl" => out.extend(option_values(cmd, &["-o", "--output"])),
        "wget" => out.extend(option_values(cmd, &["-O", "--output-document"])),
        "sort" => out.extend(option_values(cmd, &["-o"])),
        "tee" => out.extend(operands(cmd).map(|w| w.text.clone())),
        "sed" | "perl" if in_place(cmd, name) => {
            out.extend(operands(cmd).map(|w| w.text.clone()));
        }
        _ => {}
    }
    out
}

fn option_values(cmd: &SimpleCommand, flags: &[&str]) -> Vec<String> {
    cmd.args
        .windows(2)
        .filter(|pair| flags.contains(&pair[0].text.as_str()))
        .map(|pair| pair[1].text.clone())
        .collect()
}

fn in_place(cmd: &SimpleCommand, name: &str) -> bool {
    cmd.args.iter().any(|w| {
        let t = w.text.as_str();
        if t.starts_with("-i") || t.starts_with("--in-place") {
            return true;
        }
        let Some(bundle) = t.strip_prefix('-') else {
            return false;
        };
        if bundle.is_empty() || bundle.starts_with('-') || !bundle.contains('i') {
            return false;
        }
        match name {
            "sed" => bundle.chars().all(|c| c.is_ascii_alphanumeric()),
            _ => bundle
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit()),
        }
    })
}

fn interpreter_targets(cmd: &SimpleCommand) -> Vec<String> {
    let Some(name) = program(cmd) else {
        return Vec::new();
    };
    if !INTERPRETERS.contains(&name) {
        return Vec::new();
    }
    let runs_program = !cmd.heredocs.is_empty()
        || cmd
            .args
            .iter()
            .any(|w| PROGRAM_FLAGS.contains(&w.text.as_str()));
    if !runs_program {
        return Vec::new();
    }
    let mut text = cmd.heredocs.join("\n");
    for w in cmd.args.iter().filter(|w| w.quoted) {
        text.push('\n');
        text.push_str(&w.text);
    }
    let assigned: HashMap<&str, &str> = ASSIGNMENT
        .captures_iter(&text)
        .filter_map(|c| Some((c.get(1)?.as_str(), unquote_literal(c.get(2)?.as_str()))))
        .collect();
    let mut out = Vec::new();
    for cap in WRITE_TARGET.captures_iter(&text) {
        let Some(arg) = (1..=3).find_map(|i| cap.get(i)) else {
            continue;
        };
        let arg = arg.as_str();
        let literal = if arg.starts_with('\'') || arg.starts_with('"') {
            Some(unquote_literal(arg))
        } else {
            assigned.get(arg).copied()
        };
        if let Some(path) = literal {
            if !path.is_empty() && !path.contains('*') && !path.contains('$') {
                out.push(path.to_string());
            }
        }
    }
    out
}

fn unquote_literal(s: &str) -> &str {
    s.strip_prefix('\'')
        .and_then(|s| s.strip_suffix('\''))
        .or_else(|| s.strip_prefix('"').and_then(|s| s.strip_suffix('"')))
        .unwrap_or(s)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evidence::tests::TempRepo;
    use crate::{Actor, Mode};
    use std::fs;

    fn judge(cmd: &str, cwd: &Path) -> Decision {
        decide(&Request {
            action: Action::Command { text: cmd.into() },
            actor: Actor {
                name: "main".into(),
                read_only: false,
            },
            session: "s".into(),
            cwd: cwd.to_path_buf(),
            scratch: None,
            mode: Mode::Act,
        })
    }

    fn denied(cmd: &str, cwd: &Path) -> bool {
        matches!(judge(cmd, cwd), Decision::Deny { .. })
    }

    fn repo() -> TempRepo {
        let r = TempRepo::new("policy");
        r.commit_file("src/a.ts", "export const a = 1;\n");
        r.commit_file("src/config.json", "{}\n");
        r.commit_file("skills/x/SKILL.md", "# doc\n");
        r.commit_file("skills/principal-engineer/SKILL.md", "one\n");
        r.commit_file("authorize.sh", "echo hi\n");
        r.commit_file("Makefile", "all:\n");
        fs::write(r.0.join("untracked.txt"), "new\n").unwrap();
        r
    }

    #[test]
    fn shell_rewrites_of_tracked_files_are_denied() {
        let r = repo();
        let d = &r.0;
        let doc = d.join("skills/x/SKILL.md");
        for (cmd, why) in [
            (
                format!(
                    "python3 - <<'PY'\np='{}'\ns=open(p).read()\nopen(p,'w').write(s.replace('a','b'))\nPY",
                    doc.display()
                ),
                "python heredoc rewriting a tracked file through a variable",
            ),
            ("sed -i.bak 's/a/b/' src/a.ts".into(), "sed in place"),
            (
                format!("perl -pi -e 's/a/b/' {}", d.join("src/a.ts").display()),
                "perl in place",
            ),
            (
                "sed -i '' 's/a/b/' \"src/a.ts\"".into(),
                "sed in place with a quoted operand",
            ),
            ("echo x > src/a.ts".into(), "redirect over a tracked file"),
            ("echo hack >| src/a.ts".into(), "clobber-override redirect"),
            (
                "echo hack>|src/a.ts".into(),
                "no-space clobber-override redirect",
            ),
            (
                "cat new >> skills/x/SKILL.md".into(),
                "append to a tracked file",
            ),
            (
                "node -e \"require('fs').writeFileSync('src/a.ts','x')\"".into(),
                "node -e writing a tracked file",
            ),
            (
                "cat > src/a.ts <<'EOF'\nx\nEOF".into(),
                "cat writing a tracked file through a heredoc",
            ),
            (
                "tee src/a.ts <<'EOF'\nx\nEOF".into(),
                "tee writing a tracked file through a heredoc",
            ),
            ("cp /tmp/a.ts src/a.ts".into(), "cp over a tracked file"),
            (
                "cp /tmp/a.ts src/".into(),
                "cp into a directory where the name is tracked",
            ),
            (
                "mv /tmp/Makefile .".into(),
                "mv into the root where the name is tracked",
            ),
            (
                "sed \"-i\" -e s/a/b/ src/a.ts".into(),
                "a quoted -i is still in place",
            ),
            (
                "sed -e s/a/b/ -i src/a.ts".into(),
                "-i after the script operand is still in place",
            ),
            (
                "python3 -c \"import pathlib; pathlib.Path('src/a.ts').write_text('x')\"".into(),
                "write_text with a literal tracked path",
            ),
            (
                "sudo tee src/a.ts <<'EOF'\nx\nEOF".into(),
                "sudo in front of tee",
            ),
            (
                "env FOO=1 tee src/a.ts <<'EOF'\nx\nEOF".into(),
                "env with an assignment in front of tee",
            ),
            (
                "timeout 5 tee src/a.ts <<'EOF'\nx\nEOF".into(),
                "timeout in front of tee",
            ),
            (
                "bash -c 'echo x > src/a.ts'".into(),
                "an inline shell script",
            ),
            ("eval 'echo x > src/a.ts'".into(), "eval of a string"),
            (
                "bash <<'EOF'\necho x > src/a.ts\nEOF".into(),
                "a shell fed by a heredoc",
            ),
            (
                "bash -lc 'echo x > src/a.ts'".into(),
                "an inline script behind a bundled -lc flag",
            ),
            ("sed -Ei 's/a/b/' src/a.ts".into(), "sed -Ei is in place"),
            (
                "(cd src && echo x > a.ts)".into(),
                "a cd inside a subshell applies to the subshell",
            ),
            (
                "xargs -n 1 tee src/a.ts".into(),
                "xargs with a value flag in front of tee",
            ),
            (
                "env -u VAR tee src/a.ts".into(),
                "env with a value flag in front of tee",
            ),
            (
                format!(
                    "cd \"$SOMEWHERE\" && echo x > {}",
                    d.join("src/a.ts").display()
                ),
                "an absolute target after a cd to an unknown place",
            ),
        ] {
            assert!(denied(&cmd, d), "should deny: {why}");
        }
    }

    #[test]
    fn reads_new_files_scripts_and_other_tools_are_allowed() {
        let r = repo();
        let d = &r.0;
        let outside = std::env::temp_dir().join(format!("warden-out-{}.json", std::process::id()));
        for (cmd, why) in [
            (
                format!("python3 - <<'PY'\np='{}'\nprint(len(open(p).read()))\nPY", d.join("skills/x/SKILL.md").display()),
                "python heredoc that names a tracked file but only reads it",
            ),
            ("cp dist/* public/".into(), "a glob source into a directory"),
            ("mv build/* .".into(), "a glob source into the root"),
            (
                "(cd src && ls) && echo x > a.ts".into(),
                "a cd inside a subshell does not leak out",
            ),
            (
                "(cd frontend && npm run build) && cp frontend/dist/index.html public/index.html".into(),
                "a subshell cd followed by a copy to a new file",
            ),
            ("gh pr create --body-file - <<'EOF'\nOperators must edit src/a.ts before deploying.\nEOF".into(), "a pull-request body that merely names a tracked file"),
            ("gh issue create --title x --body-file - <<'EOF'\nskills/x/SKILL.md is where this lives.\nEOF".into(), "an issue body naming a tracked file"),
            ("psql -f - <<'SQL'\n-- see src/a.ts\nSQL".into(), "a heredoc feeding a database client"),
            (format!("python3 - <<'PY'\nopen('{}', 'w').write('{{}}')\nPY", outside.display()), "a python program writing to a literal path outside any repository"),
            ("python3 - <<'PY'\nprint(open('src/a.ts').read())\nPY".into(), "a python program that only reads"),
            ("python3 -c \"print(1 + 1)\"".into(), "python computing without writing"),
            ("python3 -c \"import sys; sys.stdout.write('hi')\"".into(), "writing to stdout is not a file write"),
            ("python3 -c \"import sys; print('x', file=sys.stderr)\"".into(), "print to stderr is not a file write"),
            (
                format!("python3 - <<'PY'\nimport json\nd=json.load(open('src/config.json'))\nopen('{}','w').write(json.dumps(d))\nPY", outside.display()),
                "reading a tracked file and writing outside the repository",
            ),
            (
                "python3 - <<'PY'\nfor f in ['a','b','c']:\n    open('src/' + f + '.spec.ts', 'w').write('x')\nPY".into(),
                "a path built at runtime is unknown, and unknown fails open",
            ),
            (
                "node -e \"const fs=require('fs'); ['a','b'].forEach(n=>fs.writeFileSync(n+'.ts','x'))\"".into(),
                "node building filenames in a loop is unknown, and unknown fails open",
            ),
            ("cp /tmp/new.ts src/".into(), "copying a new file into a tracked directory"),
            ("rsync -a build/ src/".into(), "syncing into a directory"),
            ("install -m755 /tmp/x bin/".into(), "installing a new file into a directory"),
            ("mkdir -p build && cd build && echo x > Makefile".into(), "a new Makefile in a directory that does not exist yet"),
            ("cd \"$SOMEWHERE\" && echo x > src/a.ts".into(), "a relative target after a cd to an unknown place is unknown, and unknown fails open"),
            ("bash src/run-me.sh >/dev/null".into(), "running a tracked script and discarding its output"),
            ("bash authorize.sh \"some words\" abc123 >/dev/null".into(), "the pattern that renews a guard's own authorization"),
            ("bash skills/x/build.sh 2>&1 | tail -5".into(), "running a tracked script and piping its output"),
            ("bash -c 'cat src/a.ts | wc -l'".into(), "an inline script that only reads"),
            ("cat src/a.ts > /dev/null".into(), "reading a tracked file into /dev/null"),
            ("grep -n foo src/a.ts".into(), "grep of a tracked file"),
            ("cat skills/x/SKILL.md | head -5".into(), "reading a tracked file"),
            ("sed -n '1,5p' src/a.ts".into(), "sed without -i"),
            ("sed -n '1,5p' skills/principal-engineer/SKILL.md".into(), "a sed read of a tracked path containing -engi"),
            ("echo x > untracked.txt".into(), "redirect over an untracked file"),
            ("echo x > src/brand-new.ts".into(), "writing a new file"),
            (format!("echo x > {}", outside.display()), "redirect outside the repo"),
            ("git add -A && git commit -m x".into(), "git itself"),
            ("npm test 2>&1 | tail -5".into(), "a test run"),
            ("perl -MFile::Find -e print".into(), "perl -MFile::Find is not an in-place edit"),
            ("perl -Ilib/inc -e print".into(), "perl -Ilib/inc is not an in-place edit"),
            ("v=$(git rev-parse --show-toplevel 2>/dev/null)".into(), "command substitution 2>/dev/null is not a write"),
            ("awk '$3 > 100 {print}' src/a.ts".into(), "an awk comparison is not a redirect"),
            ("grep -rn 'a => b' src/".into(), "a => arrow is not a redirect"),
            ("sudo -u app cat src/a.ts".into(), "sudo with a user in front of a read"),
        ] {
            assert!(!denied(&cmd, d), "should allow: {why}");
        }
    }

    #[test]
    fn a_cd_moves_the_base_for_what_follows() {
        let home = repo();
        let other = TempRepo::new("policy-other");
        other.commit_file("src/unique-to-other.spec.ts", "export const z = 1;\n");
        let o = other.0.display();
        assert!(denied(
            &format!("cd {o} && perl -0777 -i -pe 's/a/b/' src/unique-to-other.spec.ts"),
            &home.0
        ));
        assert!(denied(
            &format!("cd {o} && sed -i '' 's/a/b/' src/unique-to-other.spec.ts"),
            &home.0
        ));
        assert!(denied(
            &format!("cd {o} && echo x > src/unique-to-other.spec.ts"),
            &home.0
        ));
        assert!(!denied(
            &format!("cd {o} && grep -n z src/unique-to-other.spec.ts"),
            &home.0
        ));
        assert!(!denied(
            &format!("cd {o} && echo x > src/brand-new.ts"),
            &home.0
        ));
        assert!(!denied(
            &format!("cd {o} && bash src/unique-to-other.spec.ts >/dev/null"),
            &home.0
        ));
    }

    #[test]
    fn the_denial_names_the_file_and_the_way_forward() {
        let r = repo();
        let Decision::Deny { guard, reason } = judge("echo x > src/a.ts", &r.0) else {
            panic!("expected a denial");
        };
        assert_eq!(guard, "write");
        assert!(reason.contains("src/a.ts"));
        assert!(reason.contains("one file at a time"));
        assert!(reason.contains("warden approve --session s"));
        assert!(reason.split_whitespace().count() < 60);
    }

    #[test]
    fn file_tool_actions_are_not_judged_by_this_rule() {
        let r = repo();
        let req = Request {
            action: Action::Write {
                path: r.0.join("src/a.ts"),
            },
            actor: Actor {
                name: "main".into(),
                read_only: false,
            },
            session: "s".into(),
            cwd: r.0.clone(),
            scratch: None,
            mode: Mode::Act,
        };
        assert_eq!(decide(&req), Decision::Allow);
    }
}
