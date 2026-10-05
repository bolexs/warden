use tree_sitter::{Node, Parser};

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Parsed {
    pub commands: Vec<SimpleCommand>,
    pub had_error: bool,
    pub scopes: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SimpleCommand {
    pub name: Option<String>,
    pub args: Vec<Word>,
    pub redirects: Vec<Redirect>,
    pub heredocs: Vec<String>,
    pub scope: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Word {
    pub text: String,
    pub quoted: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Redirect {
    pub op: String,
    pub descriptor: Option<String>,
    pub target: Word,
}

pub fn parse(text: &str) -> Parsed {
    let mut parser = Parser::new();
    parser
        .set_language(&tree_sitter_bash::LANGUAGE.into())
        .expect("the bash grammar matches the tree-sitter runtime");
    let Some(tree) = parser.parse(text, None) else {
        return Parsed {
            commands: Vec::new(),
            had_error: true,
            scopes: 0,
        };
    };
    let root = tree.root_node();
    let mut parsed = Parsed {
        commands: Vec::new(),
        had_error: root.has_error(),
        scopes: 0,
    };
    walk(root, text.as_bytes(), &mut parsed, 0);
    parsed
}

fn walk(node: Node, src: &[u8], parsed: &mut Parsed, scope: u32) {
    match node.kind() {
        "command" => {
            let cmd = command(node, src, parsed, scope);
            parsed.commands.push(cmd);
        }
        "redirected_statement" => redirected(node, src, parsed, scope),
        "subshell" | "command_substitution" => {
            parsed.scopes += 1;
            let inner = parsed.scopes;
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                walk(child, src, parsed, inner);
            }
        }
        _ => {
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                walk(child, src, parsed, scope);
            }
        }
    }
}

fn command(node: Node, src: &[u8], parsed: &mut Parsed, scope: u32) -> SimpleCommand {
    let mut cmd = SimpleCommand {
        scope,
        ..SimpleCommand::default()
    };
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        match child.kind() {
            "command_name" => {
                walk(child, src, parsed, scope);
                let mut inner = child.walk();
                cmd.name = child
                    .named_children(&mut inner)
                    .next()
                    .map(|n| word(n, src).text);
            }
            "file_redirect" => {
                let r = redirect(child, src, parsed, scope);
                cmd.redirects.push(r);
            }
            "herestring_redirect" | "variable_assignment" => walk(child, src, parsed, scope),
            _ => {
                walk(child, src, parsed, scope);
                cmd.args.push(word(child, src));
            }
        }
    }
    cmd
}

fn redirected(node: Node, src: &[u8], parsed: &mut Parsed, scope: u32) {
    let mut before = parsed.commands.len();
    let body = node.child_by_field_name("body");
    if let Some(body) = body {
        walk(body, src, parsed, scope);
    }
    let end = parsed.commands.len();
    if body.is_some_and(|b| matches!(b.kind(), "list" | "pipeline")) && end > before {
        before = end - 1;
    }
    let mut redirects = Vec::new();
    let mut heredocs = Vec::new();
    let mut deferred = Vec::new();
    let mut dropped = uncovered_words(node, src);
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        match child.kind() {
            "file_redirect" => {
                let r = redirect(child, src, parsed, scope);
                redirects.push(r);
            }
            "heredoc_redirect" => {
                dropped.extend(uncovered_words(child, src));
                let mut inner = child.walk();
                for part in child.children(&mut inner) {
                    match part.kind() {
                        "heredoc_body" => {
                            walk(part, src, parsed, scope);
                            heredocs.push(text(part, src).to_string());
                        }
                        "file_redirect" => {
                            let r = redirect(part, src, parsed, scope);
                            redirects.push(r);
                        }
                        "heredoc_start" | "heredoc_end" => {}
                        _ if part.is_named() => deferred.push(part),
                        _ => {
                            if let Some(glued) = text(part, src).strip_suffix(part.kind()) {
                                push_words(glued, &mut dropped);
                            }
                        }
                    }
                }
            }
            _ => {}
        }
    }
    if end > before {
        for cmd in &mut parsed.commands[before..end] {
            cmd.args.extend(dropped.iter().cloned());
            cmd.redirects.extend(redirects.iter().cloned());
            cmd.heredocs.extend(heredocs.iter().cloned());
        }
    } else {
        parsed.commands.push(SimpleCommand {
            name: None,
            args: dropped,
            redirects,
            heredocs,
            scope,
        });
    }
    for part in deferred {
        walk(part, src, parsed, scope);
    }
}

fn uncovered_words(node: Node, src: &[u8]) -> Vec<Word> {
    let mut words = Vec::new();
    let mut pos = node.start_byte();
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        push_gap(src, pos, child.start_byte(), &mut words);
        pos = child.end_byte();
    }
    push_gap(src, pos, node.end_byte(), &mut words);
    words
}

fn push_gap(src: &[u8], from: usize, to: usize, words: &mut Vec<Word>) {
    if from >= to {
        return;
    }
    let Ok(gap) = std::str::from_utf8(&src[from..to]) else {
        return;
    };
    push_words(gap, words);
}

fn push_words(gap: &str, words: &mut Vec<Word>) {
    words.extend(gap.split_whitespace().map(|t| Word {
        text: t.to_string(),
        quoted: false,
    }));
}

fn redirect(node: Node, src: &[u8], parsed: &mut Parsed, scope: u32) -> Redirect {
    let mut op = String::new();
    let mut descriptor = None;
    let mut target = Word {
        text: String::new(),
        quoted: false,
    };
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if !child.is_named() {
            op = child.kind().to_string();
        } else if child.kind() == "file_descriptor" {
            descriptor = Some(text(child, src).to_string());
        } else {
            walk(child, src, parsed, scope);
            if target.text.is_empty() {
                target = word(child, src);
            }
        }
    }
    Redirect {
        op,
        descriptor,
        target,
    }
}

fn word(node: Node, src: &[u8]) -> Word {
    match node.kind() {
        "raw_string" => Word {
            text: unquote(text(node, src), '\''),
            quoted: true,
        },
        "string" | "translated_string" => Word {
            text: unquote(text(node, src), '"'),
            quoted: true,
        },
        "ansi_c_string" => Word {
            text: unquote(text(node, src), '\''),
            quoted: true,
        },
        "concatenation" => {
            let mut cursor = node.walk();
            let text = node
                .named_children(&mut cursor)
                .map(|n| word(n, src).text)
                .collect::<String>();
            Word {
                text,
                quoted: false,
            }
        }
        _ => Word {
            text: text(node, src).to_string(),
            quoted: false,
        },
    }
}

fn unquote(s: &str, quote: char) -> String {
    let s = s.strip_prefix('$').unwrap_or(s);
    s.strip_prefix(quote)
        .and_then(|s| s.strip_suffix(quote))
        .unwrap_or(s)
        .to_string()
}

fn text<'a>(node: Node, src: &'a [u8]) -> &'a str {
    node.utf8_text(src).unwrap_or("")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn names(p: &Parsed) -> Vec<Option<&str>> {
        p.commands.iter().map(|c| c.name.as_deref()).collect()
    }

    fn args(c: &SimpleCommand) -> Vec<&str> {
        c.args.iter().map(|w| w.text.as_str()).collect()
    }

    #[test]
    fn a_plain_command_has_a_name_and_arguments() {
        let p = parse("ls -la /tmp");
        assert!(!p.had_error);
        assert_eq!(names(&p), vec![Some("ls")]);
        assert_eq!(args(&p.commands[0]), vec!["-la", "/tmp"]);
        assert!(p.commands[0].redirects.is_empty());
    }

    #[test]
    fn lists_and_pipelines_keep_every_command_in_order() {
        let p = parse("cat f | tee g && echo done; rm -rf h || true");
        assert_eq!(
            names(&p),
            vec![
                Some("cat"),
                Some("tee"),
                Some("echo"),
                Some("rm"),
                Some("true")
            ]
        );
    }

    #[test]
    fn a_redirect_belongs_to_its_command() {
        let p = parse("echo x > out.txt");
        let r = &p.commands[0].redirects;
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].op, ">");
        assert_eq!(r[0].target.text, "out.txt");
        assert!(!r[0].target.quoted);
    }

    #[test]
    fn clobber_append_and_descriptor_forms_are_read() {
        assert_eq!(parse("echo x >| f").commands[0].redirects[0].op, ">|");
        assert_eq!(parse("echo x >> f").commands[0].redirects[0].op, ">>");
        let p = parse("echo $(cat f 2>/dev/null)");
        let cat = p
            .commands
            .iter()
            .find(|c| c.name.as_deref() == Some("cat"))
            .unwrap();
        assert_eq!(cat.redirects[0].op, ">");
        assert_eq!(cat.redirects[0].descriptor.as_deref(), Some("2"));
        assert_eq!(cat.redirects[0].target.text, "/dev/null");
    }

    #[test]
    fn a_quoted_target_is_unquoted_and_marked() {
        let p = parse(r#"echo x > "$HOME/.zshrc""#);
        let r = &p.commands[0].redirects[0];
        assert_eq!(r.target.text, "$HOME/.zshrc");
        assert!(r.target.quoted);
    }

    #[test]
    fn text_inside_quotes_is_never_a_redirect() {
        let p = parse("awk 'NR>=184' f");
        assert_eq!(names(&p), vec![Some("awk")]);
        assert!(p.commands[0].redirects.is_empty());
        assert_eq!(args(&p.commands[0]), vec!["NR>=184", "f"]);
        assert!(p.commands[0].args[0].quoted);
    }

    #[test]
    fn a_heredoc_body_is_captured_with_the_redirect_before_it() {
        let p = parse("cat > src/a.ts <<'EOF'\nx\nEOF");
        assert_eq!(names(&p), vec![Some("cat")]);
        let c = &p.commands[0];
        assert_eq!(c.redirects[0].target.text, "src/a.ts");
        assert_eq!(c.heredocs.len(), 1);
        assert_eq!(c.heredocs[0].trim(), "x");
    }

    #[test]
    fn an_interpreter_program_arrives_as_a_heredoc() {
        let p = parse("python3 - <<'PY'\nopen('f','w').write('x')\nPY");
        let c = &p.commands[0];
        assert_eq!(c.name.as_deref(), Some("python3"));
        assert_eq!(args(c), vec!["-"]);
        assert!(c.heredocs[0].contains("open('f','w')"));
    }

    #[test]
    fn a_lone_dash_before_a_redirect_is_kept() {
        let p = parse("python3 - 2>&1 <<'EOF'\nx\nEOF");
        let c = &p.commands[0];
        assert_eq!(args(c), vec!["-"]);
        assert_eq!(c.redirects[0].op, ">&");
        assert_eq!(c.redirects[0].descriptor.as_deref(), Some("2"));
        assert_eq!(c.heredocs.len(), 1);
        let p = parse("cmd -<<'EOF'\nx\nEOF");
        assert_eq!(args(&p.commands[0]), vec!["-"]);
    }

    #[test]
    fn commands_after_a_cd_are_still_separate() {
        let p = parse("cd /x && echo y > f");
        assert_eq!(names(&p), vec![Some("cd"), Some("echo")]);
        assert_eq!(args(&p.commands[0]), vec!["/x"]);
        assert_eq!(p.commands[1].redirects[0].target.text, "f");
    }

    #[test]
    fn a_quoted_command_name_is_unquoted() {
        assert_eq!(names(&parse(r#""git" push"#)), vec![Some("git")]);
    }

    #[test]
    fn a_path_containing_a_flag_is_an_argument_not_an_option() {
        let p = parse("sed -n '1,5p' skills/principal-engineer/SKILL.md");
        assert_eq!(
            args(&p.commands[0]),
            vec!["-n", "1,5p", "skills/principal-engineer/SKILL.md"]
        );
    }

    #[test]
    fn commands_nested_anywhere_are_found() {
        assert!(names(&parse("X=$(cat f > t) true")).contains(&Some("cat")));
        assert!(names(&parse("$(echo rm) -rf x")).contains(&Some("echo")));
        assert!(names(&parse("cat <<EOF\n$(rm x)\nEOF")).contains(&Some("rm")));
        let p = parse(r#"echo x > "$(date).log""#);
        assert_eq!(names(&p), vec![Some("echo"), Some("date")]);
        assert_eq!(p.commands[0].redirects[0].target.text, "$(date).log");
        assert!(p.commands[1].redirects.is_empty());
    }

    #[test]
    fn dollar_quoted_strings_are_quoted_words() {
        let p = parse("echo $'a>b' $\"c>d\"");
        assert_eq!(args(&p.commands[0]), vec!["a>b", "c>d"]);
        assert!(p.commands[0].args.iter().all(|w| w.quoted));
        assert!(p.commands[0].redirects.is_empty());
    }

    #[test]
    fn a_redirect_on_a_compound_body_reaches_every_command_in_it() {
        let p = parse("{ a; b; } > f");
        assert_eq!(names(&p), vec![Some("a"), Some("b")]);
        for c in &p.commands {
            assert_eq!(c.redirects[0].target.text, "f");
        }
    }

    #[test]
    fn commands_in_a_subshell_or_substitution_carry_their_own_scope() {
        let p = parse("(cd src && ls) && echo $(cat x) > f");
        let scopes: Vec<(Option<&str>, u32)> = p
            .commands
            .iter()
            .map(|c| (c.name.as_deref(), c.scope))
            .collect();
        assert_eq!(
            scopes,
            vec![
                (Some("cd"), 1),
                (Some("ls"), 1),
                (Some("cat"), 2),
                (Some("echo"), 0)
            ]
        );
        assert_eq!(p.scopes, 2);
    }

    #[test]
    fn a_redirect_after_a_list_or_pipeline_belongs_to_the_last_command_only() {
        for text in [
            "mkdir -p build && cd build && echo x > f",
            "a | b > f",
            "a; b > f",
        ] {
            let p = parse(text);
            let (last, rest) = p.commands.split_last().unwrap();
            assert_eq!(last.redirects[0].target.text, "f", "{text}");
            assert!(rest.iter().all(|c| c.redirects.is_empty()), "{text}");
        }
    }

    #[test]
    fn broken_input_is_flagged_but_still_returned() {
        let p = parse(r#"echo "unterminated"#);
        assert!(p.had_error);
    }
}
