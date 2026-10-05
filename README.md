# warden

A policy engine for the shell commands and file writes that coding agents
run. Given one action and who is asking, it answers allow or deny with a
reason.

The first adapter is a [Claude Code](https://code.claude.com) pre-tool hook.
The core knows nothing about any agent, so the same engine can sit behind
Cursor, Codex CLI, Gemini CLI or Copilot CLI hooks, a shell wrapper, or a CI
lint.

## Status

Milestone 1 of 5. The hook adapter, the shell parser and the first policy
work: a shell command that would rewrite a file git already tracks is denied,
whether through a redirect, cp or tee, an in-place sed or perl, or an
interpreter program that writes files. Edits through the file tools, new
files, reads and scripts are allowed. Everything else is allowed until the
next rules land. See [docs/design.md](docs/design.md) for the plan.

## Install

From a release: download the tarball for your platform from the
[releases page](https://github.com/bolexs/warden/releases), verify it, and put
`warden` on your PATH.

    gh attestation verify warden-<target>.tar.gz --repo bolexs/warden

From source, with Rust 1.85 or later:

    cargo install --git https://github.com/bolexs/warden --locked

## Wire it into Claude Code

Add a PreToolUse hook to `~/.claude/settings.json`. The exec form runs the
binary directly, with no shell in between:

    {
      "hooks": {
        "PreToolUse": [
          {
            "matcher": "Bash|Edit|Write|MultiEdit|NotebookEdit",
            "hooks": [
              { "type": "command", "command": "/path/to/warden", "args": ["check"] }
            ]
          }
        ]
      }
    }

Contract: allow is silent with exit 0. Deny prints the hook decision JSON on
stdout and exits 2. Unreadable input warns on stderr; tools warden does not
judge are silent; both exit 0 and the tool runs. A missing binary is a
silently open gate, so check the path.

## When you want it allowed anyway

A denial names the file and the one command that lifts it for the current
session. When you tell the agent to go ahead, it records your words:

    warden approve --session <session-id> "<your words>" <path>

The same path is then allowed in that session for 12 hours. Approvals are
kept as JSON lines in `~/.warden/approvals.jsonl` (or `$WARDEN_STATE_DIR`),
with the session, the path, the time and your words, so the trail shows who
approved what. To switch the rule off for a whole run, set
`WARDEN_ALLOW_SHELL_WRITES=1` in the hook's environment.

Anything warden cannot resolve, a path after a `cd` to a variable or a file
name built at runtime, is unknown, and unknown is allowed. A wrong denial is a
bug: please report the exact command.

## How it works

1. The adapter turns the hook's JSON into a request: the action, the actor,
   the session, the working directory, the scratch directory and the mode.
2. The parser turns command text into simple commands with their arguments,
   redirects and heredoc bodies, using tree-sitter-bash. Text inside quotes is
   never mistaken for a path. Tokens the grammar drops are recovered.
3. The policy classifies each command and decides. A decision log is the
   next milestone.

## Develop

    cargo test
    cargo fmt --check
    cargo clippy --all-targets -- -D warnings

CI runs those on Linux and macOS, on stable and on 1.85, plus cargo-deny for
advisories and licences, and CodeQL. Releases are built on a version tag and
signed with GitHub build attestations.

See [CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md).

## Licence

Apache-2.0. See [LICENSE](LICENSE).
