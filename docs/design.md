# Warden: design

## What it is

A policy engine for actions that a shell command or a file write would take.
Given an action and who is asking, it says allow or deny, with a reason, and
logs every answer. The first consumer is a Claude Code pre-tool hook. The core
has no knowledge of any agent.

## Why

Seven bash guards protect one engineer's repositories today. They work, and
they share one library because the same bug appeared three times when each
had its own copy. They parse shell with regular expressions, which false-
positives on paths that contain a flag, on comparisons that look like
redirects, and on heredoc text that names a file. A parser fixes that class
of defect once.

## First user and v1

First user: the author, daily, through Claude Code.
Done for v1: `warden check` replaces the kit's write-guard with zero
disagreements over one week of real sessions, and the kit's hook calls the
binary.

## Requirements

- Decide in under 50 ms per action on a laptop (a hook runs before every tool call).
- An allow costs the caller nothing: no output, no tokens. A deny costs one short reason that names the target and the way forward, so the next step is a single retry. A false denial is a defect. The first rule ships blocking because every case of the bash guard's suite passes against it; every later rule runs in shadow mode and its disagreements are counted before it may block. Anything the engine cannot resolve, a path after a `cd` to a variable or a filename built at runtime, is unknown, and unknown fails open.
- Single static binary, no runtime dependencies; `git` on PATH is the one external tool.
- Every allow and deny is appended to a JSONL log with actor, session, action, intent, decision, reason.
- Approvals are per session, exact-match, and expire after 12 hours.
- Policy is a file in the repository and a file in the user's home; the repository copy counts only once committed.

## Model

An **action** is one of: run a command, write a path, read a path.
It carries an **actor** (name, read-only or not), a **session** id, the
working directory, the scratch directory if the host has one, and a
**mode** (plan or act). Which repository owns a path is a question for
evidence, not something the host is trusted to say.

The engine turns a command into **segments**, each with an **intent**:
read, write (with targets), rewrite of a tracked file, remote, destructive,
machine-changing, or push. A **policy** maps intents and targets to a
decision. An **evidence** interface answers questions the policy needs from
outside: is this path tracked by git, which repository owns it, is there an
approval, was a plan logged recently.

Adapters translate a host's request into an action and the decision back.
Claude Code's hook is first. Cursor, OpenAI Codex CLI, Gemini CLI and GitHub
Copilot CLI each expose a pre-tool hook with the same shape, and Codex and
Copilot use the same decision vocabulary as Claude Code. An MCP server, a
shell wrapper and a CI lint follow.

## Flows

1. Hook: stdin JSON → action → parse → classify → evaluate → decision JSON on stdout, one log line appended.
2. Approval: `warden approve --session <id> "<user's words>" <path>` records the resolved path; the next check that would deny that path in that session allows it, for 12 hours.

## Failure modes

- Parse failure: allow, log `unparsed`, count it. Shadow mode makes the count visible; v1 revisits fail-open once the count is known.
- Missing `git`: path questions answer "unknown"; the policy treats unknown as not tracked.
- Log not writable: decide anyway, print a warning to stderr.
- A block is exit code 2 with the decision JSON on stdout. Exit 1 without JSON lets the tool run. A missing binary is exit 127 and a silently open gate, so the installer verifies the path and a test covers the exit code.

## Rejected

- Keep the bash guards: the regex defects above, and three copies of the same resolution logic is where the bugs came from.
- Hand-written parser: rewriting what tree-sitter-bash already does, with fewer tests.
- Build inside the engineering kit: the kit is private; this is public. The kit is a consumer.

## Milestones

1. Walking skeleton: `warden check` with write-guard semantics, the kit's write-guard cases ported as tests, CI, a release binary.
2. Shadow mode: run beside the bash guard, log disagreements, fix until zero.
3. The remaining guards: machine, plan, push, agent, impact, kit.
4. Shell wrapper adapter for a human terminal.
5. Release 1.0: README quick start, demo recording, CONTRIBUTING.

## Guard rails

Scratch repositories only for testing. No real command logs, hostnames or
paths from work as fixtures. Toolchain: stable Rust, edition 2024, rustc 1.85
or later.
