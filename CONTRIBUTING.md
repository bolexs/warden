# Contributing

Thanks for looking. Warden is small and opinionated; the design is in
[docs/design.md](docs/design.md) and is the place to argue with before code.

## Set up

Stable Rust 1.85 or later via rustup. Then:

    cargo test
    cargo fmt --check
    cargo clippy --all-targets -- -D warnings

All three run in CI on Linux and macOS, on stable and on 1.85.

## Changes

- One change per pull request, with a test that fails without it.
- Commit messages follow Conventional Commits: `feat:`, `fix:`, `docs:`,
  `test:`, `ci:`, `chore:`. They become the changelog.
- No new dependency without a sentence on why in the pull request.
- Keep the core free of any agent's field names; those belong in an adapter.

## Reporting a parser gap

If a command parses wrong, open a bug with the exact command text. The
`had_error` flag and the dropped-token recovery in `src/shell.rs` show how
grammar defects are handled today.

## Security

See [SECURITY.md](SECURITY.md). Do not report bypasses in public issues.
