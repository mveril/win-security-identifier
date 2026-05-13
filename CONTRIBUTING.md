# Contributing

Thanks for considering a contribution to `win-security-identifier`.

This repository is a Cargo workspace for Rust crates that parse, represent, and work with Windows Security Identifiers. Changes should stay focused and preserve `no_std`, `alloc`, and Windows-only feature boundaries.

## Branches

Published library work follows Git Flow:

- Start feature and fix branches from `develop`.
- Target library pull requests back to `develop`.
- Merge pull requests with squash and merge.
- Use `release/*` branches for versioned release preparation and final validation.
- Keep `main` as the stable branch.

Documentation, CI, and repository-maintenance changes can use focused branch names such as `doc/*`, `ci/*`, or `chore/*`.

## Development

Use Rust 2024 and the repository formatting settings.

Before submitting a pull request, run the relevant checks:

```powershell
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features
cargo test --workspace --all-features
cargo test --workspace --no-default-features
```

Run:

```powershell
cargo publish --workspace --dry-run
```

only from `release/*` branches during release validation.

## Code Style

- Use `snake_case` for crates, modules, files, functions, methods, and variables.
- Use `PascalCase` for public types and traits.
- Return typed errors instead of panicking.
- Do not use `unwrap`, `expect`, `panic!`, `todo!`, `dbg!`, stdout/stderr printing, or process exits in library code.
- Document unsafe blocks with a `SAFETY:` comment.
- Use `core` where possible, `alloc` only behind the `alloc` feature, and `std` only where the crate feature requires it.

## Tests

Place ordinary Rust tests next to the implementation or in crate-level `tests/` directories. Put parsing-specific tests near the parsing crate when possible, and macro behavior tests where they exercise the public macro crate.

Name tests after behavior, for example:

```text
formats_builtin_administrators_sid
```

## Pull Requests

Good pull request descriptions usually include:

- A concise description of the change.
- API, behavior, feature, or compatibility changes, when relevant.
- Test results for the checks that were run.
- Windows validation notes when Windows-only SID lookup or platform APIs are affected.

Keep commits focused and avoid unrelated formatting or dependency churn.

## Security

Do not commit private keys, generated credentials, machine-specific paths, or local secrets.

Security-sensitive areas include unsafe code, SID parsing, binary representation, Windows API calls, and serialization or deserialization boundaries.
