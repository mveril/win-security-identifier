# Repository Guidelines

## Project Structure & Module Organization

This is a Cargo workspace for a Windows Security Identifier (SID) library. The main public crate is at the repository root in `src/`. The parsing support crate lives in `parsing/`, and the optional proc macro crate lives in `macro/`. Integration tests live in `tests/`.

For new modules, prefer modern Rust layout: create `src/foo.rs` with children under `src/foo/` instead of adding new `src/foo/mod.rs` files. Leave existing `mod.rs` files alone unless refactoring that module deliberately.

## Build, Test, and Development Commands

- `cargo build --workspace --all-features`: build every workspace crate.
- `cargo test --workspace --all-features`: run unit, integration, serde, and macro-enabled tests.
- `cargo test --workspace --no-default-features`: check the no-std-oriented configuration.
- `cargo clippy --workspace --all-targets --all-features`: run workspace lints.
- `cargo fmt --all -- --check`: verify formatting only.

Run `cargo publish --workspace --dry-run` only from release branches during release validation.

## Coding Style & Naming Conventions

Use Rust 2024 and the repository `rustfmt.toml` settings. Use `snake_case` for crates, modules, files, functions, methods, and variables; use `PascalCase` for public types and traits. Workspace lints deny `unwrap`, `expect`, `panic!`, `todo!`, `dbg!`, stdout/stderr printing, and process exits. Return typed errors and document unsafe blocks with `SAFETY:` comments.

Keep `no_std` support in mind. Use `core` by default, `alloc` only behind the `alloc` feature, and `std` only behind the `std` feature or platform-specific code that already requires it.

## Testing Guidelines

Place ordinary Rust tests next to the code or in crate-level `tests/` directories. Parsing behavior belongs close to the parsing crate when possible. Macro behavior should be covered through compile-time or integration tests that exercise the public macro entry points.

Name tests after behavior, for example `parses_nt_authority_builtin_administrators`.

## Git Flow & Pull Requests

Git Flow applies to published library crates: `develop` carries versioned crate work, while `main` remains the stable branch. Create `feature/*` and `fix/*` branches from `develop`, and target their pull requests back to `develop`. Use `release/*` branches for versioned release preparation, final validation, and publishing dry runs before merging to `main` and back to `develop`.

Always create pull requests from the repository PR template at [`.github/PULL_REQUEST_TEMPLATE.md`](.github/PULL_REQUEST_TEMPLATE.md), using `gh pr create --template .github/PULL_REQUEST_TEMPLATE.md` by default. Fall back to a manually filled PR body only when GitHub CLI is unavailable or not authenticated. Pull requests need a concise description, linked issue when applicable, test results, and Windows validation notes when a change affects Windows-only SID lookup or platform APIs. Update the template when the expected PR content changes.

## Commit Guidelines

Keep commits focused. Use short imperative or descriptive subjects, for example `Add SID serde roundtrip tests` or `Fix no-std parsing regression`. Explain API or behavior changes in the body when the subject is not enough.

## Security & Configuration Tips

Do not commit private keys, generated credentials, machine-specific paths, or local secrets. Treat Windows account lookup, FFI boundaries, and unsafe code as security-sensitive. Avoid adding panics to library code; prefer typed errors.
