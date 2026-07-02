## Summary

- Describe the change in a few sentences.
- Explain the motivation or user impact.

## Changes

- What was added, changed, or removed?
- Note any API, feature, behavioral, or breaking changes.

## Components Touched

- [ ] Public API
- [ ] Parsing
- [ ] Proc macro
- [ ] Windows-only API
- [ ] Unsafe code
- [ ] Serialization
- [ ] Documentation
- [ ] CI / release workflow
- [ ] AGENTS.md instructions

## Validation

- [ ] `cargo test --workspace --all-features`
- [ ] `cargo test --workspace --no-default-features`
- [ ] `cargo clippy --workspace --all-targets --all-features`
- [ ] `cargo fmt --all -- --check`
- [ ] MSRV validated with cargo-msrv on Windows when relevant
- [ ] Relevant manual testing completed

## Windows Notes

- Does this affect Windows-only SID lookup, FFI, or platform-specific behavior?
- If yes, describe what was tested and in which environment.

## Checklist

- [ ] Tests added or updated when relevant
- [ ] Documentation updated when relevant
- [ ] No unrelated changes included
