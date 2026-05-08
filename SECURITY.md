# Security Policy

## Supported Versions

Security fixes are handled on the currently maintained development and release branches.

For published crates, report vulnerabilities against the latest released version unless the issue is only present on an unreleased branch.

## Reporting a Vulnerability

Please do not open a public GitHub issue for a suspected vulnerability.

Report security issues privately through GitHub Security Advisories when available, or contact the maintainer listed in [Cargo.toml](Cargo.toml).

Include as much detail as possible:

- Affected crate, feature, module, or workflow.
- Reproduction steps.
- Expected and actual behavior.
- Impact on SID parsing, binary representation, Windows account lookup, or serialization.
- Whether the issue requires Windows-specific behavior or elevated privileges.

## Scope

Security-sensitive areas include:

- SID parsing and formatting.
- Binary SID layout validation.
- Unsafe blocks and FFI boundaries.
- Windows account lookup APIs.
- Serialization and deserialization.
- CI or release automation that publishes crates or artifacts.

Do not commit private keys, generated credentials, machine-specific paths, or local secrets.
