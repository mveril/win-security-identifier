# win-security-identifier

A Rust library for manipulating and representing Windows Security Identifiers (SIDs) with zero-copy views and const/stack/heap variants.

## Features

- **Zero-copy SID view** (`Sid`).
- **Owned heap-allocated SID** (`SecurityIdentifier`).
- **Constant SID usable in `const` contexts** (`ConstSid<N>`).
- **Stack-allocated SID** (`StackSid`).
- **Authority types and parsing utilities.**
- **Local Windows account lookup** via `LookupAccountSidW` (available only on `cfg(windows)` with the `std` feature enabled).
- **Optional features:**
  - `std` - provide std support
    - `alloc` - enabled by default with std provide heap allocation support.
  - `macro` — provides a convenient compile-time SID builder.  
  - `serde` — enables serialization and deserialization support.

## Build & Test

Build the entire workspace:

```sh
cargo build --workspace
```

Run the test suite:

```sh
cargo test --workspace
```

Enable the macro feature:

```sh
cargo build --features macro
```

Enable Serde support:

```sh
cargo build --features serde
```

## Quick Examples

### Create an owned SID

```rust
use win_security_identifier::{
    security_identifier::SecurityIdentifier,
    sid_identifier_authority::SidIdentifierAuthority,
};

let sid = SecurityIdentifier::try_new(
    1,
    SidIdentifierAuthority::NT_AUTHORITY,
    &[32u32, 544u32],
).unwrap();

println!("{}", sid); // S-1-5-32-544
```

### Resolve a local SID (Windows only)

```rust
let sid = /* some Sid instance */;
let res = sid.lookup_local_sid().unwrap().unwrap();
println!("{}", res.domain_name);
```

## Notes

- Windows system APIs are only available on the Windows platform.  
- Designed to minimize unnecessary copies while supporting const, stack, and heap usage scenarios.

## Contribution Guidelines

- Fork the repository, make your changes, and open a pull request.  
- Run the full test suite with `cargo test`.  
- Follow workspace linting rules (see `Cargo.toml`).

## License

Dual-licensed under **MIT** or **Apache-2.0**. See `Cargo.toml` for details.
