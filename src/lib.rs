//! # Windows Security Identifier (SID) primitives for Rust
//!
//! Low-level and ergonomic building blocks to work with Windows **SIDs**.
//! The crate provides:
//! - [`Sid`]: a `repr(C)` dynamically-sized view matching the Windows SID
//!   in-memory layout (header + trailing `[u32]` sub-authorities).
//! - [`SecurityIdentifier`]: an owned, heap-allocated SID with safe construction
//!   helpers and Windows token interop.
//! - [`ConstSid`]: a const-friendly, fixed-size SID (`N` sub-authorities) that
//!   can be embedded in static data and converted to a reference of [`Sid`].
//! - [`SidIdentifierAuthority`]: the 6-byte authority component of SIDs.
//! - (Windows) [`SidType`]: Rust enum mirroring `SID_NAME_USE` for account lookup.
//! - (Windows) [`DomainAndName`] and `SidLookupResult`: helpers for
//!   `LookupAccountSidW` to resolve `DOMAIN\Name`.
//!
//! ## Overview
//! - **Zero-copy access** to the binary representation via [`Sid::as_binary`].
//! - **Ownership & cloning** via [`SecurityIdentifier`] which manages allocation
//!   and deallocation safely.
//! - **Const construction** via [`ConstSid`], ideal for well-known SIDs.
//! - **Windows interop** (gated by `cfg(windows)`): token reading and account lookups.
//!
//! ## Safety
//! - [`Sid`] is a layout-sensitive DST; it is meant to be **owned** by higher-level
//!   types like [`SecurityIdentifier`]. Creating malformed instances or using
//!   buffers with the wrong size is **undefined behavior**.
//! - Functions marked `unsafe` (e.g., [`Sid::as_binary`]) require that the backing
//!   allocation and invariants are respected. See each item’s `# Safety` section.
//!
//! ## Layout & ABI
//! The memory layout of [`Sid`] matches Windows: a `repr(C)` header followed by
//! `sub_authority_count` 32-bit sub-authorities. Use [`Sid::get_current_min_layout`]
//! to compute the minimal [`Layout`] for a given instance. [`SecurityIdentifier`]
//! uses this to allocate correctly.
//!
//! ## Windows-only functionality
//! *Available behind `cfg(windows)`.*
//!
//! - [`SecurityIdentifier::get_current_user_sid`] reads the current process token
//!   and returns the user SID.
//! - `sid_lookup` module: resolves a [`Sid`] to `DOMAIN\Name` and a [`SidType`]
//!   (`SID_NAME_USE`) using `LookupAccountSidW`.
//!
//! ## Examples
//! ### Create a SID from parts
//! ```rust
//! use win_security_identifier::{SecurityIdentifier, SidIdentifierAuthority};
//!
//! let sid = SecurityIdentifier::try_new(
//!     1, // revision
//!     SidIdentifierAuthority::nt_authority(),
//!     [32u32, 544u32], // BUILTIN\Administrators => S-1-5-32-544
//! ).expect("valid SID");
//! assert_eq!(sid.to_string(), "S-1-5-32-544");
//! ```
//!
//! ### Use a const SID
//! ```rust
//! use win_security_identifier::{ConstSid, SidIdentifierAuthority};
//!
//! const ADMIN: ConstSid<2> = ConstSid::new(
//!     1,
//!     SidIdentifierAuthority::nt_authority(),
//!     [32, 544],
//! ).unwrap();
//!
//! // Convert to owned SID for operations that need ownership
//! let owned = win_security_identifier::SecurityIdentifier::from(ADMIN);
//! assert_eq!(owned.to_string(), "S-1-5-32-544");
//! ```
//!
//! ### (Windows) Get current user SID
//! ```no_run
//! # #[cfg(windows)]
//! # {
//! # use win_security_identifier::{SecurityIdentifier};
//! let sid = SecurityIdentifier::get_current_user_sid().unwrap();
//! println!("Current user SID: {sid}");
//! # }
//! ```
//!
//! ### (Windows) Resolve DOMAIN\\Name from a SID
//! ```no_run
//! # #[cfg(windows)]
//! # {
//! use win_security_identifier::{SecurityIdentifier, SidType};
//! // ... obtain a `SecurityIdentifier` or `&Sid` named `sid`
//! # use win_security_identifier::{SidIdentifierAuthority, ConstSid};
//! # let sid = win_security_identifier::SecurityIdentifier::from(ConstSid::<2>::new(
//! #     1, SidIdentifierAuthority::nt_authority(), [32, 544]
//! # ).unwrap());
//! let res = sid.lookup_local_sid().unwrap();
//! println!("{} => {}", sid, res.domain_name); // e.g. "MACHINE\\User"
//! // Optionally: map raw type to enum
//! # #[allow(unused)]
//! let sid_type = SidType::try_from(res.sid_type_raw).ok();
//! # }
//! ```
//!
//!
//! ## No-std?
//! Not supported. The crate relies on allocation and Windows FFI (on Windows).

#![warn(missing_docs)]
#![warn(rustdoc::missing_doc_code_examples)]
#![cfg_attr(not(feature = "std"), no_std)]
#![cfg_attr(docsrs, feature(doc_auto_cfg, doc_cfg))]
#[cfg(feature = "alloc")]
mod security_identifier;
mod sid;

#[cfg(feature = "alloc")]
pub use security_identifier::SecurityIdentifier;
#[cfg(all(windows, feature = "alloc"))]
pub use security_identifier::TokenError;
pub use sid::Sid;

#[cfg(not(has_ptr_metadata))]
pub(crate) mod polyfils_ptr;
mod sid_size_info;
pub(crate) use sid_size_info::SidSizeInfo;

#[cfg(all(feature = "alloc", not(feature = "std")))]
extern crate alloc;

mod sid_identifier_authority;
#[cfg(all(test, feature = "alloc"))]
pub(crate) use security_identifier::test::arb_security_identifier;

/// Identifier authority component of a SID (6-byte value).
///
/// See also: [`Sid::identifier_authority`], [`ConstSid::identifier_authority`].
pub use sid_identifier_authority::SidIdentifierAuthority;

#[cfg(test)]
pub(crate) use sid_identifier_authority::test::arb_identifier_authority;

mod const_sid;
pub mod internal;

/// Const-friendly fixed-size SID (`N` sub-authorities).
///
/// See [`ConstSid`] for invariants and examples.
pub use const_sid::ConstSid;
#[cfg(feature = "std")]
mod domain_and_name;

#[cfg(all(windows, feature = "std"))]
mod sid_lookup;

/// Pair `DOMAIN\Name` used when resolving a [`Sid`].
///
/// Constructed by Windows account lookup helpers on success.
#[cfg(feature = "std")]
pub use domain_and_name::DomainAndName;

#[cfg_attr(docsrs, doc(cfg(all(windows, feature = "std"))))]
#[cfg(all(windows, feature = "std"))]
pub use sid_lookup::SidLookupResult;

#[cfg(windows)]
mod sid_type;

#[cfg(windows)]
/// Rust representation of `SID_NAME_USE` (Windows).
///
/// Useful to interpret results of `LookupAccountSidW`.
pub use sid_type::SidType;

/// Internal utilities for validation and layout calculations.
pub(crate) mod utils;
