//! Well-known SIDs definitions
//!
//! Source: https://learn.microsoft.com/windows/win32/secauthz/well-known-sids
//!
//! This module exposes all well-known SIDs as constants. Users do not need to
//! know the number of sub-authorities (`ConstSid<N>`), each SID is directly
//! accessible as a constant reference.

use crate::{ConstSid, SidIdentifierAuthority};

// ---- Basic Authorities ----

/// Null SID (S-1-0-0)
pub const NULL: ConstSid<1> = ConstSid::new(1, SidIdentifierAuthority::NULL_AUTHORITY, [0]);

/// World SID (S-1-1-0)
pub const WORLD: ConstSid<1> =
    ConstSid::new(1, SidIdentifierAuthority::SECURITY_WORLD_AUTHORITY, [0]);

/// Local SID (S-1-2-0)
pub const LOCAL: ConstSid<1> =
    ConstSid::new(1, SidIdentifierAuthority::SECURITY_LOCAL_AUTHORITY, [0]);

/// Creator Owner SID (S-1-3-0)
pub const CREATOR_OWNER: ConstSid<1> =
    ConstSid::new(1, SidIdentifierAuthority::SECURITY_CREATOR_AUTHORITY, [0]);

/// Creator Group SID (S-1-3-1)
pub const CREATOR_GROUP: ConstSid<1> =
    ConstSid::new(1, SidIdentifierAuthority::SECURITY_CREATOR_AUTHORITY, [1]);

// ---- NT Authority (S-1-5) ----

/// Local System (S-1-5-18)
pub const LOCAL_SYSTEM: ConstSid<1> = ConstSid::new(1, SidIdentifierAuthority::NT_AUTHORITY, [18]);

/// Local Service (S-1-5-19)
pub const LOCAL_SERVICE: ConstSid<1> = ConstSid::new(1, SidIdentifierAuthority::NT_AUTHORITY, [19]);

/// Network Service (S-1-5-20)
pub const NETWORK_SERVICE: ConstSid<1> =
    ConstSid::new(1, SidIdentifierAuthority::NT_AUTHORITY, [20]);

// ---- BUILTIN Domain (S-1-5-32) ----

/// BUILTIN\Administrators (S-1-5-32-544)
pub const BUILTIN_ADMINISTRATORS: ConstSid<2> =
    ConstSid::new(1, SidIdentifierAuthority::NT_AUTHORITY, [32, 544]);

/// BUILTIN\Users (S-1-5-32-545)
pub const BUILTIN_USERS: ConstSid<2> =
    ConstSid::new(1, SidIdentifierAuthority::NT_AUTHORITY, [32, 545]);

/// BUILTIN\Guests (S-1-5-32-546)
pub const BUILTIN_GUESTS: ConstSid<2> =
    ConstSid::new(1, SidIdentifierAuthority::NT_AUTHORITY, [32, 546]);

/// BUILTIN\Power Users (S-1-5-32-547)
pub const BUILTIN_POWER_USERS: ConstSid<2> =
    ConstSid::new(1, SidIdentifierAuthority::NT_AUTHORITY, [32, 547]);
