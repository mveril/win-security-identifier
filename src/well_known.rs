//! Well-known SIDs definitions
//!
//! Source: <https://learn.microsoft.com/windows/win32/secauthz/well-known-sids>
//!
//! This module exposes all well-known SIDs as constants. Users do not need to
//! know the number of sub-authorities (`ConstSid<N>`), each SID is directly
//! accessible as a constant reference.

use crate::{ConstSid, SidIdentifierAuthority};

// ---- Basic Authorities ----

/// Null SID (S-1-0-0)
pub const NULL: ConstSid<1> = ConstSid::new(SidIdentifierAuthority::NULL_AUTHORITY, [0]);

/// World SID (S-1-1-0)
pub const WORLD: ConstSid<1> = ConstSid::new(SidIdentifierAuthority::SECURITY_WORLD_AUTHORITY, [0]);

/// Local SID (S-1-2-0)
pub const LOCAL: ConstSid<1> = ConstSid::new(SidIdentifierAuthority::SECURITY_LOCAL_AUTHORITY, [0]);

/// Creator Owner SID (S-1-3-0)
pub const CREATOR_OWNER: ConstSid<1> =
    ConstSid::new(SidIdentifierAuthority::SECURITY_CREATOR_AUTHORITY, [0]);

/// Creator Group SID (S-1-3-1)
pub const CREATOR_GROUP: ConstSid<1> =
    ConstSid::new(SidIdentifierAuthority::SECURITY_CREATOR_AUTHORITY, [1]);

// ---- NT Authority (S-1-5) ----

/// Dialup logon SID (S-1-5-1)
pub const DIALUP: ConstSid<1> = ConstSid::new(SidIdentifierAuthority::NT_AUTHORITY, [1]);

/// Network logon SID (S-1-5-2)
pub const NETWORK: ConstSid<1> = ConstSid::new(SidIdentifierAuthority::NT_AUTHORITY, [2]);

/// Batch logon SID (S-1-5-3)
pub const BATCH: ConstSid<1> = ConstSid::new(SidIdentifierAuthority::NT_AUTHORITY, [3]);

/// Interactive logon SID (S-1-5-4)
pub const INTERACTIVE: ConstSid<1> = ConstSid::new(SidIdentifierAuthority::NT_AUTHORITY, [4]);

/// Service logon SID (S-1-5-6)
pub const SERVICE: ConstSid<1> = ConstSid::new(SidIdentifierAuthority::NT_AUTHORITY, [6]);

/// Anonymous logon SID (S-1-5-7)
pub const ANONYMOUS_LOGON: ConstSid<1> = ConstSid::new(SidIdentifierAuthority::NT_AUTHORITY, [7]);

/// Proxy SID (S-1-5-8)
pub const PROXY: ConstSid<1> = ConstSid::new(SidIdentifierAuthority::NT_AUTHORITY, [8]);

/// Enterprise domain controllers SID (S-1-5-9)
pub const ENTERPRISE_DOMAIN_CONTROLLERS: ConstSid<1> =
    ConstSid::new(SidIdentifierAuthority::NT_AUTHORITY, [9]);

/// Self SID (S-1-5-10)
pub const SELF_SID: ConstSid<1> = ConstSid::new(SidIdentifierAuthority::NT_AUTHORITY, [10]);

/// Authenticated Users SID (S-1-5-11)
pub const AUTHENTICATED_USERS: ConstSid<1> =
    ConstSid::new(SidIdentifierAuthority::NT_AUTHORITY, [11]);

/// Restricted Code SID (S-1-5-12)
pub const RESTRICTED_CODE: ConstSid<1> = ConstSid::new(SidIdentifierAuthority::NT_AUTHORITY, [12]);

/// Terminal Server Users SID (S-1-5-13)
pub const TERMINAL_SERVER_USERS: ConstSid<1> =
    ConstSid::new(SidIdentifierAuthority::NT_AUTHORITY, [13]);

/// Remote Interactive Logon SID (S-1-5-14)
pub const REMOTE_INTERACTIVE_LOGON: ConstSid<1> =
    ConstSid::new(SidIdentifierAuthority::NT_AUTHORITY, [14]);

/// Local System (S-1-5-18)
pub const LOCAL_SYSTEM: ConstSid<1> = ConstSid::new(SidIdentifierAuthority::NT_AUTHORITY, [18]);

/// Local Service (S-1-5-19)
pub const LOCAL_SERVICE: ConstSid<1> = ConstSid::new(SidIdentifierAuthority::NT_AUTHORITY, [19]);

/// Network Service (S-1-5-20)
pub const NETWORK_SERVICE: ConstSid<1> = ConstSid::new(SidIdentifierAuthority::NT_AUTHORITY, [20]);

// ---- BUILTIN Domain (S-1-5-32) ----

/// BUILTIN\Administrators (S-1-5-32-544)
pub const BUILTIN_ADMINISTRATORS: ConstSid<2> =
    ConstSid::new(SidIdentifierAuthority::NT_AUTHORITY, [32, 544]);

/// BUILTIN\Users (S-1-5-32-545)
pub const BUILTIN_USERS: ConstSid<2> =
    ConstSid::new(SidIdentifierAuthority::NT_AUTHORITY, [32, 545]);

/// BUILTIN\Guests (S-1-5-32-546)
pub const BUILTIN_GUESTS: ConstSid<2> =
    ConstSid::new(SidIdentifierAuthority::NT_AUTHORITY, [32, 546]);

/// BUILTIN\Power Users (S-1-5-32-547)
pub const BUILTIN_POWER_USERS: ConstSid<2> =
    ConstSid::new(SidIdentifierAuthority::NT_AUTHORITY, [32, 547]);

/// BUILTIN\Account Operators (S-1-5-32-548)
pub const BUILTIN_ACCOUNT_OPERATORS: ConstSid<2> =
    ConstSid::new(SidIdentifierAuthority::NT_AUTHORITY, [32, 548]);

/// BUILTIN\Server Operators (S-1-5-32-549)
pub const BUILTIN_SERVER_OPERATORS: ConstSid<2> =
    ConstSid::new(SidIdentifierAuthority::NT_AUTHORITY, [32, 549]);

/// BUILTIN\Print Operators (S-1-5-32-550)
pub const BUILTIN_PRINT_OPERATORS: ConstSid<2> =
    ConstSid::new(SidIdentifierAuthority::NT_AUTHORITY, [32, 550]);

/// BUILTIN\Backup Operators (S-1-5-32-551)
pub const BUILTIN_BACKUP_OPERATORS: ConstSid<2> =
    ConstSid::new(SidIdentifierAuthority::NT_AUTHORITY, [32, 551]);

/// BUILTIN\Replicator (S-1-5-32-552)
pub const BUILTIN_REPLICATOR: ConstSid<2> =
    ConstSid::new(SidIdentifierAuthority::NT_AUTHORITY, [32, 552]);

/// BUILTIN\Remote Desktop Users (S-1-5-32-555)
pub const BUILTIN_REMOTE_DESKTOP_USERS: ConstSid<2> =
    ConstSid::new(SidIdentifierAuthority::NT_AUTHORITY, [32, 555]);

/// BUILTIN\Network Configuration Operators (S-1-5-32-556)
pub const BUILTIN_NETWORK_CONFIGURATION_OPERATORS: ConstSid<2> =
    ConstSid::new(SidIdentifierAuthority::NT_AUTHORITY, [32, 556]);

/// BUILTIN\Performance Monitor Users (S-1-5-32-558)
pub const BUILTIN_PERFORMANCE_MONITOR_USERS: ConstSid<2> =
    ConstSid::new(SidIdentifierAuthority::NT_AUTHORITY, [32, 558]);

/// BUILTIN\Performance Log Users (S-1-5-32-559)
pub const BUILTIN_PERFORMANCE_LOG_USERS: ConstSid<2> =
    ConstSid::new(SidIdentifierAuthority::NT_AUTHORITY, [32, 559]);

/// BUILTIN\Distributed COM Users (S-1-5-32-562)
pub const BUILTIN_DISTRIBUTED_COM_USERS: ConstSid<2> =
    ConstSid::new(SidIdentifierAuthority::NT_AUTHORITY, [32, 562]);

/// BUILTIN\IIS_IUSRS (S-1-5-32-568)
pub const BUILTIN_IIS_IUSRS: ConstSid<2> =
    ConstSid::new(SidIdentifierAuthority::NT_AUTHORITY, [32, 568]);

// ---- Mandatory Integrity Levels (S-1-16) ----

const MANDATORY_LABEL_AUTHORITY: SidIdentifierAuthority =
    SidIdentifierAuthority::new([0, 0, 0, 0, 0, 16]);

/// Untrusted mandatory integrity level (S-1-16-0)
pub const INTEGRITY_UNTRUSTED: ConstSid<1> = ConstSid::new(MANDATORY_LABEL_AUTHORITY, [0]);

/// Low mandatory integrity level (S-1-16-4096)
pub const INTEGRITY_LOW: ConstSid<1> = ConstSid::new(MANDATORY_LABEL_AUTHORITY, [4096]);

/// Medium mandatory integrity level (S-1-16-8192)
pub const INTEGRITY_MEDIUM: ConstSid<1> = ConstSid::new(MANDATORY_LABEL_AUTHORITY, [8192]);

/// High mandatory integrity level (S-1-16-12288)
pub const INTEGRITY_HIGH: ConstSid<1> = ConstSid::new(MANDATORY_LABEL_AUTHORITY, [12288]);

/// System mandatory integrity level (S-1-16-16384)
pub const INTEGRITY_SYSTEM: ConstSid<1> = ConstSid::new(MANDATORY_LABEL_AUTHORITY, [16384]);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_added_nt_authority_sids() {
        assert_eq!(
            AUTHENTICATED_USERS.identifier_authority,
            SidIdentifierAuthority::NT_AUTHORITY
        );
        assert_eq!(AUTHENTICATED_USERS.sub_authorities, [11]);
        assert_eq!(
            REMOTE_INTERACTIVE_LOGON.identifier_authority,
            SidIdentifierAuthority::NT_AUTHORITY
        );
        assert_eq!(REMOTE_INTERACTIVE_LOGON.sub_authorities, [14]);
    }

    #[test]
    fn formats_added_builtin_alias_sids() {
        assert_eq!(BUILTIN_BACKUP_OPERATORS.sub_authorities, [32, 551]);
        assert_eq!(BUILTIN_REMOTE_DESKTOP_USERS.sub_authorities, [32, 555]);
        assert_eq!(BUILTIN_IIS_IUSRS.sub_authorities, [32, 568]);
    }

    #[test]
    fn formats_integrity_level_sids() {
        assert_eq!(
            INTEGRITY_UNTRUSTED.identifier_authority,
            MANDATORY_LABEL_AUTHORITY
        );
        assert_eq!(INTEGRITY_UNTRUSTED.sub_authorities, [0]);
        assert_eq!(INTEGRITY_LOW.sub_authorities, [4096]);
        assert_eq!(INTEGRITY_MEDIUM.sub_authorities, [8192]);
        assert_eq!(INTEGRITY_HIGH.sub_authorities, [12288]);
        assert_eq!(INTEGRITY_SYSTEM.sub_authorities, [16384]);
    }
}
