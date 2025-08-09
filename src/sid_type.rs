use num_enum::{IntoPrimitive, TryFromPrimitive};

/// Values specify the type of a Security Identifier (SID) returned by APIs
/// like `LookupAccountSidW``.
/// # see also
/// See Microsoft docs for [SID_NAME_USE](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ne-winnt-sid_name_use).
#[derive(Debug, Clone, Copy, PartialEq, Eq, TryFromPrimitive, IntoPrimitive)]
#[repr(i32)]
pub enum SidType {
    /// A SID for a user account.
    User = 1,

    /// A SID for a group account.

    /// A SID that identifies a domain.
    Domain = 3,

    /// A SID for an alias (local group).
    Alias = 4,

    /// A well-known group SID (e.g., Everyone, LocalSystem).
    WellKnownGroup = 5,

    /// A SID for an account that has been deleted.
    DeletedAccount = 6,

    /// An invalid SID (not a valid account/domain SID).
    Invalid = 7,

    /// A SID of unknown type (could not be determined).
    Unknown = 8,

    /// A SID that identifies a computer (machine account).
    Computer = 9,

    /// A mandatory integrity label SID.
    Label = 10,

    /// A logon session SID.
    LogonSession = 11,
}
